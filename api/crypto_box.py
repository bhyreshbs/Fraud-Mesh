"""Field-level encryption at rest (v3 phase 14): AES-256-GCM with versioned keys and associated-data binding.

Keys come from the environment, read at call time (never from code or git):
    FM_DATA_KEYS        JSON object {kid: 64 hex chars}, e.g. {"k2026a": "<hex>", "k2026b": "<hex>"}
    FM_DATA_KEY_ACTIVE  the kid new values are encrypted with (must be a key of FM_DATA_KEYS)
Neither set -> encryption is OFF and values are stored as plaintext, exactly as before (the default).

Ciphertext format (a text column / JSON string):  fmenc:v1:<kid>:<base64url(nonce12 || ciphertext || tag16)>
Associated data binds a value to where it lives:   b"fraudmesh/v1|<table>|<column>|<row id>"
so a ciphertext copied into another row or column fails authentication instead of decrypting.

Rotation: add a new kid to FM_DATA_KEYS and point FM_DATA_KEY_ACTIVE at it. Old values still decrypt with their own
kid; new writes use the active one; reencrypt() moves a value to the active key. Remove an old kid only after every
value under it has been re-encrypted.

Values that do not start with the prefix are treated as legacy plaintext and returned unchanged, so turning
encryption on needs no data migration.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "fmenc:v1:"
_KID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
NONCE_BYTES = 12

# Audit rows keep a SHA-256 of these free-text fields instead of the text when encryption is on (see redact_audit()).
AUDIT_SENSITIVE_FIELDS = {"FEEDBACK": "note", "MANUAL_ACTION": "reason"}


class CryptoConfigError(RuntimeError):
    """FM_DATA_KEYS / FM_DATA_KEY_ACTIVE are set but invalid. Fails closed: nothing is written in plaintext by mistake."""


class DecryptError(RuntimeError):
    """Wrong key, unknown kid, tampered ciphertext or a value moved to another row/column."""


def _keys() -> tuple[dict[str, bytes], str | None]:
    raw = (os.getenv("FM_DATA_KEYS") or "").strip()
    active = (os.getenv("FM_DATA_KEY_ACTIVE") or "").strip() or None
    if not raw:
        if active:
            raise CryptoConfigError("FM_DATA_KEY_ACTIVE is set but FM_DATA_KEYS is empty")
        return {}, None
    try:
        parsed = json.loads(raw)
    except ValueError as e:
        raise CryptoConfigError("FM_DATA_KEYS must be a JSON object {kid: hex}") from e
    if not isinstance(parsed, dict) or not parsed:
        raise CryptoConfigError("FM_DATA_KEYS must be a non-empty JSON object {kid: hex}")
    keys: dict[str, bytes] = {}
    for kid, hexkey in parsed.items():
        if not isinstance(kid, str) or not _KID_RE.match(kid):
            raise CryptoConfigError("FM_DATA_KEYS: key ids must match [A-Za-z0-9_-]{1,32}")
        try:
            key = bytes.fromhex(str(hexkey))
        except ValueError as e:
            raise CryptoConfigError(f"FM_DATA_KEYS[{kid}] is not hex") from e
        if len(key) != 32:
            raise CryptoConfigError(f"FM_DATA_KEYS[{kid}] must be 32 bytes (64 hex chars) for AES-256")
        keys[kid] = key
    if active is None:
        raise CryptoConfigError("FM_DATA_KEYS is set but FM_DATA_KEY_ACTIVE is not")
    if active not in keys:
        raise CryptoConfigError("FM_DATA_KEY_ACTIVE names a kid that is not in FM_DATA_KEYS")
    return keys, active


def enabled() -> bool:
    """True when an active data key is configured (raises CryptoConfigError on a broken configuration)."""
    return _keys()[1] is not None


def _aad(table: str, column: str, row_id: str) -> bytes:
    for part in (table, column, row_id):
        if "|" in part:
            raise ValueError("associated-data parts must not contain '|'")
    return f"fraudmesh/v1|{table}|{column}|{row_id}".encode()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def is_encrypted(value: object) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt_text(plaintext: str, *, table: str, column: str, row_id: str) -> str:
    """Encrypt with the active key. Encryption off -> the plaintext is returned unchanged."""
    keys, active = _keys()
    if active is None:
        return plaintext
    nonce = secrets.token_bytes(NONCE_BYTES)                 # 96-bit random nonce per value (NIST SP 800-38D)
    ct = AESGCM(keys[active]).encrypt(nonce, plaintext.encode("utf-8"), _aad(table, column, row_id))
    return f"{PREFIX}{active}:{_b64e(nonce + ct)}"


def decrypt_text(value: str, *, table: str, column: str, row_id: str) -> str:
    """Decrypt a value written by encrypt_text (any configured kid). Plaintext (legacy / encryption off) passes through."""
    if not is_encrypted(value):
        return value
    try:
        kid, blob = value[len(PREFIX):].split(":", 1)
        raw = _b64d(blob)
    except ValueError as e:
        raise DecryptError("malformed ciphertext") from e
    keys, _ = _keys()
    key = keys.get(kid)
    if key is None:
        raise DecryptError(f"no data key configured for kid {kid!r}")
    if len(raw) < NONCE_BYTES + 16:
        raise DecryptError("malformed ciphertext")
    try:
        return AESGCM(key).decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], _aad(table, column, row_id)).decode("utf-8")
    except InvalidTag as e:
        raise DecryptError("ciphertext failed authentication (wrong key, tampered, or bound to another row)") from e


def key_id_of(value: str) -> str | None:
    return value[len(PREFIX):].split(":", 1)[0] if is_encrypted(value) else None


def reencrypt(value: str, *, table: str, column: str, row_id: str) -> str:
    """Key rotation: re-encrypt a stored value under the active key (plaintext gets encrypted if encryption is on)."""
    plain = decrypt_text(value, table=table, column=column, row_id=row_id)
    return encrypt_text(plain, table=table, column=column, row_id=row_id)


def sha256_hex(text: str) -> str:
    """Integrity digest of a free-text field, for audit rows. A hash, NOT encryption: a short or guessable text can be
    confirmed by hashing a guess. It lets an auditor holding the decrypted value prove it matches the audit row."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def redact_audit(action: str, details: dict) -> dict:
    """With encryption on, audit details keep `<field>_sha256` instead of analyst free text (FEEDBACK.note,
    MANUAL_ACTION.reason): the audit chain stays verifiable and append-only, and the text itself lives only encrypted
    (decisions.data.override_reason, feedback.note). Encryption off -> details unchanged (plaintext, as before)."""
    field = AUDIT_SENSITIVE_FIELDS.get(action)
    if field is None or not enabled() or not isinstance(details.get(field), str):
        return details
    out = {k: v for k, v in details.items() if k != field}
    out[f"{field}_sha256"] = sha256_hex(details[field])
    return out


def generate_key_hex() -> str:
    """Helper for operators: python -c "from api.crypto_box import generate_key_hex as g; print(g())"."""
    return secrets.token_hex(32)
