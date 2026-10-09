"""Asymmetric keys for ingestion signatures and access tokens (opt-in; see docs/CONTRACT_REQUESTS.md, 2026-10-10).

Ed25519 ingestion signatures: same message as the HMAC rule in api/signing.py (timestamp + "." + raw_body_bytes), the
signature is lowercase hex (128 chars) and the request carries `X-FM-Signature-Alg: ed25519` (absent means hmac).
Public keys are `<FM_SIGNING_PUBLIC_KEY_DIR>/<source>.pub`, private keys `<FM_SIGNING_KEY_DIR>/<source>.key` (PEM,
written by scripts/make_certs.py). Every env var is read at call time, so tests can switch modes with monkeypatch.

FM_INGEST_AUTH: hmac | ed25519 | any (default any: accept either algorithm).
"""
from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from typing import get_args

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from engine.contracts import Source

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KEY_DIR = "data/keys"
ALG_HEADER = "X-FM-Signature-Alg"
ALGS = ("hmac", "ed25519")
INGEST_MODES = ("hmac", "ed25519", "any")
SOURCES: tuple[str, ...] = get_args(Source)          # the only names ever turned into key file paths

_cache: dict[tuple[str, int, int], object] = {}
_lock = threading.Lock()


def resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else ROOT / p


def ingest_auth_mode() -> str:
    mode = (os.getenv("FM_INGEST_AUTH") or "any").strip().lower()
    return mode if mode in INGEST_MODES else "any"


def _load(path: Path, private: bool):
    """PEM key from disk, cached by (path, mtime, size) so a regenerated key is picked up without a restart."""
    try:
        st = path.stat()
    except OSError:
        return None
    k = (str(path), st.st_mtime_ns, st.st_size)
    with _lock:
        if k in _cache:
            return _cache[k]
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None) if private else serialization.load_pem_public_key(data)
    with _lock:
        _cache[k] = key
    return key


def _source_key(source: str, private: bool):
    if source not in SOURCES:
        return None
    env = "FM_SIGNING_KEY_DIR" if private else "FM_SIGNING_PUBLIC_KEY_DIR"
    path = resolve(os.getenv(env) or DEFAULT_KEY_DIR) / f"{source}.{'key' if private else 'pub'}"
    key = _load(path, private)
    want = Ed25519PrivateKey if private else Ed25519PublicKey
    return key if isinstance(key, want) else None


def public_key(source: str) -> Ed25519PublicKey | None:
    return _source_key(source, private=False)


def private_key(source: str) -> Ed25519PrivateKey | None:
    return _source_key(source, private=True)


def ed25519_signature(key: Ed25519PrivateKey, timestamp: str, body: bytes) -> str:
    return key.sign(timestamp.encode() + b"." + body).hex()


_HEX128 = re.compile(r"^[0-9a-fA-F]{128}$")


def ed25519_verify(key: Ed25519PublicKey, timestamp: str, body: bytes, sig_hex: str) -> bool:
    if not _HEX128.match(sig_hex):
        return False
    try:
        key.verify(bytes.fromhex(sig_hex), timestamp.encode() + b"." + body)
        return True
    except InvalidSignature:
        return False


def ed25519_signed_headers(source: str, key: Ed25519PrivateKey, body: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    return {"X-FM-Source": source, "X-FM-Timestamp": ts, "X-FM-Signature": ed25519_signature(key, ts, body),
            ALG_HEADER: "ed25519", "Content-Type": "application/json"}


# ------------------------------------------------------------------ JWT keys (FM_JWT_ALG=EdDSA)
def jwt_private_key() -> Ed25519PrivateKey | None:
    key = _load(resolve(os.getenv("FM_JWT_PRIVATE_KEY") or f"{DEFAULT_KEY_DIR}/jwt.key"), private=True)
    return key if isinstance(key, Ed25519PrivateKey) else None


def jwt_public_key() -> Ed25519PublicKey | None:
    key = _load(resolve(os.getenv("FM_JWT_PUBLIC_KEY") or f"{DEFAULT_KEY_DIR}/jwt.pub"), private=False)
    return key if isinstance(key, Ed25519PublicKey) else None


# ------------------------------------------------------------------ mTLS (FM_REQUIRE_CLIENT_CERT=1, behind the proxy)
_RDN_SPLIT = re.compile(r"(?<!\\)[,/+]")


def client_cert_cn(dn: str) -> str | None:
    """The single CN in nginx's $ssl_client_s_dn (RFC 2253, e.g. "CN=network-ids,O=FraudMesh Demo"; the legacy
    format was "/O=../CN=.."). Escaped separators never split an RDN; zero or several CNs give None."""
    cns = [p.strip()[3:] for p in _RDN_SPLIT.split(dn or "") if p.strip().upper().startswith("CN=")]
    return cns[0] if len(cns) == 1 else None


def require_client_cert() -> bool:
    return os.getenv("FM_REQUIRE_CLIENT_CERT", "0").strip() == "1"
