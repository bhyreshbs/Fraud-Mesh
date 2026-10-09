"""The only code that builds ingestion signature headers for senders (PRD §7.2). The rule itself lives in api/signing.py
(HMAC) and api/keys.py (opt-in Ed25519), which the API also verifies with, so the two can never drift apart.

X-FM-Signature = hex(HMAC-SHA256(key=bytes.fromhex(HMAC_SECRETS[source]), msg=timestamp + "." + raw_body_bytes))

Opt-in Ed25519: with FM_SIGN_ALG=ed25519 and <FM_SIGNING_KEY_DIR (default data/keys)>/<source>.key present (written by
scripts/make_certs.py), X-FM-Signature is the hex Ed25519 signature of the same message and X-FM-Signature-Alg: ed25519
is added. Otherwise HMAC, exactly as before.
"""
from __future__ import annotations

import os

from api.signing import signature, signed_headers
from engine.common.settings import settings

__all__ = ["sign", "signature"]


def sign(source: str, body_bytes: bytes, timestamp: int | None = None) -> dict[str, str]:
    if (os.getenv("FM_SIGN_ALG") or "hmac").strip().lower() == "ed25519":
        from api import keys  # imported lazily: the HMAC path needs only the standard library
        priv = keys.private_key(source)
        if priv is not None:
            return keys.ed25519_signed_headers(source, priv, body_bytes, timestamp)
    return signed_headers(source, settings.hmac_secrets[source], body_bytes, timestamp)
