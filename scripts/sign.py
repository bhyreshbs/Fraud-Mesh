"""The only code that builds ingestion signature headers for senders (PRD §7.2). The rule itself lives in api/signing.py,
which the API also verifies with, so the two can never drift apart.

X-FM-Signature = hex(HMAC-SHA256(key=bytes.fromhex(HMAC_SECRETS[source]), msg=timestamp + "." + raw_body_bytes))
"""
from __future__ import annotations

from api.signing import signature, signed_headers
from engine.common.settings import settings

__all__ = ["sign", "signature"]


def sign(source: str, body_bytes: bytes, timestamp: int | None = None) -> dict[str, str]:
    return signed_headers(source, settings.hmac_secrets[source], body_bytes, timestamp)
