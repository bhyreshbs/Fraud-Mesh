"""The only code that builds ingestion signature headers (PRD §7.2).

X-FM-Signature = hex(HMAC-SHA256(key=bytes.fromhex(HMAC_SECRETS[source]), msg=timestamp + "." + raw_body_bytes))
"""
from __future__ import annotations

import hashlib
import hmac
import time

from engine.common.settings import settings


def signature(secret_hex: str, timestamp: str, body: bytes) -> str:
    return hmac.new(bytes.fromhex(secret_hex), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def sign(source: str, body_bytes: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    return {"X-FM-Source": source, "X-FM-Timestamp": ts,
            "X-FM-Signature": signature(settings.hmac_secrets[source], ts, body_bytes),
            "Content-Type": "application/json"}
