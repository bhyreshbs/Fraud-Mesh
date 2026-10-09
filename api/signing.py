"""The ingestion signature rule (PRD §7.2), in one place: the API verifies with it and signs its own events with it,
and scripts/sign.py builds sender headers with it. Standard library only, so any sender can import it.

X-FM-Signature = hex(HMAC-SHA256(key=bytes.fromhex(secret_hex), msg=timestamp + "." + raw_body_bytes))
"""
from __future__ import annotations

import hashlib
import hmac
import time


def signature(secret_hex: str, timestamp: str, body: bytes) -> str:
    return hmac.new(bytes.fromhex(secret_hex), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def signed_headers(source: str, secret_hex: str, body: bytes, timestamp: int | None = None) -> dict[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    return {"X-FM-Source": source, "X-FM-Timestamp": ts, "X-FM-Signature": signature(secret_hex, ts, body),
            "Content-Type": "application/json"}
