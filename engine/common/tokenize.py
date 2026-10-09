# engine/common/tokenize.py — the only place raw identifiers become tokens
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
from datetime import datetime, timezone

from engine.common.settings import settings
from engine.contracts import TOKENIZED_PAYLOAD_FIELDS, Envelope, StoredEvent, validate_payload


def _norm(kind: str, raw: str) -> str:
    v = raw.strip()
    if kind == "email":
        return v.lower()
    if kind == "phone":
        return "".join(c for c in v if c.isdigit())[-10:]
    if kind == "ip":
        ip = ipaddress.ip_address(v)
        prefix = 24 if ip.version == 4 else 64
        return str(ipaddress.ip_network(f"{v}/{prefix}", strict=False))
    if kind in ("acct", "cust"):
        return v.upper().replace(" ", "")
    return v


def tok(kind: str, raw: str) -> str:
    digest = hmac.new(bytes.fromhex(settings.token_key), f"{kind}:{_norm(kind, raw)}".encode(), hashlib.sha256).digest()
    return f"{kind}:{base64.b32encode(digest).decode().lower()[:16]}"


def to_stored_event(env: Envelope, received_at: datetime, network: dict | None = None) -> StoredEvent:
    """`network` (1.1.0, optional): enrichment of the RAW ip computed by the caller before this call, with keys
    network_type, network_source, network_confidence, ip_timezone. The raw ip never leaves this function untokenized."""
    validate_payload(env.event_type, env.payload)          # raises pydantic.ValidationError -> 422
    payload = dict(env.payload)
    tokens: set[str] = set()
    for (etype, fname), kind in TOKENIZED_PAYLOAD_FIELDS.items():
        if etype == env.event_type and payload.get(fname):
            payload[fname] = tok(kind, str(payload[fname]))
            tokens.add(payload[fname])
    cust = tok("cust", env.subject.customer_ref) if env.subject.customer_ref else None
    acct = tok("acct", env.subject.account_ref) if env.subject.account_ref else None
    ip = tok("ip", env.context.ip) if env.context.ip else None
    dev = tok("dev", env.context.device_id) if env.context.device_id else None
    ses = tok("ses", env.context.session_id) if env.context.session_id else None
    tokens |= {t for t in (cust, acct, ip, dev, ses) if t}
    ctx = env.context
    net = {k: v for k, v in (network or {}).items()
           if k in ("network_type", "network_source", "network_confidence", "ip_timezone")}
    return StoredEvent(
        event_id=env.event_id, event_type=env.event_type, source=env.source,
        occurred_at=env.occurred_at.astimezone(timezone.utc), received_at=received_at.astimezone(timezone.utc),
        customer=cust, account=acct, ip=ip, device=dev, asn=env.context.asn, city=env.context.city,
        lat=env.context.lat, lon=env.context.lon, payload=payload, entity_tokens=sorted(tokens),
        session=ses, browser_timezone=ctx.browser_timezone, locale=ctx.locale, platform=ctx.platform,
        webgl_renderer=ctx.webgl_renderer, screen=ctx.screen, telemetry=ctx.telemetry, **net,
    )
