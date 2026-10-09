"""POST /v1/events and /v1/events/batch (PRD §7.2, §9.2).

Order: size check -> signature verify (HMAC, or opt-in Ed25519: api/keys.py) -> client-cert check (FM_REQUIRE_CLIENT_CERT=1)
-> Envelope validate -> to_stored_event -> INSERT … ON CONFLICT DO NOTHING -> enqueue.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from pydantic import ValidationError

from api import keys
from api.errors import ApiError
from api.ratelimit import INGEST_LIMIT, limiter, per_source
from api.schemas import BatchRejected, BatchResponse, EventAccepted
from api.signing import signature, signed_headers
from engine.common.settings import settings
from engine.common.tokenize import to_stored_event
from engine.contracts import Envelope, StoredEvent

router = APIRouter(prefix="/v1", tags=["ingest"])

MAX_EVENT_BYTES = 64 * 1024
MAX_BATCH_EVENTS = 500
MAX_BATCH_BYTES = 8 * 1024 * 1024
MAX_SKEW_S = 300


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise ApiError("PAYLOAD_TOO_LARGE", f"body exceeds {limit} bytes")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise ApiError("PAYLOAD_TOO_LARGE", f"body exceeds {limit} bytes")
    return bytes(body)


def verify_signature(headers, body: bytes) -> str:
    """Returns the verified source. Raises SIGNATURE_INVALID / STALE_TIMESTAMP.

    X-FM-Signature-Alg selects the rule: absent or "hmac" -> PRD §7.2 HMAC; "ed25519" -> Ed25519 over the same message
    with <source>.pub from FM_SIGNING_PUBLIC_KEY_DIR. FM_INGEST_AUTH (hmac | ed25519 | any, default any) limits which
    algorithms are accepted."""
    source = headers.get("x-fm-source", "")
    ts = headers.get("x-fm-timestamp", "")
    sig = headers.get("x-fm-signature", "")
    alg = (headers.get("x-fm-signature-alg") or "hmac").strip().lower()
    mode = keys.ingest_auth_mode()
    if alg not in keys.ALGS or (mode != "any" and alg != mode):
        raise ApiError("SIGNATURE_INVALID", f"signature algorithm not accepted (FM_INGEST_AUTH={mode})")
    if alg == "ed25519":
        pub = keys.public_key(source)
        if pub is None or not ts.isdigit() or not sig:
            raise ApiError("SIGNATURE_INVALID", "missing or unknown signature headers")
        if not keys.ed25519_verify(pub, ts, body, sig.lower()):
            raise ApiError("SIGNATURE_INVALID", "signature does not match body")
    else:
        secret = settings.hmac_secrets.get(source)
        if not secret or not ts.isdigit() or not sig:
            raise ApiError("SIGNATURE_INVALID", "missing or unknown signature headers")
        if not hmac.compare_digest(signature(secret, ts, body), sig.lower()):
            raise ApiError("SIGNATURE_INVALID", "signature does not match body")
    if abs(time.time() - int(ts)) > MAX_SKEW_S:
        raise ApiError("STALE_TIMESTAMP", "timestamp is more than 300 s from server time")
    return source


def verify_client_cert(headers, source: str) -> None:
    """FM_REQUIRE_CLIENT_CERT=1: the TLS proxy (deploy/nginx-proxy.conf) verified a client certificate issued by the
    local CA, and its CN names the signing source. The proxy overwrites X-Client-Cert-Verify / X-Client-Cert-DN on every
    request, so enable this only when the API is reachable through that proxy alone (as in deploy/docker-compose.yml)."""
    if not keys.require_client_cert():
        return
    if headers.get("x-client-cert-verify", "") != "SUCCESS":
        raise ApiError("SIGNATURE_INVALID", "a verified client certificate is required")
    if keys.client_cert_cn(headers.get("x-client-cert-dn", "")) != source:
        raise ApiError("SIGNATURE_INVALID", "client certificate CN does not match X-FM-Source")


async def accept_envelope(app, env: Envelope) -> StoredEvent:
    """Tokenize, store and enqueue one already-authenticated envelope. Refused with 503 while the worker's backlog is
    full, before anything is stored, so a flood can neither exhaust memory nor leave stored-but-unqueued events."""
    worker = getattr(app.state, "worker", None)
    if worker is not None and worker.backlog_full():
        raise ApiError("ENGINE_UNAVAILABLE", "event backlog is full; retry later")
    try:
        stored = to_stored_event(env, datetime.now(UTC))
    except ValidationError as e:
        raise ApiError("VALIDATION_FAILED", f"payload: {e.errors()[0].get('msg', 'invalid')}") from e
    inserted = await asyncio.to_thread(app.state.store.insert_event, stored)
    if not inserted:
        raise ApiError("DUPLICATE_EVENT", f"event {env.event_id} was already ingested")
    if settings.demo_mode:
        _remember_demo(env)
    app.state.enqueue(stored)
    return stored


def _remember_demo(env: Envelope) -> None:
    """DEMO_MODE only, memory only: keep the raw customer ref, last app context and swapped SMS number so step-up
    OTPs reach the right simulated phone whether the event came from the bank app or a signed sender (autopilot)."""
    from api.demo_identities import demo_state
    cust = demo_state.remember(env.subject.customer_ref, env.context.model_dump(exclude_none=True) if env.source == "demo-bank-web" else {})
    if cust and env.event_type == "mfa_change" and env.payload.get("factor") == "sms" and env.payload.get("new_phone"):
        demo_state.phone[cust] = str(env.payload["new_phone"])


def server_headers(source: str, body: bytes) -> dict[str, str]:
    """Signature headers built inside the API for events it emits itself (same rule as scripts/sign.py, PRD §7.2).
    Ed25519 when this source's private key exists in FM_SIGNING_KEY_DIR and FM_INGEST_AUTH allows it, else HMAC."""
    mode = keys.ingest_auth_mode()
    priv = keys.private_key(source) if mode != "hmac" else None
    if priv is not None:
        return keys.ed25519_signed_headers(source, priv, body)
    if mode == "ed25519":
        raise ApiError("ENGINE_UNAVAILABLE", f"FM_INGEST_AUTH=ed25519 but there is no signing key for {source}", 503)
    return signed_headers(source, settings.hmac_secrets[source], body)


async def ingest_server_side(app, env: Envelope) -> StoredEvent:
    """Events the API builds itself (/v1/demo/emit, step_up_result): sign with the source's key, verify, ingest.
    The demo bank app never holds a secret (PRD §7.2); the server signs on its behalf."""
    body = env.model_dump_json().encode()
    verify_signature({k.lower(): v for k, v in server_headers(env.source, body).items()}, body)
    return await accept_envelope(app, Envelope.model_validate_json(body))


@router.post("/events", status_code=202, response_model=EventAccepted)
@limiter.limit(INGEST_LIMIT, key_func=per_source)
async def ingest_event(request: Request) -> EventAccepted:
    body = await _read_body(request, MAX_EVENT_BYTES)
    source = verify_signature(request.headers, body)
    verify_client_cert(request.headers, source)
    try:
        env = Envelope.model_validate_json(body)
    except ValidationError as e:
        first = e.errors()[0]
        raise ApiError("VALIDATION_FAILED", f"{'.'.join(map(str, first['loc']))}: {first['msg']}") from e
    if env.source != source:
        raise ApiError("SIGNATURE_INVALID", "X-FM-Source does not match envelope.source")
    await accept_envelope(request.app, env)
    return EventAccepted(event_id=env.event_id)


@router.post("/events/batch", status_code=202, response_model=BatchResponse)
@limiter.limit(INGEST_LIMIT, key_func=per_source)
async def ingest_batch(request: Request) -> BatchResponse:
    body = await _read_body(request, MAX_BATCH_BYTES)
    source = verify_signature(request.headers, body)
    verify_client_cert(request.headers, source)
    try:
        raw = json.loads(body)
        items = raw["events"]
        assert isinstance(items, list)
    except (ValueError, KeyError, TypeError, AssertionError) as e:
        raise ApiError("VALIDATION_FAILED", 'body must be {"events": [Envelope, …]}') from e
    if len(items) > MAX_BATCH_EVENTS:
        raise ApiError("PAYLOAD_TOO_LARGE", f"at most {MAX_BATCH_EVENTS} events per batch")
    accepted, rejected = 0, []
    for item in items:
        event_id = str(item.get("event_id", "")) if isinstance(item, dict) else ""
        try:
            env = Envelope.model_validate(item)
            if env.source != source:
                raise ApiError("SIGNATURE_INVALID", "source mismatch")
            await accept_envelope(request.app, env)
            accepted += 1
        except ValidationError:
            rejected.append(BatchRejected(event_id=event_id, code="VALIDATION_FAILED"))
        except ApiError as e:
            rejected.append(BatchRejected(event_id=event_id, code=e.code))
    return BatchResponse(accepted=accepted, rejected=rejected)
