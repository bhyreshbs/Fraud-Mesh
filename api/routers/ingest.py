"""POST /v1/events and /v1/events/batch (PRD §7.2, §9.2).

Order: size check -> HMAC verify -> Envelope validate -> to_stored_event -> INSERT … ON CONFLICT DO NOTHING -> enqueue.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from pydantic import ValidationError

from api.errors import ApiError
from api.schemas import BatchRejected, BatchResponse, EventAccepted
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


def _expected(secret_hex: str, ts: str, body: bytes) -> str:
    return hmac.new(bytes.fromhex(secret_hex), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify_signature(headers, body: bytes) -> str:
    """Returns the verified source. Raises SIGNATURE_INVALID / STALE_TIMESTAMP."""
    source = headers.get("x-fm-source", "")
    ts = headers.get("x-fm-timestamp", "")
    sig = headers.get("x-fm-signature", "")
    secret = settings.hmac_secrets.get(source)
    if not secret or not ts.isdigit() or not sig:
        raise ApiError("SIGNATURE_INVALID", "missing or unknown signature headers")
    if not hmac.compare_digest(_expected(secret, ts, body), sig.lower()):
        raise ApiError("SIGNATURE_INVALID", "signature does not match body")
    if abs(time.time() - int(ts)) > MAX_SKEW_S:
        raise ApiError("STALE_TIMESTAMP", "timestamp is more than 300 s from server time")
    return source


async def accept_envelope(app, env: Envelope) -> StoredEvent:
    """Tokenize, store and enqueue one already-authenticated envelope."""
    try:
        stored = to_stored_event(env, datetime.now(UTC))
    except ValidationError as e:
        raise ApiError("VALIDATION_FAILED", f"payload: {e.errors()[0].get('msg', 'invalid')}") from e
    inserted = await asyncio.to_thread(app.state.store.insert_event, stored)
    if not inserted:
        raise ApiError("DUPLICATE_EVENT", f"event {env.event_id} was already ingested")
    app.state.enqueue(stored)
    return stored


async def ingest_server_side(app, env: Envelope) -> StoredEvent:
    """Events the API builds itself (/v1/demo/emit, step_up_result): sign with the source's key, verify, ingest.
    The demo bank app never holds a secret (PRD §7.2); the server signs on its behalf."""
    body = env.model_dump_json().encode()
    ts = str(int(time.time()))
    headers = {"x-fm-source": env.source, "x-fm-timestamp": ts,
               "x-fm-signature": _expected(settings.hmac_secrets[env.source], ts, body)}
    verify_signature(headers, body)
    return await accept_envelope(app, Envelope.model_validate_json(body))


@router.post("/events", status_code=202, response_model=EventAccepted)
async def ingest_event(request: Request) -> EventAccepted:
    body = await _read_body(request, MAX_EVENT_BYTES)
    source = verify_signature(request.headers, body)
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
async def ingest_batch(request: Request) -> BatchResponse:
    body = await _read_body(request, MAX_BATCH_BYTES)
    source = verify_signature(request.headers, body)
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
