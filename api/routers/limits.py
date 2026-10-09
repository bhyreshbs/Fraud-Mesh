"""Two-person approval for payment-limit increases (v3 phase 10, insider controls).

    POST /v1/cases/{case_id}/limit-increase                          lead+   request an increase for the case's customer
    POST /v1/cases/{case_id}/limit-increase/{request_id}/approve     lead+   a DIFFERENT lead/admin approves it
    POST /v1/cases/{case_id}/limit-increase/{request_id}/reject      lead+   anyone lead+ (also the requester) rejects it
    GET  /v1/cases/{case_id}/limit-increase                          analyst+ the case's requests and their state

When the customer's case is at FM_LIMIT_TWO_PERSON_MIN_BAND (default MEDIUM) or above and FM_LIMIT_TWO_PERSON is on
(default 1), a request stays `pending_approval` until a second person approves it; the server refuses a self-approval
(403, audited LIMIT_SELF_APPROVAL_BLOCKED). Below that band (or with the control off) the request is applied at once.
Every case is queue-filtered (404 outside the caller's queues, audited CASE_ACCESS_DENIED by api/routers/cases.py).

State lives only in the hash-chained audit log (no new table): each request is one object_id `lim_…` with rows
LIMIT_INCREASE_REQUESTED → LIMIT_INCREASE_APPROVED | LIMIT_INCREASE_REJECTED → LIMIT_INCREASE_APPLIED. The app role can
only INSERT/SELECT audit rows, so a decision can never be edited after the fact. The bank's limit system itself is
outside FraudMesh: LIMIT_INCREASE_APPLIED is the instruction an integration would act on.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from api.db import session
from api.errors import ApiError
from api.routers.cases import _case_or_404, _engine_lock
from api.security import Principal, require_role
from engine.common.ids import new_id
from engine.contracts import BAND_ORDER

router = APIRouter(prefix="/v1/cases", tags=["limits"])
analyst = require_role("analyst")
lead = require_role("lead")
ACTIONS = ("LIMIT_INCREASE_REQUESTED", "LIMIT_INCREASE_APPROVED", "LIMIT_INCREASE_REJECTED", "LIMIT_INCREASE_APPLIED")


def two_person_enabled() -> bool:
    return os.getenv("FM_LIMIT_TWO_PERSON", "1").strip().lower() not in ("0", "false", "off", "no")


def two_person_min_band() -> str:
    band = os.getenv("FM_LIMIT_TWO_PERSON_MIN_BAND", "MEDIUM").strip().upper()
    return band if band in BAND_ORDER else "MEDIUM"


def requires_two_person(band: str) -> bool:
    return two_person_enabled() and BAND_ORDER.index(band) >= BAND_ORDER.index(two_person_min_band())


class LimitIncreaseBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_limit_paise: int = Field(gt=0, le=10**12)
    reason: str = Field(min_length=3, max_length=500)


class LimitDecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str | None = Field(default=None, max_length=500)


class LimitRequest(BaseModel):
    request_id: str
    case_id: str
    customer: str | None
    new_limit_paise: int
    reason: str
    status: str                      # pending_approval | applied | rejected
    requires_two_person: bool
    band_at_request: str
    requested_by: str
    decided_by: str | None = None
    requested_at: datetime
    decided_at: datetime | None = None


def _rows(case_id: str) -> list[dict]:
    with session.transaction() as c:
        return [dict(r) for r in c.execute(text(
            "SELECT ts, actor, action, object_id, details FROM audit_log WHERE action = ANY(:a) "
            "AND details->>'case_id' = :cid ORDER BY seq"), {"a": list(ACTIONS), "cid": case_id}).mappings()]


def _fold(rows: list[dict]) -> dict[str, LimitRequest]:
    out: dict[str, LimitRequest] = {}
    for r in rows:
        d, rid = r["details"], r["object_id"]
        if r["action"] == "LIMIT_INCREASE_REQUESTED":
            out[rid] = LimitRequest(request_id=rid, case_id=d["case_id"], customer=d.get("customer"),
                                    new_limit_paise=int(d["new_limit_paise"]), reason=d["reason"],
                                    status="pending_approval", requires_two_person=bool(d["requires_two_person"]),
                                    band_at_request=d["band"], requested_by=r["actor"], requested_at=r["ts"])
        elif rid in out and r["action"] == "LIMIT_INCREASE_REJECTED":
            out[rid] = out[rid].model_copy(update={"status": "rejected", "decided_by": r["actor"], "decided_at": r["ts"]})
        elif rid in out and r["action"] == "LIMIT_INCREASE_APPLIED":
            out[rid] = out[rid].model_copy(update={"status": "applied", "decided_by": d.get("approved_by", r["actor"]),
                                                   "decided_at": r["ts"]})
    return out


def _audit(store, actor: str, action: str, object_id: str, details: dict) -> None:
    store.append_audit(actor, action, object_id, details)


@router.get("/{case_id}/limit-increase", response_model=list[LimitRequest])
async def list_requests(case_id: str, p: Principal = Depends(analyst)) -> list[LimitRequest]:
    await _case_or_404(case_id, p)
    return list((await asyncio.to_thread(lambda: _fold(_rows(case_id)))).values())


@router.post("/{case_id}/limit-increase", response_model=LimitRequest, status_code=201)
async def request_increase(case_id: str, body: LimitIncreaseBody, request: Request,
                           p: Principal = Depends(lead)) -> LimitRequest:
    store = request.app.state.store
    async with _engine_lock(request):
        case = await _case_or_404(case_id, p)
        two = requires_two_person(case.band)
        rid = new_id("lim")
        details = {"case_id": case_id, "customer": case.customer, "new_limit_paise": body.new_limit_paise,
                   "reason": body.reason, "band": case.band, "requires_two_person": two,
                   "min_band": two_person_min_band()}

        def _write() -> None:
            with store.transaction():
                _audit(store, p.user_id, "LIMIT_INCREASE_REQUESTED", rid, details)
                if not two:                         # below the band: one person is enough, applied at once
                    _audit(store, p.user_id, "LIMIT_INCREASE_APPLIED", rid,
                           {"case_id": case_id, "approved_by": p.user_id, "single_person": True})
        await asyncio.to_thread(_write)
    return (await asyncio.to_thread(lambda: _fold(_rows(case_id))))[rid]


async def _pending(case_id: str, request_id: str) -> LimitRequest:
    req = (await asyncio.to_thread(lambda: _fold(_rows(case_id)))).get(request_id)
    if req is None:
        raise ApiError("NOT_FOUND", "limit request not found")
    if req.status != "pending_approval":
        raise ApiError("CONFLICT", f"limit request is already {req.status}")
    return req


@router.post("/{case_id}/limit-increase/{request_id}/approve", response_model=LimitRequest)
async def approve(case_id: str, request_id: str, request: Request, body: LimitDecisionBody | None = None,
                  p: Principal = Depends(lead)) -> LimitRequest:
    store = request.app.state.store
    async with _engine_lock(request):
        await _case_or_404(case_id, p)
        req = await _pending(case_id, request_id)
        if req.requested_by == p.user_id:           # server-side four-eyes rule: never trust the client for this
            await asyncio.to_thread(_audit, store, p.user_id, "LIMIT_SELF_APPROVAL_BLOCKED", request_id,
                                    {"case_id": case_id})
            raise ApiError("FORBIDDEN", "a limit increase must be approved by a different lead or admin")
        note = body.note if body else None

        def _write() -> None:
            with store.transaction():
                _audit(store, p.user_id, "LIMIT_INCREASE_APPROVED", request_id,
                       {"case_id": case_id, "requested_by": req.requested_by, "note": note})
                _audit(store, p.user_id, "LIMIT_INCREASE_APPLIED", request_id,
                       {"case_id": case_id, "approved_by": p.user_id, "requested_by": req.requested_by,
                        "new_limit_paise": req.new_limit_paise})
        await asyncio.to_thread(_write)
    return (await asyncio.to_thread(lambda: _fold(_rows(case_id))))[request_id]


@router.post("/{case_id}/limit-increase/{request_id}/reject", response_model=LimitRequest)
async def reject(case_id: str, request_id: str, request: Request, body: LimitDecisionBody | None = None,
                 p: Principal = Depends(lead)) -> LimitRequest:
    store = request.app.state.store
    async with _engine_lock(request):
        await _case_or_404(case_id, p)
        await _pending(case_id, request_id)
        await asyncio.to_thread(_audit, store, p.user_id, "LIMIT_INCREASE_REJECTED", request_id,
                                {"case_id": case_id, "note": body.note if body else None})
    return (await asyncio.to_thread(lambda: _fold(_rows(case_id))))[request_id]
