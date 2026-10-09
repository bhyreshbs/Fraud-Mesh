"""GET /v1/cases/{case_id}/payments — read-only payment-rail state per transaction of a case (opt-in addition,
docs/CONTRACT_REQUESTS.md). Role analyst or higher; a case outside the caller's queues is a 404 like every case route."""
from __future__ import annotations

import asyncio
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from api import queries
from api.errors import ApiError
from api.payments import service
from api.security import Principal, require_role
from engine.contracts import PaymentOutcome

router = APIRouter(prefix="/v1/cases", tags=["payments"])


class CasePayment(BaseModel):
    event_id: str
    outcome: PaymentOutcome
    amount_paise: int | None = None
    rail: str | None = None                # mock | paypal_sandbox; null when the payment was not mirrored
    auth_id: str | None = None
    state: str | None = None               # CREATED | AUTHORIZED | CAPTURED | VOIDED
    target: str | None = None
    currency: str | None = None
    attempts: int = 0
    last_error: str | None = None
    updated_at: datetime | None = None


class CasePayments(BaseModel):
    case_id: str
    rail: str                              # the configured rail: mock | paypal_sandbox | off
    items: list[CasePayment]


@router.get("/{case_id}/payments", response_model=CasePayments)
async def case_payments(case_id: str, request: Request, p: Principal = Depends(require_role("analyst"))) -> CasePayments:
    if await asyncio.to_thread(queries.case_in_queues, case_id, list(p.queues)) is None:
        raise ApiError("NOT_FOUND", "case not found")
    rows = await asyncio.to_thread(service.list_for_case, case_id)
    dispatcher = getattr(request.app.state, "payments", None)
    return CasePayments(case_id=case_id, rail=dispatcher.config.mode if dispatcher else "off",
                        items=[CasePayment(**{**r, "attempts": r.get("attempts") or 0}) for r in rows])
