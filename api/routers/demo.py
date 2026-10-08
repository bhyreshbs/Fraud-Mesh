"""/v1/demo/* (PRD §9.5), only mounted when DEMO_MODE=1. Phase 0 stubs returning contract shapes; real in D1-P2/D1-P5."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.schemas import (
    DemoEmitRequest,
    DemoEmitResponse,
    PaymentStatus,
    PendingResponse,
    RespondRequest,
    RespondResponse,
    RunRequest,
    RunResponse,
    SmsInbox,
    StatusOk,
)
from api.security import Principal, require_role
from engine.common.ids import new_id

router = APIRouter(prefix="/v1/demo", tags=["demo"])


@router.post("/emit", response_model=DemoEmitResponse)
async def emit(body: DemoEmitRequest) -> DemoEmitResponse:
    return DemoEmitResponse(event_id=new_id("evt"))


@router.get("/payment-status/{event_id}", response_model=PaymentStatus)
async def payment_status(event_id: str) -> PaymentStatus:
    return PaymentStatus(outcome="pending")


@router.get("/step-up/pending", response_model=PendingResponse)
async def pending(customer_ref: str, channel: str = "app") -> PendingResponse:
    return PendingResponse(challenge=None)


@router.get("/sms-inbox", response_model=SmsInbox)
async def sms_inbox(phone: str) -> SmsInbox:
    return SmsInbox(messages=[])


@router.post("/step-up/{challenge_id}/respond", response_model=RespondResponse)
async def respond(challenge_id: str, body: RespondRequest) -> RespondResponse:
    return RespondResponse(status="pending")


@router.post("/run/{scenario_id}", response_model=RunResponse)
async def run(scenario_id: str, body: RunRequest, p: Principal = Depends(require_role("admin"))) -> RunResponse:
    return RunResponse(run_id=new_id("run"))


@router.post("/reset", response_model=StatusOk)
async def reset(p: Principal = Depends(require_role("admin"))) -> StatusOk:
    return StatusOk()
