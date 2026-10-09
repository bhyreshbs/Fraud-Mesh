"""/v1/cases/* (PRD §9.3). Role analyst or higher; every case is filtered by the caller's queues and anything
outside them is a 404 (not 403), so case IDs cannot be probed. engine.api KeyError is also a 404."""
from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request

from api import engine_calls, queries, stepup
from api.errors import ApiError
from api.investigator import templates, validator
from api.investigator.tools import CaseTools
from api.schemas import (
    ActionsRequest,
    AskRequest,
    AskResponse,
    CaseDetail,
    CasesPage,
    ChallengeInfo,
    FeedbackRequest,
    ReplayRequest,
    Timeline,
)
from api.security import Principal, require_role
from engine import api as engine_api
from engine.common.ids import new_id
from engine.contracts import (
    Band,
    Case,
    CaseStatus,
    CaseUpdate,
    Decision,
    Explanation,
    FeedbackResult,
    GraphElements,
    ReplayResult,
    summarize,
)

router = APIRouter(prefix="/v1/cases", tags=["cases"])
analyst = require_role("analyst")
lead = require_role("lead")


async def _case_or_404(case_id: str, p: Principal) -> Case:
    case = await asyncio.to_thread(queries.case_in_queues, case_id, list(p.queues))
    if case is None:
        raise ApiError("NOT_FOUND", "case not found")
    return case


def _engine_lock(request: Request) -> asyncio.Lock:
    """The worker's lock (api/worker.py): held while the pipeline's memory is read or a case is rewritten."""
    return request.app.state.worker.engine_lock


@router.get("", response_model=CasesPage)
async def list_cases(status: CaseStatus | None = None, band: Band | None = None, limit: int = Query(50, ge=1, le=200),
                     cursor: str | None = Query(None, max_length=20), p: Principal = Depends(analyst)) -> CasesPage:
    offset = 0
    if cursor:
        m = re.fullmatch(r"o(\d{1,9})", cursor)
        if not m:
            raise ApiError("VALIDATION_FAILED", "cursor: invalid")
        offset = int(m.group(1))
    cases, nxt = await asyncio.to_thread(queries.list_cases, list(p.queues), status, band, limit, offset)
    return CasesPage(items=[summarize(c) for c in cases], next_cursor=nxt)


@router.get("/{case_id}", response_model=CaseDetail)
async def get_case(case_id: str, p: Principal = Depends(analyst)) -> CaseDetail:
    case = await _case_or_404(case_id, p)
    return CaseDetail(case=case, summary=summarize(case))


@router.get("/{case_id}/timeline", response_model=Timeline)
async def get_timeline(case_id: str, request: Request, p: Principal = Depends(analyst)) -> Timeline:
    await _case_or_404(case_id, p)
    store = request.app.state.store
    evidence, decisions, challenges = await asyncio.gather(
        asyncio.to_thread(store.list_evidence, case_id), asyncio.to_thread(store.list_decisions, case_id),
        asyncio.to_thread(stepup.challenges_for_case, case_id))
    return Timeline(evidence=evidence, decisions=decisions,
                    challenges=[ChallengeInfo(challenge_id=c["challenge_id"], method=c["method"], status=c["status"],
                                              created_at=c["created_at"]) for c in challenges])


@router.get("/{case_id}/graph", response_model=GraphElements)
async def get_graph(case_id: str, request: Request, hops: int = Query(2, ge=1, le=3), p: Principal = Depends(analyst)) -> GraphElements:
    await _case_or_404(case_id, p)
    async with _engine_lock(request):                    # the in-memory graph must not change while it is read
        return await engine_calls.run_engine(request.app.state.pipeline.graph_elements, case_id, hops)


@router.get("/{case_id}/explanation", response_model=Explanation)
async def get_explanation(case_id: str, request: Request, p: Principal = Depends(analyst)) -> Explanation:
    await _case_or_404(case_id, p)
    return await engine_calls.explain(request.app, case_id)


@router.post("/{case_id}/replay", response_model=ReplayResult)
async def replay(case_id: str, body: ReplayRequest, request: Request, p: Principal = Depends(analyst)) -> ReplayResult:
    await _case_or_404(case_id, p)
    return await engine_calls.replay(request.app, case_id, list(body.ablate), body.mode)


@router.post("/{case_id}/feedback", response_model=FeedbackResult)
async def feedback(case_id: str, body: FeedbackRequest, request: Request, p: Principal = Depends(analyst)) -> FeedbackResult:
    await _case_or_404(case_id, p)
    app = request.app
    async with _engine_lock(request):                    # feedback rewrites the case and the pipeline's seeds
        result: FeedbackResult = await engine_calls.run_engine(engine_api.apply_feedback, app.state.store, app.state.pipeline,
                                                               case_id, body.verdict, p.user_id)
        await asyncio.to_thread(queries.save_feedback, case_id, body.verdict, p.user_id, body.note, result.model_dump_json())
        await asyncio.to_thread(app.state.store.append_audit, p.user_id, "FEEDBACK", case_id,
                                {"verdict": body.verdict, "note": body.note, "reliability_before": result.reliability_before,
                                 "reliability_after": result.reliability_after, "seeds_added": result.seeds_added})
        case = await asyncio.to_thread(app.state.store.get_case, case_id)
    if getattr(app.state, "payments", None) is not None:    # held payments: capture (FALSE_POSITIVE) / void (CONFIRMED_FRAUD)
        app.state.payments.submit_verdict(case_id, body.verdict, p.user_id)
    if case:
        await app.state.broadcaster.broadcast(
            CaseUpdate(case=summarize(case), event_id="feedback", new_evidence_ids=[]).model_dump(mode="json"))
    return result


_STATE_RANK = {"normal": 0, "held": 1, "blocked": 2}


@router.post("/{case_id}/actions", response_model=Decision)
async def manual_actions(case_id: str, body: ActionsRequest, request: Request, p: Principal = Depends(lead)) -> Decision:
    await _case_or_404(case_id, p)
    store = request.app.state.store
    async with _engine_lock(request):                    # read-modify-write: the worker must not save this case meanwhile
        case = await _case_or_404(case_id, p)              # re-read under the lock: the latest band, P and payment state
        evidence = await asyncio.to_thread(store.list_evidence, case_id)
        trigger = evidence[-1].event_id if evidence else "manual"
        decision = Decision(decision_id=new_id("dec"), case_id=case_id, trigger_event_id=trigger, band=case.band,
                            p_attack=case.p_attack, policy_rule="manual_override", actions=list(body.actions), actor=p.user_id,
                            override_reason=body.reason, created_at=datetime.now(UTC))
        new_state = ("blocked" if "BLOCK_PENDING_PAYMENTS" in body.actions
                     else "held" if "HOLD_OUTBOUND_PAYMENTS" in body.actions else case.payment_state)
        if _STATE_RANK[new_state] < _STATE_RANK[case.payment_state]:
            new_state = case.payment_state                         # payment state never goes down by hand
        case = case.model_copy(update={"latest_actions": list(body.actions), "payment_state": new_state})

        def _write() -> None:
            with store.transaction():
                store.save_decision(decision)
                store.save_case(case)
                store.append_audit(p.user_id, "MANUAL_ACTION", case_id,
                                   {"decision_id": decision.decision_id, "actions": list(body.actions), "reason": body.reason})
        await asyncio.to_thread(_write)
    await request.app.state.broadcaster.broadcast(
        CaseUpdate(case=summarize(case), event_id=trigger, new_evidence_ids=[], decision_id=decision.decision_id).model_dump(mode="json"))
    return decision


@router.post("/{case_id}/ask", response_model=AskResponse)
async def ask(case_id: str, body: AskRequest, request: Request, p: Principal = Depends(analyst)) -> AskResponse:
    """Investigator AI (PRD §15.6): keyword-routed templates over read-only case tools, then the validator."""
    case = await _case_or_404(case_id, p)

    def _answer() -> AskResponse:
        tools = CaseTools(request.app, case)
        sentences = templates.answer(body.question, tools)
        kept, removed = validator.validate(sentences, tools.ids, tools.numbers)
        return AskResponse(answer=" ".join(s.text for s in kept), sentences=kept, removed=removed)

    try:
        return await asyncio.to_thread(_answer)
    except KeyError as e:
        raise ApiError("NOT_FOUND", "case not found") from e
