"""/v1/cases/* (PRD §9.3). Phase 0 stubs: every route returns its contract shape from fixtures/api or the
engine.api stubs. D1-P2 replaces the fixture reads with PgStore queries, the queue filter and real 404s."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Query, Request

from api.errors import ApiError
from api.fixture_data import fixture
from api.schemas import ActionsRequest, AskRequest, AskResponse, CaseDetail, CasesPage, FeedbackRequest, ReplayRequest, Timeline
from api.security import Principal, require_role
from engine import api as engine_api
from engine.common.ids import new_id
from engine.contracts import Band, CaseStatus, Decision, Explanation, FeedbackResult, GraphElements, ReplayResult

router = APIRouter(prefix="/v1/cases", tags=["cases"])
analyst = require_role("analyst")
lead = require_role("lead")


def _known(case_id: str) -> None:
    ids = {c["case_id"] for c in fixture("cases_list.json")["items"]}
    if case_id not in ids:
        raise ApiError("NOT_FOUND", "case not found")


@router.get("", response_model=CasesPage)
async def list_cases(status: CaseStatus | None = None, band: Band | None = None, limit: int = Query(50, ge=1, le=200),
                     p: Principal = Depends(analyst)) -> CasesPage:
    page = CasesPage.model_validate(fixture("cases_list.json"))
    items = [c for c in page.items if (status is None or c.status == status) and (band is None or c.band == band)]
    return CasesPage(items=items[:limit], next_cursor=None)


@router.get("/{case_id}", response_model=CaseDetail)
async def get_case(case_id: str, p: Principal = Depends(analyst)) -> CaseDetail:
    _known(case_id)
    return CaseDetail.model_validate(fixture("case.json"))


@router.get("/{case_id}/timeline", response_model=Timeline)
async def get_timeline(case_id: str, p: Principal = Depends(analyst)) -> Timeline:
    _known(case_id)
    return Timeline.model_validate(fixture("timeline.json"))


@router.get("/{case_id}/graph", response_model=GraphElements)
async def get_graph(case_id: str, hops: int = Query(2, ge=1, le=3), p: Principal = Depends(analyst)) -> GraphElements:
    _known(case_id)
    return GraphElements.model_validate(fixture("graph.json"))


@router.get("/{case_id}/explanation", response_model=Explanation)
async def get_explanation(case_id: str, request: Request, p: Principal = Depends(analyst)) -> Explanation:
    _known(case_id)
    return await asyncio.to_thread(engine_api.explain_case, request.app.state.store, case_id)


@router.post("/{case_id}/replay", response_model=ReplayResult)
async def replay(case_id: str, body: ReplayRequest, request: Request, p: Principal = Depends(analyst)) -> ReplayResult:
    _known(case_id)
    return await asyncio.to_thread(engine_api.replay_case, request.app.state.store, case_id, list(body.ablate), body.mode)


@router.post("/{case_id}/feedback", response_model=FeedbackResult)
async def feedback(case_id: str, body: FeedbackRequest, request: Request, p: Principal = Depends(analyst)) -> FeedbackResult:
    _known(case_id)
    return await asyncio.to_thread(engine_api.apply_feedback, request.app.state.store, request.app.state.pipeline,
                                   case_id, body.verdict, p.user_id)


@router.post("/{case_id}/actions", response_model=Decision)
async def manual_actions(case_id: str, body: ActionsRequest, p: Principal = Depends(lead)) -> Decision:
    _known(case_id)
    last = Decision.model_validate(fixture("timeline.json")["decisions"][-1])
    return last.model_copy(update={"decision_id": new_id("dec"), "actions": body.actions, "actor": p.user_id,
                                   "override_reason": body.reason, "policy_rule": "manual"})


@router.post("/{case_id}/ask", response_model=AskResponse)
async def ask(case_id: str, body: AskRequest, p: Principal = Depends(analyst)) -> AskResponse:
    _known(case_id)
    return AskResponse(answer="The Investigator AI arrives in D1-P6.", sentences=[], removed=0)
