"""Digital Twin routes (analyst or higher; read-only, nothing is written or audited):

  GET /v1/twin/overview         the virtual bank: entities by kind, cases by band, interventions, money at risk
  GET /v1/cases/{case_id}/twin  one case replayed into the twin: virtual state step by step, every prevention strategy
                                simulated on an isolated copy, and the attack-progression forecast

Case access follows /v1/cases: anything outside the caller's queues is a 404.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request

from api import queries
from api.errors import ApiError
from api.security import Principal, require_role
from engine.twin import twin_case, twin_overview
from engine.twin.models import CaseTwin, TwinOverview

router = APIRouter(tags=["twin"])
analyst = require_role("analyst")


def _graph(request: Request):
    return getattr(request.app.state.pipeline, "graph", None)      # the dev stand-in pipeline has no graph


@router.get("/v1/twin/overview", response_model=TwinOverview)
async def overview(request: Request, p: Principal = Depends(analyst)) -> TwinOverview:
    ov = await asyncio.to_thread(twin_overview, request.app.state.store, _graph(request))
    visible = await asyncio.to_thread(queries.case_ids_in_queues, [c["case_id"] for c in ov.hottest_cases], list(p.queues))
    ov.hottest_cases = [c for c in ov.hottest_cases if c["case_id"] in visible]
    return ov


@router.get("/v1/cases/{case_id}/twin", response_model=CaseTwin)
async def case_twin(case_id: str, request: Request, p: Principal = Depends(analyst)) -> CaseTwin:
    if await asyncio.to_thread(queries.case_in_queues, case_id, list(p.queues)) is None:
        raise ApiError("NOT_FOUND", "case not found")
    labels = await asyncio.to_thread(queries.labels_for_case, case_id)
    try:
        return await asyncio.to_thread(lambda: twin_case(request.app.state.store, case_id, graph=_graph(request), labels=labels))
    except KeyError as e:
        raise ApiError("NOT_FOUND", "case not found") from e
