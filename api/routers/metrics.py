"""/v1/metrics/summary, /v1/simulate, /v1/detectors, /v1/audit/verify (PRD §9.4). Phase 0 stubs; real in D1-P2/D1-P4."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request

from api.fixture_data import fixture
from api.schemas import AuditVerify, DetectorInfo, MetricsSummary
from api.security import Principal, require_role
from engine import api as engine_api
from engine.contracts import BandThresholds, SimulationResult

router = APIRouter(prefix="/v1", tags=["metrics"])


@router.get("/metrics/summary", response_model=MetricsSummary)
async def summary(p: Principal = Depends(require_role("analyst"))) -> MetricsSummary:
    return MetricsSummary.model_validate(fixture("metrics.json"))


@router.post("/simulate", response_model=SimulationResult)
async def simulate(body: BandThresholds, request: Request, p: Principal = Depends(require_role("analyst"))) -> SimulationResult:
    return await asyncio.to_thread(engine_api.simulate_policy, request.app.state.store, body)


@router.get("/detectors", response_model=list[DetectorInfo])
async def detectors(p: Principal = Depends(require_role("analyst"))) -> list[DetectorInfo]:
    return [DetectorInfo.model_validate(d) for d in fixture("detectors.json")]


@router.get("/audit/verify", response_model=AuditVerify)
async def audit_verify(p: Principal = Depends(require_role("lead"))) -> AuditVerify:
    return AuditVerify(ok=True, rows=0, broken_at=None)
