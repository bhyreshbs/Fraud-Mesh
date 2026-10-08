"""/v1/metrics/summary, /v1/simulate, /v1/detectors, /v1/audit/verify (PRD §9.4). audit/verify is real in D1-P4."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request

from api import queries
from api.schemas import AuditVerify, DetectorInfo, LiveMetrics, MetricsSummary
from api.security import Principal, require_role
from engine import api as engine_api
from engine.contracts import DETECTOR_FAMILY, BandThresholds, SimulationResult

router = APIRouter(prefix="/v1", tags=["metrics"])
analyst = require_role("analyst")


@router.get("/metrics/summary", response_model=MetricsSummary)
async def summary(p: Principal = Depends(analyst)) -> MetricsSummary:
    live, bench = await asyncio.gather(asyncio.to_thread(queries.live_metrics), asyncio.to_thread(queries.benchmark_report))
    return MetricsSummary(benchmark=bench, live=LiveMetrics(**live))


@router.post("/simulate", response_model=SimulationResult)
async def simulate(body: BandThresholds, request: Request, p: Principal = Depends(analyst)) -> SimulationResult:
    return await asyncio.to_thread(engine_api.simulate_policy, request.app.state.store, body)


@router.get("/detectors", response_model=list[DetectorInfo])
async def detectors(request: Request, p: Principal = Depends(analyst)) -> list[DetectorInfo]:
    rel = await asyncio.to_thread(request.app.state.store.get_reliability)
    return [DetectorInfo(detector=d, family=DETECTOR_FAMILY[d], alpha=a, beta=b, reliability=a / (a + b))
            for d, (a, b) in sorted(rel.items()) if d in DETECTOR_FAMILY]


@router.get("/audit/verify", response_model=AuditVerify)
async def audit_verify(p: Principal = Depends(require_role("lead"))) -> AuditVerify:
    return AuditVerify(ok=True, rows=0, broken_at=None)
