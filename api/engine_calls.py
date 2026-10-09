"""engine.api calls from the routers and the Investigator AI (PRD §6.3): synchronous functions run in a thread, KeyError
-> 404."""
from __future__ import annotations

import asyncio

from api.errors import ApiError
from engine import api as engine_api
from engine.contracts import BandThresholds, Explanation, ReplayResult, SimulationResult


def explain_sync(app, case_id: str) -> Explanation:
    return engine_api.explain_case(app.state.store, case_id)


def replay_sync(app, case_id: str, ablate: list[str], mode: str) -> ReplayResult:
    return engine_api.replay_case(app.state.store, case_id, ablate, mode)


async def run_engine(fn, *args):
    """Run a synchronous engine call in a thread; engine.api's KeyError (unknown case) becomes a 404."""
    try:
        return await asyncio.to_thread(fn, *args)
    except KeyError as e:
        raise ApiError("NOT_FOUND", "case not found") from e


async def explain(app, case_id: str) -> Explanation:
    return await run_engine(explain_sync, app, case_id)


async def replay(app, case_id: str, ablate: list[str], mode: str) -> ReplayResult:
    return await run_engine(replay_sync, app, case_id, ablate, mode)


async def simulate(app, thresholds: BandThresholds) -> SimulationResult:
    return await run_engine(engine_api.simulate_policy, app.state.store, thresholds)
