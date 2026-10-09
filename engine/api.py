"""engine.api (PRD §6.3): the four functions Dev 1's routers call, all synchronous (Dev 1 uses asyncio.to_thread).

All are read-only except replay_case (saves the replay) and apply_feedback (reliability, seeds, case status).
Each raises KeyError for an unknown case_id, which the API maps to 404.
"""
from __future__ import annotations

from typing import Any

from engine.contracts import BandThresholds, Explanation, FeedbackResult, ReplayResult, SimulationResult, Store
from engine.explain.explain import explain_case as _explain
from engine.feedback import apply_feedback as _feedback
from engine.replay.replay import replay_case as _replay
from engine.replay.simulate import simulate_policy as _simulate


def explain_case(store: Store, case_id: str) -> Explanation:
    return _explain(store, case_id)


def replay_case(store: Store, case_id: str, ablate: list[str] | None = None, mode: str = "fused") -> ReplayResult:
    return _replay(store, case_id, ablate, mode)


def simulate_policy(store: Store, thresholds: BandThresholds) -> SimulationResult:
    return _simulate(store, thresholds)


def apply_feedback(store: Store, pipeline: Any, case_id: str, verdict: str, analyst: str) -> FeedbackResult:
    return _feedback(store, pipeline, case_id, verdict, analyst)
