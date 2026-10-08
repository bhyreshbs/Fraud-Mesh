# engine/api.py (Phase 0 stub, PRD §6.3/§6.5 — owned by DEV2, replaced in D2-P5).
# Each function returns its fixtures/engine/*_example.json, re-keyed to the requested case_id.
from __future__ import annotations

from pathlib import Path

from engine.contracts import BandThresholds, Explanation, FeedbackResult, ReplayResult, SimulationResult

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "engine"


def _load(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


def explain_case(store, case_id: str) -> Explanation:
    return Explanation.model_validate_json(_load("explanation_example.json")).model_copy(update={"case_id": case_id})


def replay_case(store, case_id: str, ablate: list[str] | None = None, mode: str = "fused") -> ReplayResult:
    r = ReplayResult.model_validate_json(_load("replay_example.json"))
    return r.model_copy(update={"case_id": case_id, "mode": mode, "ablated": list(ablate or [])})


def simulate_policy(store, thresholds: BandThresholds) -> SimulationResult:
    return SimulationResult.model_validate_json(_load("simulation_example.json")).model_copy(update={"thresholds": thresholds})


def apply_feedback(store, pipeline, case_id: str, verdict: str, analyst: str) -> FeedbackResult:
    f = FeedbackResult.model_validate_json(_load("feedback_example.json"))
    return f.model_copy(update={"case_id": case_id, "verdict": verdict})
