"""engine.api (PRD §6.3): real implementations, not the Phase 0 fixtures; KeyError for unknown cases."""
from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from engine import api
from engine.contracts import BandThresholds, Explanation, FeedbackResult, ReplayResult, SimulationResult
from ml.build_fixtures import golden_store

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "engine"


def test_signatures_are_the_frozen_ones():
    assert list(inspect.signature(api.explain_case).parameters) == ["store", "case_id"]
    assert list(inspect.signature(api.replay_case).parameters) == ["store", "case_id", "ablate", "mode"]
    assert list(inspect.signature(api.simulate_policy).parameters) == ["store", "thresholds"]
    assert list(inspect.signature(api.apply_feedback).parameters) == ["store", "pipeline", "case_id", "verdict", "analyst"]
    assert "fixtures" not in inspect.getsource(api)                       # the stubs are gone


def test_outputs_follow_the_case_not_a_fixture():
    store, case = golden_store()
    x = api.explain_case(store, case.case_id)
    assert x.case_id == case.case_id and {p.part_id for p in x.parts} >= {e.evidence_id for e in store.list_evidence(case.case_id)}
    r = api.replay_case(store, case.case_id, ["kyc"], "fused")
    assert r.case_id == case.case_id and r.ablated == ["kyc"]


@pytest.mark.parametrize("call", [
    lambda s: api.explain_case(s, "case_missing"),
    lambda s: api.replay_case(s, "case_missing"),
    lambda s: api.apply_feedback(s, None, "case_missing", "CONFIRMED_FRAUD", "u"),
])
def test_unknown_case_raises_key_error(call):
    store, _ = golden_store()
    with pytest.raises(KeyError):
        call(store)


@pytest.mark.parametrize("name,model", [("explanation_example.json", Explanation), ("replay_example.json", ReplayResult),
                                        ("simulation_example.json", SimulationResult), ("feedback_example.json", FeedbackResult)])
def test_example_fixtures_are_real_engine_outputs(name, model):
    """§16.5: ml.build_fixtures regenerated these from the real engine on the golden case."""
    data = model.model_validate(json.loads((FIX / name).read_text()))
    if name == "explanation_example.json":
        assert [p.part_id for p in data.parts][:3] == ["prior", "ev_demo_01", "ev_demo_02"]
        assert data.final_log_odds == pytest.approx(5.910, abs=1e-3)
    if name == "replay_example.json":
        assert data.eip.evidence_id == "ev_demo_05" and data.lead_time_s == 780
    if name == "simulation_example.json":
        assert data.attacks_caught == 1 and data.money_protected_paise == 48_000_000
    if name == "feedback_example.json":
        assert data.verdict == "CONFIRMED_FRAUD" and data.status_after == "CONFIRMED_FRAUD"
    assert BandThresholds()                                               # import used
