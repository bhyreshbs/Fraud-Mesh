"""PRD §16.0: every engine fixture validates against its contract model."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.contracts import Evidence, Explanation, FeedbackResult, ReplayResult, SimulationResult

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "engine"


@pytest.mark.parametrize("name,model", [("explanation_example.json", Explanation), ("replay_example.json", ReplayResult),
                                        ("simulation_example.json", SimulationResult),
                                        ("feedback_example.json", FeedbackResult)])
def test_stub_fixtures_validate(name, model):
    model.model_validate(json.loads((FIX / name).read_text()))


def test_demo_evidence_is_the_8_golden_items():
    items = [Evidence.model_validate(x) for x in json.loads((FIX / "demo_evidence.json").read_text())]
    assert [e.evidence_id for e in items] == [f"ev_demo_0{i}" for i in range(1, 9)]
    assert [(e.detector, e.p, e.reliability) for e in items] == [
        ("netsec", 0.03, 0.5), ("behaviour", 0.05, 0.6), ("auth", 0.06, 0.7), ("auth", 0.08, 0.7), ("kyc", 0.06, 0.6),
        ("cyber", 0.04, 0.5), ("graph", 0.10, 0.8), ("txn", 0.20, 0.85)]
    assert [e.ts.strftime("%H:%M") for e in items] == ["00:39", "00:41", "00:44", "00:52", "00:52", "00:58", "01:03", "01:05"]
    assert all(e.ts.utcoffset().total_seconds() == 19800 for e in items)        # IST


def test_demo_expected_shape():
    exp = json.loads((FIX / "demo_expected.json").read_text())
    assert len(exp["items"]) == 8 and exp["final"]["band"] == "CRITICAL"
    assert exp["pipeline_band_path"] == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "CRITICAL", "CRITICAL", "CRITICAL"]
