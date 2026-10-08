"""Golden fusion test (PRD §12.4, §16.2): the 8 Midnight ATO evidence items with fixed p and r must reproduce
fixtures/engine/demo_expected.json to 3 decimals. Pure fusion: no models, no store."""
from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from engine.contracts import BandThresholds, Evidence
from engine.fusion.fusion import fuse, logit
from engine.fusion.patterns import load_patterns

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "engine"
EVIDENCE = [Evidence.model_validate(x) for x in json.loads((FIX / "demo_evidence.json").read_text())]
EXPECTED = json.loads((FIX / "demo_expected.json").read_text())
TH = BandThresholds(**EXPECTED["thresholds"])
TOL = 1e-3


def run(items: list[Evidence]):
    return fuse(items, base_rate=EXPECTED["base_rate"], thresholds=TH, patterns=load_patterns())


def test_prior():
    assert logit(EXPECTED["base_rate"]) == pytest.approx(EXPECTED["prior_log_odds"], abs=TOL)
    empty = run([])
    assert empty.log_odds == pytest.approx(EXPECTED["prior_log_odds"], abs=TOL) and empty.band == "LOW"


@pytest.mark.parametrize("k", range(1, 9))
def test_each_step_matches_the_golden_table(k):
    exp = EXPECTED["items"][k - 1]
    res = run(EVIDENCE[:k])
    assert res.log_odds == pytest.approx(exp["log_odds"], abs=TOL)
    assert res.p_attack == pytest.approx(exp["p_attack"], abs=TOL)
    assert res.band == exp["band"]
    if exp["pattern"]:                                    # the pattern completes at this item, not before
        assert exp["pattern"] in res.pattern_hits
        assert exp["pattern"] not in run(EVIDENCE[:k - 1]).pattern_hits
        assert res.pattern_completed_by[exp["pattern"]] == exp["evidence_id"]


def test_contributions_at_end():
    res = run(EVIDENCE)
    for exp in EXPECTED["items"]:
        assert res.contributions[exp["evidence_id"]] == pytest.approx(exp["contribution_at_end"], abs=TOL)
    final = EXPECTED["final"]
    assert res.log_odds == pytest.approx(final["log_odds"], abs=TOL)
    assert res.p_attack == pytest.approx(final["p_attack"], abs=TOL)
    assert res.band == final["band"]
    assert sorted(res.pattern_hits) == sorted(final["pattern_hits"])
    bonus = sum(final["pattern_bonus"].values())
    assert math.isclose(res.log_odds, logit(EXPECTED["base_rate"]) + sum(res.contributions.values()) + bonus, abs_tol=1e-9)


def test_order_of_input_does_not_matter():
    assert run(list(reversed(EVIDENCE))).log_odds == pytest.approx(run(EVIDENCE).log_odds, abs=1e-12)
