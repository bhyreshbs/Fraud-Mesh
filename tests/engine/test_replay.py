"""Replay (PRD §10.9) — reproduces every replay check of §12.4 on the golden case."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.api import replay_case
from engine.contracts import BandThresholds, ReplayResult
from engine.replay.replay import build_replay
from ml.build_fixtures import golden_store

EXP = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "engine" / "demo_expected.json").read_text())["replay"]


@pytest.fixture(scope="module")
def golden():
    return golden_store()


def test_baseline_eip_is_item_5_with_780_s_lead(golden):
    store, case = golden
    r = replay_case(store, case.case_id)
    assert r.eip.evidence_id == EXP["baseline_eip_evidence_id"] == r.baseline_eip.evidence_id
    assert r.eip.band == "HIGH" and r.eip.severity == 2 and "HOLD_OUTBOUND_PAYMENTS" in r.eip.actions
    assert r.lead_time_s == EXP["baseline_lead_time_s"] == 780 and r.lead_time_lost_s == 0
    assert r.money_protected_paise == EXP["money_protected_paise"] == 48_000_000
    assert [p.band for p in r.timeline] == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "CRITICAL", "CRITICAL", "CRITICAL"]


def test_without_kyc_first_high_is_item_6_and_360_s_are_lost(golden):
    store, case = golden
    r = replay_case(store, case.case_id, ["kyc"])
    w = EXP["without_kyc"]
    assert r.eip.evidence_id == w["first_high_evidence_id"] and r.eip.p == pytest.approx(w["p_attack"], abs=1e-3)
    assert r.lead_time_lost_s == w["lead_time_lost_s"] == 360 and r.ablated == ["kyc"]
    assert all(p.evidence_id != "ev_demo_05" for p in r.timeline)


def test_without_netsec_first_high_is_still_item_5(golden):
    store, case = golden
    r = replay_case(store, case.case_id, ["netsec"])
    w = EXP["without_netsec"]
    assert r.eip.evidence_id == w["first_high_evidence_id"] and r.eip.p == pytest.approx(w["p_attack"], abs=1e-3)
    assert r.lead_time_lost_s == 0


def test_siloed_has_no_block_and_six_alerts(golden):
    store, case = golden
    r = replay_case(store, case.case_id, mode="siloed")
    s = EXP["siloed"]
    assert sum("BLOCK_PENDING_PAYMENTS" in p.actions for p in r.timeline) == s["block_actions"] == 0
    assert sum(p.p >= 0.5 for p in r.timeline) == s["items_with_p_ge_0_5"] == 0
    alerts = [p.evidence_id for p in r.timeline if p.p >= 0.05]
    assert alerts == s["alert_ids"] and len(alerts) == s["alerts_p_ge_0_05"] == 6
    assert len(r.timeline) / len(alerts) == pytest.approx(8 / 6)
    assert {p.band for p in r.timeline} == {"SILOED_NONE"} and r.eip is None and r.money_protected_paise == 0
    assert r.baseline_eip.evidence_id == "ev_demo_05"                     # baseline is always fused, nothing ablated


def test_replay_is_saved_validates_and_is_deterministic(golden):
    store, case = golden
    a, b = replay_case(store, case.case_id), replay_case(store, case.case_id)
    assert store.get_replay(a.replay_id) == a and a.replay_id != b.replay_id
    assert ReplayResult.model_validate_json(a.model_dump_json()) == a
    assert [p.model_dump() for p in a.timeline] == [p.model_dump() for p in b.timeline]


def test_replay_uses_stored_p_and_r_only(golden):
    store, case = golden
    evs = store.list_evidence(case.case_id)
    stricter = build_replay(case.case_id, evs, thresholds=BandThresholds(medium=0.3, high=0.9, critical=0.95))
    assert stricter.eip.evidence_id == "ev_demo_07"                       # first p >= 0.9 is the graph item (0.966)


def test_errors(golden):
    store, case = golden
    with pytest.raises(KeyError):
        replay_case(store, "case_missing")
    with pytest.raises(ValueError):
        replay_case(store, case.case_id, ["nope"])
    with pytest.raises(ValueError):
        replay_case(store, case.case_id, mode="parallel")
