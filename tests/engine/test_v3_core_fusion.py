"""v3 core: ATO floor (S2 → new payee), pat_ATO2, model-confidence floor, correlated evidence, golden invariance."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.contracts import BandThresholds, Evidence, Reason
from engine.fusion.fusion import (
    FLOOR_S2_THEN_NEW_PAYEE,
    FLOOR_TXN_HIGH_CONFIDENCE,
    floor_label,
    fuse,
)
from engine.fusion.patterns import load_patterns
from engine.fusion.v3_core import load_v3_core, merged

T0 = datetime(2026, 10, 9, 0, 39, tzinfo=timezone(timedelta(hours=5, minutes=30)))
TH = BandThresholds()
FIX = Path(__file__).resolve().parents[2] / "fixtures" / "engine"
_n = 0


def ev(detector="auth", family="device", stage="S2_CONTROL_TAKEOVER", p=0.06, r=0.7, minutes=0.0, reasons=("X",),
       entities=("cust:a",), degraded=False) -> Evidence:
    global _n
    _n += 1
    return Evidence(evidence_id=f"ev_v3c{_n:04d}", event_id=f"evt_v3c{_n:08d}", detector=detector, detector_version="t",
                    family=family, stage=stage, p=p, reliability=r, entities=list(entities),
                    reasons=[Reason(code=c) for c in reasons], degraded=degraded, ts=T0 + timedelta(minutes=minutes))


def s1(minutes=0.0):
    return ev("behaviour", "identity", "S1_INITIAL_ACCESS", p=0.05, r=0.6, minutes=minutes, reasons=("NEW_DEVICE",))


def s2(minutes=0.0, code="MFA_CHANGED_AFTER_NEW_DEVICE"):
    return ev(minutes=minutes, reasons=(code,))


def s5(minutes=0.0, p=0.03):
    return ev("graph", "graph", "S5_POSITIONING", p=p, r=0.8, minutes=minutes, reasons=("PAYEE_NAME_MISMATCH",))


def trusted(minutes=0.0):
    return ev(minutes=minutes, p=0.003, reasons=("STEP_UP_PASSED_TRUSTED",))


def txn(minutes=0.0, p=0.95, degraded=False):
    return ev("txn", "transaction", "S6_MONETIZATION", p=p, r=0.85, minutes=minutes, reasons=("AMOUNT_HIGH",),
              degraded=degraded)


def run(items, v3=None, patterns=()):
    return fuse(items, base_rate=0.01, thresholds=TH, patterns=patterns, v3=v3)


# ------------------------------------------------------------------ 3.1a floor_S2_THEN_NEW_PAYEE
def test_s2_then_payee_raises_to_high_on_the_payee_item_and_cites_it():
    a, b = s2(0), s5(20)
    assert run([a]).band == "LOW"
    res = run([a, b])
    assert res.band_before_floors in ("LOW", "MEDIUM") and res.band == "HIGH"
    assert FLOOR_S2_THEN_NEW_PAYEE in res.floors_raising
    assert res.floor_evidence[FLOOR_S2_THEN_NEW_PAYEE] == b.evidence_id
    assert res.floor_cause[FLOOR_S2_THEN_NEW_PAYEE] == f"{b.evidence_id} after {a.evidence_id}"
    assert b.evidence_id in floor_label(FLOOR_S2_THEN_NEW_PAYEE, res.floor_cause[FLOOR_S2_THEN_NEW_PAYEE])


def test_boundary_exactly_24h_counts_and_just_after_does_not():
    assert FLOOR_S2_THEN_NEW_PAYEE in run([s2(0), s5(24 * 60)]).floors
    assert FLOOR_S2_THEN_NEW_PAYEE not in run([s2(0), s5(24 * 60 + 1 / 60)]).floors


def test_order_matters_payee_before_s2_does_not_fire():
    assert FLOOR_S2_THEN_NEW_PAYEE not in run([s5(0), s2(10)]).floors


def test_delayed_s2_evidence_pairs_by_event_time():
    """The payee item is processed first; an S2 item that arrives later but happened earlier still triggers."""
    payee, late_s2 = s5(30), s2(5)
    assert FLOOR_S2_THEN_NEW_PAYEE not in run([payee]).floors
    res = run([payee, late_s2])                     # arrival order is irrelevant: fuse orders by ts
    assert FLOOR_S2_THEN_NEW_PAYEE in res.floors and res.floor_evidence[FLOOR_S2_THEN_NEW_PAYEE] == payee.evidence_id


def test_missing_events_no_s2_or_no_s5():
    assert FLOOR_S2_THEN_NEW_PAYEE not in run([s5(0), s5(5)]).floors
    assert FLOOR_S2_THEN_NEW_PAYEE not in run([s2(0), s2(5)]).floors


def test_duplicate_payee_evidence_is_one_floor():
    a, b = s2(0), s5(10)
    dup = b.model_copy(update={"evidence_id": "ev_v3c_dup"})
    res = run([a, b, dup])
    assert res.floors.count(FLOOR_S2_THEN_NEW_PAYEE) == 1 and res.band == "HIGH"


def test_legit_security_change_confirmed_with_trusted_factor_is_not_floored():
    """A genuine customer: new phone, MFA re-bound, passes the push on the long-held factor, then adds a payee."""
    res = run([s1(0), s2(2), trusted(3), s5(60)])
    assert FLOOR_S2_THEN_NEW_PAYEE not in res.floors and res.band in ("LOW", "MEDIUM")


def test_legit_new_payee_without_security_change_is_not_floored():
    assert run([s5(0)]).band == "LOW" and not run([s5(0)]).floors


def test_floor_can_be_disabled():
    off = merged({"floors": {"s2_then_new_payee": {"enabled": False}}})
    assert FLOOR_S2_THEN_NEW_PAYEE not in run([s2(0), s5(10)], v3=off).floors


# ------------------------------------------------------------------ 3.1b pat_ATO2
def test_pat_ato2_slow_takeover_and_mutual_exclusion_with_ato1():
    pats = load_patterns()
    slow = run([s1(0), s2(120), s5(600)], patterns=pats)          # S1 → S2 after 2 h: pat_ATO1 (30 min) misses
    assert "pat_ATO2" in slow.pattern_hits and "pat_ATO1" not in slow.pattern_hits
    fast = run([s1(0), s2(5), s5(30)], patterns=pats)
    assert fast.pattern_hits == ["pat_ATO1"]                      # not rewarded twice
    too_slow = run([s1(0), s2(120), s5(24 * 60 + 1)], patterns=pats)
    assert "pat_ATO2" not in too_slow.pattern_hits                # whole chain must fit in 24 h
    wrong_order = run([s2(0), s1(10), s5(20)], patterns=pats)
    assert "pat_ATO2" not in wrong_order.pattern_hits


# ------------------------------------------------------------------ 3.2a floor_TXN_HIGH_CONFIDENCE
def test_txn_high_confidence_floor():
    res = run([txn(0, p=0.95)])
    assert res.band_before_floors == "LOW" and res.band == "HIGH" and FLOOR_TXN_HIGH_CONFIDENCE in res.floors_raising
    assert FLOOR_TXN_HIGH_CONFIDENCE not in run([txn(0, p=0.89)]).floors
    assert FLOOR_TXN_HIGH_CONFIDENCE in run([txn(0, p=0.90)]).floors          # inclusive
    assert FLOOR_TXN_HIGH_CONFIDENCE not in run([txn(0, p=0.99, degraded=True)]).floors
    assert FLOOR_TXN_HIGH_CONFIDENCE not in run([txn(0), trusted(2)]).floors   # confirmed on a trusted factor
    assert "not proof" in floor_label(FLOOR_TXN_HIGH_CONFIDENCE)


# ------------------------------------------------------------------ 11.5 correlated evidence
CORR = merged({"correlation": {"enabled": True, "groups": load_v3_core()["correlation"]["groups"]}})


def test_correlation_discounts_the_weaker_item_of_one_fact():
    weak, strong = s1(0), s2(3)                     # ℓ 0.99 (NEW_DEVICE) vs 1.29 (MFA_CHANGED_AFTER_NEW_DEVICE)
    off, on = run([weak, strong]), run([weak, strong], v3=CORR)
    assert on.correlated == {weak.evidence_id: ("corr_NEW_DEVICE", strong.evidence_id, 0.5)}
    assert on.contributions[weak.evidence_id] == pytest.approx(0.5 * off.contributions[weak.evidence_id])
    assert on.contributions[strong.evidence_id] == pytest.approx(off.contributions[strong.evidence_id])
    assert on.log_odds < off.log_odds


def test_correlation_needs_shared_customer_window_and_other_family():
    assert run([s1(0), ev(minutes=3, reasons=("MFA_CHANGED_AFTER_NEW_DEVICE",), entities=("cust:b",))], v3=CORR).correlated == {}
    assert run([s1(0), s2(61)], v3=CORR).correlated == {}
    assert run([s2(0), s2(3)], v3=CORR).correlated == {}               # same family: δ already discounts


def test_golden_values_unchanged_by_default_and_changed_when_correlation_is_on():
    evidence = [Evidence.model_validate(x) for x in json.loads((FIX / "demo_evidence.json").read_text())]
    expected = json.loads((FIX / "demo_expected.json").read_text())
    th = BandThresholds(**expected["thresholds"])
    default = fuse(evidence, base_rate=0.01, thresholds=th, patterns=load_patterns())
    assert default.log_odds == pytest.approx(expected["final"]["log_odds"], abs=1e-3)
    assert sorted(default.pattern_hits) == ["pat_ATO1", "pat_CASE_IP_CLOUD"] and default.correlated == {}
    on = fuse(evidence, base_rate=0.01, thresholds=th, patterns=load_patterns(), v3=CORR)
    assert set(on.correlated) == {"ev_demo_03"}                         # MFA change shares the new-device fact
    assert on.log_odds == pytest.approx(expected["final"]["log_odds"] - 0.5 * 0.645, abs=1e-3)
    assert on.band == "CRITICAL"
