"""Fusion rules (PRD §10.5) beyond the golden table: clipping, family discount, negative evidence, floors."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from engine.contracts import BandThresholds, Evidence, Reason
from engine.fusion.fusion import band_of, fuse, logit, weight

T0 = datetime(2026, 10, 9, 0, 39, tzinfo=timezone(timedelta(hours=5, minutes=30)))
TH = BandThresholds()
_n = 0


def ev(detector="auth", family="device", stage="S2_CONTROL_TAKEOVER", p=0.06, r=0.7, minutes=0, reasons=("X",),
       entities=("cust:a",), amount=None) -> Evidence:
    global _n
    _n += 1
    return Evidence(evidence_id=f"ev_{_n:04d}", event_id=f"evt_{_n:08d}", detector=detector, detector_version="t",
                    family=family, stage=stage, p=p, reliability=r, entities=list(entities),
                    reasons=[Reason(code=c) for c in reasons], amount_paise=amount, ts=T0 + timedelta(minutes=minutes))


def run(items):
    return fuse(items, base_rate=0.01, thresholds=TH, patterns=())


def test_weight_is_clipped():
    assert weight(ev(p=0.99, r=1.0), 0.01) == pytest.approx(3.0)
    assert weight(ev(p=0.0001, r=1.0), 0.01) == pytest.approx(-2.0)
    assert weight(ev(p=0.01, r=0.9), 0.01) == 0.0


def test_family_discount_halves_all_but_the_strongest():
    a, b, c = ev(p=0.06), ev(p=0.08, minutes=1), ev(p=0.05, minutes=2)
    res = run([a, b, c])
    assert res.contributions[b.evidence_id] == pytest.approx(weight(b, 0.01))
    assert res.contributions[a.evidence_id] == pytest.approx(0.5 * weight(a, 0.01))
    assert res.contributions[c.evidence_id] == pytest.approx(0.5 * weight(c, 0.01))


def test_different_families_count_fully():
    a, b = ev(family="device"), ev(detector="kyc", family="kyc", stage="S3_IDENTITY_MANIPULATION")
    res = run([a, b])
    assert all(res.contributions[x.evidence_id] == pytest.approx(weight(x, 0.01)) for x in (a, b))


def test_negative_evidence_lowers_p_and_marks_no_stage():
    pos = ev(stage="S1_INITIAL_ACCESS", detector="behaviour", family="identity", p=0.05)
    trusted = ev(p=0.003, reasons=("STEP_UP_PASSED_TRUSTED",), minutes=1)
    res = run([pos, trusted])
    assert res.contributions[trusted.evidence_id] < 0
    assert res.log_odds < run([pos]).log_odds
    assert "S2_CONTROL_TAKEOVER" not in res.stages


def test_bands():
    assert [band_of(p, TH) for p in (0.19, 0.2, 0.49, 0.5, 0.79, 0.8)] == ["LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH",
                                                                            "CRITICAL"]
    assert band_of(0.3, BandThresholds(medium=0.4, high=0.6, critical=0.9)) == "LOW"


def test_floor_customer_denied():
    res = run([ev(p=0.01, reasons=("CUSTOMER_DENIED",))])
    assert res.band == "CRITICAL" and res.band_before_floors == "LOW"
    assert res.floors == ["floor_CUSTOMER_DENIED"] and res.floors_raising == ["floor_CUSTOMER_DENIED"]
    assert res.log_odds == pytest.approx(logit(0.01))


def test_floor_seed_payee():
    res = run([ev(detector="graph", family="graph", stage="S5_POSITIONING", p=0.3, reasons=("SEED_DISTANCE_0",))])
    assert res.band == "HIGH" and "floor_SEED_PAYEE" in res.floors
    assert "floor_SEED_PAYEE" not in run([ev(detector="graph", family="graph", stage="S5_POSITIONING", p=0.3,
                                             reasons=("SEED_DISTANCE_1",))]).floors


def test_floor_three_stages_needs_30_minutes():
    def three(gap):
        return [ev(detector="netsec", family="cyber", stage="S0_RECON", p=0.02, r=0.2),
                ev(detector="behaviour", family="identity", stage="S1_INITIAL_ACCESS", p=0.02, r=0.2, minutes=gap),
                ev(stage="S2_CONTROL_TAKEOVER", p=0.02, r=0.2, minutes=2 * gap)]
    within, outside = run(three(15)), run(three(16))
    assert within.band == "MEDIUM" and within.floors_raising == ["floor_THREE_STAGES"]
    assert outside.band == "LOW" and "floor_THREE_STAGES" not in outside.floors


def test_floors_only_raise():
    strong = [ev(p=0.95, r=1.0), ev(detector="kyc", family="kyc", p=0.95, r=1.0),            # ℓ is capped at 3 per item,
              ev(detector="txn", family="transaction", p=0.95, r=1.0)]                      # so 3 families → L ≈ +4.4
    res = run(strong + [ev(p=0.01, reasons=("CUSTOMER_DENIED",), minutes=1)])
    assert res.band == "CRITICAL" and res.floors_raising == []


def test_amount_at_risk_sums_s6_evidence():
    res = run([ev(detector="txn", family="transaction", stage="S6_MONETIZATION", p=0.2, amount=100),
               ev(detector="txn", family="transaction", stage="S6_MONETIZATION", p=0.2, amount=50, minutes=1)])
    assert res.amount_at_risk_paise == 150
