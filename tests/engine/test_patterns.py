"""Sequence patterns (PRD §10.5)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from engine.contracts import Evidence, Reason
from engine.fusion.fusion import fuse
from engine.fusion.patterns import load_patterns

T0 = datetime(2026, 10, 9, 0, 39, tzinfo=UTC)
_n = 0


def ev(detector, family, stage, minutes, entities=("cust:a",), p=0.06) -> Evidence:
    global _n
    _n += 1
    return Evidence(evidence_id=f"ev_{_n:04d}", event_id=f"evt_{_n:08d}", detector=detector, detector_version="t",
                    family=family, stage=stage, p=p, reliability=0.7, entities=list(entities),
                    reasons=[Reason(code="X")], ts=T0 + timedelta(minutes=minutes))


def hits(items):
    return fuse(items, base_rate=0.01).pattern_hits


def test_patterns_file():
    pats = {p.id: p for p in load_patterns()}
    assert set(pats) == {"pat_ATO1", "pat_CASE_IP_CLOUD"}
    assert pats["pat_ATO1"].bonus == 0.5 and pats["pat_CASE_IP_CLOUD"].bonus == 0.3


def login(m):
    return ev("behaviour", "identity", "S1_INITIAL_ACCESS", m)


def mfa(m):
    return ev("auth", "device", "S2_CONTROL_TAKEOVER", m)


def test_ato1_needs_s2_after_s1_within_30_minutes():
    assert hits([login(0), mfa(30)]) == ["pat_ATO1"]
    assert hits([login(0), mfa(31)]) == []
    assert hits([mfa(0), login(5)]) == []                                  # S2 before S1
    assert hits([login(0), mfa(5), mfa(6)]) == ["pat_ATO1"]                # at most once
    assert fuse([login(0), mfa(5), mfa(6)], base_rate=0.01).pattern_bonus == {"pat_ATO1": 0.5}


def test_ato1_ignores_negative_evidence():
    assert hits([login(0), ev("auth", "device", "S2_CONTROL_TAKEOVER", 5, p=0.003)]) == []


def test_case_ip_cloud_needs_an_ip_seen_earlier():
    netsec = ev("netsec", "cyber", "S0_RECON", 0, entities=("ip:attacker",), p=0.03)
    cloud = ev("cyber", "cyber", "S4_ESCALATION", 5, entities=("cid:svc", "ip:attacker"), p=0.04)
    other = ev("cyber", "cyber", "S4_ESCALATION", 5, entities=("cid:svc", "ip:other"), p=0.04)
    assert hits([netsec, cloud]) == ["pat_CASE_IP_CLOUD"]
    assert hits([netsec, other]) == []
    assert hits([cloud]) == []
    assert fuse([netsec, cloud], base_rate=0.01).pattern_completed_by == {"pat_CASE_IP_CLOUD": cloud.evidence_id}
