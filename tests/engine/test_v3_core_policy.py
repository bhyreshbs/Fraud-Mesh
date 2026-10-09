"""v3 core: floor rules record the cause (3.1d), late evidence held → blocked (11.6), replay parity, feedback guards (11.4)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from engine.contracts import Case, Evidence, Reason, StoredEvent
from engine.feedback import FeedbackGuard, apply_feedback, apply_feedback_with_provenance, bounded_delta
from engine.fusion.fusion import FLOOR_S2_THEN_NEW_PAYEE, Fusion
from engine.fusion.v3_core import merged
from engine.policy.policy import LATE_EVIDENCE_RULE, Policy
from engine.replay.replay import fused_timeline
from engine.store_memory import MemoryStore
from ml.build_fixtures import golden_store

T0 = datetime(2026, 10, 9, 0, 39, tzinfo=UTC)
_n = 0


def ev(detector, family, stage, p, r=0.7, minutes=0.0, code="X") -> Evidence:
    global _n
    _n += 1
    return Evidence(evidence_id=f"ev_v3p{_n:04d}", event_id=f"evt_v3p{_n:08d}", detector=detector, detector_version="t",
                    family=family, stage=stage, p=p, reliability=r, entities=["cust:a"], reasons=[Reason(code=code)],
                    ts=T0 + timedelta(minutes=minutes))


def event_for(e: Evidence) -> StoredEvent:
    return StoredEvent(event_id=e.event_id, event_type="login", source="simulator", occurred_at=e.ts, received_at=e.ts,
                       payload={}, entity_tokens=[])


def play(items):
    """Process evidence like Pipeline.process does after the joiner: fusion → contribution → policy."""
    store = MemoryStore()
    case = Case(case_id="case_v3p", anchor_entity="cust:a", customer="cust:a", opened_at=T0, updated_at=T0, last_event_ts=T0)
    store.save_case(case)
    fusion, policy, decisions = Fusion(store), Policy(store), []
    for e in items:
        store.save_evidence(e, case.case_id)
        res = fusion.recompute(case)
        e.contribution = res.contributions[e.evidence_id]
        decisions.append(policy.decide(case, event_for(e), e)[0])
        store.save_case(case)
    return store, case, decisions


def test_ato_floor_decides_on_the_payee_evidence_with_its_own_rule():
    s2 = ev("auth", "device", "S2_CONTROL_TAKEOVER", 0.06, code="MFA_CHANGED_AFTER_NEW_DEVICE")
    s5 = ev("graph", "graph", "S5_POSITIONING", 0.03, r=0.8, minutes=20, code="PAYEE_NAME_MISMATCH")
    store, case, decisions = play([s2, s5])
    assert [d.policy_rule for d in decisions] == ["low", "ato_new_payee_hold"]
    d = decisions[-1]
    assert d.trigger_evidence_id == s5.evidence_id and d.band == "HIGH" and "HOLD_OUTBOUND_PAYMENTS" in d.actions
    assert case.payment_state == "held" and FLOOR_S2_THEN_NEW_PAYEE in case.floors
    tl = fused_timeline(store.list_evidence(case.case_id))                 # replay agrees with live
    assert [p.actions for p in tl.points] == [x.actions for x in decisions]


def test_ato_floor_explanation_part_cites_the_evidence():
    from engine.explain.explain import explain_case
    s2 = ev("auth", "device", "S2_CONTROL_TAKEOVER", 0.06, code="MFA_CHANGED_AFTER_NEW_DEVICE")
    s5 = ev("graph", "graph", "S5_POSITIONING", 0.03, r=0.8, minutes=20, code="PAYEE_NAME_MISMATCH")
    store, case, _ = play([s2, s5])
    x = explain_case(store, case.case_id)
    part = next(p for p in x.parts if p.part_id == FLOOR_S2_THEN_NEW_PAYEE)
    assert part.kind == "floor" and part.contribution == 0 and s5.evidence_id in part.label and s2.evidence_id in part.label
    assert sum(p.contribution for p in x.parts) == pytest.approx(case.log_odds, abs=1e-9)


def test_late_cloud_audit_escalates_held_to_blocked():
    s2 = ev("auth", "device", "S2_CONTROL_TAKEOVER", 0.06, code="MFA_CHANGED_AFTER_NEW_DEVICE")
    s5 = ev("graph", "graph", "S5_POSITIONING", 0.03, r=0.8, minutes=20, code="PAYEE_NAME_MISMATCH")
    late = ev("cyber", "cyber", "S4_ESCALATION", 0.035, r=0.5, minutes=10, code="cloud_limit_raise_untrusted_ip")
    store, case, decisions = play([s2, s5, late])                 # arrives last, happened between S2 and S5
    assert decisions[-1].band == "HIGH" and decisions[-1].policy_rule == LATE_EVIDENCE_RULE
    assert "BLOCK_PENDING_PAYMENTS" in decisions[-1].actions and case.payment_state == "blocked"
    # replay re-orders by EVENT time (the cyber item lands before the payee, when nothing was held yet), so it shows
    # the hold, not the block: live arrival order is not stored with the evidence (see CONTRACT_REQUESTS v3 core)
    assert fused_timeline(store.list_evidence(case.case_id)).payment_states[-1] == "held"


def test_step_up_answer_does_not_escalate_and_switch_off_works():
    s2 = ev("auth", "device", "S2_CONTROL_TAKEOVER", 0.06, code="MFA_CHANGED_AFTER_NEW_DEVICE")
    s5 = ev("graph", "graph", "S5_POSITIONING", 0.03, r=0.8, minutes=20, code="PAYEE_NAME_MISMATCH")
    fresh = ev("auth", "device", "S2_CONTROL_TAKEOVER", 0.08, minutes=22, code="STEP_UP_PASSED_WITH_FRESH_FACTOR")
    _, case, decisions = play([s2, s5, fresh])
    assert case.payment_state == "held" and decisions[-1].policy_rule != LATE_EVIDENCE_RULE
    late = ev("kyc", "kyc", "S3_IDENTITY_MANIPULATION", 0.06, r=0.6, minutes=25, code="LOW_LIVENESS")
    off = Policy(None, v3=merged({"late_evidence": {"enabled": False}}))
    late.contribution = 1.0
    assert off.evaluate("HIGH", late, payment_state="held")[0] != LATE_EVIDENCE_RULE
    assert Policy(None).evaluate("HIGH", late, payment_state="held")[0] == LATE_EVIDENCE_RULE
    assert Policy(None).evaluate("HIGH", late, payment_state="normal")[0] != LATE_EVIDENCE_RULE
    assert Policy(None).evaluate("MEDIUM", late, payment_state="held")[0] != LATE_EVIDENCE_RULE


# ------------------------------------------------------------------ 11.4 feedback poisoning guards
def test_golden_feedback_step_is_unchanged():
    store, case = golden_store()
    r, prov = apply_feedback_with_provenance(store, None, case.case_id, "FALSE_POSITIVE", "usr_analyst")
    assert store.get_reliability()["cyber"] == (5.0, 6.0) and round(r.reliability_after["cyber"], 3) == 0.455
    assert prov["updates"]["cyber"]["applied"] == [0.0, 1.0] and prov["updates"]["cyber"]["cut_by"] == []
    assert prov["analyst"] == "usr_analyst" and prov["credited_evidence"]["cyber"] == ["ev_demo_06"]
    assert not [x for x in store.audit_log if x["action"] == "FEEDBACK"]      # the API still writes the audit row


def test_bounds_never_push_reliability_past_the_limits():
    assert bounded_delta(19.0, 1.0, 1.0, 0.0, 0.2, 0.95) == (0.0, 0.0)          # already at 0.95
    a, _ = bounded_delta(17.0, 1.0, 5.0, 0.0, 0.2, 0.95)
    assert (17 + a) / (18 + a) == pytest.approx(0.95)
    _, b = bounded_delta(1.0, 3.0, 0.0, 5.0, 0.2, 0.95)
    assert 1 / (4 + b) == pytest.approx(0.2)


def test_repeated_false_positives_are_capped_per_batch_and_bounded():
    store, case = golden_store()
    guard = FeedbackGuard()
    for i in range(10):                                     # a poisoning burst: 10 FALSE_POSITIVE in one hour
        apply_feedback_with_provenance(store, None, case.case_id, "FALSE_POSITIVE", "usr_x",
                                       feedback_ts=T0 + timedelta(minutes=i), guard=guard)
    a, b = store.get_reliability()["cyber"]
    assert b - 5.0 == pytest.approx(3.0, abs=1e-2) and a == 5.0   # max_batch 3.0 in 24 h (minus minutes of decay)
    _, prov = apply_feedback_with_provenance(store, None, case.case_id, "FALSE_POSITIVE", "usr_x",
                                             feedback_ts=T0 + timedelta(minutes=30), guard=guard)
    assert "max_batch" in prov["updates"]["cyber"]["cut_by"]
    cfg = merged({"feedback": {"max_batch": 100.0}})["feedback"]
    for i in range(40):
        apply_feedback_with_provenance(store, None, case.case_id, "FALSE_POSITIVE", "usr_x",
                                       feedback_ts=T0 + timedelta(minutes=40 + i), guard=guard, cfg=cfg)
    a, b = store.get_reliability()["cyber"]
    assert a / (a + b) == pytest.approx(0.2) or a / (a + b) > 0.2


def test_decay_toward_prior_is_deterministic_by_feedback_time():
    def run():
        store, case = golden_store()
        guard = FeedbackGuard()
        apply_feedback_with_provenance(store, None, case.case_id, "FALSE_POSITIVE", "u", feedback_ts=T0, guard=guard)
        _, prov = apply_feedback_with_provenance(store, None, case.case_id, "FALSE_POSITIVE", "u",
                                                 feedback_ts=T0 + timedelta(days=30), guard=guard)
        return store.get_reliability()["cyber"], prov
    (a, b), prov = run()
    assert prov["updates"]["cyber"]["decay"] == [pytest.approx(0.0), pytest.approx(-0.5)]   # 1 beta, half-life 30 d
    assert (a, b) == (5.0, pytest.approx(6.5)) and run()[0] == (a, b)


def test_plain_apply_feedback_signature_unchanged():
    store, case = golden_store()
    assert apply_feedback(store, None, case.case_id, "INCONCLUSIVE", "u").status_after == "INVESTIGATING"
