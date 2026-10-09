"""Policy (PRD §10.8) and stages (§10.7)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from engine.cases.stages import Stages
from engine.contracts import Case, Evidence, Reason, StoredEvent
from engine.policy.policy import Policy, load_rules, payment_state_after, severity
from engine.store_memory import MemoryStore

T0 = datetime(2026, 10, 9, 0, 39, tzinfo=UTC)
EVENT = StoredEvent(event_id="evt_policy0001", event_type="login", source="simulator", occurred_at=T0, received_at=T0,
                    payload={"result": "success", "auth_method": "password"}, entity_tokens=[])


def ev(code="X", contribution=1.0, stage="S1_INITIAL_ACCESS") -> Evidence:
    return Evidence(evidence_id="ev_p1", event_id=EVENT.event_id, detector="netsec", detector_version="t", family="cyber",
                    stage=stage, p=0.04, reliability=0.5, contribution=contribution, entities=["ip:x"],
                    reasons=[Reason(code=code)], ts=T0)


@pytest.fixture
def setup():
    store = MemoryStore()
    case = Case(case_id="case_p", anchor_entity="cust:a", customer="cust:a", opened_at=T0, updated_at=T0, last_event_ts=T0)
    store.save_case(case)
    return store, Policy(store), case


@pytest.mark.parametrize("band,rule,actions", [
    ("CRITICAL", "critical", ["BLOCK_PENDING_PAYMENTS", "FREEZE_NEW_PAYEES", "REVOKE_SESSIONS", "OPEN_CASE_P1"]),
    ("HIGH", "high", ["HOLD_OUTBOUND_PAYMENTS", "STEP_UP_TRUSTED_FACTOR", "OPEN_CASE_P2"]),
    ("MEDIUM", "medium", ["STEP_UP_ANY_FACTOR"]),
    ("LOW", "low", ["ALLOW"]),
])
def test_rule_per_band(setup, band, rule, actions):
    store, policy, case = setup
    case.band, case.p_attack = band, 0.5
    d, _ = policy.decide(case, EVENT, ev())
    assert (d.policy_rule, d.actions, d.band, d.created_at, d.trigger_evidence_id) == (rule, actions, band, T0, "ev_p1")
    assert d.trigger_event_id == EVENT.event_id and d.actor == "engine"
    assert store.list_decisions("case_p") == [d] and case.latest_actions == actions


def test_credential_stuffing_gets_a_captcha_only_when_low(setup):
    _, policy, case = setup
    assert policy.decide(case, EVENT, ev("CREDENTIAL_STUFFING_IP"))[0].actions == ["CAPTCHA_CHALLENGE"]
    case.band = "MEDIUM"
    assert policy.decide(case, EVENT, ev("CREDENTIAL_STUFFING_IP"))[0].policy_rule == "medium"


def test_step_up_only_when_newly_requested(setup):
    _, policy, case = setup
    case.band = "MEDIUM"
    _, s1 = policy.decide(case, EVENT, ev())
    _, s2 = policy.decide(case, EVENT, ev())
    case.band = "HIGH"
    _, s3 = policy.decide(case, EVENT, ev())
    case.band = "CRITICAL"
    _, s4 = policy.decide(case, EVENT, ev())
    case.band = "HIGH"
    _, s5 = policy.decide(case, EVENT, ev())
    assert (s1.method_class, s2, s3.method_class, s4, s5.method_class) == ("any", None, "trusted", None, "trusted")
    assert s1.case_id == "case_p" and s1.customer == "cust:a" and s1.reason_event_id == EVENT.event_id


def test_no_step_up_without_a_customer(setup):
    _, policy, case = setup
    case.customer, case.band = None, "MEDIUM"
    assert policy.decide(case, EVENT, ev())[1] is None


def test_payment_state_never_goes_down():
    assert payment_state_after("normal", ["HOLD_OUTBOUND_PAYMENTS"]) == "held"
    assert payment_state_after("held", ["BLOCK_PENDING_PAYMENTS"]) == "blocked"
    assert payment_state_after("blocked", ["HOLD_OUTBOUND_PAYMENTS"]) == "blocked"
    assert payment_state_after("held", ["ALLOW"]) == "held"
    assert payment_state_after("normal", ["STEP_UP_ANY_FACTOR"]) == "normal"


def test_severity_and_rules_file():
    assert severity(["ALLOW"]) == 0 and severity(["HOLD_OUTBOUND_PAYMENTS", "OPEN_CASE_P2"]) == 2
    # §10.8's rules in order, plus app_scam_hold (DEV1 FW) between high and medium: it can only raise actions below HIGH
    # v3 core: ato_new_payee_hold and txn_high_confidence_hold (floor_any) between critical and high
    # v3 graph/scam/insider and network/session rules (docs/v3_policy_requests.yaml, v3 NET report) merged in order
    assert [r.id for r in load_rules()] == ["critical", "ato_new_payee_hold", "txn_high_confidence_hold",
                                            "app_scam_cooling_off", "high", "app_scam_hold", "insider_staff_change",
                                            "app_scam_warning_medium", "medium", "app_scam_warning", "credential_stuffing",
                                            "distributed_stuffing", "session_context_change", "low"]


def test_stages_mark_first_positive_evidence_only():
    case = Case(case_id="c", anchor_entity="cust:a", opened_at=T0, updated_at=T0, last_event_ts=T0)
    st = Stages()
    assert not st.update(case, ev(contribution=0.0))
    assert not st.update(case, ev(contribution=-0.4))
    assert st.update(case, ev(contribution=0.3, stage="S2_CONTROL_TAKEOVER"))
    assert st.update(case, ev(contribution=0.3, stage="S0_RECON"))
    assert not st.update(case, ev(contribution=0.9, stage="S2_CONTROL_TAKEOVER"))
    assert list(case.stages) == ["S0_RECON", "S2_CONTROL_TAKEOVER"]
