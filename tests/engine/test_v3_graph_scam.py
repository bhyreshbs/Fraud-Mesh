"""v3 phase 7: the APP-scam path (engine/features/app_scam.py via the graph detector) and the interventions proposed in
docs/v3_policy_requests.yaml, tested exactly as written there (the live policy.yaml is owned elsewhere)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import ACTION_SEVERITY, BAND_ORDER, SEVERITY_HOLD, Envelope, Telemetry
from engine.detectors.graph_det import GraphDetector
from engine.features.app_scam import COOLING_OFF, WARNING, AppScamAssessor, PayeeRiskSignal
from engine.graph.store import EntityGraph
from engine.policy.policy import load_rules
from tests.engine.test_v3_graph_mule import play, step_cases

ROOT = Path(__file__).resolve().parents[2]
IST = timezone(timedelta(hours=5, minutes=30))
T0 = datetime(2026, 10, 9, 15, 0, tzinfo=IST)
REL = {"graph": (8.0, 2.0)}


@pytest.fixture(scope="module")
def proposed_policy(tmp_path_factory) -> Path:
    raw = yaml.safe_load((ROOT / "docs" / "v3_policy_requests.yaml").read_text(encoding="utf-8"))
    path = tmp_path_factory.mktemp("policy") / "policy.yaml"
    path.write_text(yaml.safe_dump(raw["policy"], sort_keys=False), encoding="utf-8")
    load_rules(path)                                                       # validates every action name
    assert raw["patterns_append"] == []
    return path


# ---------------------------------------------------------------------------- the assessment itself
def _txn(amount, payee="A-NEWP1", telemetry=None, cust="C-APP1"):
    env = Envelope(event_id=f"evt_v3app{amount:010d}", event_type="transaction", source="demo-bank-web",
                   occurred_at=T0, schema_version="1.1", subject={"customer_ref": cust, "account_ref": f"A-{cust}"},
                   context={"device_id": "fp_app1", "ip": "49.207.90.1", "telemetry": telemetry},
                   payload={"amount_paise": amount, "payee_account": payee, "channel": "IMPS"})
    return to_stored_event(env, T0)


FEATS = {"amount_to_median_30d": 1.0, "payee_fan_in_24h": 0, "minutes_since_mfa_change": 10_080.0,
         "minutes_since_new_device": 10_080.0, "payee_is_new": 1.0}


def _assess(ev, feats=None, risk=None):
    g = EntityGraph()
    g.apply(ev)
    return AppScamAssessor().assess(ev, {**FEATS, **(feats or {})}, g, risk)


def test_first_payment_far_above_baseline_to_a_young_payee_warns():
    a = _assess(_txn(5_000_000), {"amount_to_median_30d": 25.0})
    assert a.level == WARNING
    assert [c for c, _ in a.indicators] == ["APP_FIRST_PAYMENT_TO_PAYEE", "APP_AMOUNT_FAR_ABOVE_BASELINE",
                                            "APP_YOUNG_PAYEE_ACCOUNT"]
    assert a.reasons()[0][0] == WARNING


def test_ordinary_first_payment_is_silent():
    assert _assess(_txn(800_000), {"amount_to_median_30d": 1.1}).level is None


def test_session_telemetry_and_demo_indicators_raise_to_cooling_off():
    t = Telemetry(paste_in_sensitive_field=True, payment_screen_dwell_s=3, active_call_demo=True)
    a = _assess(_txn(900_000, telemetry=t), {"amount_to_median_30d": 1.0})
    codes = [c for c, _ in a.indicators]
    assert {"APP_PASTED_PAYEE_DETAILS", "APP_RUSHED_PAYMENT", "APP_ACTIVE_CALL_DEMO"} <= set(codes)
    assert a.level == COOLING_OFF
    assert any("demo-only" in d for c, d in a.indicators if c == "APP_ACTIVE_CALL_DEMO")
    remote = _assess(_txn(900_000, telemetry=Telemetry(remote_access_demo=True)))
    assert "APP_REMOTE_ACCESS_DEMO" in [c for c, _ in remote.indicators]


def test_payee_risk_provider_report_counts_only_when_attached():
    ev = _txn(2_000_000, payee="A-REPORTED")
    reported = tok("acct", "A-REPORTED")

    def lookup(payee, now):
        return PayeeRiskSignal(score=0.9, reports=4, source="fixture") if payee == reported else None
    assert "APP_PAYEE_REPORTED" not in [c for c, _ in _assess(ev).indicators]
    a = _assess(ev, risk=lookup)
    assert "APP_PAYEE_REPORTED" in [c for c, _ in a.indicators] and a.level == WARNING


def test_a_new_device_payment_is_the_takeover_path_not_app():
    a = _assess(_txn(5_000_000), {"amount_to_median_30d": 25.0, "minutes_since_new_device": 30.0})
    assert a.level is None and a.indicators == []


def test_graph_detector_emits_app_reasons_with_a_small_p():
    ev = _txn(5_000_000)
    g = EntityGraph()
    g.apply(ev)
    (e,) = GraphDetector().score(ev, {**FEATS, "amount_to_median_30d": 25.0}, g, REL)
    assert e.detector == "graph" and e.stage == "S5_POSITIONING" and e.p == pytest.approx(0.02)
    assert e.reasons[0].code == WARNING


# ---------------------------------------------------------------------------- scenarios under the proposed policy
def _actions(store, case_id):
    return [(d.policy_rule, d.actions, d.trigger_event_id) for d in store.list_decisions(case_id)]


def test_scam_app_cooling_off_holds_and_a_passed_push_does_not_release_it(proposed_policy):
    store, _, steps, updates = play("scam_app", proposed_policy)
    txns = [(s, us) for s, us in zip(steps, updates, strict=True) if s.event_type == "transaction"]
    (s1, (u1,)), (s2, (u2,)) = txns
    assert u1.payment_outcome == "held" and u2.payment_outcome == "held"
    assert u1.step_up is not None and u1.step_up.method_class == "trusted"   # the push is still asked
    case = store.get_case(u1.case.case_id)
    decisions = _actions(store, case.case_id)
    cooling = [d for d in decisions if d[0] == "app_scam_cooling_off"]
    assert cooling and cooling[0][2] == s1.event_id
    assert {"COOLING_OFF_HOLD", "SCAM_WARNING", "HOLD_OUTBOUND_PAYMENTS"} <= set(cooling[0][1])
    first_hold = next(d for d in decisions if max(ACTION_SEVERITY[a] for a in d[1]) >= SEVERITY_HOLD)
    assert first_hold[2] == s1.event_id                                     # at the first transfer, not before
    i = next(k for k, s in enumerate(steps) if s.event_type == "step_up_result")
    (after,) = updates[i]
    assert after.case.payment_state == "held"                               # OTP/push approval does not clear it
    assert any(a in after.case.latest_actions for a in ("HOLD_OUTBOUND_PAYMENTS", "COOLING_OFF_HOLD"))
    assert "pat_APP_SCAM1" in case.pattern_hits


def test_scam_app_steps_only_still_warns_and_holds(proposed_policy):
    """The autopilot plays steps only (no earlier victims): the first transfer still scores at least a warning."""
    store, _, steps, updates = play("scam_app", proposed_policy, preload=False)
    codes = {r.code for c in step_cases(store, steps) for e in store.list_evidence(c.case_id) for r in e.reasons}
    assert WARNING in codes
    (s1, (u1,)), _ = [(s, us) for s, us in zip(steps, updates, strict=True) if s.event_type == "transaction"]
    assert u1.payment_outcome == "held"
    rules = [d.policy_rule for d in store.list_decisions(u1.case.case_id) if d.trigger_event_id == s1.event_id]
    assert any(r.startswith("app_scam_warning") for r in rules)            # the warning is shown at the transfer


def test_midnight_and_benign_are_unchanged_under_the_proposed_policy(proposed_policy):
    store, _, steps, updates = play("midnight_ato", proposed_policy)
    (case,) = step_cases(store, steps)
    assert case.band == "CRITICAL" and case.anchor_entity == tok("cust", "C-1042")
    txn = next(s for s in steps if s.event_type == "transaction")
    outcome = next(u.payment_outcome for s, us in zip(steps, updates, strict=True) for u in us if s is txn)
    assert outcome == "blocked"
    decisions = store.list_decisions(case.case_id)
    first_hold = next(d for d in decisions if max(ACTION_SEVERITY[a] for a in d.actions) >= SEVERITY_HOLD)
    assert first_hold.created_at < txn.occurred_at
    assert not any(d.policy_rule.startswith("app_scam") for d in decisions)
    store, _, steps, updates = play("benign_odd", proposed_policy)
    assert all(BAND_ORDER.index(u.case.band) <= BAND_ORDER.index("MEDIUM") for us in updates for u in us)
    assert not any("SCAM_WARNING" in d.actions or "COOLING_OFF_HOLD" in d.actions
                   for c in store.list_cases() for d in store.list_decisions(c.case_id) if c.customer == tok("cust", "C-1042"))


def test_insider_scenario_holds_under_the_proposed_policy(proposed_policy):
    store, _, steps, _ = play("insider_trusted_network", proposed_policy)
    anita = tok("cust", "C-ANITA-01")
    case = next(c for c in step_cases(store, steps) if c.customer == anita)
    assert any(d.policy_rule == "insider_staff_change" for d in store.list_decisions(case.case_id))
    assert store.get_case(case.case_id).payment_state == "held"
