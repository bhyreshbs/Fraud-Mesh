"""APP scam (scenarios/scam_app.yaml; DEV1 FW, pending Dev 2 review) in direct mode through Pipeline + MemoryStore with
REAL detectors, after a background, as tests/engine/test_midnight_direct.py does for the Midnight ATO.

The genuine customer (Priya, her own registered phone, home IP) adds a "safe account" whose name check fails and pays it
₹4,90,000 two minutes later. No attacker device, so no account-takeover signal fires. Expected outcome:
  - one case, anchored on Priya's customer token, holds all the scenario's evidence;
  - the FIRST transfer is held AT that transfer: its txn evidence completes pat_APP_SCAM1 (S5 name-mismatch payee → S6
    payment within 30 min, no S2 takeover evidence). Nothing earlier can justify a hold: before the transfer the only
    signal is the failed name check (one weak S5 item, P ≈ 0.03), and holding every payee whose name check fails would
    stop many honest payments (nicknames, joint accounts);
  - she PASSES the trusted push (she is the one paying): STEP_UP_PASSED_TRUSTED lowers P, but policy.yaml's app_scam_hold
    rule keeps HOLD_OUTBOUND_PAYMENTS (a passed step-up proves identity, not intent), and payment state never goes down
    without an analyst's FALSE_POSITIVE verdict (§10.8);
  - the second "try again" transfer is held too.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from engine.api import explain_case, replay_case
from engine.common.tokenize import to_stored_event, tok
from engine.contracts import ACTION_SEVERITY, BAND_ORDER, SEVERITY_HOLD
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from ml.generator.run import generate
from ml.scenario import expand, labels_for, load_scenario, preload_envelopes, seed_tokens

ROOT = Path(__file__).resolve().parents[2]
BACKGROUND_CUSTOMERS = 60
PRIYA = tok("cust", "C-1042")
SAFE = tok("acct", "A-SAFE-4471")


def play(name: str, with_preload: bool = True):
    sc = load_scenario(str(ROOT / "scenarios" / f"{name}.yaml"))
    start = sc.default_start
    store = MemoryStore()
    pipe = Pipeline(store)
    pipe.startup()
    background, bg_labels = generate(days=14, customers=BACKGROUND_CUSTOMERS, seed=7, end=start - timedelta(minutes=10))
    pre = preload_envelopes(sc, start) if with_preload else []
    store.save_labels(bg_labels + labels_for(sc, pre))
    for e in background + pre:
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        pipe.process(ev)
    pipe.set_seeds(seed_tokens(sc))
    steps, updates = [], []
    envs = expand(sc, start, "direct")
    store.save_labels(labels_for(sc, envs))
    for e in envs:
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        steps.append(ev)
        updates.append(pipe.process(ev))
    return store, steps, updates


@pytest.fixture(scope="module")
def scam():
    return play("scam_app")


@pytest.fixture(scope="module")
def scam_steps_only():
    """What the API autopilot plays after a demo reset: the steps only (the reset loads the midnight_ato preload, not
    this one), so the payee has no earlier victims and MULE_FLOW cannot fire."""
    return play("scam_app", with_preload=False)


def _owners(store, step) -> set[str]:
    return {c.case_id for c in store.list_cases() for e in store.list_evidence(c.case_id) if e.event_id == step.event_id}


def _case(store, steps):
    ids = set().union(*(_owners(store, s) for s in steps))
    assert len(ids) == 1, ids
    return store.get_case(ids.pop())


def _txns(steps, updates):
    return [(s, u) for s, u in zip(steps, updates, strict=True) if s.event_type == "transaction"]


def test_scenario_shape():
    sc = load_scenario(str(ROOT / "scenarios" / "scam_app.yaml"))
    direct = expand(sc, sc.default_start, "direct")
    assert [e.event_type for e in direct] == ["login", "payee_added", "transaction", "step_up_result", "transaction"]
    devices = {e.context.device_id for e in direct}
    assert devices == {"fp_priya_phone"}                                 # her own registered phone, no attacker device
    assert {e.context.ip for e in direct} == {"49.207.10.21"}
    assert direct[1].payload["payee_name_match"] is False and "safe account" in direct[1].payload["nickname"]
    assert direct[3].payload == {"method": "device_push", "result": "passed", "factor_age_h": 2160, "challenge_id": "chl_direct"}
    assert all(lab.is_attack and lab.attack_id == "atk_scam_app_1" for lab in labels_for(sc, direct))


def test_one_case_anchored_on_priya(scam):
    store, steps, _ = scam
    case = _case(store, [s for s in steps if _owners(store, s)])
    assert case.anchor_entity == case.customer == PRIYA
    assert {s.event_type for s in steps if _owners(store, s)} == {"payee_added", "transaction", "step_up_result"}
    assert SAFE in case.entities


def test_no_account_takeover_signal_fires(scam):
    store, steps, _ = scam
    case = _case(store, [s for s in steps if _owners(store, s)])
    evs = store.list_evidence(case.case_id)
    assert "S2_CONTROL_TAKEOVER" not in case.stages and "S1_INITIAL_ACCESS" not in case.stages
    assert "pat_ATO1" not in case.pattern_hits and "pat_APP_SCAM1" in case.pattern_hits
    assert all(e.contribution <= 0 for e in evs if e.detector in ("auth", "behaviour", "kyc", "cyber", "netsec"))
    codes = {r.code for e in evs for r in e.reasons}
    assert {"PAYEE_NAME_MISMATCH", "MULE_FLOW", "STEP_UP_PASSED_TRUSTED", "STRUCTURING"} <= codes


def test_first_transfer_is_held_at_the_transfer(scam):
    store, steps, updates = scam
    (s1, (u1,)), _ = _txns(steps, updates)
    assert u1.payment_outcome == "held"
    assert u1.case.band == "HIGH" and u1.step_up is not None and u1.step_up.method_class == "trusted"
    case = _case(store, [s1])
    decisions = store.list_decisions(case.case_id)
    first_hold = next(d for d in decisions if max(ACTION_SEVERITY[a] for a in d.actions) >= SEVERITY_HOLD)
    assert first_hold.trigger_event_id == s1.event_id                    # at the transfer, not before it
    assert first_hold.created_at == s1.occurred_at


def test_passed_trusted_step_up_does_not_release_the_hold(scam):
    _, steps, updates = scam
    i = next(k for k, s in enumerate(steps) if s.event_type == "step_up_result")
    (before,), (after,) = updates[i - 1], updates[i]
    assert after.case.p_attack < before.case.p_attack                   # the identity proof is real negative evidence ...
    assert BAND_ORDER.index(after.case.band) < BAND_ORDER.index("HIGH")
    assert "HOLD_OUTBOUND_PAYMENTS" in after.case.latest_actions         # ... but app_scam_hold keeps the hold
    assert after.case.payment_state == "held" and after.step_up is None


def test_second_transfer_is_held_too(scam):
    store, steps, updates = scam
    _, (s2, (u2,)) = _txns(steps, updates)
    assert u2.payment_outcome == "held" and u2.case.payment_state == "held"
    assert BAND_ORDER.index(u2.case.band) >= BAND_ORDER.index("HIGH")
    case = _case(store, [s2])
    assert case.amount_at_risk_paise == 98_000_000


def test_explanation_parts_sum_to_log_odds(scam):
    store, steps, _ = scam
    case = _case(store, [s for s in steps if _owners(store, s)])
    x = explain_case(store, case.case_id)
    assert abs(sum(p.contribution for p in x.parts) - case.log_odds) < 1e-6
    assert abs(x.parts[-1].running_log_odds - case.log_odds) < 1e-9
    assert any(p.part_id == "pat_APP_SCAM1" for p in x.parts)
    ids = {e.evidence_id for e in store.list_evidence(case.case_id)} | {d.decision_id for d in store.list_decisions(case.case_id)}
    assert all(s.cites and set(s.cites) <= ids | set(case.pattern_hits) for s in x.narrative)


def test_replay_intervenes_at_the_first_transfer(scam):
    store, steps, updates = scam
    (s1, _), _ = _txns(steps, updates)
    case = _case(store, [s1])
    r = replay_case(store, case.case_id)
    assert r.eip is not None and r.eip.ts == s1.occurred_at and r.lead_time_s == 0
    assert r.money_protected_paise == 98_000_000                       # both transfers are at or after the EIP
    siloed = replay_case(store, case.case_id, mode="siloed")
    assert any("BLOCK_PENDING_PAYMENTS" in p.actions for p in siloed.timeline)   # a lone txn model would block outright


def test_steps_only_still_holds_the_first_transfer(scam_steps_only):
    store, steps, updates = scam_steps_only
    (s1, (u1,)), (_, (u2,)) = _txns(steps, updates)
    assert u1.payment_outcome == "held" and u2.payment_outcome == "held"
    assert u1.step_up is not None and u1.step_up.method_class == "trusted"   # the push the scenario's phone step answers
    case = _case(store, [s for s in steps if _owners(store, s)])
    assert case.customer == PRIYA and "pat_APP_SCAM1" in case.pattern_hits


def test_benign_odd_and_midnight_never_match_the_scam_pattern():
    for name in ("benign_odd", "midnight_ato"):
        store, _, updates = play(name)
        assert not any("pat_APP_SCAM1" in c.pattern_hits for c in store.list_cases())
        assert not any(d.policy_rule == "app_scam_hold" for c in store.list_cases() for d in store.list_decisions(c.case_id))
        if name == "benign_odd":
            assert all(BAND_ORDER.index(u.case.band) <= BAND_ORDER.index("MEDIUM") for us in updates for u in us)
