"""PRD §16.3 item 4: Midnight ATO in direct mode through Pipeline + MemoryStore with REAL detectors, after a
background (as in §12.3: background up to start − 10 min, then preload, then seeds), asserting the §12.4 end-to-end
list. The two explanation/replay assertions of that list need engine.api, which is D2-P5.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import ACTION_SEVERITY, BAND_ORDER, SEVERITY_HOLD
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from ml.generator.run import generate
from ml.scenario import expand, labels_for, load_scenario, preload_envelopes, seed_tokens

ROOT = Path(__file__).resolve().parents[2]
BACKGROUND_CUSTOMERS = 60


def play(name: str):
    sc = load_scenario(str(ROOT / "scenarios" / f"{name}.yaml"))
    start = sc.default_start
    store = MemoryStore()
    pipe = Pipeline(store)
    pipe.startup()
    background, bg_labels = generate(days=14, customers=BACKGROUND_CUSTOMERS, seed=7, end=start - timedelta(minutes=10))
    pre = preload_envelopes(sc, start)
    store.save_labels(bg_labels + labels_for(sc, pre))
    for e in background + pre:
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        pipe.process(ev)
    pipe.set_seeds(seed_tokens(sc))
    steps, updates = [], []
    for e in expand(sc, start, "direct"):
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        steps.append(ev)
        updates.append(pipe.process(ev))
    return store, steps, updates


@pytest.fixture(scope="module")
def midnight():
    return play("midnight_ato")


def _case_of_step(store, step):
    owners = {c.case_id for c in store.list_cases() for e in store.list_evidence(c.case_id) if e.event_id == step.event_id}
    return owners


def test_every_step_produces_evidence_in_one_case(midnight):
    store, steps, _ = midnight
    owners = [_case_of_step(store, s) for s in steps]
    assert all(len(o) == 1 for o in owners), owners
    assert len(set.union(*owners)) == 1


def test_the_case_is_anchored_on_priya(midnight):
    store, steps, _ = midnight
    (case_id,) = _case_of_step(store, steps[1])
    case = store.get_case(case_id)
    assert case.anchor_entity == case.customer == tok("cust", "C-1042")


def test_final_band_is_critical(midnight):
    store, steps, updates = midnight
    (case_id,) = _case_of_step(store, steps[0])
    assert store.get_case(case_id).band == "CRITICAL"
    assert updates[-1][0].case.band == "CRITICAL"


def test_first_hold_decision_precedes_the_transaction_evidence(midnight):
    store, steps, _ = midnight
    (case_id,) = _case_of_step(store, steps[0])
    txn_step = next(s for s in steps if s.event_type == "transaction")
    txn_ev = next(e for e in store.list_evidence(case_id) if e.event_id == txn_step.event_id)
    first_hold = next(d for d in store.list_decisions(case_id) if max(ACTION_SEVERITY[a] for a in d.actions) >= SEVERITY_HOLD)
    assert first_hold.created_at < txn_ev.ts
    kyc = next(s for s in steps if s.event_type == "kyc_result")
    assert first_hold.created_at <= kyc.occurred_at                        # HOLD at the KYC step at the latest


def test_transaction_payment_outcome_is_blocked(midnight):
    _, steps, updates = midnight
    (u,) = next(u for s, u in zip(steps, updates, strict=True) if s.event_type == "transaction")
    assert u.payment_outcome == "blocked"


def test_not_me_keeps_p_and_sets_the_floor(midnight):
    store, steps, updates = midnight
    assert steps[-1].event_type == "step_up_result" and steps[-1].payload["result"] == "denied_by_customer"
    before, after = updates[-2][0].case, updates[-1][0].case
    assert after.p_attack == pytest.approx(before.p_attack, abs=1e-12)
    case = store.get_case(after.case_id)
    assert "floor_CUSTOMER_DENIED" in case.floors and case.status == "INVESTIGATING" and case.band == "CRITICAL"


def test_step_ups_follow_the_bands(midnight):
    _, _, updates = midnight
    seen = [u[0].step_up.method_class for u in updates if u and u[0].step_up]
    assert seen and seen[0] == "any" and "trusted" in seen


def test_evidence_is_real_not_degraded(midnight):
    store, steps, _ = midnight
    (case_id,) = _case_of_step(store, steps[0])
    evs = store.list_evidence(case_id)
    scenario_ids = {s.event_id for s in steps}
    detectors = [e.detector for e in evs if e.event_id in scenario_ids]
    assert detectors == ["netsec", "behaviour", "auth", "auth", "kyc", "cyber", "graph", "txn", "auth"]
    assert not any(e.degraded for e in evs)
    assert list(store.get_case(case_id).stages) == ["S0_RECON", "S1_INITIAL_ACCESS", "S2_CONTROL_TAKEOVER",
                                                     "S3_IDENTITY_MANIPULATION", "S4_ESCALATION", "S5_POSITIONING",
                                                     "S6_MONETIZATION"]


def test_benign_odd_never_exceeds_medium():
    store, steps, updates = play("benign_odd")
    bands = [u.case.band for us in updates for u in us]
    assert all(BAND_ORDER.index(b) <= BAND_ORDER.index("MEDIUM") for b in bands), bands
    priya = tok("cust", "C-1042")
    assert all(BAND_ORDER.index(c.band) <= BAND_ORDER.index("MEDIUM") for c in store.list_cases() if c.customer == priya)
    (txn,) = [u for s, u in zip(steps, updates, strict=True) if s.event_type == "transaction"]
    assert not any(u.payment_outcome in ("held", "blocked") for u in txn)   # no update → Dev 1 writes completed
