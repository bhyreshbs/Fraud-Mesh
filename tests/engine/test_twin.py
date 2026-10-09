"""Digital Twin (engine/twin): virtual state, strategy simulation on isolated copies, and the stage forecast, on the three
§12.2 scenarios played through the real Pipeline + MemoryStore (labels saved for every step, as the autopilot does)."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from engine.common.tokenize import to_stored_event
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from engine.twin import twin_case, twin_overview
from engine.twin.predict import load, p_reach, predict
from engine.twin.simulate import STRATEGIES, simulate
from engine.twin.state import VirtualBank
from ml.generator.run import generate
from ml.scenario import expand, labels_for, load_scenario, preload_envelopes, seed_tokens

ROOT = Path(__file__).resolve().parents[2]
INR_4_80_000 = 48_000_000


def _play(name: str):
    """(store, pipeline, case ids holding the scenario's evidence, highest risk first)."""
    sc = load_scenario(str(ROOT / "scenarios" / f"{name}.yaml"))
    store = MemoryStore()
    pipe = Pipeline(store)
    pipe.startup()
    background, bg_labels = generate(days=14, customers=60, seed=7, end=sc.default_start - timedelta(minutes=10))
    pre, steps = preload_envelopes(sc, sc.default_start), expand(sc, sc.default_start, "direct")
    store.save_labels(bg_labels + labels_for(sc, pre) + labels_for(sc, steps))
    for e in background + pre:
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        pipe.process(ev)
    pipe.set_seeds(seed_tokens(sc))
    for e in steps:
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        pipe.process(ev)
    step_ids = {e.event_id for e in steps}
    cases = [c for c in store.list_cases() if any(e.event_id in step_ids for e in store.list_evidence(c.case_id))]
    return store, pipe, [c.case_id for c in sorted(cases, key=lambda c: -c.p_attack)]


@pytest.fixture(scope="module")
def midnight():
    store, pipe, (case_id,) = _play("midnight_ato")
    return store, pipe, twin_case(store, case_id, graph=pipe.graph)


def by_id(twin):
    return {o.policy_id: o for o in twin.policies}


def test_unknown_case_is_a_key_error(midnight):
    store, _, _ = midnight
    with pytest.raises(KeyError):
        twin_case(store, "case_nope")


def test_midnight_steps_and_actors(midnight):
    _, _, t = midnight
    actors = [(s.event_type, s.actor) for s in t.steps]
    assert actors[0] == ("network_ids_alert", "network")
    assert ("login", "attacker") in actors and ("cloud_audit", "insider") in actors
    assert actors[-1] == ("step_up_result", "customer")                     # Priya's "Not me" from her own phone
    assert any("OTPs now reach the attacker" in c for s in t.steps for c in s.changes)
    tags: dict[str, set[str]] = {}
    for e in t.entities:
        tags.setdefault(e.kind, set()).update(e.tags)
    assert "attacker device" in tags["dev"] and "attacker phone" in tags["phone"]


def test_midnight_strategies_compared_on_isolated_copies(midnight):
    _, _, t = midnight
    o = by_id(t)
    assert [p.policy_id for p in t.policies] == [s.policy_id for s in STRATEGIES] and len(t.policies) == 8
    assert all(len(p.steps) == len(t.steps) for p in t.policies)
    assert o["allow_all"].money_lost_paise == INR_4_80_000 and not o["allow_all"].attack_stopped
    # SMS OTP alone does not help: the attacker swapped the SMS number first
    assert o["otp_only"].money_lost_paise == INR_4_80_000
    assert "attacker passed" in o["otp_only"].interventions[0].effect
    for pid in ("hold_at_high", "block_at_critical", "freeze_payees_at_medium", "fraudmesh", "fraudmesh_strong_txn"):
        assert o[pid].money_lost_paise == 0 and o[pid].money_protected_paise == INR_4_80_000, pid
    fm = o["fraudmesh"]
    assert fm.attack_stopped and fm.lead_time_s and fm.lead_time_s > 0               # locked out before the transfer
    assert fm.steps[[s.event_type for s in t.steps].index("transaction")] == "prevented"
    assert t.best_policy in ("fraudmesh", "fraudmesh_strong_txn") and t.earliest_intervention is not None


def test_midnight_forecast_follows_the_attack(midnight):
    _, _, t = midnight
    login = next(s for s in t.steps if s.event_type == "login")
    payee = next(s for s in t.steps if s.event_type == "payee_added")
    assert login.forecast_stage == "S1_INITIAL_ACCESS" and login.forecast_p_money == pytest.approx(1.0)
    assert payee.forecast_next == "S6_MONETIZATION" and payee.forecast_probability == pytest.approx(1.0)
    assert payee.forecast_minutes_to_money is not None and payee.forecast_minutes_to_money < 5
    assert t.prediction.from_stage == "S6_MONETIZATION"


def test_simulation_never_mutates_the_start_state(midnight):
    store, pipe, t = midnight
    start = VirtualBank()
    again = twin_case(store, t.case_id, graph=pipe.graph)
    assert start.customers == {} and start.tags == {}
    assert [p.model_dump() for p in again.policies] == [p.model_dump() for p in t.policies]
    assert simulate(STRATEGIES[0], [], start, None).money_lost_paise == 0


def test_benign_traveller_opens_no_case_so_there_is_nothing_to_simulate():
    _, _, cases = _play("benign_odd")
    assert cases == []                       # new phone in Mumbai, push approved on the registered phone: no case


def test_mule_fan_in_senders_are_scammed_customers():
    store, pipe, cases = _play("mule_fanin")
    t = twin_case(store, cases[0], graph=pipe.graph)
    o = by_id(t)
    transfers = [s for s in t.steps if s.event_type == "transaction"]
    assert transfers and all(s.actor == "customer" for s in transfers)
    assert o["allow_all"].money_lost_paise > 0
    assert o["otp_only"].money_lost_paise == o["allow_all"].money_lost_paise      # the real customer passes the OTP
    assert o["fraudmesh"].money_lost_paise < o["allow_all"].money_lost_paise


def test_forecast_table_and_reachability():
    data = load()
    assert data["attacks"] > 0 and data["transitions"]
    assert p_reach(data["transitions"], "S5_POSITIONING") == pytest.approx(1.0)
    f = predict("S2_CONTROL_TAKEOVER")
    assert 0.99 <= sum(n.probability for n in f.next_stages) <= 1.0 + 1e-9 or len(f.next_stages) == 3
    assert f.p_reach_monetization and f.expected_minutes_to_monetization and f.sample_size == data["attacks"]
    assert predict(None).next_stages == [] and predict("S2_CONTROL_TAKEOVER", directory="/nonexistent").sample_size == 0


def test_overview_counts_the_virtual_bank(midnight):
    store, pipe, _ = midnight
    ov = twin_overview(store, pipe.graph)
    assert ov.entities["cust"] >= 60 and ov.fraud_seeds == 2
    assert sum(ov.cases_by_band.values()) == len(store.list_cases()) and ov.cases_by_band["CRITICAL"] >= 1
    assert ov.hottest_cases[0]["band"] == "CRITICAL"
