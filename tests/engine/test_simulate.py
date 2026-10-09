"""Policy simulator (PRD §10.9) over a store built by the real Pipeline: background + Midnight ATO + benign_odd."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from engine.api import simulate_policy
from engine.common.tokenize import to_stored_event
from engine.contracts import BandThresholds, SimulationResult
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from ml.generator.run import generate
from ml.scenario import expand, labels_for, load_scenario, preload_envelopes, seed_tokens

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def store():
    ato = load_scenario(str(ROOT / "scenarios" / "midnight_ato.yaml"))
    odd = load_scenario(str(ROOT / "scenarios" / "benign_odd.yaml"))
    st = MemoryStore()
    pipe = Pipeline(st)
    pipe.startup()
    bg, bg_labels = generate(days=14, customers=80, seed=7, end=ato.default_start - timedelta(minutes=10))
    st.save_labels(bg_labels)

    def play(envs, sc=None):
        if sc is not None:
            st.save_labels(labels_for(sc, envs))
        for e in envs:
            ev = to_stored_event(e, e.occurred_at)
            st.insert_event(ev)
            pipe.process(ev)

    play(bg)
    play(preload_envelopes(ato, ato.default_start), ato)
    pipe.set_seeds(seed_tokens(ato))
    play(expand(ato, ato.default_start, "direct"), ato)
    play(expand(odd, odd.default_start, "direct"), odd)
    return st


def test_default_thresholds(store):
    r = simulate_policy(store, BandThresholds())
    SimulationResult.model_validate_json(r.model_dump_json())
    assert (r.attacks_total, r.attacks_caught) == (1, 1)
    assert r.money_protected_paise == 48_000_000 and r.median_lead_time_s > 0
    assert r.benign_customers_total >= 80 and r.benign_customers_flagged == 0
    assert r.legit_payments_total > 500 and r.legit_payments_stopped == 0
    assert r.thresholds == BandThresholds()


def test_stricter_thresholds_catch_less(store):
    base = simulate_policy(store, BandThresholds())
    strict = simulate_policy(store, BandThresholds(medium=0.9999, high=0.99999, critical=0.999999))
    assert strict.attacks_caught <= base.attacks_caught and strict.money_protected_paise <= base.money_protected_paise
    # v3 core: floors ignore thresholds; floor_S2_THEN_NEW_PAYEE holds at the payee_added, 2 min before the transfer
    assert strict.attacks_caught == 1 and strict.median_lead_time_s == 120 < base.median_lead_time_s


def test_looser_thresholds_flag_more(store):
    base = simulate_policy(store, BandThresholds())
    loose = simulate_policy(store, BandThresholds(medium=0.005, high=0.01, critical=0.02))
    assert loose.benign_customers_flagged >= base.benign_customers_flagged
    assert loose.legit_payments_stopped >= base.legit_payments_stopped
    assert loose.benign_customers_flagged > 0
    assert loose.attacks_caught == 1 and loose.median_lead_time_s >= base.median_lead_time_s


def test_simulation_is_read_only(store):
    before = (len(store.list_cases()), store.get_reliability(), len(store.audit_log))
    simulate_policy(store, BandThresholds(medium=0.1, high=0.2, critical=0.3))
    assert (len(store.list_cases()), store.get_reliability(), len(store.audit_log)) == before
