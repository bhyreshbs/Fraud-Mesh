"""D2-P2 "Done when" (PRD §16.2): Pipeline + FixtureDetector + MemoryStore over the Midnight ATO scenario.

One case; band path LOW, LOW, MEDIUM, MEDIUM, HIGH, CRITICAL, CRITICAL, CRITICAL; step_up `any` at item 3 and
`trusted` at item 5; the transaction's payment_outcome is blocked; a CUSTOMER_DENIED item afterwards leaves P
unchanged and sets floor_CUSTOMER_DENIED and status INVESTIGATING.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import ACTION_SEVERITY, SEVERITY_HOLD, Evidence, Reason
from engine.detectors.fixture import FixtureDetector
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from ml.scenario import expand, load_scenario, preload_envelopes, seed_tokens

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = json.loads((ROOT / "fixtures" / "engine" / "demo_expected.json").read_text())


def customer_denied_item(at) -> Evidence:
    """The "Not me" step_up_result as auth evidence: p = BASE_RATE, reason CUSTOMER_DENIED (§10.4)."""
    return Evidence(evidence_id="ev_fixture_deny", event_id="evt_placeholder0", detector="auth", detector_version="fixture-1",
                    family="device", stage="S2_CONTROL_TAKEOVER", attack_technique=None, p=0.01, reliability=0.7,
                    entities=[], reasons=[Reason(code="CUSTOMER_DENIED")], ts=at)


@pytest.fixture(scope="module")
def run():
    sc = load_scenario(str(ROOT / "scenarios" / "midnight_ato.yaml"))
    steps = [to_stored_event(e, e.occurred_at) for e in expand(sc, sc.default_start, "direct")]
    detector = FixtureDetector.from_file()
    detector.items.append(customer_denied_item(steps[-1].occurred_at))
    store = MemoryStore()
    pipe = Pipeline(store, detectors=[detector])
    pipe.startup()
    for e in preload_envelopes(sc, sc.default_start):
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        assert pipe.process(ev) == []                          # preload produces no evidence
    pipe.set_seeds(seed_tokens(sc))
    updates = []
    for ev in steps:
        store.insert_event(ev)
        updates.append(pipe.process(ev))
    return store, pipe, steps, updates


def test_every_scenario_step_yields_exactly_one_update(run):
    _, _, steps, updates = run
    assert [len(u) for u in updates] == [1] * len(steps)


def test_one_case_anchored_on_priya(run):
    store, _, _, updates = run
    assert len(store.list_cases()) == 1
    assert len({u[0].case.case_id for u in updates}) == 1
    case = store.list_cases()[0]
    assert case.anchor_entity == tok("cust", "C-1042") and case.customer == tok("cust", "C-1042")
    assert len(store.list_evidence(case.case_id)) == 9


def test_band_path(run):
    _, _, _, updates = run
    assert [u[0].case.band for u in updates[:8]] == EXPECTED["pipeline_band_path"]


def test_p_attack_path_matches_the_golden_table(run):
    _, _, _, updates = run
    assert [round(u[0].case.p_attack, 3) for u in updates[:8]] == [i["p_attack"] for i in EXPECTED["items"]]


def test_step_up_any_at_item_3_and_trusted_at_item_5(run):
    _, _, _, updates = run
    got = {i + 1: u[0].step_up.method_class for i, u in enumerate(updates) if u[0].step_up}
    assert got == {3: "any", 5: "trusted"}
    su = updates[2][0].step_up
    assert su.customer == tok("cust", "C-1042") and su.reason_event_id == updates[2][0].event_id


def test_transaction_payment_outcome_is_blocked(run):
    _, _, steps, updates = run
    outcomes = {s.event_type: u[0].payment_outcome for s, u in zip(steps, updates, strict=True)}
    assert outcomes["transaction"] == EXPECTED["pipeline_payment_outcome"] == "blocked"
    assert all(u[0].payment_outcome is None for s, u in zip(steps, updates, strict=True) if s.event_type != "transaction")


def test_customer_denied_afterwards(run):
    store, _, _, updates = run
    before, after = updates[7][0].case, updates[8][0].case
    assert after.p_attack == pytest.approx(before.p_attack, abs=1e-12)
    assert after.band == "CRITICAL" and after.status == "INVESTIGATING"
    case = store.get_case(after.case_id)
    assert "floor_CUSTOMER_DENIED" in case.floors
    deny = [e for e in store.list_evidence(case.case_id) if e.reasons[0].code == "CUSTOMER_DENIED"]
    assert len(deny) == 1 and deny[0].contribution == pytest.approx(0.0, abs=1e-12)
    assert "S2_CONTROL_TAKEOVER" in case.stages and case.stages["S2_CONTROL_TAKEOVER"].evidence_id != deny[0].evidence_id


def test_stages_patterns_and_case_state(run):
    store, _, _, _ = run
    case = store.list_cases()[0]
    assert list(case.stages) == ["S0_RECON", "S1_INITIAL_ACCESS", "S2_CONTROL_TAKEOVER", "S3_IDENTITY_MANIPULATION",
                                 "S4_ESCALATION", "S5_POSITIONING", "S6_MONETIZATION"]
    assert sorted(case.pattern_hits) == ["pat_ATO1", "pat_CASE_IP_CLOUD"]
    assert case.log_odds == pytest.approx(EXPECTED["final"]["log_odds"], abs=1e-3)
    assert case.payment_state == "blocked" and case.amount_at_risk_paise == 48_000_000
    assert case.latest_actions == ["BLOCK_PENDING_PAYMENTS", "FREEZE_NEW_PAYEES", "REVOKE_SESSIONS", "OPEN_CASE_P1"]
    stored = {e.evidence_id: e.contribution for e in store.list_evidence(case.case_id)}
    assert sum(stored.values()) + 0.8 + (-4.59512) == pytest.approx(case.log_odds, abs=1e-4)


def test_decisions_one_per_evidence_and_first_hold_before_the_transfer(run):
    store, _, steps, _ = run
    case = store.list_cases()[0]
    decisions = store.list_decisions(case.case_id)
    assert len(decisions) == 9
    assert [d.policy_rule for d in decisions[:8]] == ["low", "low", "medium", "medium", "high", "critical", "critical",
                                                      "critical"]
    first_hold = next(d for d in decisions if max(ACTION_SEVERITY[a] for a in d.actions) >= SEVERITY_HOLD)
    txn = next(s for s in steps if s.event_type == "transaction")
    assert first_hold.created_at < txn.occurred_at
    kyc = next(s for s in steps if s.event_type == "kyc_result")
    assert first_hold.created_at == kyc.occurred_at                 # HOLD at the KYC step (§17 "never cut")
    # §12.2 timing puts the KYC step at 00:52:10, so the live lead time is 770 s; the §12.4 table rounds it to
    # 00:52 (780 s), which the pure fixture reproduces (see docs/CONTRACT_REQUESTS.md).
    assert (txn.occurred_at - first_hold.created_at).total_seconds() == EXPECTED["replay"]["baseline_lead_time_s"] - 10


def test_reanchor_and_audit(run):
    store, _, _, _ = run
    actions = [r["action"] for r in store.audit_log]
    assert actions.count("CASE_REANCHORED") == 1 and "CASE_MERGED" not in actions


def test_graph_elements(run):
    store, pipe, _, _ = run
    case = store.list_cases()[0]
    ge = pipe.graph_elements(case.case_id, hops=2)
    ids = {n.id for n in ge.nodes}
    assert tok("acct", "A-RAVI-778") in ids and tok("dev", "fp_mule_shared") in ids
    seeds = {n.id for n in ge.nodes if n.seed}
    assert tok("dev", "fp_mule_shared") in seeds
    assert all(n.in_case == (n.id in case.entities) for n in ge.nodes)
    assert all(e.source in ids and e.target in ids for e in ge.edges)
    assert len(pipe.graph_elements(case.case_id, hops=2, max_nodes=3).nodes) == 3
    with pytest.raises(KeyError):
        pipe.graph_elements("case_missing")


def test_startup_rebuilds_the_same_graph(run):
    store, pipe, _, _ = run
    fresh = Pipeline(store)
    assert not fresh.ready
    fresh.startup()
    fresh.startup()                                             # idempotent
    assert fresh.ready
    assert fresh.graph.seed_distance(tok("acct", "A-RAVI-778")) == pipe.graph.seed_distance(tok("acct", "A-RAVI-778"))
    assert len(fresh.graph.edges()) == len(pipe.graph.edges())


def test_two_evidence_items_from_one_event_give_one_update(run):
    """§10.1: the last CaseUpdate wins and new_evidence_ids lists both."""
    _, _, steps, _ = run
    login = next(s for s in steps if s.event_type == "login")
    items = [i for i in FixtureDetector.from_file().items if i.detector in ("behaviour", "netsec")]
    double = [items[1].model_copy(update={"ts": login.occurred_at}), items[0].model_copy(update={"ts": login.occurred_at})]
    store = MemoryStore()
    pipe = Pipeline(store, detectors=[FixtureDetector(double)])
    pipe.startup()
    store.insert_event(login)
    (update,) = pipe.process(login)
    assert len(update.new_evidence_ids) == 2 and len(store.list_evidence(update.case.case_id)) == 2
    assert update.payment_outcome is None


def test_a_pipeline_without_detectors_only_builds_the_graph():
    store = MemoryStore()
    pipe = Pipeline(store)
    pipe.startup()
    sc = load_scenario(str(ROOT / "scenarios" / "midnight_ato.yaml"))
    for e in expand(sc, sc.default_start, "direct"):
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        assert pipe.process(ev) == []
    assert store.list_cases() == [] and store.load_edges()
