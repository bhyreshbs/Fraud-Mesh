"""Payee reputation (engine/graph/reputation.py; DEV1 FW, pending Dev 2 review).

The CP1 finding (docs/CONTRACT_REQUESTS.md "Shared-payee chaining"): a payee with 2–20 payers is not a §10.2 hub, so the
§10.6 joiner chained every payer's case through it. A popular legitimate payee (an established account with long-standing
payers) is now skipped for joining, while a young mule account still joins its victims (mule_fanin → one case).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import Envelope, Reason
from engine.detectors.base import make_evidence
from engine.detectors.graph_det import GraphDetector
from engine.graph.reputation import PayeeReputation, load_config
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from ml.scenario import expand, load_scenario, preload_envelopes

IST = timezone(timedelta(hours=5, minutes=30))
DAY_X = datetime(2026, 10, 9, 9, 0, tzinfo=IST)
PAYERS = 15                                  # 13–20 payers: not a hub (> 20), so §10.6 alone would chain them all
ROOT = Path(__file__).resolve().parents[2]


class FlagEveryTxnOnDayX:
    """Test detector: one txn evidence item (p = 0.05, above BASE_RATE) for every transaction on day X, so each payer
    has a case to join or open. The joining is what is under test, not the scoring."""
    id = "txn"
    handles = frozenset({"transaction"})

    def score(self, event, feats, graph, rel):
        if event.occurred_at < DAY_X:
            return []
        return [make_evidence("txn", "test", event, "S6_MONETIZATION", 0.05, rel, [Reason(code="TEST_FLAG")],
                              amount_paise=event.payload["amount_paise"])]


class World:
    def __init__(self) -> None:
        self.store = MemoryStore()
        self.pipe = Pipeline(self.store, detectors=[GraphDetector(), FlagEveryTxnOnDayX()])
        self.pipe.startup()
        self.n = 0

    def send(self, event_type: str, payload: dict, at: datetime, i: int):
        self.n += 1
        env = Envelope(event_id=f"evt_rep{self.n:08d}", event_type=event_type, source="simulator", occurred_at=at,
                       subject={"customer_ref": f"C-POP-{i:02d}", "account_ref": f"A-POP-{i:02d}"},
                       context={"ip": f"49.207.{100 + i}.5", "device_id": f"fp_pop_{i:02d}", "asn": "AS24560 Airtel"},
                       payload=payload)
        ev = to_stored_event(env, at)
        self.store.insert_event(ev)
        return self.pipe.process(ev)

    def history(self, payee: str, payers: range) -> None:
        """Each payer has paid `payee` for six weeks: added 45 days ago, then one transfer on its own day (44, 42, …
        days ago), so the history never has 5 payers in 24 h. Events are sent in time order."""
        for i in payers:
            self.send("login", {"result": "success", "auth_method": "password+otp"},
                      DAY_X - timedelta(days=45, minutes=30 - i), i)
        for i in payers:
            self.send("payee_added", {"payee_account": payee, "payee_name_match": True, "nickname": "Tuition"},
                      DAY_X - timedelta(days=45, minutes=-i), i)
        for i in payers:
            self.send("transaction", {"amount_paise": 1_200_000, "payee_account": payee, "channel": "UPI"},
                      DAY_X - timedelta(days=44 - 2 * i), i)

    def pay_on_day_x(self, payee: str, i: int):
        return self.send("transaction", {"amount_paise": 1_200_000, "payee_account": payee, "channel": "UPI"},
                         DAY_X + timedelta(minutes=10 * i), i)

    def cases_by_customer(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for c in self.store.list_cases():
            for e in self.store.list_evidence(c.case_id):
                cust = next(t for t in e.entities if t.startswith("cust:"))
                out.setdefault(cust, set()).add(c.case_id)
        return out

    def codes(self) -> set[str]:
        return {r.code for c in self.store.list_cases() for e in self.store.list_evidence(c.case_id) for r in e.reasons}


@pytest.fixture(scope="module")
def popular():
    w = World()
    w.history("A-TUTOR-POP", range(PAYERS))
    for i in range(PAYERS):
        w.pay_on_day_x("A-TUTOR-POP", i)
    return w


@pytest.fixture(scope="module")
def young():
    """Control: the same 15 payments on day X, but to an account nobody had paid before (mule-shaped)."""
    w = World()
    for i in range(PAYERS):
        w.send("login", {"result": "success", "auth_method": "password+otp"}, DAY_X - timedelta(days=45), i)
    for i in range(PAYERS):
        w.pay_on_day_x("A-YOUNG-01", i)
    return w


def test_popular_legit_payee_is_reputable(popular):
    rep = PayeeReputation(popular.pipe.graph)
    payee = tok("acct", "A-TUTOR-POP")
    prof = rep.profile(payee, DAY_X + timedelta(hours=3))
    assert prof.payers == PAYERS and prof.tenured_payers == PAYERS and prof.account_age_days >= 45
    assert prof.new_payers_recent == 0 and not prof.seed_nearby
    assert rep.is_reputable(payee, DAY_X + timedelta(hours=3))
    assert not rep.is_reputable(tok("acct", "A-POP-00"), DAY_X)          # a payer's own account has no payers


def test_popular_legit_payee_no_longer_chains_unrelated_customers(popular):
    by_cust = popular.cases_by_customer()
    assert len(by_cust) == PAYERS                                       # every payer was flagged on day X ...
    assert all(len(ids) == 1 for ids in by_cust.values())
    assert len(popular.store.list_cases()) == PAYERS                     # ... into its own case: no chaining
    for c in popular.store.list_cases():
        assert sum(t.startswith("cust:") for t in c.entities) == 1


def test_without_reputation_the_same_traffic_chains_into_one_case():
    """The CP1 behaviour this fixes: with reputation switched off, the 15 payers chain through the shared payee."""
    w = World()
    cfg = load_config()
    w.pipe.joiner.reputation = PayeeReputation(w.pipe.graph, cfg.__class__(**{**cfg.__dict__, "min_tenured_payers": 10**6}))
    w.history("A-TUTOR-POP", range(PAYERS))
    for i in range(PAYERS):
        w.pay_on_day_x("A-TUTOR-POP", i)
    day_x_cases = {cid for ids in w.cases_by_customer().values() for cid in ids}
    assert len(day_x_cases) == 1


def test_reputable_payee_does_not_trigger_mule_flow(popular):
    assert "MULE_FLOW" not in popular.codes()                           # fan-in 15 in 24 h, but long-standing payers


def test_young_payee_still_chains_its_payers_into_one_case(young):
    assert not PayeeReputation(young.pipe.graph).is_reputable(tok("acct", "A-YOUNG-01"), DAY_X + timedelta(hours=3))
    assert len(young.store.list_cases()) == 1                           # mule-shaped: one case, as before
    assert len(young.cases_by_customer()) == PAYERS
    assert "MULE_FLOW" in young.codes()                                  # fan-in >= 5 from the 6th payer on


def test_each_signal_can_veto_reputation(popular):
    g = popular.pipe.graph
    payee, now = tok("acct", "A-TUTOR-POP"), DAY_X + timedelta(hours=3)
    cfg = load_config()
    assert not PayeeReputation(g, cfg.__class__(**{**cfg.__dict__, "min_account_age_days": 60})).is_reputable(payee, now)
    assert not PayeeReputation(g, cfg.__class__(**{**cfg.__dict__, "min_tenured_payers": 16})).is_reputable(payee, now)
    assert not PayeeReputation(g, cfg.__class__(**{**cfg.__dict__, "min_payer_tenure_days": 50})).is_reputable(payee, now)
    assert not PayeeReputation(g).is_reputable(payee, DAY_X - timedelta(days=40))   # too young back then
    popular.pipe.set_seeds([tok("dev", "fp_pop_03")])                   # a payer's device is a fraud seed → seed nearby?
    try:
        # dev → acct (LOGGED_IN_FROM) → payee (SENT) is 2 hops: within seed_clear_hops
        assert not PayeeReputation(g).is_reputable(payee, now)
    finally:
        popular.pipe.set_seeds([tok("dev", "fp_pop_03")], False)
    assert PayeeReputation(g).is_reputable(payee, now)


def test_burst_of_new_payers_and_pass_through_veto():
    w = World()
    w.history("A-RENTED-01", range(3))                                  # 3 long-standing payers ...
    for i in range(3, 10):
        w.pay_on_day_x("A-RENTED-01", i)                                # ... then 7 brand-new payers in one day
    rep = PayeeReputation(w.pipe.graph)
    payee = tok("acct", "A-RENTED-01")
    prof = rep.profile(payee, DAY_X + timedelta(hours=2))
    assert prof.tenured_payers == 3 and prof.new_payers_recent == 7 and not rep.is_reputable(payee, DAY_X + timedelta(hours=2))

    w2 = World()
    w2.history("A-PASS-01", range(4))
    w2.pay_on_day_x("A-PASS-01", 4)                                     # one new payer today ...
    assert PayeeReputation(w2.pipe.graph).is_reputable(tok("acct", "A-PASS-01"), DAY_X + timedelta(hours=1))
    env = Envelope(event_id="evt_reppass0001", event_type="transaction", source="simulator",
                   occurred_at=DAY_X + timedelta(hours=1), subject={"customer_ref": "C-PASS", "account_ref": "A-PASS-01"},
                   context={"ip": "49.207.99.5", "device_id": "fp_pass"},
                   payload={"amount_paise": 1_000_000, "payee_account": "A-ONWARD-77", "channel": "IMPS"})
    ev = to_stored_event(env, env.occurred_at)
    w2.store.insert_event(ev)
    w2.pipe.process(ev)                                                 # ... and money out to a new account: pass-through
    assert not PayeeReputation(w2.pipe.graph).is_reputable(tok("acct", "A-PASS-01"), DAY_X + timedelta(hours=1, minutes=1))


def test_mule_fanin_scenario_is_still_one_case():
    sc = load_scenario(str(ROOT / "scenarios" / "mule_fanin.yaml"))
    store = MemoryStore()
    pipe = Pipeline(store)
    pipe.startup()
    steps = []
    for e in preload_envelopes(sc, sc.default_start) + expand(sc, sc.default_start, "direct"):
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        pipe.process(ev)
        steps.append(ev)
    mule = tok("acct", "A-MULE-02")
    rep = PayeeReputation(pipe.graph)
    assert not rep.is_reputable(mule, steps[-1].occurred_at)
    step_ids = {s.event_id for s in steps[-len(sc.raw["steps"]):]}
    owners = {c.case_id for c in store.list_cases() for e in store.list_evidence(c.case_id)
              if e.event_id in step_ids and mule in e.entities}
    assert len(owners) == 1
