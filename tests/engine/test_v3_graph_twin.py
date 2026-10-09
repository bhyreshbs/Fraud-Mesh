"""v3: the Digital Twin tells (1) an account takeover, (2) a manipulated genuine customer (APP scam) and (3) a legitimate
high-value payment apart. Regression for the twin labelling the APP-scam victim "attacker" because her device edge was
younger than 24 h (engine/twin/build.py _customer_devices)."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from engine.common.tokenize import to_stored_event
from engine.contracts import Envelope, Label, Reason
from engine.detectors.base import make_evidence
from engine.detectors.registry import default_detectors
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from engine.twin import twin_case
from ml.generator.run import generate
from tests.engine.test_twin import _play


class FlagOne:
    """Test detector: one txn evidence item (p 0.3) for one event id."""
    id = "txn"
    handles = frozenset({"transaction"})

    def __init__(self, event_id: str) -> None:
        self.event_id = event_id

    def score(self, event, feats, graph, rel):
        if event.event_id != self.event_id:
            return []
        return [make_evidence("txn", "test", event, "S6_MONETIZATION", 0.3, rel, [Reason(code="TEST_FLAG")],
                              amount_paise=event.payload["amount_paise"])]


@pytest.fixture(scope="module")
def scam_twin():
    store, pipe, cases = _play("scam_app")
    priya = next(c for c in cases if store.get_case(c).customer and "pat_APP_SCAM1" in store.get_case(c).pattern_hits)
    return twin_case(store, priya, graph=pipe.graph)


def test_app_scam_victim_is_the_customer_not_an_attacker(scam_twin):
    t = scam_twin
    assert t.case_kind == "app_scam"
    assert {s.actor for s in t.steps} == {"customer"}
    assert all(s.actor == "customer" for s in t.steps if s.event_type in ("payee_added", "transaction"))
    assert not any("Attacker" in s.summary for s in t.steps)


def test_midnight_is_still_an_account_takeover():
    store, pipe, (case_id,) = _play("midnight_ato")
    t = twin_case(store, case_id, graph=pipe.graph)
    assert t.case_kind == "account_takeover"
    actors = {(s.event_type, s.actor) for s in t.steps}
    assert ("login", "attacker") in actors and ("transaction", "attacker") in actors
    assert ("step_up_result", "customer") in actors


def test_legitimate_high_value_payment_is_the_customer():
    """A background customer pays 25x their median to a payee they have paid before, from their own phone. The real
    detectors let it through (no case), so a test detector flags exactly that transfer to give the twin a case."""
    store = MemoryStore()
    pipe = Pipeline(store, detectors=default_detectors() + [FlagOne("evt_v3legitbig0001")])
    pipe.startup()
    end = datetime.fromisoformat("2026-10-09T10:00:00+05:30")
    envs, labels = generate(days=14, customers=40, seed=7, end=end)
    store.save_labels(labels)
    for e in envs:
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        pipe.process(ev)
    txns = [e for e in envs if e.event_type == "transaction" and e.subject.customer_ref != "C-1042"]
    last = txns[-1]
    amounts = [e.payload["amount_paise"] for e in txns if e.subject.customer_ref == last.subject.customer_ref]
    big = Envelope(event_id="evt_v3legitbig0001", event_type="transaction", source="demo-bank-web",
                   occurred_at=end + timedelta(minutes=5), subject=last.subject, context=last.context,
                   payload={"amount_paise": int(sorted(amounts)[len(amounts) // 2] * 25),
                            "payee_account": last.payload["payee_account"], "channel": "NEFT"})
    store.save_labels([Label(event_id=big.event_id, scenario="legit_high_value", is_attack=False)])
    ev = to_stored_event(big, big.occurred_at)
    store.insert_event(ev)
    updates = pipe.process(ev)
    graph_codes = {r.code for u in updates for e in store.list_evidence(u.case.case_id) for r in e.reasons
                   if e.event_id == ev.event_id}
    assert not any(c.startswith("APP_SCAM_") for c in graph_codes)       # a known payee: no scam intervention
    assert updates                                                         # the big transfer opened / joined a case
    t = twin_case(store, updates[0].case.case_id, graph=pipe.graph)
    assert t.case_kind == "legitimate"
    assert all(s.actor == "customer" for s in t.steps if s.event_id == ev.event_id)
