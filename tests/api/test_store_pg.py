"""PgStore against the Store semantics of PRD §5/§8. Dev 2's tests/engine/test_store_contract.py (STORE=pg) is the
cross-check at Checkpoint 1; these tests cover the same rules from Dev 1's side."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from api.audit import GENESIS, row_hash
from api.db.session import get_engine
from api.store_pg import PgStore
from engine.contracts import Case, Decision, Edge, Evidence, Label, Reason, ReplayResult, StageHit, StoredEvent

T0 = datetime(2026, 10, 9, 0, 39, tzinfo=timezone(timedelta(hours=5, minutes=30)))


@pytest.fixture
def store():
    return PgStore()


def event(eid: str, minutes: int, cust: str = "cust:aaaaaaaaaaaaaaaa") -> StoredEvent:
    t = T0 + timedelta(minutes=minutes)
    return StoredEvent(event_id=eid, event_type="login", source="simulator", occurred_at=t, received_at=t, customer=cust,
                       payload={"result": "success", "auth_method": "password"}, entity_tokens=[cust])


def case(cid: str, entities: list[str], minutes: int = 0, status: str = "OPEN", p: float = 0.1) -> Case:
    t = T0 + timedelta(minutes=minutes)
    return Case(case_id=cid, anchor_entity=entities[0], customer=entities[0], status=status, p_attack=p, entities=entities,
                opened_at=t, updated_at=t, last_event_ts=t)


def evidence(eid: str, event_id: str, minutes: int, p: float = 0.05) -> Evidence:
    return Evidence(evidence_id=eid, event_id=event_id, detector="behaviour", detector_version="1", family="identity",
                    stage="S1_INITIAL_ACCESS", p=p, reliability=0.6, entities=["cust:aaaaaaaaaaaaaaaa"],
                    reasons=[Reason(code="NEW_DEVICE")], ts=T0 + timedelta(minutes=minutes))


def test_events_roundtrip_and_order(store):
    for eid, m in [("evt_bbbbbbbb", 5), ("evt_aaaaaaaa", 5), ("evt_cccccccc", 1)]:
        assert store.insert_event(event(eid, m))
    assert not store.insert_event(event("evt_aaaaaaaa", 5))          # duplicate
    assert [e.event_id for e in store.iter_events()] == ["evt_cccccccc", "evt_aaaaaaaa", "evt_bbbbbbbb"]
    assert [e.event_id for e in store.iter_events(since=T0 + timedelta(minutes=2))] == ["evt_aaaaaaaa", "evt_bbbbbbbb"]
    assert store.get_event("evt_cccccccc") == event("evt_cccccccc", 1)
    assert store.get_event("evt_missing0") is None


def test_find_open_cases_semantics(store):
    store.save_case(case("case_a", ["cust:aaaaaaaaaaaaaaaa", "dev:dddddddddddddddd"], minutes=0))
    store.save_case(case("case_old", ["dev:dddddddddddddddd"], minutes=-600))
    store.save_case(case("case_closed", ["dev:dddddddddddddddd"], minutes=0, status="CLOSED"))
    store.save_case(case("case_inv", ["ip:iiiiiiiiiiiiiiii"], minutes=0, status="INVESTIGATING"))
    since = T0 - timedelta(hours=6)
    assert [c.case_id for c in store.find_open_cases(["dev:dddddddddddddddd"], since)] == ["case_a"]
    assert {c.case_id for c in store.find_open_cases(["dev:dddddddddddddddd", "ip:iiiiiiiiiiiiiiii"], since)} == {"case_a", "case_inv"}
    assert store.find_open_cases(["phone:none"], since) == []
    assert store.find_open_cases([], since) == []


def test_save_case_replaces_entities(store):
    c = case("case_a", ["cust:aaaaaaaaaaaaaaaa", "dev:dddddddddddddddd"])
    store.save_case(c)
    c.entities = ["cust:aaaaaaaaaaaaaaaa"]
    c.stages = {"S1_INITIAL_ACCESS": StageHit(ts=T0, evidence_id="ev_1")}
    store.save_case(c)
    assert store.get_case("case_a") == c
    assert store.find_open_cases(["dev:dddddddddddddddd"], T0 - timedelta(hours=1)) == []
    assert store.get_case("case_nope") is None
    assert [x.case_id for x in store.list_cases()] == ["case_a"]


def test_evidence_decisions_and_merge(store):
    store.insert_event(event("evt_aaaaaaaa", 0))
    store.insert_event(event("evt_bbbbbbbb", 2))
    store.save_case(case("case_keep", ["cust:aaaaaaaaaaaaaaaa"], p=0.4))
    store.save_case(case("case_drop", ["cust:aaaaaaaaaaaaaaaa"], p=0.1))
    store.save_evidence(evidence("ev_2", "evt_bbbbbbbb", 2), "case_drop")
    store.save_evidence(evidence("ev_1", "evt_aaaaaaaa", 0), "case_keep")
    ev = evidence("ev_1", "evt_aaaaaaaa", 0)
    ev.contribution = 0.99
    store.save_evidence(ev, "case_keep")                              # upsert
    d = Decision(decision_id="dec_1", case_id="case_drop", trigger_event_id="evt_bbbbbbbb", band="LOW", p_attack=0.1,
                 policy_rule="low", actions=["ALLOW"], created_at=T0 + timedelta(minutes=2))
    store.save_decision(d)
    store.merge_cases("case_keep", "case_drop")
    assert store.get_case("case_drop") is None
    evs = store.list_evidence("case_keep")
    assert [e.evidence_id for e in evs] == ["ev_1", "ev_2"] and evs[0].contribution == 0.99
    assert [x.case_id for x in store.list_decisions("case_keep")] == ["case_keep"]


def test_transaction_rolls_back_together(store):
    with pytest.raises(RuntimeError):
        with store.transaction():
            store.save_case(case("case_tx", ["cust:aaaaaaaaaaaaaaaa"]))
            store.set_fraud_seeds(["dev:dddddddddddddddd"])
            raise RuntimeError("boom")
    assert store.get_case("case_tx") is None and store.list_fraud_seeds() == set()


def test_edges_upsert(store):
    e1 = Edge(src="acct:a", dst="dev:d", edge_type="LOGGED_IN_FROM", confidence=0.5, first_seen=T0, last_seen=T0,
              source_event_ids=["evt_1"])
    e2 = e1.model_copy(update={"confidence": 0.9, "last_seen": T0 + timedelta(hours=1), "first_seen": T0 + timedelta(hours=1),
                               "source_event_ids": ["evt_2"]})
    store.upsert_edges([e1])
    store.upsert_edges([e2])
    (got,) = store.load_edges()
    assert got.count == 2 and got.confidence == pytest.approx(0.9) and got.first_seen == T0
    assert got.last_seen == T0 + timedelta(hours=1) and got.source_event_ids == ["evt_1", "evt_2"]


def test_seeds(store):
    store.set_fraud_seeds(["dev:x", "acct:y"])
    assert store.list_fraud_seeds() == {"dev:x", "acct:y"}
    store.set_fraud_seeds(["dev:x"], False)
    assert store.list_fraud_seeds() == {"acct:y"}


def test_reliability(store):
    assert store.get_reliability()["txn"] == (17.0, 3.0)
    store.add_reliability("cyber", 0, 1)
    assert store.get_reliability()["cyber"] == (5.0, 6.0)
    with get_engine().begin() as c:
        c.execute(text("DELETE FROM detector_reliability WHERE detector = 'graph'"))
    store.add_reliability("graph", 1, 0)                              # missing row -> seed (8, 2) then add
    assert store.get_reliability()["graph"] == (9.0, 2.0)


def test_labels_and_replays(store):
    store.save_labels([Label(event_id="evt_aaaaaaaa", scenario="midnight_ato", is_attack=True, attack_id="atk_1")])
    assert store.get_labels()["evt_aaaaaaaa"].attack_id == "atk_1"
    r = ReplayResult(replay_id="rep_1", case_id="case_a", mode="fused", ablated=[], timeline=[], eip=None, baseline_eip=None,
                     lead_time_s=None, lead_time_lost_s=None, money_protected_paise=0)
    store.save_replay(r)
    with get_engine().connect() as c:
        assert c.execute(text("SELECT count(*) FROM replays")).scalar() == 1


def test_audit_chain_is_linear(store):
    for i in range(3):
        store.append_audit("engine", "DECISION", f"dec_{i}", {"i": i, "nested": {"b": 2, "a": 1}})
    with get_engine().connect() as c:
        rows = c.execute(text("SELECT ts, actor, action, object_id, details, prev_hash, row_hash FROM audit_log ORDER BY seq")).all()
    prev = GENESIS
    for r in rows:
        assert r.prev_hash == prev
        assert r.row_hash == row_hash(prev, r.actor, r.action, r.object_id, r.details, r.ts)
        prev = r.row_hash
