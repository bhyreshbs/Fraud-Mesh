"""Store protocol semantics (PRD §5, §8), run against either implementation:

    STORE=memory pytest tests/engine/test_store_contract.py     # engine.store_memory.MemoryStore (default)
    STORE=pg     pytest tests/engine/test_store_contract.py     # api.store_pg.PgStore, needs DATABASE_URL

Only Store protocol methods are asserted on, plus the two shared non-protocol helpers both stores expose
(insert_event, save_labels — see docs/CONTRACT_REQUESTS.md); a store without them skips those tests.
For pg, the store module is imported inside the fixture only, and the database setup reuses tests/api/conftest.py
(the migrated <DATABASE_URL db>_test database), truncating the runtime tables before every test.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from engine.contracts import (
    Case,
    Decision,
    Edge,
    Evidence,
    Label,
    Reason,
    ReplayPoint,
    ReplayResult,
    StageHit,
    Store,
    StoredEvent,
)

STORE = os.getenv("STORE", "memory")
T0 = datetime(2026, 10, 8, 19, 9, tzinfo=UTC)          # 2026-10-09 00:39 IST
SEED_RELIABILITY = {"txn": (17.0, 3.0), "behaviour": (6.0, 4.0), "auth": (7.0, 3.0), "kyc": (6.0, 4.0),
                    "cyber": (5.0, 5.0), "netsec": (5.0, 5.0), "graph": (8.0, 2.0)}


def _pg_store():
    import tests.api.conftest as pg  # sets env + migrates the test DB before settings load
    if not pg._PG_OK:
        pytest.skip(f"PostgreSQL not reachable at {pg.TEST_DB_URL}")
    from sqlalchemy import text

    from api.db.session import admin_engine
    from api.store_pg import PgStore
    with admin_engine().begin() as c:
        c.execute(text("TRUNCATE " + ", ".join(pg.RUNTIME_TABLES) + " RESTART IDENTITY CASCADE"))
        c.execute(text("DELETE FROM detector_reliability"))
        c.execute(text("INSERT INTO detector_reliability (detector, alpha, beta) VALUES ('txn',17,3), ('behaviour',6,4), "
                       "('auth',7,3), ('kyc',6,4), ('cyber',5,5), ('netsec',5,5), ('graph',8,2)"))
    return PgStore()


@pytest.fixture
def store() -> Store:
    if STORE == "memory":
        from engine.store_memory import MemoryStore
        return MemoryStore()
    if STORE == "pg":
        return _pg_store()
    raise pytest.UsageError(f"STORE must be memory or pg, not {STORE!r}")


# ---------------------------------------------------------------------------- builders
def event(eid: str, at: datetime, customer: str | None = "cust:aaaaaaaaaaaaaaaa") -> StoredEvent:
    toks = sorted(t for t in (customer, "ip:bbbbbbbbbbbbbbbb") if t)
    return StoredEvent(event_id=eid, event_type="login", source="simulator", occurred_at=at, received_at=at,
                       customer=customer, ip="ip:bbbbbbbbbbbbbbbb", payload={"result": "success", "auth_method": "password"},
                       entity_tokens=toks)


def case(cid: str, entities: list[str], last: datetime = T0, status: str = "OPEN", **kw) -> Case:
    return Case(case_id=cid, anchor_entity=entities[0], customer=kw.pop("customer", None), status=status,
                entities=entities, opened_at=kw.pop("opened_at", last), updated_at=last, last_event_ts=last, **kw)


def evidence(evid: str, event_id: str, ts: datetime, contribution: float = 0.0) -> Evidence:
    return Evidence(evidence_id=evid, event_id=event_id, detector="netsec", detector_version="1", family="cyber",
                    stage="S0_RECON", p=0.03, reliability=0.5, contribution=contribution, entities=["ip:bbbbbbbbbbbbbbbb"],
                    reasons=[Reason(code="IDS_SEV2")], ts=ts)


def decision(did: str, case_id: str, at: datetime) -> Decision:
    return Decision(decision_id=did, case_id=case_id, trigger_event_id="evt_00000001", band="LOW", p_attack=0.017,
                    policy_rule="low", actions=["ALLOW"], created_at=at)


def edge(src: str, dst: str, et: str = "LOGGED_IN_FROM", conf: float = 0.9, at: datetime = T0,
         ids: list[str] | None = None) -> Edge:
    return Edge(src=src, dst=dst, edge_type=et, confidence=conf, first_seen=at, last_seen=at, count=1,
                source_event_ids=ids or ["evt_00000001"])


def insert_events(store, *events: StoredEvent) -> None:
    ins = getattr(store, "insert_event", None)
    if ins is None:
        pytest.skip("store has no insert_event helper")
    for ev in events:
        ins(ev)


# ---------------------------------------------------------------------------- protocol + transaction
def test_satisfies_store_protocol(store):
    for name in [n for n in vars(Store) if not n.startswith("_")]:
        assert callable(getattr(store, name, None)), f"missing Store method {name}"


def test_transaction_is_a_nestable_context_manager(store):
    insert_events(store, event("evt_00000001", T0))
    with store.transaction():
        store.save_case(case("case_tx", ["cust:aaaaaaaaaaaaaaaa"]))
        with store.transaction():
            store.save_evidence(evidence("ev_tx", "evt_00000001", T0), "case_tx")
    assert store.get_case("case_tx") is not None
    assert [e.evidence_id for e in store.list_evidence("case_tx")] == ["ev_tx"]


# ---------------------------------------------------------------------------- events
def test_iter_events_orders_by_occurred_at_then_event_id(store):
    later, same_b, same_a, earliest = (event("evt_0000000d", T0 + timedelta(minutes=5)), event("evt_0000000b", T0),
                                      event("evt_0000000a", T0), event("evt_0000000z", T0 - timedelta(hours=1)))
    insert_events(store, later, same_b, same_a, earliest)
    assert [e.event_id for e in store.iter_events()] == ["evt_0000000z", "evt_0000000a", "evt_0000000b", "evt_0000000d"]
    assert [e.event_id for e in store.iter_events(since=T0)] == ["evt_0000000a", "evt_0000000b", "evt_0000000d"]


def test_get_event_round_trips(store):
    ev = event("evt_00000042", T0)
    insert_events(store, ev)
    assert store.get_event("evt_00000042") == ev
    assert store.get_event("evt_missing0") is None


def test_insert_event_reports_duplicates(store):
    insert_events(store, event("evt_00000077", T0))
    assert store.insert_event(event("evt_00000077", T0 + timedelta(hours=1))) is False
    assert store.get_event("evt_00000077").occurred_at == T0


# ---------------------------------------------------------------------------- graph
def test_upsert_edges_inserts_then_merges(store):
    store.upsert_edges([edge("acct:a", "dev:d", ids=["evt_00000001"])])
    store.upsert_edges([edge("acct:a", "dev:d", conf=0.5, at=T0 + timedelta(hours=2), ids=["evt_00000002"]),
                        edge("acct:a", "dev:d", et="SENT", conf=1.0)])
    edges = {(e.src, e.dst, e.edge_type): e for e in store.load_edges()}
    assert set(edges) == {("acct:a", "dev:d", "LOGGED_IN_FROM"), ("acct:a", "dev:d", "SENT")}
    merged = edges[("acct:a", "dev:d", "LOGGED_IN_FROM")]
    assert merged.count == 2
    assert merged.confidence == pytest.approx(0.9)                       # GREATEST
    assert merged.first_seen == T0                                       # kept
    assert merged.last_seen == T0 + timedelta(hours=2)                   # GREATEST
    assert merged.source_event_ids == ["evt_00000001", "evt_00000002"]


def test_upsert_edges_keeps_latest_last_seen_and_caps_source_ids(store):
    store.upsert_edges([edge("dev:d", "ip:i", "CONNECTED_VIA", 0.5, at=T0, ids=[f"evt_{i:08d}" for i in range(30)])])
    store.upsert_edges([edge("dev:d", "ip:i", "CONNECTED_VIA", 0.0, at=T0 - timedelta(days=1),
                             ids=[f"evt_{i:08d}" for i in range(30, 60)])])
    (e,) = store.load_edges()
    assert e.last_seen == T0 and e.confidence == pytest.approx(0.5)
    assert e.source_event_ids == [f"evt_{i:08d}" for i in range(50)]


def test_edge_direction_is_part_of_the_key(store):
    store.upsert_edges([edge("acct:a", "acct:b", "SENT", 1.0), edge("acct:b", "acct:a", "SENT", 1.0)])
    assert sorted((e.src, e.dst) for e in store.load_edges()) == [("acct:a", "acct:b"), ("acct:b", "acct:a")]


def test_fraud_seeds_set_and_unset(store):
    assert store.list_fraud_seeds() == set()
    store.set_fraud_seeds(["dev:d", "acct:m"])
    store.upsert_edges([edge("acct:m", "dev:d")])                      # an edge upsert never clears a seed
    assert store.list_fraud_seeds() == {"dev:d", "acct:m"}
    store.set_fraud_seeds(["dev:d"], False)
    assert store.list_fraud_seeds() == {"acct:m"}


# ---------------------------------------------------------------------------- cases
def test_find_open_cases_filters_status_time_and_entities(store):
    since = T0 - timedelta(hours=6)
    for cid, status in [("case_open", "OPEN"), ("case_inv", "INVESTIGATING"), ("case_conf", "CONFIRMED_FRAUD"),
                        ("case_fp", "FALSE_POSITIVE"), ("case_closed", "CLOSED")]:
        store.save_case(case(cid, ["dev:x", "ip:y"], status=status))
    store.save_case(case("case_old", ["dev:x"], last=since - timedelta(seconds=1)))
    store.save_case(case("case_edge", ["dev:x"], last=since))            # last_event_ts == since is included
    store.save_case(case("case_other", ["dev:other"]))
    found = store.find_open_cases(["dev:x", "ip:y", "cust:nobody"], since)
    assert sorted(c.case_id for c in found) == ["case_edge", "case_inv", "case_open"]   # each case once
    assert store.find_open_cases([], since) == []
    assert store.find_open_cases(["cust:nobody"], since) == []


def test_save_case_upserts_and_replaces_entities(store):
    store.save_case(case("case_1", ["cust:a", "dev:b"], customer="cust:a"))
    updated = case("case_1", ["dev:b", "ip:c"], last=T0 + timedelta(minutes=3), customer="cust:a", band="HIGH",
                   p_attack=0.67, stages={"S0_RECON": StageHit(ts=T0, evidence_id="ev_1")})
    store.save_case(updated)
    since = T0 - timedelta(hours=1)
    assert store.find_open_cases(["cust:a"], since) == []
    assert [c.case_id for c in store.find_open_cases(["ip:c"], since)] == ["case_1"]
    assert store.get_case("case_1") == updated
    assert [c.case_id for c in store.list_cases()] == ["case_1"]


def test_get_case_and_list_cases(store):
    assert store.get_case("case_missing") is None
    assert store.list_cases() == []
    store.save_case(case("case_a", ["dev:a"]))
    store.save_case(case("case_b", ["dev:b"], last=T0 + timedelta(minutes=1)))
    assert {c.case_id for c in store.list_cases()} == {"case_a", "case_b"}


def test_returned_cases_are_copies(store):
    store.save_case(case("case_c", ["dev:a"]))
    got = store.get_case("case_c")
    got.band = "CRITICAL"
    got.entities.append("dev:z")
    assert store.get_case("case_c").band == "LOW"
    assert store.find_open_cases(["dev:z"], T0 - timedelta(hours=1)) == []


# ---------------------------------------------------------------------------- evidence and decisions
def test_evidence_ordered_by_ts_then_id_and_upserted(store):
    insert_events(store, event("evt_00000001", T0))
    store.save_case(case("case_e", ["ip:bbbbbbbbbbbbbbbb"]))
    store.save_evidence(evidence("ev_c", "evt_00000001", T0 + timedelta(minutes=1)), "case_e")
    store.save_evidence(evidence("ev_b", "evt_00000001", T0), "case_e")
    store.save_evidence(evidence("ev_a", "evt_00000001", T0), "case_e")
    assert [e.evidence_id for e in store.list_evidence("case_e")] == ["ev_a", "ev_b", "ev_c"]
    store.save_evidence(evidence("ev_b", "evt_00000001", T0, contribution=0.28), "case_e")       # re-save = update
    got = store.list_evidence("case_e")
    assert len(got) == 3 and got[1].contribution == pytest.approx(0.28)
    assert store.list_evidence("case_missing") == []


def test_decisions_ordered_by_created_at(store):
    store.save_case(case("case_d", ["dev:a"]))
    store.save_decision(decision("dec_2", "case_d", T0 + timedelta(minutes=2)))
    store.save_decision(decision("dec_1", "case_d", T0))
    assert [d.decision_id for d in store.list_decisions("case_d")] == ["dec_1", "dec_2"]
    assert store.list_decisions("case_missing") == []


def test_merge_cases_repoints_evidence_and_decisions_and_drops_the_case(store):
    insert_events(store, event("evt_00000001", T0))
    store.save_case(case("case_keep", ["dev:a"]))
    store.save_case(case("case_drop", ["ip:b"]))
    store.save_evidence(evidence("ev_k", "evt_00000001", T0), "case_keep")
    store.save_evidence(evidence("ev_d", "evt_00000001", T0 + timedelta(minutes=1)), "case_drop")
    store.save_decision(decision("dec_k", "case_keep", T0))
    store.save_decision(decision("dec_d", "case_drop", T0 + timedelta(minutes=1)))
    store.merge_cases("case_keep", "case_drop")
    assert store.get_case("case_drop") is None
    assert [e.evidence_id for e in store.list_evidence("case_keep")] == ["ev_k", "ev_d"]
    assert store.list_evidence("case_drop") == []
    assert [(d.decision_id, d.case_id) for d in store.list_decisions("case_keep")] == [("dec_k", "case_keep"),
                                                                                     ("dec_d", "case_keep")]
    assert store.find_open_cases(["ip:b"], T0 - timedelta(hours=1)) == []


# ---------------------------------------------------------------------------- learning, labels, replays, audit
def test_reliability_starts_at_the_seed_values_and_adds_deltas(store):
    assert store.get_reliability() == SEED_RELIABILITY
    store.add_reliability("cyber", 0.0, 1.0)
    store.add_reliability("txn", 1.0, 0.0)
    rel = store.get_reliability()
    assert rel["cyber"] == (5.0, 6.0)
    assert rel["cyber"][0] / sum(rel["cyber"]) == pytest.approx(5 / 11)       # PRD §16.5 feedback example
    assert rel["txn"] == (18.0, 3.0)
    assert rel["graph"] == (8.0, 2.0)


def test_labels_round_trip(store):
    assert store.get_labels() == {}
    save = getattr(store, "save_labels", None)
    if save is None:
        pytest.skip("store has no save_labels helper")
    insert_events(store, event("evt_00000001", T0), event("evt_00000002", T0))
    labels = [Label(event_id="evt_00000001", scenario="midnight_ato", is_attack=True, attack_id="atk_midnight_1"),
              Label(event_id="evt_00000002", scenario="background", is_attack=False)]
    save(labels)
    assert store.get_labels() == {lb.event_id: lb for lb in labels}


def test_save_replay_is_an_idempotent_upsert(store):
    store.save_case(case("case_r", ["dev:a"]))
    point = ReplayPoint(ts=T0, evidence_id="ev_1", p=0.4, band="MEDIUM", actions=["STEP_UP_ANY_FACTOR"], severity=1)
    r = ReplayResult(replay_id="rep_1", case_id="case_r", mode="fused", ablated=[], timeline=[point], eip=None,
                     baseline_eip=None, lead_time_s=None, lead_time_lost_s=None, money_protected_paise=0)
    store.save_replay(r)
    store.save_replay(r.model_copy(update={"money_protected_paise": 48000000}))


def test_append_audit_accepts_rows(store):
    store.append_audit("engine", "CASE_MERGED", "case_keep", {"dropped": "case_drop"})
    store.append_audit("usr_analyst", "FEEDBACK", "case_keep", {"verdict": "CONFIRMED_FRAUD"})
