"""Case joiner (PRD §10.6)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from engine.cases import joiner as joiner_mod
from engine.cases.joiner import Joiner
from engine.common.tokenize import to_stored_event, tok
from engine.contracts import Envelope, Evidence, Reason, StageHit
from engine.graph.store import EntityGraph
from engine.store_memory import MemoryStore

T0 = datetime(2026, 10, 9, 0, 39, tzinfo=UTC)
_n = 0


def ev(entities, p=0.05, minutes=0.0, stage="S1_INITIAL_ACCESS") -> Evidence:
    global _n
    _n += 1
    return Evidence(evidence_id=f"ev_{_n:04d}", event_id=f"evt_{_n:08d}", detector="behaviour", detector_version="t",
                    family="identity", stage=stage, p=p, reliability=0.6, entities=sorted(entities),
                    reasons=[Reason(code="X")], ts=T0 + timedelta(minutes=minutes))


@pytest.fixture
def env():
    store, graph = MemoryStore(), EntityGraph()
    return store, graph, Joiner(store, graph, base_rate=0.01)


def test_opens_a_case_anchored_on_the_customer(env):
    store, _, j = env
    case = j.attach(ev(["cust:a", "ip:x"]))
    assert case.anchor_entity == "cust:a" and case.customer == "cust:a" and case.opened_at == T0
    assert store.get_case(case.case_id) is not None and [e.evidence_id for e in store.list_evidence(case.case_id)]


def test_without_a_customer_the_anchor_is_the_first_sorted_entity(env):
    _, _, j = env
    case = j.attach(ev(["ip:x", "dev:d"]))
    assert case.anchor_entity == "dev:d" and case.customer is None


def test_low_p_evidence_never_opens_a_case_but_joins_one(env):
    store, _, j = env
    assert j.attach(ev(["cust:a"], p=0.01)) is None and store.list_cases() == []
    case = j.attach(ev(["cust:a"]))
    joined = j.attach(ev(["cust:a"], p=0.01, minutes=1))
    assert joined.case_id == case.case_id and len(store.list_evidence(case.case_id)) == 2


def test_attach_updates_entities_and_times(env):
    _, _, j = env
    case = j.attach(ev(["cust:a"]))
    case = j.attach(ev(["cust:a", "dev:new"], minutes=10))
    assert case.entities == ["cust:a", "dev:new"]
    assert case.last_event_ts == case.updated_at == T0 + timedelta(minutes=10)


def test_six_hour_window(env):
    store, _, j = env
    first = j.attach(ev(["cust:a"]))
    assert j.attach(ev(["cust:a"], minutes=6 * 60)).case_id == first.case_id
    late = j.attach(ev(["cust:a"], minutes=12 * 60 + 1))
    assert late.case_id != first.case_id and len(store.list_cases()) == 2


def test_closed_cases_are_not_joined(env):
    store, _, j = env
    first = j.attach(ev(["cust:a"]))
    first.status = "CONFIRMED_FRAUD"
    store.save_case(first)
    assert j.attach(ev(["cust:a"], minutes=1)).case_id != first.case_id


def test_reanchors_on_the_first_customer_and_audits(env):
    store, _, j = env
    case = j.attach(ev(["ip:x"], p=0.03))
    assert case.anchor_entity == "ip:x"
    case = j.attach(ev(["cust:priya", "ip:x"], minutes=2))
    assert case.anchor_entity == case.customer == "cust:priya"
    assert [r["action"] for r in store.audit_log] == ["CASE_REANCHORED"]
    j.attach(ev(["cust:other", "ip:x"], minutes=3))                       # a cust anchor is never replaced
    assert store.get_case(case.case_id).anchor_entity == "cust:priya"


def test_merges_into_the_case_with_the_highest_p(env):
    store, _, j = env
    a = j.attach(ev(["ip:x"], p=0.03))
    b = j.attach(ev(["dev:d"], p=0.03, minutes=1))
    a.p_attack, b.p_attack = 0.2, 0.4
    store.save_case(a)
    store.save_case(b)
    merged = j.attach(ev(["cust:c", "dev:d", "ip:x"], minutes=2))
    assert merged.case_id == b.case_id and store.get_case(a.case_id) is None
    assert len(store.list_evidence(b.case_id)) == 3
    assert merged.opened_at == T0 and set(merged.entities) >= {"ip:x", "dev:d", "cust:c"}
    assert [r["action"] for r in store.audit_log if r["action"] == "CASE_MERGED"] == ["CASE_MERGED"]


def test_merge_tie_keeps_the_oldest(env):
    store, _, j = env
    a = j.attach(ev(["ip:x"], p=0.03))
    j.attach(ev(["dev:d"], p=0.03, minutes=1))
    assert j.attach(ev(["dev:d", "ip:x"], minutes=2)).case_id == a.case_id


def _login(cust, acct, ip, dev):
    e = Envelope(event_id=f"evt_join{dev}0000", event_type="login", source="simulator", occurred_at=T0,
                 subject={"customer_ref": cust, "account_ref": acct}, context={"ip": ip, "device_id": dev},
                 payload={"result": "success", "auth_method": "password"})
    return to_stored_event(e, T0)


def test_joins_through_graph_neighbours_but_not_through_cgnat(env):
    store, graph, j = env
    graph.apply(_login("C-1", "A-1", "103.21.4.9", "fp1"))
    graph.apply(_login("C-2", "A-2", "49.36.128.20", "fp2"))               # CGNAT /24
    graph.apply(_login("C-3", "A-3", "49.36.128.21", "fp3"))
    first = j.attach(ev([tok("acct", "A-1")]))
    assert j.attach(ev([tok("dev", "fp1")], minutes=1)).case_id == first.case_id      # acct-dev neighbour
    two = j.attach(ev([tok("cust", "C-2"), tok("ip", "49.36.128.20")], minutes=2))
    three = j.attach(ev([tok("cust", "C-3"), tok("ip", "49.36.128.21")], minutes=3))
    assert two.case_id != three.case_id                                    # the CGNAT IP joins nobody


def test_join_tokens_are_capped(env, monkeypatch):
    _, _, j = env
    monkeypatch.setattr(joiner_mod, "MAX_JOIN_TOKENS", 2)
    assert len(j.join_tokens(ev(["cust:a", "dev:b", "ip:c"]))) == 2


def _s2_case(store, j):
    case = j.attach(ev(["cust:a"], stage="S2_CONTROL_TAKEOVER"))
    case.stages = {"S2_CONTROL_TAKEOVER": StageHit(ts=T0, evidence_id="ev_x")}
    store.save_case(case)
    return case


def test_sticky_same_customer_past_s2_joins_after_30_hours(env):
    store, _, j = env
    case = _s2_case(store, j)
    assert j.attach(ev(["cust:a", "dev:other"], minutes=30 * 60)).case_id == case.case_id


def test_sticky_needs_s2_the_same_customer_and_72_hours(env):
    store, _, j = env
    s1 = j.attach(ev(["cust:a"]))                                        # S1 only: not sticky
    assert j.attach(ev(["cust:a"], minutes=30 * 60)).case_id != s1.case_id
    store2, graph2 = MemoryStore(), EntityGraph()
    j2 = Joiner(store2, graph2, base_rate=0.01)
    case = _s2_case(store2, j2)
    assert j2.attach(ev(["cust:b", "cust:a"], minutes=30 * 60)).case_id == case.case_id     # carries cust:a ... joins
    store3 = MemoryStore()
    j3 = Joiner(store3, EntityGraph(), base_rate=0.01)
    c3 = _s2_case(store3, j3)
    assert j3.attach(ev(["cust:a"], minutes=72 * 60 + 1)).case_id != c3.case_id             # beyond 72 h
    store4 = MemoryStore()
    j4 = Joiner(store4, EntityGraph(), base_rate=0.01)
    c4 = _s2_case(store4, j4)
    c4.customer = "cust:zzz"                                                                  # a different customer
    store4.save_case(c4)
    assert j4.attach(ev(["cust:a"], minutes=30 * 60)).case_id != c4.case_id
