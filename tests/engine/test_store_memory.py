"""MemoryStore behaviour beyond the shared Store contract (test_store_contract.py runs the shared part)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from engine.contracts import Case, Decision, Evidence, Reason, StoredEvent
from engine.store_memory import MemoryStore

T0 = datetime(2026, 10, 8, 19, 9, tzinfo=UTC)


def _case(cid: str = "case_1") -> Case:
    return Case(case_id=cid, anchor_entity="cust:a", entities=["cust:a"], opened_at=T0, updated_at=T0, last_event_ts=T0)


def test_add_reliability_reseeds_a_missing_row_with_the_prd_values():
    s = MemoryStore(reliability={})
    s.add_reliability("cyber", 0, 1)
    s.add_reliability("graph", 1, 0)
    s.add_reliability("custom", 1, 0)                     # not in §8: starts at (1, 1) like PgStore
    assert s.get_reliability() == {"cyber": (5.0, 6.0), "graph": (9.0, 2.0), "custom": (2.0, 1.0)}


def test_audit_rows_are_appended_in_order_and_copied():
    s = MemoryStore()
    details = {"before": {"cyber": 0.5}}
    s.append_audit("engine", "CASE_MERGED", "case_1", details)
    s.append_audit("usr_lead", "FEEDBACK", "case_1", {"verdict": "FALSE_POSITIVE"})
    details["before"]["cyber"] = 0.0
    assert [(r["seq"], r["actor"], r["action"]) for r in s.audit_log] == [(1, "engine", "CASE_MERGED"),
                                                                          (2, "usr_lead", "FEEDBACK")]
    assert s.audit_log[0]["details"] == {"before": {"cyber": 0.5}}


def test_evidence_and_decisions_need_an_existing_case_like_the_foreign_keys():
    s = MemoryStore()
    ev = Evidence(evidence_id="ev_1", event_id="evt_00000001", detector="netsec", detector_version="1", family="cyber",
                  stage="S0_RECON", p=0.03, reliability=0.5, entities=[], reasons=[Reason(code="IDS_SEV2")], ts=T0)
    dec = Decision(decision_id="dec_1", case_id="case_x", trigger_event_id="evt_00000001", band="LOW", p_attack=0.01,
                   policy_rule="low", actions=["ALLOW"], created_at=T0)
    with pytest.raises(KeyError):
        s.save_evidence(ev, "case_x")
    with pytest.raises(KeyError):
        s.save_decision(dec)


def test_saved_models_are_isolated_from_the_caller():
    s = MemoryStore()
    c = _case()
    s.save_case(c)
    c.entities.append("dev:z")
    assert s.get_case("case_1").entities == ["cust:a"]


def test_iter_events_sees_inserts_made_after_a_previous_iteration():
    s = MemoryStore()
    mk = lambda eid, at: StoredEvent(event_id=eid, event_type="login", source="simulator", occurred_at=at,  # noqa: E731
                                     received_at=at, payload={"result": "success", "auth_method": "password"},
                                     entity_tokens=[])
    s.insert_event(mk("evt_0000000b", T0))
    assert [e.event_id for e in s.iter_events()] == ["evt_0000000b"]
    s.insert_event(mk("evt_0000000a", T0 - timedelta(minutes=1)))
    assert [e.event_id for e in s.iter_events()] == ["evt_0000000a", "evt_0000000b"]


def test_transaction_is_a_no_op_that_does_not_swallow_errors():
    s = MemoryStore()
    with pytest.raises(RuntimeError), s.transaction():
        s.save_case(_case())
        raise RuntimeError("boom")
    assert s.get_case("case_1") is not None              # no rollback in MemoryStore (PRD §5 allows a no-op)
