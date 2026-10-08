"""Feedback (PRD §10.11)."""
from __future__ import annotations

import pytest

from engine.api import apply_feedback
from engine.common.tokenize import tok
from engine.pipeline import Pipeline
from ml.build_fixtures import golden_store


def test_false_positive_moves_cyber_from_0_50_to_5_11():
    """§16.5: a FALSE_POSITIVE on a case where cyber contributed > 0.5."""
    store, case = golden_store()
    assert next(e for e in store.list_evidence(case.case_id) if e.detector == "cyber").contribution > 0.5
    r = apply_feedback(store, None, case.case_id, "FALSE_POSITIVE", "usr_analyst")
    assert r.reliability_before["cyber"] == pytest.approx(0.50)
    assert r.reliability_after["cyber"] == pytest.approx(5 / 11) and round(r.reliability_after["cyber"], 3) == 0.455
    assert r.reliability_after["netsec"] == pytest.approx(0.5)            # netsec contributed 0.28 < 0.5
    assert store.get_reliability()["cyber"] == (5.0, 6.0)
    assert r.status_after == "FALSE_POSITIVE" and r.seeds_added == []
    case = store.get_case(case.case_id)
    assert case.status == "FALSE_POSITIVE" and case.payment_state == "normal"


def test_confirmed_fraud_credits_detectors_and_seeds_entities():
    store, case = golden_store()
    pipe = Pipeline(store, detectors=[])
    pipe.startup()
    r = apply_feedback(store, pipe, case.case_id, "CONFIRMED_FRAUD", "usr_lead")
    assert {d for d in r.reliability_after if r.reliability_after[d] > r.reliability_before[d]} == \
        {"txn", "behaviour", "auth", "kyc", "cyber", "graph"}
    assert tok("dev", "fp_attacker_01") in r.seeds_added and tok("ip", "185.220.101.7") in r.seeds_added
    assert tok("cid", "svc-support-07") in r.seeds_added and tok("acct", "A-RAVI-778") in r.seeds_added
    assert tok("acct", "A-88213") not in r.seeds_added                    # the customer's own account
    assert not any(t.startswith(("cust:", "phone:")) for t in r.seeds_added)
    assert set(r.seeds_added) <= store.list_fraud_seeds() and pipe.graph.is_seed(tok("dev", "fp_attacker_01"))
    case_after = store.get_case(case.case_id)
    assert case_after.status == "CONFIRMED_FRAUD" and case_after.payment_state == case.payment_state == "blocked"


def test_inconclusive_changes_only_the_status():
    store, case = golden_store()
    before = store.get_reliability()
    r = apply_feedback(store, None, case.case_id, "INCONCLUSIVE", "usr_analyst")
    assert r.status_after == "INVESTIGATING" and r.reliability_after == r.reliability_before and r.seeds_added == []
    assert store.get_reliability() == before and store.list_fraud_seeds() == {tok("dev", "fp_mule_shared"), tok("acct", "A-MULE-01")}


def test_engine_writes_no_feedback_audit_row():
    store, case = golden_store()
    apply_feedback(store, None, case.case_id, "CONFIRMED_FRAUD", "usr_lead")
    assert not [r for r in store.audit_log if r["action"] == "FEEDBACK"]  # the API route writes it (CONTRACT_REQUESTS)


def test_errors():
    store, case = golden_store()
    with pytest.raises(KeyError):
        apply_feedback(store, None, "case_missing", "CONFIRMED_FRAUD", "u")
    with pytest.raises(ValueError):
        apply_feedback(store, None, case.case_id, "MAYBE", "u")
