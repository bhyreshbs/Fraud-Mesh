"""v3 phase 10 (API): two-person approval for payment-limit increases (api/routers/limits.py) and audited out-of-queue
case access (CASE_ACCESS_DENIED in api/routers/cases.py)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from api.db.session import admin_engine, get_engine
from api.security import hash_password
from api.store_pg import PgStore
from engine.contracts import Case
from tests.api.conftest import TEST_PASSWORD, login

T = datetime(2026, 10, 9, 10, 0, tzinfo=UTC)


def q(sql: str, **params):
    with get_engine().connect() as c:
        return c.execute(text(sql), params).mappings().all()


def _case(case_id: str, band: str, queue: str = "default") -> str:
    PgStore().save_case(Case(case_id=case_id, anchor_entity="cust:v3limits", customer="cust:v3limits", band=band,
                             p_attack={"LOW": 0.05, "MEDIUM": 0.3, "HIGH": 0.6, "CRITICAL": 0.9}[band],
                             opened_at=T, updated_at=T, last_event_ts=T))
    if queue != "default":
        with admin_engine().begin() as c:
            c.execute(text("UPDATE cases SET queue = :q WHERE case_id = :id"), {"q": queue, "id": case_id})
    return case_id


@pytest.fixture
def second_lead():
    with admin_engine().begin() as c:
        c.execute(text("INSERT INTO users (user_id, email, pw_hash, role, queues) VALUES "
                       "('usr_lead2', 'lead2@fraudmesh.local', :h, 'lead', ARRAY['default']) ON CONFLICT DO NOTHING"),
                  {"h": hash_password(TEST_PASSWORD)})
    return "lead2"


def _h(client, role):
    return {"Authorization": f"Bearer {login(client, role)}"}


BODY = {"new_limit_paise": 100_000_000, "reason": "customer asked by phone"}


def test_medium_case_needs_a_second_person(client, second_lead):
    cid = _case("case_v3lim_medium01", "MEDIUM")
    lead, lead2 = _h(client, "lead"), _h(client, second_lead)
    r = client.post(f"/v1/cases/{cid}/limit-increase", json=BODY, headers=lead)
    assert r.status_code == 201, r.text
    req = r.json()
    assert req["status"] == "pending_approval" and req["requires_two_person"] and req["band_at_request"] == "MEDIUM"
    rid = req["request_id"]
    # the requester cannot approve their own request, whatever the client sends
    self_ok = client.post(f"/v1/cases/{cid}/limit-increase/{rid}/approve", json={}, headers=lead)
    assert self_ok.status_code == 403 and self_ok.json()["error"]["code"] == "FORBIDDEN"
    assert q("SELECT actor FROM audit_log WHERE action = 'LIMIT_SELF_APPROVAL_BLOCKED' AND object_id = :r", r=rid)
    ok = client.post(f"/v1/cases/{cid}/limit-increase/{rid}/approve", json={"note": "verified"}, headers=lead2)
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "applied" and ok.json()["decided_by"] == "usr_lead2"
    again = client.post(f"/v1/cases/{cid}/limit-increase/{rid}/approve", json={}, headers=_h(client, "admin"))
    assert again.status_code == 409
    actions = [r["action"] for r in q("SELECT action FROM audit_log WHERE object_id = :r ORDER BY seq", r=rid)]
    assert actions == ["LIMIT_INCREASE_REQUESTED", "LIMIT_SELF_APPROVAL_BLOCKED", "LIMIT_INCREASE_APPROVED",
                       "LIMIT_INCREASE_APPLIED"]
    listed = client.get(f"/v1/cases/{cid}/limit-increase", headers=_h(client, "analyst")).json()
    assert [x["status"] for x in listed] == ["applied"]


def test_low_case_is_single_person_and_the_band_threshold_is_configurable(client, monkeypatch):
    cid = _case("case_v3lim_low0001", "LOW")
    r = client.post(f"/v1/cases/{cid}/limit-increase", json=BODY, headers=_h(client, "lead"))
    assert r.status_code == 201 and r.json()["status"] == "applied" and not r.json()["requires_two_person"]
    monkeypatch.setenv("FM_LIMIT_TWO_PERSON_MIN_BAND", "LOW")
    r2 = client.post(f"/v1/cases/{cid}/limit-increase", json=BODY, headers=_h(client, "lead"))
    assert r2.json()["status"] == "pending_approval"
    monkeypatch.setenv("FM_LIMIT_TWO_PERSON", "0")
    cid2 = _case("case_v3lim_crit0001", "CRITICAL")
    assert client.post(f"/v1/cases/{cid2}/limit-increase", json=BODY, headers=_h(client, "lead")).json()["status"] == "applied"


def test_reject_and_role_rules(client):
    cid = _case("case_v3lim_high0001", "HIGH")
    analyst = _h(client, "analyst")
    assert client.post(f"/v1/cases/{cid}/limit-increase", json=BODY, headers=analyst).status_code == 403
    rid = client.post(f"/v1/cases/{cid}/limit-increase", json=BODY, headers=_h(client, "lead")).json()["request_id"]
    assert client.post(f"/v1/cases/{cid}/limit-increase/{rid}/approve", json={}, headers=analyst).status_code == 403
    rej = client.post(f"/v1/cases/{cid}/limit-increase/{rid}/reject", json={"note": "no"}, headers=_h(client, "lead"))
    assert rej.status_code == 200 and rej.json()["status"] == "rejected"
    assert client.post(f"/v1/cases/{cid}/limit-increase/lim_nope/approve", json={},
                       headers=_h(client, "admin")).status_code == 404
    assert client.post(f"/v1/cases/{cid}/limit-increase", json={"new_limit_paise": -1, "reason": "x"},
                       headers=_h(client, "lead")).status_code == 422


def test_out_of_queue_case_is_404_and_audited(client, monkeypatch):
    cid = _case("case_v3lim_vip00001", "HIGH", queue="vip")
    lead = _h(client, "lead")
    monkeypatch.setenv("FM_CASE_DENIED_ALERT_N", "2")
    for path in (f"/v1/cases/{cid}", f"/v1/cases/{cid}/limit-increase"):
        assert client.get(path, headers=lead).status_code == 404
    r = client.post(f"/v1/cases/{cid}/limit-increase", json=BODY, headers=lead)
    assert r.status_code == 404
    rows = q("SELECT actor, details FROM audit_log WHERE action = 'CASE_ACCESS_DENIED' AND object_id = :c ORDER BY seq", c=cid)
    assert [r["actor"] for r in rows] == ["usr_lead"] * 3
    assert [r["details"]["denials_last_hour"] for r in rows] == [1, 2, 3]
    assert [r["details"]["repeated"] for r in rows] == [False, True, True]
    assert not q("SELECT 1 FROM audit_log WHERE action LIKE 'LIMIT_%'")      # nothing was requested
    # an unknown id is a plain 404 and is not written to the audit chain
    assert client.get("/v1/cases/case_doesnotexist", headers=lead).status_code == 404
    assert not q("SELECT 1 FROM audit_log WHERE object_id = 'case_doesnotexist'")
