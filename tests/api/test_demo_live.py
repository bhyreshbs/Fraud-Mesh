"""Live two-laptop demo: demo IDS sensor on logins from unregistered devices, baseline snapshot, the live-case list and
the fast reset that undoes only what happened after the baseline (api/demo_baseline.py, /v1/demo/baseline|live|reset-live)."""
from __future__ import annotations

import pytest
from sqlalchemy import text

from api.db.session import admin_engine, get_engine
from api.demo_identities import demo_state
from tests.api.test_worker_stepup import drain

PRIYA = {"customer_ref": "C-1042", "account_ref": "A-88213"}
PRIYA_PHONE = {"device_id": "fp_priya_phone"}
ATTACKER = {"device_id": "fp_attacker_01"}


@pytest.fixture(autouse=True)
def no_baseline():
    with admin_engine().begin() as c:
        c.execute(text("DROP SCHEMA IF EXISTS demo_baseline CASCADE"))
    demo_state.reset()
    yield
    with admin_engine().begin() as c:
        c.execute(text("DROP SCHEMA IF EXISTS demo_baseline CASCADE"))


def emit(client, event_type: str, payload: dict, context: dict) -> None:
    r = client.post("/v1/demo/emit", json={"event_type": event_type, "subject": PRIYA, "context": context, "payload": payload})
    assert r.status_code == 200, r.text
    drain(client)


def counts() -> dict[str, int]:
    with get_engine().connect() as c:
        return dict(c.execute(text("SELECT event_type, count(*) FROM events GROUP BY event_type")).all())


def n_cases() -> int:
    with get_engine().connect() as c:
        return c.execute(text("SELECT count(*) FROM cases")).scalar()


def test_ids_sensor_fires_for_an_unregistered_device_only_once(client):
    emit(client, "login", {"result": "success", "auth_method": "password+push"}, PRIYA_PHONE)
    assert "network_ids_alert" not in counts()                   # Priya's own registered phone: no alert
    emit(client, "login", {"result": "success", "auth_method": "password+otp"}, ATTACKER)
    emit(client, "login", {"result": "success", "auth_method": "password+otp"}, ATTACKER)
    assert counts()["network_ids_alert"] == 1                    # once per IP per 30 min
    with get_engine().connect() as c:
        src, login_ts, ids_ts = c.execute(text(
            "SELECT (SELECT data->'payload'->>'src_ip' FROM events WHERE event_type = 'network_ids_alert'), "
            "(SELECT min(occurred_at) FROM events WHERE event_type = 'login' AND data->>'device' IS NOT NULL "
            " AND data->>'device' != (SELECT data->>'device' FROM events WHERE event_type = 'login' ORDER BY occurred_at LIMIT 1)), "
            "(SELECT occurred_at FROM events WHERE event_type = 'network_ids_alert')")).one()
    assert src.startswith("ip:") and ids_ts < login_ts            # tokenized attacker IP, alert precedes the login


def test_baseline_live_cases_and_fast_reset(client, auth_headers):
    admin, analyst = auth_headers("admin"), auth_headers()
    assert client.post("/v1/demo/reset-live", headers=admin).status_code == 404       # nothing saved yet
    emit(client, "login", {"result": "success", "auth_method": "password+push"}, PRIYA_PHONE)
    base_events, base_cases = sum(counts().values()), n_cases()
    r = client.post("/v1/demo/baseline", headers=admin)
    assert r.status_code == 200 and r.json()["counts"]["events"] == base_events
    assert client.get("/v1/demo/live", headers=analyst).json()["cases"] == []

    # the attacker's laptop: login, SMS number swap, mule-linked payee, large transfer
    emit(client, "login", {"result": "success", "auth_method": "password+otp"}, ATTACKER)
    emit(client, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": "+91 90000 11111"}, ATTACKER)
    emit(client, "payee_added", {"payee_account": "A-RAVI-778", "payee_name_match": True, "nickname": "Rent - Ravi"}, ATTACKER)
    emit(client, "transaction", {"amount_paise": 48_000_000, "payee_account": "A-RAVI-778", "channel": "IMPS"}, ATTACKER)
    live = client.get("/v1/demo/live", headers=analyst).json()
    assert live["baseline"]["counts"]["events"] == base_events
    assert live["cases"] and n_cases() > base_cases and sum(counts().values()) > base_events

    assert client.post("/v1/demo/reset-live", headers=analyst).status_code == 403
    r = client.post("/v1/demo/reset-live", headers=admin)
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert sum(counts().values()) == base_events and n_cases() == base_cases          # only the live demo is gone
    assert client.get("/v1/demo/live", headers=analyst).json()["cases"] == []
    assert client.get("/v1/audit/verify", headers=admin).json()["ok"] is True         # chain intact after restore
    # the demo can run again right away: the sensor alerts again for the same attacker IP
    emit(client, "login", {"result": "success", "auth_method": "password+otp"}, ATTACKER)
    assert counts()["network_ids_alert"] == 1


def test_reset_live_keeps_feedback_ids_working_and_records_removed_audit_rows(client, auth_headers, seeded):
    admin = auth_headers("admin")
    cid = seeded[0]
    assert client.post(f"/v1/cases/{cid}/feedback", json={"verdict": "INCONCLUSIVE", "note": "before"}, headers=admin).status_code == 200
    assert client.post("/v1/demo/baseline", headers=admin).status_code == 200
    auth_headers("lead")                                                               # a LOGIN audit row after the snapshot
    r = client.post("/v1/demo/reset-live", headers=admin)
    assert r.status_code == 200
    removed = r.json()["baseline"]["audit_removed"]
    assert removed["rows"] >= 1 and len(removed["last_row_hash_before"]) == 64
    with get_engine().connect() as c:
        details = c.execute(text("SELECT details FROM audit_log WHERE action = 'DEMO_RESET_LIVE'")).scalar()
    assert details["audit_removed"]["rows"] == removed["rows"]
    # used to fail: RESTART IDENTITY reset feedback_id to 1 while the restored row 1 still exists
    assert client.post(f"/v1/cases/{cid}/feedback", json={"verdict": "INCONCLUSIVE", "note": "after"}, headers=admin).status_code == 200
    assert client.get("/v1/audit/verify", headers=admin).json()["ok"] is True
