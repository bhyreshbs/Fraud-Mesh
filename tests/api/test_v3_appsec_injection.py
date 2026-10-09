"""v3 phase 12: SQL injection and stored-XSS regression tests across the backend.

SQL: metacharacters on every user-influenced input (login, case filters/cursor, case ids in paths, sms-inbox phone,
step-up pending customer_ref, ask question, feedback note, payee nickname) leave every table intact and the values are
stored verbatim as data. Dynamic identifiers in SQL come only from module constants (checked here).
XSS: stored payloads round-trip as JSON strings and the API never answers text/html."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy import text

from api import demo_baseline, store_pg
from api.db.session import admin_engine, get_engine
from tests.api.conftest import TEST_PASSWORD
from tests.api.test_hardening import SQLI, _tables
from tests.api.test_worker_stepup import drain

ROOT = Path(__file__).resolve().parents[2]
XSS = ["<img src=x onerror=alert(1)>", "<script>alert(document.cookie)</script>", "javascript:alert(1)",
       "\"><svg onload=alert(1)>", "{{constructor.constructor('alert(1)')()}}"]
PAYLOADS = SQLI + XSS
PRIYA = {"customer_ref": "C-1042", "account_ref": "A-88213"}


def _assert_json(r) -> None:
    assert "text/html" not in r.headers.get("content-type", ""), (r.request.url, r.headers.get("content-type"))
    if r.status_code != 204:
        assert r.headers.get("content-type", "").startswith("application/json"), r.request.url
    assert r.headers.get("x-content-type-options") == "nosniff"


def test_every_input_with_metacharacters_leaves_tables_intact(client, auth_headers, seeded):
    h = auth_headers("lead")
    cid = seeded[2]
    before = {k: v for k, v in _tables().items() if k not in ("audit_log", "feedback", "auth_sessions", "auth_refresh_tokens")}
    for s in PAYLOADS:
        responses = [
            client.post("/v1/auth/login", json={"email": s, "password": s}),
            client.get("/v1/cases", params={"status": s}, headers=h), client.get("/v1/cases", params={"band": s}, headers=h),
            client.get("/v1/cases", params={"cursor": s[:20]}, headers=h),
            client.get(f"/v1/cases/{s}", headers=h), client.get(f"/v1/cases/{s}/graph", headers=h),
            client.get("/v1/demo/sms-inbox", params={"phone": s[:32]}),
            client.get("/v1/demo/step-up/pending", params={"customer_ref": s[:64], "channel": "app"}),
            client.post(f"/v1/cases/{cid}/ask", json={"question": s}, headers=h),
        ]
        for r in responses:
            _assert_json(r)
            assert r.status_code < 500, (r.request.url, r.status_code)
            assert "Traceback" not in r.text and "psycopg" not in r.text and "sqlalchemy" not in r.text.lower()
    after = {k: v for k, v in _tables().items() if k in before}
    assert after == before


def test_feedback_note_and_reason_are_stored_verbatim_and_returned_as_json(client, auth_headers, seeded):
    h = auth_headers("lead")
    cid = seeded[2]
    for s in PAYLOADS:
        r = client.post(f"/v1/cases/{cid}/feedback", json={"verdict": "INCONCLUSIVE", "note": s}, headers=h)
        assert r.status_code == 200, r.text
        _assert_json(r)
    with admin_engine().connect() as c:
        notes = c.execute(text("SELECT note FROM feedback WHERE case_id = :c ORDER BY feedback_id"), {"c": cid}).scalars().all()
    assert notes == PAYLOADS
    reason = XSS[0]
    r = client.post(f"/v1/cases/{cid}/actions", json={"actions": ["HOLD_OUTBOUND_PAYMENTS"], "reason": reason}, headers=h)
    assert r.status_code == 200 and r.json()["override_reason"] == reason
    tl = client.get(f"/v1/cases/{cid}/timeline", headers=h)
    _assert_json(tl)
    assert reason in [d["override_reason"] for d in tl.json()["decisions"]]       # data, as JSON; React renders it as text
    assert client.get("/v1/audit/verify", headers=h).json()["ok"] is True


def test_payee_nickname_payloads_are_data(client):
    for i, s in enumerate(XSS + SQLI[:2]):
        r = client.post("/v1/demo/emit", json={"event_type": "payee_added", "subject": PRIYA, "context": {"device_id": "fp_priya_phone"},
                                               "payload": {"payee_account": f"A-X{i}", "payee_name_match": True, "nickname": s}})
        assert r.status_code == 200, r.text
        _assert_json(r)
    drain(client)
    with get_engine().connect() as c:
        stored = c.execute(text("SELECT data->'payload'->>'nickname' FROM events WHERE event_type = 'payee_added' "
                                "ORDER BY occurred_at")).scalars().all()
    assert sorted(stored) == sorted(XSS + SQLI[:2])


def test_error_responses_are_json_and_generic(client):
    for r in (client.get("/v1/<script>"), client.post("/v1/auth/login", content=b"<html>", headers={"Content-Type": "text/html"}),
              client.post("/v1/auth/login", json={"email": XSS[0]})):
        _assert_json(r)
        assert r.json()["error"]["code"] in ("NOT_FOUND", "VALIDATION_FAILED", "UNAUTHENTICATED")
        assert "<script>" not in r.json()["error"]["message"] or r.status_code == 404


def test_login_with_metacharacters_does_not_authenticate(client):
    for s in SQLI:
        r = client.post("/v1/auth/login", json={"email": "admin@fraudmesh.local' --", "password": s})
        assert r.status_code in (401, 429)
    assert client.post("/v1/auth/login", json={"email": "admin@fraudmesh.local", "password": TEST_PASSWORD}).status_code == 200


# ------------------------------------------------------------------ dynamic SQL identifiers are allowlisted constants
IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")


def test_dynamic_sql_identifiers_are_constants():
    with admin_engine().connect() as c:
        real = set(c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).scalars())
    assert set(demo_baseline.TABLES) <= real and all(IDENT.match(t) for t in demo_baseline.TABLES)
    assert IDENT.match(demo_baseline.SCHEMA)
    assert all(IDENT.match(t) and IDENT.match(c) for t, c in demo_baseline.SERIAL_COLUMNS.items())
    src = (ROOT / "api" / "store_pg.py").read_text(encoding="utf-8")
    merge_tables = re.search(r'for table in \(([^)]*)\)', src).group(1)
    assert all(IDENT.match(t.strip(' "')) and t.strip(' "') in real for t in merge_tables.split(",") if t.strip())
    assert store_pg  # imported for the module path above


def test_app_role_is_least_privilege(client):
    with get_engine().connect() as c:
        assert c.execute(text("SELECT current_user")).scalar() == "fm_app"
        for table in ("cases", "events", "users", "auth_sessions", "audit_log"):
            assert c.execute(text("SELECT has_table_privilege('fm_app', :t, 'TRUNCATE')"), {"t": table}).scalar() is False, table
        assert c.execute(text("SELECT rolsuper OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname = 'fm_app'")).scalar() is False


@pytest.mark.parametrize("path", ["/v1/health", "/v1/demo/payment-status/evt_<script>"])
def test_public_routes_answer_json(client, path):
    _assert_json(client.get(path))
