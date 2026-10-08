"""D1-P4 done-when (PRD §15.4):
- editing one audit_log.details row as superuser makes /audit/verify report broken_at at that row
- analyst calling /actions gets 403; analyst reading a case in another queue gets 404
- security headers present on every response; 150 requests in 1 s from one source get 429s
Plus: the app DB role cannot UPDATE/DELETE audit rows, every route is guarded as specified, login is limited 5/min/IP."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from api.db.session import admin_engine, get_engine
from api.ratelimit import limiter
from engine.common.ids import new_id
from scripts.sign import sign
from tests.api.conftest import TEST_PASSWORD

SECURITY_HEADERS = {"content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer", "x-frame-options": "DENY"}


@pytest.fixture
def limits_on():
    limiter.reset()
    limiter.enabled = True
    yield
    limiter.enabled = False


# ------------------------------------------------------------------ audit chain
def _audit_rows(n: int, client, auth_headers) -> None:
    for _ in range(n):
        auth_headers("lead")                                    # each login appends a LOGIN row


def test_audit_verify_ok_then_tamper_detected(client, auth_headers, seeded):
    h = auth_headers("lead")
    cid = seeded[2]
    client.post(f"/v1/cases/{cid}/actions", json={"actions": ["HOLD_OUTBOUND_PAYMENTS"], "reason": "r1"}, headers=h)
    client.post(f"/v1/cases/{cid}/feedback", json={"verdict": "INCONCLUSIVE", "note": "n"}, headers=h)
    _audit_rows(2, client, auth_headers)
    v = client.get("/v1/audit/verify", headers=h).json()
    assert v["ok"] is True and v["broken_at"] is None and v["rows"] >= 5
    with admin_engine().begin() as c:                           # superuser edits one row's details
        seq = c.execute(text("SELECT seq FROM audit_log WHERE action = 'MANUAL_ACTION'")).scalar()
        c.execute(text("UPDATE audit_log SET details = jsonb_set(details, '{reason}', '\"edited\"') WHERE seq = :s"), {"s": seq})
    v = client.get("/v1/audit/verify", headers=h).json()
    assert v == {"ok": False, "rows": v["rows"], "broken_at": seq}


def test_audit_verify_detects_deleted_row(client, auth_headers):
    _audit_rows(3, client, auth_headers)
    with admin_engine().begin() as c:
        seq = c.execute(text("SELECT min(seq) + 1 FROM audit_log")).scalar()
        c.execute(text("DELETE FROM audit_log WHERE seq = :s"), {"s": seq})
    v = client.get("/v1/audit/verify", headers=auth_headers("lead")).json()
    assert v["ok"] is False and v["broken_at"] == seq + 1           # the row after the gap no longer links


def test_audit_verify_is_lead_only(client, auth_headers):
    assert client.get("/v1/audit/verify", headers=auth_headers("analyst")).status_code == 403
    assert client.get("/v1/audit/verify").status_code == 401


def test_app_role_cannot_rewrite_audit_rows(client, auth_headers):
    auth_headers("analyst")
    with get_engine().connect() as c:
        assert c.execute(text("SELECT current_user")).scalar() == "fm_app"
        assert c.execute(text("SELECT count(*) FROM audit_log")).scalar() >= 1          # SELECT allowed
    for sql in ("UPDATE audit_log SET actor = 'x'", "DELETE FROM audit_log", "TRUNCATE audit_log"):
        with pytest.raises(ProgrammingError, match="permission denied"):
            with get_engine().begin() as c:
                c.execute(text(sql))
    with get_engine().begin() as c:                             # other tables stay writable for the app
        c.execute(text("UPDATE users SET queues = queues WHERE user_id = 'usr_analyst'"))


# ------------------------------------------------------------------ RBAC / IDOR
def test_analyst_actions_403_and_other_queue_404(client, auth_headers, seeded):
    h = auth_headers("analyst")
    r = client.post(f"/v1/cases/{seeded[0]}/actions", json={"actions": ["ALLOW"], "reason": "x"}, headers=h)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    with get_engine().begin() as c:
        c.execute(text("UPDATE cases SET queue = 'vip' WHERE case_id = :c"), {"c": seeded[0]})
    for path in ("", "/timeline", "/graph", "/explanation"):
        r = client.get(f"/v1/cases/{seeded[0]}{path}", headers=h)
        assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND", path
    for path, body in (("/replay", {"ablate": [], "mode": "fused"}), ("/feedback", {"verdict": "FALSE_POSITIVE", "note": None}),
                       ("/ask", {"question": "why?"})):
        assert client.post(f"/v1/cases/{seeded[0]}{path}", json=body, headers=h).status_code == 404, path
    # a lead without that queue is also refused (404, not 403: case ids cannot be probed)
    lead = auth_headers("lead")
    assert client.post(f"/v1/cases/{seeded[0]}/actions", json={"actions": ["ALLOW"], "reason": "x"}, headers=lead).status_code == 404


PUBLIC = {("GET", "/v1/health"), ("POST", "/v1/auth/login"), ("POST", "/v1/auth/refresh"),
          ("POST", "/v1/events"), ("POST", "/v1/events/batch"),          # HMAC-signed instead of JWT
          ("POST", "/v1/demo/emit"), ("GET", "/v1/demo/payment-status/{event_id}"), ("GET", "/v1/demo/step-up/pending"),
          ("GET", "/v1/demo/sms-inbox"), ("POST", "/v1/demo/step-up/{challenge_id}/respond")}   # demo bank app (DEMO_MODE only)
MIN_ROLE = {("POST", "/v1/cases/{case_id}/actions"): "lead", ("GET", "/v1/audit/verify"): "lead",
            ("POST", "/v1/demo/run/{scenario_id}"): "admin", ("POST", "/v1/demo/reset"): "admin"}


def test_every_route_has_the_specified_guard(client):
    """Walk the app's routes: everything outside PUBLIC needs a bearer token; MIN_ROLE routes need that role."""
    seen = set()
    for route, ops in client.app.openapi()["paths"].items():
        if not route.startswith("/v1/"):
            continue
        for m in ops:
            m = m.upper()
            seen.add((m, route))
            path = route.replace("{case_id}", "case_x").replace("{event_id}", "evt_x").replace("{challenge_id}", "chl_x") \
                .replace("{scenario_id}", "midnight_ato")
            resp = client.request(m, path, json={})
            if (m, route) in PUBLIC:
                assert resp.status_code != 401 or route.startswith("/v1/events") or route.endswith("refresh"), (m, route)
            else:
                assert resp.status_code == 401, (m, route, resp.status_code)
    assert len(seen) >= 25 and set(MIN_ROLE) <= seen and set(PUBLIC) <= seen
    unexpected_public = seen - set(PUBLIC) - {(m, p) for m, p in seen if p not in {q for _, q in PUBLIC}}
    assert not unexpected_public


def test_role_matrix(client, auth_headers):
    tokens = {role: auth_headers(role) for role in ("analyst", "lead", "admin")}
    expect = {("POST", "/v1/demo/run/midnight_ato", '{"speed": 8}'): {"analyst": 403, "lead": 403},
              ("POST", "/v1/demo/reset", None): {"analyst": 403, "lead": 403},
              ("GET", "/v1/audit/verify", None): {"analyst": 403}}
    for (m, path, body), denied in expect.items():
        for role, h in tokens.items():
            r = client.request(m, path, content=body, headers={**h, "Content-Type": "application/json"})
            assert (r.status_code == denied[role]) if role in denied else r.status_code == 200, (role, path, r.status_code)


# ------------------------------------------------------------------ headers
def test_security_headers_on_every_kind_of_response(client, auth_headers):
    h = auth_headers()
    responses = [client.get("/v1/health"), client.get("/v1/cases", headers=h), client.get("/v1/cases"),          # 200, 401
                 client.get("/v1/cases/case_missing", headers=h), client.get("/v1/nope"),                         # 404s
                 client.post("/v1/auth/login", json={"email": 1}),                                                   # 422
                 client.post("/v1/events", content=b"{}"),                                                           # 401 HMAC
                 client.options("/v1/cases", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})]
    for r in responses:
        for k, v in SECURITY_HEADERS.items():
            assert r.headers.get(k) == v, (r.request.url, r.status_code, k)
        assert "max-age=" in r.headers.get("strict-transport-security", ""), r.request.url
        assert r.headers.get("x-request-id", "").startswith("req_")


def test_cors_only_for_configured_origins(client):
    ok = client.options("/v1/cases", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.options("/v1/cases", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in bad.headers


def test_unhandled_error_uses_error_format(client, monkeypatch):
    import api.routers.health as health
    monkeypatch.setattr(health, "db_ok", lambda: 1 / 0)
    r = client.get("/v1/health")
    assert r.status_code == 500 and r.json()["error"]["code"] == "INTERNAL_ERROR"
    assert r.headers["x-frame-options"] == "DENY"


# ------------------------------------------------------------------ rate limits
def _signed_login_event() -> tuple[bytes, dict]:
    env = {"event_id": new_id("evt"), "event_type": "login", "source": "simulator", "occurred_at": "2026-10-09T00:41:07+05:30",
           "subject": {"customer_ref": "C-1"}, "payload": {"result": "success", "auth_method": "password"}}
    body = json.dumps(env).encode()
    return body, sign("simulator", body)


def test_ingestion_150_in_one_second_gets_429s(client, limits_on):
    # The limit is counted per source before the handler runs, so cheap requests (valid headers, tampered body ->
    # 401 after one HMAC) let all 150 land inside one 1-second window even on a slow CI runner.
    body, headers = _signed_login_event()
    tampered = body.replace(b"success", b"failure")
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=50) as pool:
        codes = list(pool.map(lambda _: client.post("/v1/events", content=tampered, headers=headers).status_code, range(150)))
    elapsed = time.monotonic() - start
    assert set(codes) <= {401, 429}
    if elapsed < 1.0:
        assert codes.count(401) == 100 and codes.count(429) == 50, (codes.count(401), elapsed)
    else:                                                       # never more than 100 per window
        assert codes.count(429) > 0 and codes.count(401) <= 100 * (int(elapsed) + 1), (codes.count(401), elapsed)
    r = client.post("/v1/events", content=body, headers=headers)                # same window: even a valid event waits
    if time.monotonic() - start < 1.0:
        assert r.status_code == 429 and r.json()["error"]["code"] == "RATE_LIMITED" and r.headers["retry-after"] == "1"

def test_ingestion_limit_is_per_source(client, limits_on):
    body, headers = _signed_login_event()
    tampered = body.replace(b"success", b"failure")
    with ThreadPoolExecutor(max_workers=50) as pool:
        list(pool.map(lambda _: client.post("/v1/events", content=tampered, headers=headers), range(120)))
    env = {"event_id": new_id("evt"), "event_type": "login", "source": "demo-bank-web", "occurred_at": "2026-10-09T00:41:07+05:30",
           "subject": {"customer_ref": "C-1"}, "payload": {"result": "success", "auth_method": "password"}}
    other = json.dumps(env).encode()
    assert client.post("/v1/events", content=other, headers=sign("demo-bank-web", other)).status_code == 202


def test_login_limited_to_5_per_minute_per_ip(client, limits_on):
    codes = [client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": "wrong"}).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    r = client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": TEST_PASSWORD})
    assert r.status_code == 429 and r.json()["error"]["code"] == "RATE_LIMITED"     # even the right password, until the window resets


def test_other_routes_limited_to_20_per_second_per_user(client, limits_on):
    token = client.post("/v1/auth/login", json={"email": "lead@fraudmesh.local", "password": TEST_PASSWORD}).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    with ThreadPoolExecutor(max_workers=30) as pool:
        codes = list(pool.map(lambda _: client.get("/v1/detectors", headers=h).status_code, range(60)))
    assert set(codes) <= {200, 429} and 429 in codes and codes.count(200) >= 20
    # a different user has their own budget
    other = client.post("/v1/auth/login", json={"email": "admin@fraudmesh.local", "password": TEST_PASSWORD}).json()["access_token"]
    assert client.get("/v1/detectors", headers={"Authorization": f"Bearer {other}"}).status_code == 200
