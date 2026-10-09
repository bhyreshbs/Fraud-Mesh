"""v3 phase 6.3: server-side sessions, refresh rotation + reuse detection, sid revocation, privilege-change rotation,
revoke-all, cookie flags and the CSRF check on cookie-authenticated routes."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from sqlalchemy import text
from starlette.websockets import WebSocketDisconnect

from api import sessions
from api.db.session import admin_engine
from api.security import REFRESH_COOKIE
from engine.common.settings import settings
from tests.api.conftest import TEST_PASSWORD

GOOD_ORIGIN = "http://localhost:5173"


def _login(client, role: str = "analyst") -> tuple[str, str]:
    r = client.post("/v1/auth/login", json={"email": f"{role}@fraudmesh.local", "password": TEST_PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["access_token"], client.cookies.get(REFRESH_COOKIE)


def _bearer(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


def _db(sql: str, **params):
    with admin_engine().begin() as c:
        r = c.execute(text(sql), params)
        return r.all() if r.returns_rows else r.rowcount


def _set_refresh(client, token: str) -> None:
    client.cookies.clear()
    client.cookies.set(REFRESH_COOKIE, token, path="/v1/auth")


def test_access_token_carries_sid_and_only_hashes_are_stored(client):
    access, refresh = _login(client)
    sid = jwt.decode(access, options={"verify_signature": False})["sid"]
    assert sid.startswith("ses_")
    [(user, role)] = _db("SELECT user_id, role FROM auth_sessions WHERE session_id = :s", s=sid)
    assert (user, role) == ("usr_analyst", "analyst")
    hashes = [h for (h,) in _db("SELECT token_hash FROM auth_refresh_tokens WHERE session_id = :s", s=sid)]
    assert hashes == [hashlib.sha256(refresh.encode()).hexdigest()]
    assert refresh not in json.dumps(_db("SELECT * FROM auth_refresh_tokens", ), default=str)


def test_cookie_flags(client, monkeypatch):
    r = client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": TEST_PASSWORD})
    c = r.headers["set-cookie"].lower()
    assert "httponly" in c and "samesite=strict" in c and "path=/v1/auth" in c and "secure" not in c
    monkeypatch.setenv("FM_TLS", "1")
    r = client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": TEST_PASSWORD})
    assert "secure" in r.headers["set-cookie"].lower()


def test_rotation_and_reuse_detection_revokes_the_family(client):
    access, first = _login(client, "lead")
    r = client.post("/v1/auth/refresh")
    assert r.status_code == 200
    second, new_access = client.cookies.get(REFRESH_COOKIE), r.json()["access_token"]
    assert second != first
    # inside the race window: refused, but the session survives (two tabs on one cookie)
    _set_refresh(client, first)
    assert client.post("/v1/auth/refresh").status_code == 401
    assert client.get("/v1/cases", headers=_bearer(new_access)).status_code == 200
    # later reuse of the old token = theft signal: the whole session dies, including the legitimate new token
    _db("UPDATE auth_refresh_tokens SET used_at = now() - interval '1 minute' WHERE token_hash = :h",
        h=sessions.token_hash(first))
    assert client.post("/v1/auth/refresh").status_code == 401
    for tok in (access, new_access):
        assert client.get("/v1/cases", headers=_bearer(tok)).status_code == 401
    _set_refresh(client, second)
    assert client.post("/v1/auth/refresh").status_code == 401
    assert ("SESSION_REUSE_DETECTED",) in _db("SELECT action FROM audit_log")


def test_logout_kills_the_access_token_immediately(client):
    access, refresh = _login(client)
    assert client.get("/v1/cases", headers=_bearer(access)).status_code == 200
    assert client.post("/v1/auth/logout", headers=_bearer(access)).status_code == 204
    assert client.get("/v1/cases", headers=_bearer(access)).status_code == 401
    _set_refresh(client, refresh)
    assert client.post("/v1/auth/refresh").status_code == 401


def test_revoke_all_and_admin_revoke(client):
    a1, _ = _login(client, "analyst")
    a2, _ = _login(client, "analyst")
    listed = client.get("/v1/auth/sessions", headers=_bearer(a2)).json()["sessions"]
    assert len(listed) >= 2 and sum(s["current"] for s in listed) == 1
    assert "token" not in json.dumps(listed).lower().replace("user_agent", "")
    r = client.post("/v1/auth/sessions/revoke-all", headers=_bearer(a1))
    assert r.status_code == 200 and r.json()["revoked"] >= 2
    assert client.get("/v1/cases", headers=_bearer(a1)).status_code == 401
    assert client.get("/v1/cases", headers=_bearer(a2)).status_code == 401
    lead, _ = _login(client, "lead")
    analyst, _ = _login(client, "analyst")
    assert client.post("/v1/auth/users/usr_lead/sessions/revoke", headers=_bearer(analyst)).status_code == 403
    admin, _ = _login(client, "admin")
    r = client.post("/v1/auth/users/usr_lead/sessions/revoke", headers=_bearer(admin))
    assert r.status_code == 200 and r.json()["revoked"] >= 1
    assert client.get("/v1/cases", headers=_bearer(lead)).status_code == 401
    assert client.post("/v1/auth/users/x';DROP TABLE users;--/sessions/revoke", headers=_bearer(admin)).status_code in (404, 422)


def test_privilege_change_rotates_the_session(client):
    access, _ = _login(client, "analyst")
    old_sid = jwt.decode(access, options={"verify_signature": False})["sid"]
    _db("UPDATE users SET role = 'lead' WHERE user_id = 'usr_analyst'")
    r = client.post("/v1/auth/refresh")
    assert r.status_code == 200 and r.json()["role"] == "lead"
    new_sid = jwt.decode(r.json()["access_token"], options={"verify_signature": False})["sid"]
    assert new_sid != old_sid
    assert client.get("/v1/cases", headers=_bearer(access)).status_code == 401         # the old-role token is dead
    assert _db("SELECT rotated_from FROM auth_sessions WHERE session_id = :s", s=new_sid) == [(old_sid,)]
    # on_privilege_change revokes everything at once
    assert sessions.on_privilege_change("usr_analyst") >= 1
    assert client.get("/v1/cases", headers=_bearer(r.json()["access_token"])).status_code == 401


def test_deleted_user_and_expired_session_are_refused(client):
    access, refresh = _login(client, "analyst")
    sid = jwt.decode(access, options={"verify_signature": False})["sid"]
    _db("UPDATE auth_sessions SET expires_at = now() - interval '1 second' WHERE session_id = :s", s=sid)
    sessions.clear_cache()
    assert client.get("/v1/cases", headers=_bearer(access)).status_code == 401
    assert client.post("/v1/auth/refresh").status_code == 401
    _login(client, "lead")
    _db("DELETE FROM users WHERE user_id = 'usr_lead'")
    assert client.post("/v1/auth/refresh").status_code == 401


def test_tokens_without_a_live_session_are_refused(client):
    now = datetime.now(UTC)
    base = {"iss": "fraudmesh", "sub": "usr_admin", "role": "admin", "queues": ["default"], "iat": now,
            "exp": now + timedelta(minutes=5)}
    no_sid = jwt.encode(base, settings.jwt_secret, algorithm="HS256")
    ghost = jwt.encode({**base, "sid": "ses_" + "0" * 32}, settings.jwt_secret, algorithm="HS256")
    for t in (no_sid, ghost):
        assert client.get("/v1/cases", headers=_bearer(t)).status_code == 401


def test_websocket_refuses_a_revoked_session(client):
    access, _ = _login(client)
    client.post("/v1/auth/logout", headers=_bearer(access))
    with client.websocket_connect("/v1/stream") as ws:
        ws.send_text(json.dumps({"token": access}))
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_text()
    assert e.value.code == 4401


# ------------------------------------------------------------------ CSRF
def test_refresh_csrf_checks(client):
    _login(client)
    evil = {"Origin": "https://evil.example", "X-FM-CSRF": "1"}
    for headers in (evil, {"Origin": "null", "X-FM-CSRF": "1"}, {"Origin": GOOD_ORIGIN},
                    {"Sec-Fetch-Site": "cross-site", "X-FM-CSRF": "1"},
                    {"Referer": "https://evil.example/page", "X-FM-CSRF": "1"}):
        r = client.post("/v1/auth/refresh", headers=headers)
        assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN", headers
    assert client.post("/v1/auth/refresh", headers={"Origin": GOOD_ORIGIN, "X-FM-CSRF": "1"}).status_code == 200
    assert client.post("/v1/auth/refresh", headers={"Sec-Fetch-Site": "same-site", "X-FM-CSRF": "1"}).status_code == 200
    assert client.post("/v1/auth/refresh", headers={"Referer": GOOD_ORIGIN + "/queue", "X-FM-CSRF": "1"}).status_code == 200


def test_login_csrf_and_preflight_allows_the_header(client):
    body = {"email": "analyst@fraudmesh.local", "password": TEST_PASSWORD}
    assert client.post("/v1/auth/login", json=body, headers={"Origin": "https://evil.example", "X-FM-CSRF": "1"}).status_code == 403
    assert client.post("/v1/auth/login", json=body, headers={"Origin": GOOD_ORIGIN, "X-FM-CSRF": "1"}).status_code == 200
    pre = client.options("/v1/auth/refresh", headers={"Origin": GOOD_ORIGIN, "Access-Control-Request-Method": "POST",
                                                      "Access-Control-Request-Headers": "x-fm-csrf"})
    assert pre.status_code == 200 and "x-fm-csrf" in pre.headers.get("access-control-allow-headers", "").lower()
    bad = client.options("/v1/auth/refresh", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
                                                      "Access-Control-Request-Headers": "x-fm-csrf"})
    assert "access-control-allow-origin" not in bad.headers
