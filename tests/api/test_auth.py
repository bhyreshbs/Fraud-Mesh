"""D1-P1 done-when: login works for all three users; a wrong password returns 401. Plus refresh rotation and role checks."""
from __future__ import annotations

import jwt
import pytest

from api.security import REFRESH_COOKIE
from tests.api.conftest import TEST_PASSWORD


@pytest.mark.parametrize("role", ["analyst", "lead", "admin"])
def test_login_each_seed_user(client, role):
    r = client.post("/v1/auth/login", json={"email": f"{role}@fraudmesh.local", "password": TEST_PASSWORD})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token_type"] == "bearer" and body["expires_in"] == 900 and body["role"] == role
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["sub"] == f"usr_{role}" and claims["role"] == role and claims["queues"] == ["default"] and "exp" in claims
    cookie = r.headers["set-cookie"]
    assert REFRESH_COOKIE in cookie and "HttpOnly" in cookie


def test_wrong_password_is_401(client):
    r = client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": "nope"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "UNAUTHENTICATED"
    r = client.post("/v1/auth/login", json={"email": "nobody@fraudmesh.local", "password": TEST_PASSWORD})
    assert r.status_code == 401


def test_refresh_rotates_and_old_token_dies(client):
    client.post("/v1/auth/login", json={"email": "lead@fraudmesh.local", "password": TEST_PASSWORD})
    old = client.cookies.get(REFRESH_COOKIE)
    r = client.post("/v1/auth/refresh")
    assert r.status_code == 200 and r.json()["role"] == "lead"
    new = client.cookies.get(REFRESH_COOKIE)
    assert new and new != old
    client.cookies.set(REFRESH_COOKIE, old, path="/v1/auth")
    assert client.post("/v1/auth/refresh").status_code == 401


def test_logout_revokes_refresh(client):
    r = client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": TEST_PASSWORD})
    token, refresh = r.json()["access_token"], client.cookies.get(REFRESH_COOKIE)
    assert client.post("/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 204
    client.cookies.set(REFRESH_COOKIE, refresh, path="/v1/auth")
    assert client.post("/v1/auth/refresh").status_code == 401


def test_bearer_required_and_roles_enforced(client, auth_headers):
    assert client.get("/v1/cases").status_code == 401
    assert client.get("/v1/cases", headers={"Authorization": "Bearer garbage"}).status_code == 401
    analyst = auth_headers("analyst")
    assert client.get("/v1/cases", headers=analyst).status_code == 200
    case_id = client.get("/v1/cases", headers=analyst).json()["items"][0]["case_id"]
    body = {"actions": ["HOLD_OUTBOUND_PAYMENTS"], "reason": "test"}
    r = client.post(f"/v1/cases/{case_id}/actions", json=body, headers=analyst)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    assert client.post(f"/v1/cases/{case_id}/actions", json=body, headers=auth_headers("lead")).status_code == 200
    assert client.post("/v1/demo/reset", headers=auth_headers("lead")).status_code == 403
    assert client.post("/v1/demo/reset", headers=auth_headers("admin")).status_code == 200


def test_login_is_audited(client):
    from sqlalchemy import text

    from api.db.session import get_engine
    client.post("/v1/auth/login", json={"email": "admin@fraudmesh.local", "password": TEST_PASSWORD})
    with get_engine().connect() as c:
        rows = c.execute(text("SELECT actor, action FROM audit_log")).all()
    assert ("usr_admin", "LOGIN") in [tuple(r) for r in rows]
