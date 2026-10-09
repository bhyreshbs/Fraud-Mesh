"""Regression tests for the backend audit fixes (branch dev1/security-hardening):
- ingestion backlog cap (503, nothing stored), body-size cap on every route, Cache-Control: no-store
- the ingestion rate-limit key includes the client IP; per-account login limit
- WebSocket: expired tokens are disconnected (4401); a stalled client cannot block a broadcast
- merge_cases re-points feedback / challenges / payment outcomes / replays instead of failing or orphaning them
- keyed OTP hashes, refresh-token pruning, docs off outside demo mode, one bad Suricata line does not stop the file
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from starlette.requests import Request
from starlette.websockets import WebSocketDisconnect

from api import security, stepup
from api.db.session import get_engine
from api.ratelimit import limiter, login_account_limited, per_source
from api.routers import stream
from api.store_pg import PgStore
from engine.common.ids import new_id
from engine.common.settings import settings
from engine.contracts import Case
from scripts.sign import sign
from tests.api.test_ingest import LOGIN, env, post


def q(sql: str, **params):
    with get_engine().connect() as c:
        return c.execute(text(sql), params).all()


# ------------------------------------------------------------------ ingestion backlog and body size
def test_full_backlog_refuses_ingestion_before_storing(client, monkeypatch):
    monkeypatch.setattr("api.worker.MAX_BACKLOG", 0)
    e = env("login", {"result": "success", "auth_method": "password"})
    r = post(client, e)
    assert r.status_code == 503 and r.json()["error"]["code"] == "ENGINE_UNAVAILABLE"
    assert q("SELECT 1 FROM events WHERE event_id = :e", e=e["event_id"]) == []


def test_every_route_caps_the_body(client):
    big = json.dumps({"email": "a@b.c", "password": "x" * 70_000})
    r = client.post("/v1/auth/login", content=big, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    r = client.post("/v1/demo/emit", content=(b"x" * 10_000 for _ in range(10)), headers={"Content-Type": "application/json"})
    assert r.status_code == 413                                   # chunked body, no Content-Length to check up front


def test_responses_are_not_cacheable(client):
    assert client.get("/v1/health").headers["cache-control"] == "no-store"


# ------------------------------------------------------------------ rate limits
def _request(source: str, ip: str) -> Request:
    return Request({"type": "http", "method": "POST", "path": "/v1/events", "headers": [(b"x-fm-source", source.encode())],
                    "client": (ip, 1234), "query_string": b""})


def test_ingestion_limit_key_includes_client_ip():
    assert per_source(_request("network-ids", "10.0.0.1")) != per_source(_request("network-ids", "10.0.0.2"))
    assert per_source(_request("network-ids", "10.0.0.1")) == per_source(_request("network-ids", "10.0.0.1"))


def test_login_is_limited_per_account():
    limiter.reset()
    limiter.enabled = True
    try:
        assert not any(login_account_limited("Analyst@FraudMesh.local ") for _ in range(10))
        assert login_account_limited("analyst@fraudmesh.local")
        assert not login_account_limited("lead@fraudmesh.local")
    finally:
        limiter.enabled = False


# ------------------------------------------------------------------ WebSocket
def test_websocket_closes_when_the_token_expires(client):
    now = datetime.now(UTC)
    token = jwt.encode({"sub": "usr_analyst", "role": "analyst", "queues": ["default"], "iat": now,
                        "exp": now + timedelta(seconds=1)}, settings.jwt_secret, algorithm="HS256")
    with client.websocket_connect("/v1/stream") as ws:
        ws.send_text(json.dumps({"token": token}))
        with pytest.raises(WebSocketDisconnect) as e:
            ws.receive_text()
    assert e.value.code == 4401


class _FakeSocket:
    def __init__(self, stall: bool) -> None:
        self.stall, self.got, self.closed = stall, [], False

    async def send_text(self, text: str) -> None:
        if self.stall:
            await asyncio.sleep(3600)
        self.got.append(text)

    async def close(self, code: int = 1000) -> None:
        self.closed = True


def test_a_stalled_client_cannot_block_a_broadcast(monkeypatch):
    monkeypatch.setattr(stream, "SEND_TIMEOUT_S", 0.05)
    hub, slow, fast = stream.Broadcaster(), _FakeSocket(stall=True), _FakeSocket(stall=False)

    async def go() -> None:
        await hub.add(slow)
        await hub.add(fast)
        await asyncio.wait_for(hub.broadcast({"type": "case_update"}), timeout=2)
    asyncio.run(go())
    assert fast.got and hub.count == 1 and slow.closed


# ------------------------------------------------------------------ merge_cases
def _case(case_id: str, status: str = "OPEN") -> Case:
    ts = datetime(2026, 10, 9, tzinfo=UTC)
    return Case(case_id=case_id, anchor_entity="cust:aaaaaaaaaaaaaaaa", status=status, opened_at=ts, updated_at=ts,
                last_event_ts=ts, entities=["cust:aaaaaaaaaaaaaaaa"])


def test_merge_repoints_feedback_and_api_rows():
    store, keep, drop = PgStore(), new_id("case"), new_id("case")
    store.save_case(_case(keep))
    store.save_case(_case(drop, "INVESTIGATING"))                 # e.g. after an INCONCLUSIVE verdict
    evt = new_id("evt")
    with get_engine().begin() as c:
        c.execute(text("INSERT INTO feedback (case_id, verdict, analyst, data) VALUES (:c, 'INCONCLUSIVE', 'usr_x', '{}')"), {"c": drop})
        c.execute(text("INSERT INTO step_up_challenges (challenge_id, case_id, customer, method, status, created_at, expires_at) "
                       "VALUES (:id, :c, 'cust:x', 'sms_otp', 'pending', now(), now())"), {"id": new_id("chl"), "c": drop})
        c.execute(text("INSERT INTO events (event_id, event_type, source, occurred_at, received_at, entity_tokens, data) "
                       "VALUES (:e, 'transaction', 'simulator', now(), now(), '{}', '{}')"), {"e": evt})
        c.execute(text("INSERT INTO payment_outcomes (event_id, outcome, case_id) VALUES (:e, 'held', :c)"), {"e": evt, "c": drop})
    store.merge_cases(keep, drop)                                  # used to fail: feedback.case_id REFERENCES cases
    assert store.get_case(drop) is None
    for table in ("feedback", "step_up_challenges", "payment_outcomes"):
        assert q(f"SELECT DISTINCT case_id FROM {table}") == [(keep,)], table


# ------------------------------------------------------------------ smaller fixes
def test_otp_hash_is_keyed():
    assert stepup._otp_hash("123456") != hashlib.sha256(b"123456").hexdigest()
    assert stepup._otp_hash("123456") == stepup._otp_hash("123456")


def test_expired_refresh_tokens_are_pruned():
    stale = "stale-" + new_id("x")
    with security._refresh_lock:
        security._refresh[security._h(stale)] = ("usr_x", datetime.now(UTC) - timedelta(seconds=1))
    security.issue_refresh("usr_y")
    assert security._h(stale) not in security._refresh


def test_docs_and_schema_are_off_outside_demo_mode(monkeypatch):
    import api.main
    monkeypatch.setattr(api.main, "settings", dataclasses.replace(settings, demo_mode=False))
    app = api.main.create_app()
    c = TestClient(app)                                            # no lifespan needed for these routes
    assert app.openapi_url is None
    assert all(c.get(p).status_code == 404 for p in ("/docs", "/redoc", "/openapi.json"))


def test_one_bad_suricata_line_does_not_stop_the_file(tmp_path):
    from api.adapters.suricata import read_alerts
    good = {"timestamp": "2026-10-09T00:39:00.000000+0530", "event_type": "alert", "src_ip": "185.220.101.7",
            "dest_ip": "10.0.1.20", "dest_port": 443, "alert": {"signature_id": 9000001, "signature": "x", "category": "y", "severity": 2}}
    icmp = {**good, "dest_port": None}
    del icmp["dest_port"]
    f = tmp_path / "eve.jsonl"
    f.write_text("\n".join([json.dumps(icmp), "{not json", json.dumps({"event_type": "flow"}), json.dumps(good)]), encoding="utf-8")
    envs, skipped = read_alerts(str(f))
    assert len(envs) == 1 and skipped == 3


def test_signed_headers_match_the_shared_rule():
    body = json.dumps(LOGIN).encode()
    h = sign("demo-bank-web", body, 1_700_000_000)
    from api.signing import signature
    assert h["X-FM-Signature"] == signature(settings.hmac_secrets["demo-bank-web"], "1700000000", body)
