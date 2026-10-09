"""Payment rail (api/payments): offline PayPal mock, PayPal sandbox adapter (httpx.MockTransport only — no real
PayPal call), the worker -> rail mapping, feedback -> capture/void, failure isolation, and GET /v1/cases/{id}/payments."""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
from urllib.parse import parse_qs

import httpx
import pytest

from api.payments import MockPayPalRail, PayPalSandboxRail, RailError, rail_from_env
from api.payments.rails import ORDER_DESCRIPTION, format_amount
from api.payments.service import RailConfig
from engine.contracts import FeedbackResult
from tests.api import test_worker_stepup as tws
from tests.api.test_worker_stepup import PRIYA, FakePipeline, q

PAYEE = "A-RAVI-778"


# ====================================================================================== mock rail state machine
def test_mock_state_machine_and_paypal_shapes():
    rail = MockPayPalRail()
    a = rail.authorize("evt_aaaaaaaa01", 48000000, payee_token="acct:abcdefghijklmnop")
    assert rail.authorize("evt_aaaaaaaa01", 48000000) == a                  # idempotent per event (PayPal-Request-Id)
    assert MockPayPalRail().authorize("evt_aaaaaaaa01", 48000000) == a      # deterministic across instances
    assert len(a) == 17 and a.isalnum() and rail.get(a) == "AUTHORIZED"
    order = rail.order("evt_aaaaaaaa01")
    assert order["intent"] == "AUTHORIZE" and order["purchase_units"][0]["amount"] == {"currency_code": "INR", "value": "480000.00"}
    assert order["purchase_units"][0]["description"] == ORDER_DESCRIPTION and "acct:" not in json.dumps(order)
    assert rail.authorization(a)["status"] == "CREATED"                    # PayPal's name for a live authorization

    assert rail.capture(a) == "CAPTURED" and rail.capture(a) == "CAPTURED"  # second capture is a no-op
    with pytest.raises(RailError) as e:
        rail.void(a)
    assert e.value.code == "PREVIOUSLY_CAPTURED" and not e.value.retryable

    b = rail.authorize("evt_bbbbbbbb02", 150000)
    assert rail.void(b) == "VOIDED" and rail.void(b) == "VOIDED"
    with pytest.raises(RailError) as e:
        rail.capture(b)
    assert e.value.code == "AUTHORIZATION_VOIDED"
    with pytest.raises(RailError) as e:
        rail.get("NOPE")
    assert e.value.code == "RESOURCE_NOT_FOUND"
    assert rail._auths[b].history == ["CREATED", "AUTHORIZED", "VOIDED"]

    fresh = MockPayPalRail()                                              # process restart: re-registered from the table
    fresh.restore(a, "evt_aaaaaaaa01", "AUTHORIZED")
    assert fresh.capture(a) == "CAPTURED"


def test_amount_conversion():
    assert format_amount(150000, "INR") == "1500.00" and format_amount(150005, "USD") == "1500.05"
    assert format_amount(7, "USD") == "0.07" and format_amount(150000, "JPY") == "1500"
    with pytest.raises(ValueError):
        format_amount(0, "USD")


def test_rail_from_env():
    cfg, rail = rail_from_env({})
    assert cfg.mode == "mock" and isinstance(rail, MockPayPalRail) and cfg.currency == "INR"
    assert rail_from_env({"FM_PAYMENT_RAIL": "off"})[1] is None
    cfg, rail = rail_from_env({"FM_PAYMENT_RAIL": "paypal_sandbox"})                     # no credentials -> mock
    assert cfg.mode == "mock" and isinstance(rail, MockPayPalRail)
    cfg, rail = rail_from_env({"FM_PAYMENT_RAIL": "paypal_sandbox", "PAYPAL_CLIENT_ID": "id", "PAYPAL_CLIENT_SECRET": "s3cr3t"})
    assert cfg.mode == "paypal_sandbox" and isinstance(rail, PayPalSandboxRail) and cfg.currency == "USD"
    assert "s3cr3t" not in repr(rail)
    rail.close()
    cfg, _ = rail_from_env({"FM_PAYMENT_RAIL": "mock", "FM_PAYMENT_CURRENCY": "usd"})
    assert cfg.currency == "USD"


# ====================================================================================== PayPal sandbox adapter
CLIENT_ID, CLIENT_SECRET = "AZsandboxClientId123", "EKsandboxSuperSecret456"
ORDER_ID, AUTH_ID, CAPTURE_ID = "5O190127TN364715T", "0VF52814937998046", "2GG279541U471931P"


class FakePayPal:
    """Reproduces PayPal REST v2 request/response shapes (token, orders create/authorize, capture, void, get)."""

    def __init__(self, fail_first: dict[str, list[int]] | None = None, vaulted: bool = False) -> None:
        self.requests: list[httpx.Request] = []
        self.fail_first = {k: list(v) for k, v in (fail_first or {}).items()}
        self.vaulted, self.tokens_issued, self.auth_status = vaulted, 0, "CREATED"

    def _maybe_fail(self, key: str):
        codes = self.fail_first.get(key)
        if codes:
            code = codes.pop(0)
            return httpx.Response(code, json={"name": "SERVICE_UNAVAILABLE" if code >= 500 else "RATE_LIMIT_REACHED",
                                              "message": "try later", "debug_id": "f00dfeed"})
        return None

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        path = req.url.path
        if path == "/v1/oauth2/token":
            assert req.headers["Authorization"] == "Basic " + base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
            assert parse_qs(req.content.decode()) == {"grant_type": ["client_credentials"]}
            self.tokens_issued += 1
            return httpx.Response(200, json={"scope": "https://uri.paypal.com/services/payments/payment",
                                             "access_token": f"A21AAtoken{self.tokens_issued}", "token_type": "Bearer",
                                             "app_id": "APP-80W284485P519543T", "expires_in": 32400, "nonce": "2026-10-10T00:00:00Z"})
        assert req.headers["Authorization"] == f"Bearer A21AAtoken{self.tokens_issued}"
        if (r := self._maybe_fail(path)) is not None:
            return r
        if path == "/v2/checkout/orders" and req.method == "POST":
            body = json.loads(req.content)
            assert body["intent"] == "AUTHORIZE"
            pu = body["purchase_units"][0]
            order = {"id": ORDER_ID, "intent": "AUTHORIZE", "status": "CREATED", "purchase_units": [{"reference_id": pu["reference_id"], "amount": pu["amount"]}],
                     "links": [{"href": f"https://api-m.sandbox.paypal.com/v2/checkout/orders/{ORDER_ID}", "rel": "self", "method": "GET"},
                               {"href": f"https://www.sandbox.paypal.com/checkoutnow?token={ORDER_ID}", "rel": "approve", "method": "GET"}]}
            if self.vaulted:
                order["status"] = "COMPLETED"
                order["purchase_units"][0]["payments"] = {"authorizations": [{"id": AUTH_ID, "status": "CREATED", "amount": pu["amount"]}]}
            return httpx.Response(201, json=order)
        if path == f"/v2/checkout/orders/{ORDER_ID}/authorize":
            return httpx.Response(201, json={"id": ORDER_ID, "status": "COMPLETED", "purchase_units": [{"reference_id": "default", "payments": {
                "authorizations": [{"id": AUTH_ID, "status": "CREATED", "amount": {"currency_code": "USD", "value": "1500.00"},
                                    "expiration_time": "2026-11-08T00:00:00Z"}]}}]})
        if path == f"/v2/payments/authorizations/{AUTH_ID}/capture":
            if self.auth_status == "VOIDED":
                return httpx.Response(422, json={"name": "UNPROCESSABLE_ENTITY", "debug_id": "abc123",
                                                 "details": [{"issue": "AUTHORIZATION_VOIDED", "description": "voided"}]})
            self.auth_status = "CAPTURED"
            return httpx.Response(201, json={"id": CAPTURE_ID, "status": "COMPLETED"})
        if path == f"/v2/payments/authorizations/{AUTH_ID}/void":
            self.auth_status = "VOIDED"
            return httpx.Response(204)
        if path == f"/v2/payments/authorizations/{AUTH_ID}" and req.method == "GET":
            return httpx.Response(200, json={"id": AUTH_ID, "status": self.auth_status})
        return httpx.Response(404, json={"name": "RESOURCE_NOT_FOUND"})


def _sandbox(fake: FakePayPal, **kw) -> tuple[PayPalSandboxRail, list[float], list[float]]:
    sleeps, now = [], [1000.0]
    rail = PayPalSandboxRail(CLIENT_ID, CLIENT_SECRET, transport=httpx.MockTransport(fake), sleep=sleeps.append,
                             clock=lambda: now[0], **kw)
    return rail, sleeps, now


def test_sandbox_authorize_capture_flow_and_token_cache():
    fake = FakePayPal()
    rail, sleeps, now = _sandbox(fake)
    auth = rail.authorize("evt_paypal0001", 150000, payee_token="acct:abcdefghijklmnop")
    assert auth == AUTH_ID and rail.get(auth) == "AUTHORIZED"
    assert rail.capture(auth) == "CAPTURED" and rail.get(auth) == "CAPTURED"
    paths = [(r.method, r.url.path) for r in fake.requests]
    assert paths == [("POST", "/v1/oauth2/token"), ("POST", "/v2/checkout/orders"), ("POST", f"/v2/checkout/orders/{ORDER_ID}/authorize"),
                     ("GET", f"/v2/payments/authorizations/{AUTH_ID}"), ("POST", f"/v2/payments/authorizations/{AUTH_ID}/capture"),
                     ("GET", f"/v2/payments/authorizations/{AUTH_ID}")]
    assert fake.tokens_issued == 1                                         # cached across calls
    create = fake.requests[1]
    assert create.headers["PayPal-Request-Id"] == "evt_paypal0001"         # idempotency = event_id
    assert fake.requests[2].headers["PayPal-Request-Id"] == "evt_paypal0001-authorize"
    assert fake.requests[4].headers["PayPal-Request-Id"] == "evt_paypal0001-capture"
    assert json.loads(fake.requests[4].content) == {"final_capture": True}
    body = json.loads(create.content)
    assert body["purchase_units"][0] == {"reference_id": "evt_paypal0001", "description": ORDER_DESCRIPTION,
                                         "amount": {"currency_code": "USD", "value": "1500.00"}}
    assert all(b"acct:" not in r.content and b"A-RAVI" not in r.content for r in fake.requests)   # no payee data sent
    assert sleeps == []

    now[0] += 32400                                                        # token expired -> a new one
    rail.void(auth)
    assert fake.tokens_issued == 2 and fake.requests[-1].headers["PayPal-Request-Id"] == "evt_paypal0001-void"


def test_sandbox_void_then_capture_is_a_business_error_and_vault_skips_authorize():
    fake = FakePayPal(vaulted=True)
    rail, _, _ = _sandbox(fake, vault_id="vault_tok_8kk")
    auth = rail.authorize("evt_paypal0002", 990000)
    assert auth == AUTH_ID and not any(r.url.path.endswith("/authorize") for r in fake.requests)
    assert json.loads(fake.requests[1].content)["payment_source"] == {"paypal": {"vault_id": "vault_tok_8kk"}}
    assert rail.void(auth) == "VOIDED"
    with pytest.raises(RailError) as e:
        rail.capture(auth)
    assert e.value.code == "AUTHORIZATION_VOIDED" and e.value.status == 422 and not e.value.retryable


def test_sandbox_retries_503_and_429_with_backoff():
    fake = FakePayPal(fail_first={"/v2/checkout/orders": [503, 429]})
    rail, sleeps, _ = _sandbox(fake, backoff_s=0.5)
    assert rail.authorize("evt_paypal0003", 150000) == AUTH_ID
    creates = [r for r in fake.requests if r.url.path == "/v2/checkout/orders"]
    assert len(creates) == 3 and {r.headers["PayPal-Request-Id"] for r in creates} == {"evt_paypal0003"}   # same id on retry
    assert sleeps == [0.5, 1.0]

    fake = FakePayPal(fail_first={"/v2/checkout/orders": [503] * 10})
    rail, sleeps, _ = _sandbox(fake, max_retries=2)
    with pytest.raises(RailError) as e:
        rail.authorize("evt_paypal0004", 150000)
    assert e.value.retryable and e.value.status == 503 and len(sleeps) == 2


def test_sandbox_401_refreshes_token_once():
    fake = FakePayPal(fail_first={"/v2/checkout/orders": [401]})
    rail, _, _ = _sandbox(fake)
    assert rail.authorize("evt_paypal0005", 150000) == AUTH_ID
    assert fake.tokens_issued == 2


def test_sandbox_transport_error_is_retried_then_retryable():
    calls = []

    def boom(req):
        calls.append(req.url.path)
        raise httpx.ConnectError("connection refused")
    sleeps = []
    rail = PayPalSandboxRail(CLIENT_ID, CLIENT_SECRET, transport=httpx.MockTransport(boom), sleep=sleeps.append, max_retries=1)
    with pytest.raises(RailError) as e:
        rail.authorize("evt_paypal0006", 150000)
    assert e.value.code == "TRANSPORT_ERROR" and e.value.retryable and len(calls) == 2


def test_no_secret_in_logs_or_errors(caplog):
    caplog.set_level(logging.DEBUG)
    fake = FakePayPal(fail_first={"/v2/checkout/orders": [503, 503, 503, 503, 503]})
    rail, _, _ = _sandbox(fake, max_retries=2)
    with pytest.raises(RailError) as e:
        rail.authorize("evt_paypal0007", 150000)
    fake2 = FakePayPal()
    rail2, _, _ = _sandbox(fake2)
    rail2.void(rail2.authorize("evt_paypal0008", 150000))
    with pytest.raises(RailError) as e2:
        rail2.capture(AUTH_ID)
    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    text_seen = caplog.text + str(e.value) + str(e2.value) + repr(rail) + repr(rail2)
    for secret in (CLIENT_SECRET, basic, "A21AAtoken"):
        assert secret not in text_seen
    assert "retry" in caplog.text                                           # retries are logged, without secrets


# ====================================================================================== worker + dispatcher (Postgres)
class FlakyRail(MockPayPalRail):
    """Mock rail that fails the first `fails` authorize calls (retryable), optionally slow, and records the lock state."""

    def __init__(self, app, fails: int = 0, delay: float = 0.0, error: Exception | None = None) -> None:
        super().__init__()
        self.app, self.fails, self.delay, self.error = app, fails, delay, error
        self.lock_held: list[bool] = []

    def authorize(self, event_id, amount_paise, currency=None, payee_token=None):
        self.lock_held.append(self.app.state.worker.engine_lock.locked())
        if self.delay:
            time.sleep(self.delay)
        if self.fails > 0:
            self.fails -= 1
            raise self.error or RailError("SERVICE_UNAVAILABLE", "HTTP 503", retryable=True, status=503)
        return super().authorize(event_id, amount_paise, currency, payee_token)


@pytest.fixture
def pay_client(client, monkeypatch):
    app = client.app
    app.state.pipeline = FakePipeline(app.state.store)
    tws.demo_state.reset()
    d = app.state.payments
    assert d.config.mode == "mock" and isinstance(d.rail, MockPayPalRail)       # the default rail
    d.config = RailConfig("mock", "INR", max_attempts=3, retry_base_s=0.01)

    def fake_feedback(store, pipeline, case_id, verdict, analyst):
        return FeedbackResult(case_id=case_id, verdict=verdict, reliability_before={}, reliability_after={}, seeds_added=[],
                              status_after=verdict if verdict != "INCONCLUSIVE" else "OPEN")
    monkeypatch.setattr("engine.api.apply_feedback", fake_feedback)
    return client


def _pay_drain(client) -> None:
    client.portal.call(client.app.state.payments.drain)


def _txn(client, outcome: str, monkeypatch, amount: int = 48000000) -> str:
    pay = {"completed": "normal", "held": "held", "blocked": "blocked"}[outcome]
    band = {"completed": "LOW", "held": "HIGH", "blocked": "CRITICAL"}[outcome]
    monkeypatch.setitem(tws.SCRIPT, "transaction", (band, 0.9, "S6_MONETIZATION", ["ALLOW"], None, pay))
    eid = tws.emit(client, "transaction", {"amount_paise": amount, "payee_account": PAYEE, "channel": "IMPS"})
    _pay_drain(client)
    return eid


def _rail_row(eid: str) -> dict:
    (row,) = q("SELECT * FROM payment_rail WHERE event_id = :e", e=eid)
    return dict(row)


@pytest.mark.parametrize(("outcome", "state", "audit"), [("completed", "CAPTURED", None), ("held", "AUTHORIZED", None),
                                                         ("blocked", "VOIDED", "PAYMENT_VOIDED")])
def test_worker_maps_outcome_to_rail(pay_client, monkeypatch, outcome, state, audit):
    eid = _txn(pay_client, outcome, monkeypatch)
    assert pay_client.get(f"/v1/demo/payment-status/{eid}").json() == {"outcome": outcome}   # §9.5 shape unchanged
    row = _rail_row(eid)
    assert row["state"] == state and row["rail"] == "mock" and row["auth_id"] and row["currency"] == "INR"
    assert row["amount_paise"] == 48000000 and row["payee_token"].startswith("acct:") and row["last_error"] is None
    assert pay_client.app.state.payments.rail.get(row["auth_id"]) == state
    actions = [r["action"] for r in q("SELECT action FROM audit_log WHERE action LIKE 'PAYMENT_%'")]
    assert actions == ([audit] if audit else [])


@pytest.mark.parametrize(("verdict", "state", "audit"), [("FALSE_POSITIVE", "CAPTURED", "PAYMENT_CAPTURED"),
                                                         ("CONFIRMED_FRAUD", "VOIDED", "PAYMENT_VOIDED")])
def test_feedback_releases_or_voids_held_payment(pay_client, monkeypatch, auth_headers, verdict, state, audit):
    held = _txn(pay_client, "held", monkeypatch)
    blocked = _txn(pay_client, "blocked", monkeypatch, amount=150000)
    case_id = _rail_row(held)["case_id"]
    assert case_id and _rail_row(blocked)["case_id"] == case_id
    r = pay_client.post(f"/v1/cases/{case_id}/feedback", json={"verdict": verdict, "note": None}, headers=auth_headers())
    assert r.status_code == 200, r.text
    _pay_drain(pay_client)
    assert _rail_row(held)["state"] == state
    assert _rail_row(blocked)["state"] == "VOIDED"                            # a blocked payment is never released
    (sched,) = q("SELECT actor, details FROM audit_log WHERE action LIKE 'PAYMENT_%_SCHEDULED'")
    assert sched["actor"] == "usr_analyst" and sched["details"]["event_ids"] == [held]
    (done,) = q("SELECT details FROM audit_log WHERE action = :a AND object_id = :e", a=audit, e=held)
    assert done["details"]["reason"] == f"verdict:{verdict}"


def test_inconclusive_feedback_keeps_the_hold(pay_client, monkeypatch, auth_headers):
    held = _txn(pay_client, "held", monkeypatch)
    pay_client.post(f"/v1/cases/{_rail_row(held)['case_id']}/feedback", json={"verdict": "INCONCLUSIVE", "note": None},
                    headers=auth_headers())
    _pay_drain(pay_client)
    assert _rail_row(held)["state"] == "AUTHORIZED"


def test_rail_failure_is_audited_retried_and_never_breaks_the_worker(pay_client, monkeypatch):
    d = pay_client.app.state.payments
    d.rail = FlakyRail(pay_client.app, fails=1)
    eid = _txn(pay_client, "blocked", monkeypatch)
    assert pay_client.get(f"/v1/demo/payment-status/{eid}").json() == {"outcome": "blocked"}
    row = _rail_row(eid)
    assert row["state"] == "VOIDED" and row["attempts"] == 1 and row["last_error"] is None     # retried and succeeded
    (err,) = q("SELECT actor, details FROM audit_log WHERE action = 'PAYMENT_RAIL_ERROR'")
    assert err["actor"] == "payments" and err["details"]["code"] == "SERVICE_UNAVAILABLE" and err["details"]["final"] is False
    assert d.rail.lock_held == [False, False]                                  # the rail never runs under engine_lock

    # a rail that keeps failing (even with a non-RailError) gives up after max_attempts; the worker keeps going
    d.rail = FlakyRail(pay_client.app, fails=99, error=RuntimeError("rail down"))
    eid2 = _txn(pay_client, "completed", monkeypatch)
    row = _rail_row(eid2)
    assert row["state"] == "CREATED" and row["attempts"] == 3 and "rail down" in row["last_error"]
    finals = q("SELECT details FROM audit_log WHERE action = 'PAYMENT_RAIL_ERROR' AND object_id = :e ORDER BY seq", e=eid2)
    assert [f["details"]["final"] for f in finals] == [False, False, True]
    eid3 = tws.emit(pay_client, "login", {"result": "success", "auth_method": "password"})
    assert eid3 in pay_client.app.state.pipeline.seen
    assert not q("SELECT 1 FROM audit_log WHERE action = 'ENGINE_ERROR'")


def test_slow_rail_does_not_slow_the_worker(pay_client, monkeypatch):
    d = pay_client.app.state.payments
    d.rail = FlakyRail(pay_client.app, delay=0.6)
    monkeypatch.setitem(tws.SCRIPT, "transaction", ("LOW", 0.1, "S6_MONETIZATION", ["ALLOW"], None, "normal"))
    t0 = time.monotonic()
    ids = [tws.emit(pay_client, "transaction", {"amount_paise": 1000 + i, "payee_account": PAYEE, "channel": "UPI"}) for i in range(3)]
    worker_s = time.monotonic() - t0
    assert all(pay_client.get(f"/v1/demo/payment-status/{e}").json() == {"outcome": "completed"} for e in ids)
    assert worker_s < 1.2, worker_s                                            # 3 rail calls alone take 1.8 s
    _pay_drain(pay_client)
    assert [_rail_row(e)["state"] for e in ids] == ["CAPTURED"] * 3


def test_rail_off_writes_nothing(pay_client, monkeypatch):
    d = pay_client.app.state.payments
    d.rail = None
    eid = _txn(pay_client, "blocked", monkeypatch)
    assert pay_client.get(f"/v1/demo/payment-status/{eid}").json() == {"outcome": "blocked"}
    assert not q("SELECT 1 FROM payment_rail")


def test_app_role_can_write_payment_rail():
    """0003 relies on 0002's default privileges (plus an explicit GRANT): the API's role reads and writes the table."""
    from sqlalchemy import text

    from api.db.session import get_engine
    with get_engine().begin() as c:
        assert c.execute(text("SELECT current_user")).scalar() == "fm_app"
        c.execute(text("INSERT INTO payment_rail (event_id, rail, target, amount_paise, currency) VALUES ('evt_grant0001', 'mock', 'CAPTURED', 1, 'INR')"))
        c.execute(text("UPDATE payment_rail SET state = 'AUTHORIZED' WHERE event_id = 'evt_grant0001'"))
        c.execute(text("DELETE FROM payment_rail WHERE event_id = 'evt_grant0001'"))


def test_mock_restored_from_table_after_restart(pay_client, monkeypatch):
    held = _txn(pay_client, "held", monkeypatch)
    d = pay_client.app.state.payments
    d.rail = MockPayPalRail()                                                  # a new process: empty mock memory
    d._restore_mock()
    assert d.rail.get(_rail_row(held)["auth_id"]) == "AUTHORIZED"


# ====================================================================================== GET /v1/cases/{id}/payments
def test_case_payments_route(pay_client, monkeypatch, auth_headers):
    held = _txn(pay_client, "held", monkeypatch)
    case_id = _rail_row(held)["case_id"]
    assert pay_client.get(f"/v1/cases/{case_id}/payments").status_code == 401
    r = pay_client.get(f"/v1/cases/{case_id}/payments", headers=auth_headers())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["case_id"] == case_id and body["rail"] == "mock"
    (item,) = body["items"]
    assert item["event_id"] == held and item["outcome"] == "held" and item["state"] == "AUTHORIZED" and item["amount_paise"] == 48000000
    assert "payee_token" not in item

    nf = pay_client.get("/v1/cases/case_doesnotexist/payments", headers=auth_headers())
    assert nf.status_code == 404 and nf.json()["error"]["code"] == "NOT_FOUND"
    from sqlalchemy import text

    from api.db.session import admin_engine
    with admin_engine().begin() as c:                                         # move the case out of the analyst's queues
        c.execute(text("UPDATE cases SET queue = 'vip' WHERE case_id = :c"), {"c": case_id})
    assert pay_client.get(f"/v1/cases/{case_id}/payments", headers=auth_headers()).status_code == 404
    assert PRIYA["customer_ref"] not in r.text and PAYEE not in r.text


def test_sandbox_rail_is_thread_safe_token_fetch():
    """Concurrent first calls fetch one token (the dispatcher is single-consumer, but the rail must not assume it)."""
    fake = FakePayPal()
    rail, _, _ = _sandbox(fake)
    threads = [threading.Thread(target=rail.get, args=(AUTH_ID,)) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert fake.tokens_issued == 1


def test_paused_rail_drops_jobs_until_resumed(pay_client, monkeypatch):
    """Demo resets (_engine_paused) pause the rail: queued jobs and retries are dropped, new ones are refused, so no
    payment_rail or PAYMENT_* audit row is written for events the reset truncates or restores."""
    d = pay_client.app.state.payments
    pay_client.portal.call(d.pause)
    assert d.queue.empty() and not d._retries
    held = _txn(pay_client, "held", monkeypatch)                       # emitted while paused: not scheduled
    assert q("SELECT 1 FROM payment_rail WHERE event_id = :e", e=held) == []
    d.resume()
    eid = _txn(pay_client, "held", monkeypatch)
    assert _rail_row(eid)["state"] == "AUTHORIZED"
