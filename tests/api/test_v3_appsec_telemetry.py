"""v3 phase 8: the bank app's behavioural telemetry reaches the engine only through the contract models, so malicious,
oversized or extra telemetry is refused (422 / 413) before anything is signed or stored."""
from __future__ import annotations

import pytest
from sqlalchemy import text

from api.db.session import get_engine
from tests.api.test_worker_stepup import drain

PRIYA = {"customer_ref": "C-1042", "account_ref": "A-88213"}
LOGIN = {"result": "success", "auth_method": "password"}
GOOD_TELEMETRY = {"pointer_type": "touch", "keystroke_interval_ms_mean": 180, "keystroke_interval_ms_std": 40,
                  "paste_in_sensitive_field": True, "payment_screen_dwell_s": 12.5, "beneficiary_screen_dwell_s": 3.0,
                  "screen_resolution_changes": 1, "remote_access_demo": True, "active_call_demo": None}
GOOD_CONTEXT = {"device_id": "fp_priya_phone", "session_id": "tab_" + "ab" * 16, "browser_timezone": "Asia/Kolkata",
                "locale": "en-IN", "platform": "Android", "webgl_renderer": "Adreno (TM) 640", "screen": "412x915",
                "telemetry": GOOD_TELEMETRY}


def _emit(client, context: dict):
    return client.post("/v1/demo/emit", json={"event_type": "login", "subject": PRIYA, "context": context, "payload": LOGIN})


def test_valid_telemetry_is_accepted_and_stored_without_raw_session_id(client):
    r = _emit(client, GOOD_CONTEXT)
    assert r.status_code == 200, r.text
    drain(client)
    with get_engine().connect() as c:
        data = c.execute(text("SELECT data FROM events WHERE event_id = :e"), {"e": r.json()["event_id"]}).scalar()
    assert data["telemetry"]["pointer_type"] == "touch" and data["telemetry"]["remote_access_demo"] is True
    assert GOOD_CONTEXT["session_id"] not in str(data)                                 # tokenized (ses:...)


BAD_TELEMETRY = [
    {"pointer_type": "<script>alert(1)</script>"},
    {"keystroke_interval_ms_mean": -1},
    {"keystroke_interval_ms_std": 1e9},
    {"payment_screen_dwell_s": 86_401},
    {"screen_resolution_changes": 1001},
    {"screen_resolution_changes": "1; DROP TABLE events"},
    {"paste_in_sensitive_field": "yes please"},
    {"keys": "hunter2"},                                   # no raw keys: unknown fields are refused
    {"clipboard": "4111 1111 1111 1111"},
    {"otp": "123456"},
]
BAD_CONTEXT = [
    {"session_id": "s" * 129},
    {"browser_timezone": "x" * 65},
    {"locale": "<img src=x onerror=alert(1)>" * 2},
    {"platform": "p" * 65},
    {"webgl_renderer": "w" * 257},
    {"screen": "9" * 33},
    {"telemetry": "not an object"},
    {"telemetry": [GOOD_TELEMETRY]},
    {"password": "hunter2"},
]


@pytest.mark.parametrize("bad", BAD_TELEMETRY)
def test_malicious_telemetry_is_422(client, bad):
    r = _emit(client, {**GOOD_CONTEXT, "telemetry": {**GOOD_TELEMETRY, **bad}})
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_FAILED", bad
    assert "hunter2" not in r.text and "4111" not in r.text                         # errors never echo values


@pytest.mark.parametrize("bad", BAD_CONTEXT)
def test_malicious_context_is_422(client, bad):
    r = _emit(client, {**GOOD_CONTEXT, **bad})
    assert r.status_code == 422, bad


def test_oversized_body_is_413(client):
    r = client.post("/v1/demo/emit", content=b'{"pad": "' + b"x" * 70_000 + b'"}', headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
