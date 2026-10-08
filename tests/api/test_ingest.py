"""D1-P1 done-when: signed 202, tampered 401 SIGNATURE_INVALID, repeated 409, no raw PII in events.data."""
from __future__ import annotations

import json
import time

from sqlalchemy import text

from api.db.session import get_engine
from engine.common.ids import new_id
from scripts.sign import sign

PRIYA = {"customer_ref": "C-1042", "account_ref": "A-88213"}
ATTACKER_CTX = {"ip": "185.220.101.7", "device_id": "fp_attacker_01", "asn": "AS64500 HostCo", "user_agent": "Mozilla/5.0 test"}


def env(event_type: str, payload: dict, source: str = "demo-bank-web", subject=PRIYA, context=ATTACKER_CTX, **kw) -> dict:
    return {"event_id": kw.get("event_id") or new_id("evt"), "event_type": event_type, "source": source,
            "occurred_at": "2026-10-09T00:41:07+05:30", "subject": subject or {}, "context": context or {}, "payload": payload}


def post(client, envelope: dict, source: str | None = None, body: bytes | None = None, ts: int | None = None):
    raw = body if body is not None else json.dumps(envelope).encode()
    headers = sign(source or envelope["source"], json.dumps(envelope).encode() if body is not None else raw, ts)
    return client.post("/v1/events", content=raw, headers=headers)


LOGIN = env("login", {"result": "success", "auth_method": "password+otp"})


def test_signed_event_is_accepted(client):
    r = post(client, LOGIN)
    assert r.status_code == 202, r.text
    assert r.json() == {"event_id": LOGIN["event_id"], "status": "accepted"}
    with get_engine().connect() as c:
        row = c.execute(text("SELECT event_type, source, customer FROM events WHERE event_id = :id"), {"id": LOGIN["event_id"]}).one()
    assert row.event_type == "login" and row.source == "demo-bank-web" and row.customer.startswith("cust:")


def test_tampered_body_is_rejected(client):
    e = env("login", {"result": "success", "auth_method": "password"})
    tampered = json.dumps({**e, "payload": {"result": "failure", "auth_method": "password"}}).encode()
    r = post(client, e, body=tampered)
    assert r.status_code == 401
    err = r.json()["error"]
    assert err["code"] == "SIGNATURE_INVALID" and err["request_id"].startswith("req_")


def test_repeated_event_id_is_409(client):
    e = env("login", {"result": "success", "auth_method": "password"})
    assert post(client, e).status_code == 202
    r = post(client, e)
    assert r.status_code == 409 and r.json()["error"]["code"] == "DUPLICATE_EVENT"


def test_stale_timestamp(client):
    e = env("login", {"result": "success", "auth_method": "password"})
    r = post(client, e, ts=int(time.time()) - 301)
    assert r.status_code == 401 and r.json()["error"]["code"] == "STALE_TIMESTAMP"


def test_missing_headers_and_unknown_source(client):
    r = client.post("/v1/events", content=json.dumps(LOGIN).encode())
    assert r.status_code == 401 and r.json()["error"]["code"] == "SIGNATURE_INVALID"


def test_header_source_must_match_envelope(client):
    e = env("login", {"result": "success", "auth_method": "password"})
    r = post(client, e, source="simulator")
    assert r.status_code == 401 and r.json()["error"]["code"] == "SIGNATURE_INVALID"


def test_validation_failures_are_422(client):
    naive = {**env("login", {"result": "success", "auth_method": "password"}), "occurred_at": "2026-10-09T00:41:07"}
    r = post(client, naive)
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_FAILED"
    bad_payload = env("transaction", {"amount_paise": -5, "payee_account": "A-1", "channel": "IMPS"})
    assert post(client, bad_payload).status_code == 422
    bad_id = env("login", {"result": "success", "auth_method": "password"}, event_id="evt_x")
    assert post(client, bad_id).status_code == 422


def test_payload_too_large(client):
    e = env("payee_added", {"payee_account": "A-RAVI-778", "nickname": "x" * 70_000})
    r = post(client, e)
    assert r.status_code == 413 and r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_batch_accepts_and_rejects(client):
    good = env("login", {"result": "success", "auth_method": "password"})
    dup = dict(good)
    invalid = env("login", {"result": "maybe", "auth_method": "password"})
    body = json.dumps({"events": [good, dup, invalid]}).encode()
    r = client.post("/v1/events/batch", content=body, headers=sign("demo-bank-web", body))
    assert r.status_code == 202, r.text
    out = r.json()
    assert out["accepted"] == 1
    assert {(x["event_id"], x["code"]) for x in out["rejected"]} == {(good["event_id"], "DUPLICATE_EVENT"),
                                                                     (invalid["event_id"], "VALIDATION_FAILED")}


RAW_VALUES = ["C-1042", "A-88213", "185.220.101.7", "185.220.101", "fp_attacker_01", "A-RAVI-778",
              "90000 11111", "9000011111", "svc-support-07", "Mozilla/5.0"]


def test_no_raw_pii_is_stored(client):
    events = [
        LOGIN | {"event_id": new_id("evt")},
        env("mfa_change", {"factor": "sms", "action": "replace", "new_phone": "+91 90000 11111"}),
        env("payee_added", {"payee_account": "A-RAVI-778", "payee_name_match": True, "nickname": "Rent - Ravi"}),
        env("transaction", {"amount_paise": 48000000, "payee_account": "A-RAVI-778", "channel": "IMPS"}),
        env("cloud_audit", {"actor_type": "support_console", "actor_identity": "svc-support-07", "action": "UpdateTransferLimit",
                            "target_customer": "C-1042", "src_ip": "185.220.101.7", "result": "success"},
            source="cloud-audit", subject=None, context=None),
        env("network_ids_alert", {"src_ip": "185.220.101.7", "dest_ip": "10.0.1.20", "dest_port": 443, "signature_id": 9000001,
                                  "signature": "FM LOCAL credential stuffing", "category": "Attempted User Privilege Gain",
                                  "severity": 2}, source="network-ids", subject=None, context=None),
        env("kyc_result", {"liveness_score": 0.38, "face_match_score": 0.81, "doc_tamper_score": 0.12,
                           "injection_suspected": False, "reason": "re_verification"}),
    ]
    for e in events:
        assert post(client, e).status_code == 202
    with get_engine().connect() as c:
        dump = " ".join(c.execute(text("SELECT data::text || array_to_string(entity_tokens, ' ') || coalesce(customer,'') "
                                       "FROM events")).scalars().all())
    for raw in RAW_VALUES:
        assert raw not in dump, f"raw value {raw!r} leaked into events"
    assert "10.0.1.20" in dump                     # dest_ip is the bank's own server and is not tokenized (PRD §5)
