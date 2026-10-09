"""Tokenization rules the engine relies on (PRD §4 entity tokens, §7.3). engine/common/tokenize.py is BOTH-FROZEN;
these tests pin its behaviour so a drift on either side fails CI."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import Envelope

TOKEN = re.compile(r"^(cust|acct|dev|ip|phone|email|cid|res|mer):[a-z2-7]{16}$")
AT = datetime(2026, 10, 9, 0, 41, tzinfo=timezone(timedelta(hours=5, minutes=30)))


def envelope(event_type: str, payload: dict, **kw) -> Envelope:
    return Envelope(event_id="evt_tok00000001", event_type=event_type, source="demo-bank-web", occurred_at=AT,
                    subject=kw.get("subject", {}), context=kw.get("context", {}), payload=payload)


@pytest.mark.parametrize("kind,a,b", [
    ("cust", " c-1042 ", "C-1042"), ("acct", "a-ravi 778", "A-RAVI778"),
    ("acct", "A-RAVI-778 ", "a-ravi-778"), ("dev", " fp_priya_phone", "fp_priya_phone"),
    ("ip", "185.220.101.7", "185.220.101.254"), ("ip", "2409:4072:8e00:1::1", "2409:4072:8e00:1:ffff::9"),
    ("phone", "+91 90000 11111", "9000011111"), ("email", " Priya@Example.com", "priya@example.com"),
    ("cid", "svc-support-07 ", "svc-support-07"),
])
def test_normalisation_makes_equal_tokens(kind, a, b):
    assert tok(kind, a) == tok(kind, b)
    assert TOKEN.match(tok(kind, a))


@pytest.mark.parametrize("kind,a,b", [
    ("ip", "185.220.101.7", "185.220.102.7"), ("dev", "fp_priya_phone", "FP_PRIYA_PHONE"),
    ("cid", "svc-support-07", "SVC-SUPPORT-07")])
def test_different_values_make_different_tokens(kind, a, b):
    assert tok(kind, a) != tok(kind, b)


def test_kind_is_part_of_the_token():
    assert tok("cust", "X-1").split(":")[1] != tok("acct", "X-1").split(":")[1]


def test_payee_and_customer_accounts_share_the_acct_kind():
    login = to_stored_event(envelope("login", {"result": "success", "auth_method": "password"},
                                     subject={"customer_ref": "C-RAVI-01", "account_ref": "A-RAVI-778"}), AT)
    payee = to_stored_event(envelope("payee_added", {"payee_account": "A-RAVI-778", "nickname": "Rent - Ravi"},
                                     subject={"customer_ref": "C-1042", "account_ref": "A-88213"}), AT)
    assert login.account == payee.payload["payee_account"]


def test_stored_event_tokens_and_untokenized_fields():
    ev = to_stored_event(envelope(
        "login", {"result": "success", "auth_method": "password+otp"},
        subject={"customer_ref": "C-1042", "account_ref": "A-88213"},
        context={"ip": "185.220.101.7", "device_id": "fp_attacker_01", "asn": "AS64500 HostCo", "city": "Bengaluru",
                 "lat": 12.97, "lon": 77.59, "user_agent": "Mozilla/5.0"}), AT)
    assert ev.customer == tok("cust", "C-1042") and ev.account == tok("acct", "A-88213")
    assert ev.ip == tok("ip", "185.220.101.7") and ev.device == tok("dev", "fp_attacker_01")
    assert (ev.asn, ev.city, ev.lat, ev.lon) == ("AS64500 HostCo", "Bengaluru", 12.97, 77.59)
    assert ev.entity_tokens == sorted({ev.customer, ev.account, ev.ip, ev.device})
    assert "Mozilla" not in ev.model_dump_json()                                 # user_agent is dropped
    assert ev.occurred_at.utcoffset() == timedelta(0)


def test_payload_fields_tokenized_per_contract():
    cloud = to_stored_event(envelope("cloud_audit", {
        "actor_type": "support_console", "actor_identity": "svc-support-07", "action": "UpdateTransferLimit",
        "target_customer": "C-1042", "src_ip": "185.220.101.7", "result": "success"}), AT)
    assert cloud.payload["actor_identity"] == tok("cid", "svc-support-07")
    assert cloud.payload["target_customer"] == tok("cust", "C-1042")
    assert cloud.payload["src_ip"] == tok("ip", "185.220.101.7")
    assert cloud.payload["action"] == "UpdateTransferLimit"
    mfa = to_stored_event(envelope("mfa_change", {"factor": "sms", "action": "replace", "new_phone": "+91 90000 11111"}), AT)
    assert mfa.payload["new_phone"] == tok("phone", "9000011111")
    ids = to_stored_event(envelope("network_ids_alert", {
        "src_ip": "185.220.101.7", "dest_ip": "10.0.1.20", "dest_port": 443, "signature_id": 9000001,
        "signature": "FM LOCAL credential stuffing", "category": "Attempted User Privilege Gain", "severity": 2}), AT)
    assert ids.payload["src_ip"] == tok("ip", "185.220.101.7")
    assert ids.payload["dest_ip"] == "10.0.1.20" and ids.payload["signature"] == "FM LOCAL credential stuffing"
    payee = to_stored_event(envelope("payee_added", {"payee_account": "A-RAVI-778", "nickname": "Rent - Ravi"}), AT)
    assert payee.payload["nickname"] == "Rent - Ravi"


def test_naive_datetimes_are_rejected():
    with pytest.raises(ValueError):
        Envelope(event_id="evt_tok00000002", event_type="login", source="simulator", occurred_at=datetime(2026, 10, 9),
                 payload={"result": "success", "auth_method": "password"})
