"""v3 phase 5: ingestion-time network enrichment of the raw ip (api/enrichment.py)."""
from __future__ import annotations

import json
import logging

from sqlalchemy import text

from api import enrichment
from api.db.session import get_engine
from engine.common.ids import new_id
from engine.contracts import Envelope
from scripts.sign import sign

PRIYA = {"customer_ref": "C-1042", "account_ref": "A-88213"}


def _env(context: dict) -> dict:
    return {"event_id": new_id("evt"), "event_type": "login", "source": "demo-bank-web", "schema_version": "1.1",
            "occurred_at": "2026-10-09T00:41:07+05:30", "subject": PRIYA, "context": context,
            "payload": {"result": "success", "auth_method": "password+otp"}}


def _stored(event_id: str) -> dict:
    with get_engine().connect() as c:
        return c.execute(text("SELECT data FROM events WHERE event_id = :id"), {"id": event_id}).scalar()


def test_network_for_classifies_the_raw_ip():
    assert enrichment.network_for("185.220.101.7", "AS64500 HostCo")["network_type"] == "hosting"
    assert enrichment.network_for("49.207.10.21")["network_type"] == "mobile"
    assert enrichment.network_for(None) is None
    assert enrichment.network_for("8.8.4.4")["network_type"] == "unknown"


def test_enrichment_failure_degrades_to_unknown_without_logging_the_ip(monkeypatch, caplog):
    class Broken:
        def lookup(self, ip, asn=None):
            raise RuntimeError(f"boom {ip}")
    monkeypatch.setattr(enrichment, "_intel", Broken())
    with caplog.at_level(logging.WARNING, logger="fraudmesh.enrichment"):
        out = enrichment.network_for("185.220.101.7")
    assert out["network_type"] == "unknown"
    assert "185.220.101.7" not in caplog.text and "RuntimeError" in caplog.text


def test_platform_is_derived_from_the_user_agent_only_when_missing():
    ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36"
    env, _ = enrichment.enrich(Envelope.model_validate(_env({"ip": "49.207.10.21", "user_agent": ua})))
    assert env.context.platform == "ua:Android"
    env2, _ = enrichment.enrich(Envelope.model_validate(_env({"ip": "49.207.10.21", "user_agent": ua, "platform": "Win32"})))
    assert env2.context.platform == "Win32"


def test_signed_event_is_stored_with_network_fields_and_no_raw_ip(client):
    e = _env({"ip": "185.220.101.7", "device_id": "fp_attacker_01", "asn": "AS64500 HostCo", "session_id": "sess-abc",
              "browser_timezone": "Asia/Kolkata", "platform": "Linux x86_64"})
    body = json.dumps(e).encode()
    r = client.post("/v1/events", content=body, headers=sign("demo-bank-web", body))
    assert r.status_code == 202, r.text
    data = _stored(e["event_id"])
    assert data["network_type"] == "hosting" and data["network_source"] == "demo_list"
    assert data["ip_timezone"] == "Europe/Berlin" and data["session"].startswith("ses:")
    raw = json.dumps(data)
    assert "185.220.101.7" not in raw and "sess-abc" not in raw


def test_bank_app_emit_passes_the_new_context_fields_through(client):
    r = client.post("/v1/demo/emit", json={"event_type": "login", "subject": PRIYA,
                                           "context": {"device_id": "fp_priya_phone", "session_id": "s-1"},
                                           "payload": {"result": "success", "auth_method": "password+push"}})
    assert r.status_code == 200, r.text
    data = _stored(r.json()["event_id"])
    assert data["network_type"] == "mobile" and data["platform"] == "Android" and data["session"].startswith("ses:")
