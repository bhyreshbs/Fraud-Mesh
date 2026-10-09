"""The Midnight ATO story end to end through the bank-app / phone / ingest routes the UI uses, on the real engine:
IDS alert (signed ingest) -> attacker login -> SMS number swap -> deepfake KYC -> support-console limit raise (signed
ingest) -> mule-linked payee -> OTP read from the attacker's inbox -> ₹4,80,000 transfer blocked -> Priya taps "Not me".

Real detectors (engine.pipeline.Pipeline) on an empty history plus the midnight_ato preload (mule seeds), so P values are
not the PRD §12.4 golden table: this asserts the behaviour (step-up to the swapped number, push to the registered phone,
hold before the transfer, transfer blocked, "Not me" floor), not exact numbers."""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from api import loader
from api.demo_identities import demo_state
from engine.common.ids import new_id
from engine.pipeline import Pipeline
from scripts.seed_demo_factors import seed_demo_factors
from scripts.sign import sign
from tests.api.test_worker_stepup import drain

IST = timezone(timedelta(hours=5, minutes=30))
PRIYA = {"customer_ref": "C-1042", "account_ref": "A-88213"}
ATTACKER = {"device_id": "fp_attacker_01"}


@pytest.fixture
def flow(client):
    store = client.app.state.store
    client.app.state.pipeline = Pipeline(store)
    client.app.state.pipeline.startup()
    loader.load_preload("midnight_ato", datetime.now(UTC), store, client.app.state.pipeline)   # mule seeds for the graph detector
    demo_state.reset()
    seed_demo_factors()
    return client


def signed_post(client, source: str, event_type: str, payload: dict) -> None:
    env = {"event_id": new_id("evt"), "event_type": event_type, "source": source, "occurred_at": datetime.now(IST).isoformat(),
           "payload": payload}
    body = json.dumps(env).encode()
    assert client.post("/v1/events", content=body, headers=sign(source, body)).status_code == 202
    drain(client)


def emit(client, event_type: str, payload: dict, context=ATTACKER) -> str:
    r = client.post("/v1/demo/emit", json={"event_type": event_type, "subject": PRIYA, "context": context, "payload": payload})
    assert r.status_code == 200, r.text
    drain(client)
    return r.json()["event_id"]


def pending(client, channel: str):
    return client.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042", "channel": channel}).json()["challenge"]


def test_midnight_ato_through_the_ui_routes(flow, auth_headers):
    h = auth_headers("analyst")
    trail: list[dict] = []

    def step():
        (item,) = flow.get("/v1/cases", headers=h).json()["items"]
        trail.append(item)
        return item

    signed_post(flow, "network-ids", "network_ids_alert", {"src_ip": "185.220.101.7", "dest_ip": "10.0.1.20", "dest_port": 443,
                "signature_id": 9000001, "signature": "FM LOCAL credential stuffing against /api/login",
                "category": "Attempted User Privilege Gain", "severity": 2})
    assert step()["customer"] is None                                    # IDS case is anchored on the IP for now
    emit(flow, "login", {"result": "success", "auth_method": "password+otp"})
    step()
    emit(flow, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": "+91 90000 11111"})
    assert step()["customer"] is not None                                # joined and re-anchored to Priya
    emit(flow, "kyc_result", {"liveness_score": 0.38, "face_match_score": 0.81, "doc_tamper_score": 0.12,
                              "injection_suspected": False, "reason": "re_verification"})
    step()
    signed_post(flow, "cloud-audit", "cloud_audit", {"actor_type": "support_console", "actor_identity": "svc-support-07",
                "action": "UpdateTransferLimit", "target_customer": "C-1042", "src_ip": "185.220.101.7", "result": "success"})
    step()
    emit(flow, "payee_added", {"payee_account": "A-RAVI-778", "payee_name_match": True, "nickname": "Rent - Ravi"})
    before_txn = step()
    bands = [(t["band"], round(t["p_attack"], 3), t["latest_actions"]) for t in trail]

    # MEDIUM -> sms_otp to the swapped number: the bank app sees it pending, the attacker's phone has the code
    pend = pending(flow, "app")
    assert pend and pend["method"] == "sms_otp" and pend["masked_destination"].endswith("1111"), bands
    text = flow.get("/v1/demo/sms-inbox", params={"phone": "+919000011111"}).json()["messages"][-1]["text"]
    code = re.search(r"\b\d{6}\b", text).group(0)
    assert flow.post(f"/v1/demo/step-up/{pend['challenge_id']}/respond", json={"code": code}).json() == {"status": "passed"}
    drain(flow)
    # HIGH -> payments held before the money moves, and a push to Priya's registered phone
    assert before_txn["payment_state"] == "held" and "HOLD_OUTBOUND_PAYMENTS" in before_txn["latest_actions"], bands
    push = pending(flow, "phone")
    assert push and push["method"] == "device_push", bands

    txn = emit(flow, "transaction", {"amount_paise": 48000000, "payee_account": "A-RAVI-778", "channel": "IMPS"})
    item = step()
    assert item["band"] == "CRITICAL" and flow.get(f"/v1/demo/payment-status/{txn}").json() == {"outcome": "blocked"}

    # Priya taps "Not me": CRITICAL via floor, INVESTIGATING
    assert flow.post(f"/v1/demo/step-up/{push['challenge_id']}/respond", json={"decision": "deny"}).json() == {"status": "denied_by_customer"}
    drain(flow)
    case = flow.get(f"/v1/cases/{item['case_id']}", headers=h).json()["case"]
    assert case["status"] == "INVESTIGATING" and "floor_CUSTOMER_DENIED" in case["floors"] and case["band"] == "CRITICAL"
    assert {"S0_RECON", "S3_IDENTITY_MANIPULATION", "S5_POSITIONING", "S6_MONETIZATION"} <= set(case["stages"])

    tl = flow.get(f"/v1/cases/{item['case_id']}/timeline", headers=h).json()
    assert {c["status"] for c in tl["challenges"]} == {"passed", "denied_by_customer"}
    assert any(e["detector"] == "auth" and e["reasons"][0]["code"] == "CUSTOMER_DENIED" for e in tl["evidence"])
    ex = flow.get(f"/v1/cases/{item['case_id']}/explanation", headers=h).json()
    assert abs(ex["parts"][-1]["running_log_odds"] - case["log_odds"]) < 1e-6
    g = flow.get(f"/v1/cases/{item['case_id']}/graph", headers=h).json()
    assert any(n["seed"] for n in g["nodes"]) and g["edges"]
