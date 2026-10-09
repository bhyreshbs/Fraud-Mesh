"""The Midnight ATO story end to end through the real API routes, with the FM_DEV_PIPELINE stand-in as the engine:
IDS alert (signed ingest) -> attacker login -> SMS number swap -> OTP read from the attacker's inbox -> deepfake KYC
-> support-console limit raise (signed ingest) -> mule-linked payee -> ₹4,80,000 transfer blocked -> Priya taps "Not me".
P values must follow the PRD §12.4 golden table; this also exercises every bank-app/phone route the UI uses."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from api.demo_identities import demo_state
from api.dev_pipeline import ScriptedPipeline
from engine.common.ids import new_id
from scripts.seed_demo_factors import seed_demo_factors
from scripts.sign import sign
from tests.api.test_worker_stepup import drain

IST = timezone(timedelta(hours=5, minutes=30))
PRIYA = {"customer_ref": "C-1042", "account_ref": "A-88213"}
ATTACKER = {"device_id": "fp_attacker_01"}
GOLDEN_P = [0.017, 0.045, 0.222, 0.403, 0.671, 0.809, 0.966, 0.997]


@pytest.fixture
def flow(client):
    client.app.state.pipeline = ScriptedPipeline(client.app.state.store)
    client.app.state.pipeline.startup()
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


def test_midnight_ato_through_the_ui_routes(flow, auth_headers):
    h = auth_headers("analyst")
    trail: list[tuple[str, float]] = []

    def snap():
        (item,) = flow.get("/v1/cases", headers=h).json()["items"]
        trail.append((item["band"], round(item["p_attack"], 3)))
        return item

    signed_post(flow, "network-ids", "network_ids_alert", {"src_ip": "185.220.101.7", "dest_ip": "10.0.1.20", "dest_port": 443,
                "signature_id": 9000001, "signature": "FM LOCAL credential stuffing against /api/login",
                "category": "Attempted User Privilege Gain", "severity": 2})
    assert snap()["customer"] is None                                    # IDS case is anchored on the IP for now
    emit(flow, "login", {"result": "success", "auth_method": "password+otp"})
    assert snap()["customer"] is not None                                # same /24 -> joined and re-anchored to Priya
    emit(flow, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": "+91 90000 11111"})
    snap()

    # MEDIUM -> sms_otp to the swapped number: the bank app sees it pending, the attacker's phone has the code
    pend = flow.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042", "channel": "app"}).json()["challenge"]
    assert pend["method"] == "sms_otp" and pend["masked_destination"].endswith("1111")
    text = flow.get("/v1/demo/sms-inbox", params={"phone": "+919000011111"}).json()["messages"][-1]["text"]
    code = re.search(r"\b\d{6}\b", text).group(0)
    assert flow.post(f"/v1/demo/step-up/{pend['challenge_id']}/respond", json={"code": code}).json() == {"status": "passed"}
    drain(flow)
    snap()

    emit(flow, "kyc_result", {"liveness_score": 0.38, "face_match_score": 0.81, "doc_tamper_score": 0.12,
                              "injection_suspected": False, "reason": "re_verification"})
    item = snap()
    assert item["payment_state"] == "held" and "HOLD_OUTBOUND_PAYMENTS" in item["latest_actions"]
    push = flow.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042", "channel": "phone"}).json()["challenge"]
    assert push["method"] == "device_push"                               # HIGH -> push to Priya's registered phone

    signed_post(flow, "cloud-audit", "cloud_audit", {"actor_type": "support_console", "actor_identity": "svc-support-07",
                "action": "UpdateTransferLimit", "target_customer": "C-1042", "src_ip": "185.220.101.7", "result": "success"})
    snap()
    emit(flow, "payee_added", {"payee_account": "A-RAVI-778", "payee_name_match": True, "nickname": "Rent - Ravi"})
    snap()
    txn = emit(flow, "transaction", {"amount_paise": 48000000, "payee_account": "A-RAVI-778", "channel": "IMPS"})
    item = snap()
    assert flow.get(f"/v1/demo/payment-status/{txn}").json() == {"outcome": "blocked"}

    assert [b for b, _ in trail] == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "CRITICAL", "CRITICAL", "CRITICAL"]
    assert [p for _, p in trail] == pytest.approx(GOLDEN_P, abs=0.002)

    # Priya taps "Not me": CRITICAL via floor, INVESTIGATING, P unchanged
    assert flow.post(f"/v1/demo/step-up/{push['challenge_id']}/respond", json={"decision": "deny"}).json() == {"status": "denied_by_customer"}
    drain(flow)
    case = flow.get(f"/v1/cases/{item['case_id']}", headers=h).json()["case"]
    assert case["status"] == "INVESTIGATING" and "floor_CUSTOMER_DENIED" in case["floors"]
    assert case["p_attack"] == pytest.approx(0.997, abs=0.002) and case["band"] == "CRITICAL"
    assert case["pattern_hits"] == ["pat_ATO1", "pat_CASE_IP_CLOUD"]
    assert set(case["stages"]) == {"S0_RECON", "S1_INITIAL_ACCESS", "S2_CONTROL_TAKEOVER", "S3_IDENTITY_MANIPULATION",
                                   "S4_ESCALATION", "S5_POSITIONING", "S6_MONETIZATION"}

    tl = flow.get(f"/v1/cases/{item['case_id']}/timeline", headers=h).json()
    assert len(tl["evidence"]) == 9 and {c["status"] for c in tl["challenges"]} == {"passed", "denied_by_customer"}
    ex = flow.get(f"/v1/cases/{item['case_id']}/explanation", headers=h).json()
    assert abs(ex["parts"][-1]["running_log_odds"] - case["log_odds"]) < 1e-6
    g = flow.get(f"/v1/cases/{item['case_id']}/graph", headers=h).json()
    assert any(n["seed"] for n in g["nodes"]) and g["edges"]
