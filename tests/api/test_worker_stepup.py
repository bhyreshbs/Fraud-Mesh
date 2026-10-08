"""D1-P2: worker loop + §6.4 side effects, step-up challenges, demo routes, WebSocket broadcast.

A scripted FakePipeline stands in for Dev 2's engine (the Phase 0 stub returns nothing), so the API side can be
tested end to end: mfa_change -> MEDIUM + step_up any, kyc_result -> HIGH + step_up trusted + held,
transaction -> CRITICAL + blocked, profile_change -> engine exception.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from api.db.session import get_engine
from api.demo_identities import demo_state
from engine.common.ids import new_id
from engine.common.tokenize import tok
from engine.contracts import Case, CaseUpdate, Decision, Evidence, Reason, StageHit, StepUpRequest, summarize

PRIYA = {"customer_ref": "C-1042", "account_ref": "A-88213"}
ATTACKER = {"device_id": "fp_attacker_01"}
NEW_PHONE = "+91 90000 11111"

SCRIPT = {  # event_type -> (band, p, stage, actions, step_up method_class, payment_state)
    "login": ("LOW", 0.05, "S1_INITIAL_ACCESS", ["ALLOW"], None, "normal"),
    "mfa_change": ("MEDIUM", 0.22, "S2_CONTROL_TAKEOVER", ["STEP_UP_ANY_FACTOR"], "any", "normal"),
    "kyc_result": ("HIGH", 0.67, "S3_IDENTITY_MANIPULATION", ["HOLD_OUTBOUND_PAYMENTS", "STEP_UP_TRUSTED_FACTOR", "OPEN_CASE_P2"], "trusted", "held"),
    "transaction": ("CRITICAL", 0.997, "S6_MONETIZATION", ["BLOCK_PENDING_PAYMENTS", "FREEZE_NEW_PAYEES", "REVOKE_SESSIONS", "OPEN_CASE_P1"], None, "blocked"),
}


class FakePipeline:
    def __init__(self, store) -> None:
        self.store, self.case_by_customer, self.seen = store, {}, []

    @property
    def ready(self) -> bool:
        return True

    def startup(self) -> None:
        pass

    def graph_elements(self, case_id, hops=2, max_nodes=300):
        from engine.contracts import GraphElements
        return GraphElements(nodes=[], edges=[])

    def process(self, ev):
        self.seen.append(ev.event_id)
        if ev.event_type == "profile_change":
            raise RuntimeError("scripted engine failure")
        if ev.event_type not in SCRIPT or not ev.customer:
            return []
        band, p, stage, actions, step, pay = SCRIPT[ev.event_type]
        with self.store.transaction():
            case = self.case_by_customer.get(ev.customer)
            if case is None:
                case = Case(case_id=new_id("case"), anchor_entity=ev.customer, customer=ev.customer,
                            opened_at=ev.occurred_at, updated_at=ev.occurred_at, last_event_ts=ev.occurred_at)
            evd = Evidence(evidence_id=new_id("ev"), event_id=ev.event_id, detector="auth", detector_version="fake",
                           family="device", stage=stage, p=p, reliability=0.7, entities=ev.entity_tokens,
                           reasons=[Reason(code="FAKE")], ts=ev.occurred_at,
                           amount_paise=ev.payload.get("amount_paise") if ev.event_type == "transaction" else None)
            stages = dict(case.stages)
            stages.setdefault(stage, StageHit(ts=ev.occurred_at, evidence_id=evd.evidence_id))
            case = case.model_copy(update={"band": band, "p_attack": p, "stages": stages, "latest_actions": actions,
                                           "payment_state": pay, "entities": sorted(set(case.entities) | set(ev.entity_tokens)),
                                           "updated_at": ev.occurred_at, "last_event_ts": ev.occurred_at})
            self.store.save_case(case)
            self.store.save_evidence(evd, case.case_id)
            dec = Decision(decision_id=new_id("dec"), case_id=case.case_id, trigger_event_id=ev.event_id,
                           trigger_evidence_id=evd.evidence_id, band=band, p_attack=p, policy_rule=band.lower(),
                           actions=actions, created_at=ev.occurred_at)
            self.store.save_decision(dec)
            self.case_by_customer[ev.customer] = case
        upd = CaseUpdate(case=summarize(case), event_id=ev.event_id, new_evidence_ids=[evd.evidence_id], decision_id=dec.decision_id,
                         step_up=StepUpRequest(case_id=case.case_id, customer=ev.customer, method_class=step, reason_event_id=ev.event_id) if step else None,
                         payment_outcome={"blocked": "blocked", "held": "held"}.get(pay, "completed") if ev.event_type == "transaction" else None)
        return [upd]


@pytest.fixture
def app_client(client):
    """The TestClient with the FakePipeline swapped in, Priya's two factors seeded 90 days ago, demo memory cleared."""
    app = client.app
    app.state.pipeline = FakePipeline(app.state.store)
    demo_state.reset()
    enrolled = datetime.now(UTC) - timedelta(days=90)
    with get_engine().begin() as c:
        c.execute(text("INSERT INTO mfa_factors (factor_id, customer, kind, enrolled_at, phone_token) VALUES ('fac_sms', :cu, 'sms', :t, :p)"),
                  {"cu": tok("cust", "C-1042"), "t": enrolled, "p": tok("phone", "+91 98450 00000")})
        c.execute(text("INSERT INTO mfa_factors (factor_id, customer, kind, enrolled_at, device_token) VALUES ('fac_push', :cu, 'device_push', :t, :d)"),
                  {"cu": tok("cust", "C-1042"), "t": enrolled, "d": tok("dev", "fp_priya_phone")})
    return client


def drain(client) -> None:
    client.portal.call(client.app.state.worker.drain)


def emit(client, event_type: str, payload: dict, context=ATTACKER, subject=PRIYA) -> str:
    r = client.post("/v1/demo/emit", json={"event_type": event_type, "subject": subject, "context": context, "payload": payload})
    assert r.status_code == 200, r.text
    drain(client)
    return r.json()["event_id"]


def q(sql: str, **params):
    with get_engine().connect() as c:
        return c.execute(text(sql), params).mappings().all()


# ------------------------------------------------------------------ emit + worker
def test_emit_fills_demo_context_and_tokenizes(app_client):
    eid = emit(app_client, "login", {"result": "success", "auth_method": "password+otp"})
    (row,) = q("SELECT data FROM events WHERE event_id = :e", e=eid)
    d = row["data"]
    assert d["asn"] == "AS64500 HostCo" and d["ip"].startswith("ip:") and d["device"] == tok("dev", "fp_attacker_01")
    assert d["customer"] == tok("cust", "C-1042") and d["source"] == "demo-bank-web"
    assert eid in app_client.app.state.pipeline.seen


def test_emit_rejects_api_only_event_types(app_client):
    r = app_client.post("/v1/demo/emit", json={"event_type": "step_up_result", "subject": PRIYA, "context": {},
                                               "payload": {"challenge_id": "chl_x", "method": "sms_otp", "result": "passed", "factor_age_h": 999}})
    assert r.status_code == 403
    r = app_client.post("/v1/demo/emit", json={"event_type": "login", "subject": PRIYA, "context": {}, "payload": {"result": "??"}})
    assert r.status_code == 422


def test_transaction_without_update_is_completed(app_client):
    emit(app_client, "login", {"result": "success", "auth_method": "password"})        # LOW case, no step-up
    app_client.app.state.pipeline.case_by_customer.clear()
    other = {"customer_ref": "C-0093", "account_ref": "A-0093"}
    eid = emit(app_client, "payee_added", {"payee_account": "A-RAVI-778"}, subject=other)  # not scripted -> []
    assert app_client.get(f"/v1/demo/payment-status/{eid}").json() == {"outcome": "pending"}    # not a transaction
    app_client.app.state.pipeline = type("Stub", (), {"process": lambda self, ev: [], "ready": True,
                                                      "startup": lambda self: None})()
    eid = emit(app_client, "transaction", {"amount_paise": 150000, "payee_account": "A-RAVI-778", "channel": "UPI"}, subject=other)
    assert app_client.get(f"/v1/demo/payment-status/{eid}").json() == {"outcome": "completed"}


def test_engine_error_is_audited_and_worker_continues(app_client):
    emit(app_client, "profile_change", {"field": "email"})
    assert q("SELECT action FROM audit_log WHERE action = 'ENGINE_ERROR'")
    eid = emit(app_client, "login", {"result": "success", "auth_method": "password"})
    assert eid in app_client.app.state.pipeline.seen


# ------------------------------------------------------------------ step-up any (sms_otp) — the Midnight ATO KYC step
def test_mfa_change_updates_factor_and_otp_reaches_attacker_phone(app_client):
    emit(app_client, "login", {"result": "success", "auth_method": "password+otp"})
    emit(app_client, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": NEW_PHONE})
    (f,) = q("SELECT phone_token, changed_at FROM mfa_factors WHERE factor_id = 'fac_sms'")
    assert f["phone_token"] == tok("phone", NEW_PHONE) and f["changed_at"] is not None

    pend = app_client.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042", "channel": "app"}).json()["challenge"]
    assert pend["method"] == "sms_otp" and pend["masked_destination"].endswith("1111")
    assert app_client.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042", "channel": "phone"}).json()["challenge"] is None
    inbox = app_client.get("/v1/demo/sms-inbox", params={"phone": "+919000011111"}).json()["messages"]
    assert len(inbox) == 1
    code = next(w for w in inbox[0]["text"].split() if w.isdigit() and len(w) == 6)

    # the code is never stored in clear
    (ch,) = q("SELECT otp_hash, status FROM step_up_challenges WHERE challenge_id = :c", c=pend["challenge_id"])
    assert ch["status"] == "pending" and code not in ch["otp_hash"]

    r = app_client.post(f"/v1/demo/step-up/{pend['challenge_id']}/respond", json={"code": code})
    assert r.json() == {"status": "passed"}
    drain(app_client)
    (res,) = q("SELECT data FROM events WHERE event_type = 'step_up_result'")
    p = res["data"]["payload"]
    assert p == {"challenge_id": pend["challenge_id"], "method": "sms_otp", "result": "passed", "factor_age_h": p["factor_age_h"]}
    assert p["factor_age_h"] < 0.1                                # the factor was changed seconds ago -> fresh factor
    assert res["data"]["device"] == tok("dev", "fp_attacker_01")  # answered from the attacker's app session
    # responding again does not emit a second event
    assert app_client.post(f"/v1/demo/step-up/{pend['challenge_id']}/respond", json={"code": code}).json() == {"status": "passed"}
    assert len(q("SELECT 1 FROM events WHERE event_type = 'step_up_result'")) == 1


def test_three_wrong_codes_fail_the_challenge(app_client):
    emit(app_client, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": NEW_PHONE})
    cid = app_client.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042"}).json()["challenge"]["challenge_id"]
    statuses = [app_client.post(f"/v1/demo/step-up/{cid}/respond", json={"code": "000000"}).json()["status"] for _ in range(3)]
    if statuses[0] == "passed":                                   # 1-in-a-million: the random code was 000000
        return
    assert statuses == ["pending", "pending", "failed"]
    drain(app_client)
    (res,) = q("SELECT data FROM events WHERE event_type = 'step_up_result'")
    assert res["data"]["payload"]["result"] == "failed"


def test_only_one_pending_sms_challenge(app_client):
    emit(app_client, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": NEW_PHONE})
    emit(app_client, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": NEW_PHONE})
    assert len(q("SELECT 1 FROM step_up_challenges WHERE method = 'sms_otp'")) == 1


def test_respond_validation(app_client):
    emit(app_client, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": NEW_PHONE})
    cid = app_client.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042"}).json()["challenge"]["challenge_id"]
    assert app_client.post(f"/v1/demo/step-up/{cid}/respond", json={}).status_code == 422
    assert app_client.post(f"/v1/demo/step-up/{cid}/respond", json={"decision": "approve"}).status_code == 422
    assert app_client.post(f"/v1/demo/step-up/{cid}/respond", json={"code": "12ab56"}).status_code == 422
    assert app_client.post("/v1/demo/step-up/chl_nope/respond", json={"code": "123456"}).status_code == 404


# ------------------------------------------------------------------ step-up trusted (device_push) + "Not me"
def test_kyc_high_pushes_to_registered_phone_and_not_me(app_client):
    emit(app_client, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": NEW_PHONE})
    emit(app_client, "kyc_result", {"liveness_score": 0.38, "face_match_score": 0.81, "doc_tamper_score": 0.12,
                                    "injection_suspected": False, "reason": "re_verification"})
    pend = app_client.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042", "channel": "phone"}).json()["challenge"]
    assert pend["method"] == "device_push"
    (ch,) = q("SELECT factor_id FROM step_up_challenges WHERE challenge_id = :c", c=pend["challenge_id"])
    assert ch["factor_id"] == "fac_push"           # the sms factor changed inside this case, so it is not trusted
    assert app_client.post(f"/v1/demo/step-up/{pend['challenge_id']}/respond", json={"decision": "deny"}).json() == {"status": "denied_by_customer"}
    drain(app_client)
    res = q("SELECT data FROM events WHERE event_type = 'step_up_result' ORDER BY occurred_at")[-1]["data"]
    assert res["payload"]["result"] == "denied_by_customer" and res["payload"]["factor_age_h"] > 2000   # 90-day-old factor
    assert res["device"] == tok("dev", "fp_priya_phone") and res["asn"] == "AS24560 Airtel"


def test_trusted_needs_a_factor_older_than_72h(app_client):
    with get_engine().begin() as c:
        c.execute(text("UPDATE mfa_factors SET enrolled_at = now() - interval '1 hour'"))
    emit(app_client, "kyc_result", {"liveness_score": 0.38, "face_match_score": 0.81, "doc_tamper_score": 0.12,
                                    "injection_suspected": False, "reason": "re_verification"})
    assert not q("SELECT 1 FROM step_up_challenges WHERE method = 'device_push'")
    assert q("SELECT 1 FROM audit_log WHERE action = 'CHALLENGE_SKIPPED'")


def test_expiry_marks_timeout_and_emits(app_client):
    emit(app_client, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": NEW_PHONE})
    with get_engine().begin() as c:
        c.execute(text("UPDATE step_up_challenges SET expires_at = now() - interval '1 second'"))
    assert app_client.portal.call(app_client.app.state.worker.expire_once) == 1
    drain(app_client)
    assert q("SELECT status FROM step_up_challenges")[0]["status"] == "timeout"
    assert q("SELECT data FROM events WHERE event_type = 'step_up_result'")[0]["data"]["payload"]["result"] == "timeout"
    assert app_client.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042"}).json()["challenge"] is None


# ------------------------------------------------------------------ payments + case routes from the database
def test_blocked_transfer_and_case_routes(app_client, auth_headers):
    emit(app_client, "kyc_result", {"liveness_score": 0.38, "face_match_score": 0.81, "doc_tamper_score": 0.12,
                                    "injection_suspected": False, "reason": "re_verification"})
    eid = emit(app_client, "transaction", {"amount_paise": 48000000, "payee_account": "A-RAVI-778", "channel": "IMPS"})
    assert app_client.get(f"/v1/demo/payment-status/{eid}").json() == {"outcome": "blocked"}

    h = auth_headers("analyst")
    page = app_client.get("/v1/cases", headers=h).json()
    (item,) = page["items"]
    assert item["band"] == "CRITICAL" and item["payment_state"] == "blocked"
    cid = item["case_id"]
    tl = app_client.get(f"/v1/cases/{cid}/timeline", headers=h).json()
    assert len(tl["evidence"]) == 2 and len(tl["decisions"]) == 2
    assert [c["method"] for c in tl["challenges"]] == ["device_push"]
    m = app_client.get("/v1/metrics/summary", headers=h).json()["live"]
    assert m == {"cases_open": 1, "critical_open": 1, "money_protected_paise": 48000000, "alert_compression": 2.0}


def test_websocket_receives_case_and_challenge_updates(app_client, auth_headers):
    token = auth_headers()["Authorization"].split()[1]
    with app_client.websocket_connect("/v1/stream") as ws:
        ws.send_text(f'{{"token": "{token}"}}')
        deadline = time.time() + 5
        while app_client.app.state.broadcaster.count == 0 and time.time() < deadline:
            time.sleep(0.02)
        emit(app_client, "mfa_change", {"factor": "sms", "action": "replace", "new_phone": NEW_PHONE})
        first, second = ws.receive_json(), ws.receive_json()
    assert first["type"] == "case_update" and first["case"]["band"] == "MEDIUM"
    assert first["step_up"]["method_class"] == "any"
    assert second["type"] == "challenge_update" and second["status"] == "pending" and second["case_id"] == first["case"]["case_id"]


# ------------------------------------------------------------------ queue filter, paging, manual actions
def test_queue_filter_paging_and_404(client, auth_headers, seeded):
    h = auth_headers("analyst")
    page = client.get("/v1/cases?limit=2", headers=h).json()
    assert [i["band"] for i in page["items"]] == ["CRITICAL", "HIGH"] and page["next_cursor"] == "o2"
    rest = client.get(f"/v1/cases?limit=50&cursor={page['next_cursor']}", headers=h).json()
    assert len(rest["items"]) == 4 and rest["next_cursor"] is None
    assert all(i["band"] == "MEDIUM" for i in client.get("/v1/cases?band=MEDIUM", headers=h).json()["items"])
    assert client.get("/v1/cases?cursor=x;drop", headers=h).status_code == 422
    with get_engine().begin() as c:                              # move one case into a queue the analyst cannot see
        c.execute(text("UPDATE cases SET queue = 'vip' WHERE case_id = :c"), {"c": seeded[0]})
    assert client.get(f"/v1/cases/{seeded[0]}", headers=h).status_code == 404
    assert client.get(f"/v1/cases/{seeded[0]}/timeline", headers=h).status_code == 404
    assert seeded[0] not in [i["case_id"] for i in client.get("/v1/cases", headers=h).json()["items"]]


def test_manual_action_by_lead(client, auth_headers, seeded):
    cid = seeded[2]                                               # a MEDIUM case with payment_state normal
    r = client.post(f"/v1/cases/{cid}/actions", json={"actions": ["HOLD_OUTBOUND_PAYMENTS"], "reason": "customer called in"},
                    headers=auth_headers("lead"))
    assert r.status_code == 200
    d = r.json()
    assert d["actor"] == "usr_lead" and d["override_reason"] == "customer called in" and d["policy_rule"] == "manual_override"
    case = client.get(f"/v1/cases/{cid}", headers=auth_headers()).json()["case"]
    assert case["payment_state"] == "held" and case["latest_actions"] == ["HOLD_OUTBOUND_PAYMENTS"]
    assert q("SELECT 1 FROM audit_log WHERE action = 'MANUAL_ACTION' AND actor = 'usr_lead'")
    assert d["decision_id"] in [x["decision_id"] for x in client.get(f"/v1/cases/{cid}/timeline", headers=auth_headers()).json()["decisions"]]


def test_feedback_and_detectors(client, auth_headers, seeded):
    h = auth_headers()
    r = client.post(f"/v1/cases/{seeded[0]}/feedback", json={"verdict": "CONFIRMED_FRAUD", "note": "confirmed by phone"}, headers=h)
    assert r.status_code == 200 and r.json()["case_id"] == seeded[0]
    assert q("SELECT verdict, analyst FROM feedback")[0] == {"verdict": "CONFIRMED_FRAUD", "analyst": "usr_analyst"}
    assert q("SELECT 1 FROM audit_log WHERE action = 'FEEDBACK'")
    dets = {d["detector"]: d for d in client.get("/v1/detectors", headers=h).json()}
    assert dets["txn"]["reliability"] == pytest.approx(0.85) and dets["netsec"]["family"] == "cyber"


def test_challenge_created_by_hand_appears_and_respond_emits(app_client):
    """PRD D1-P2 done-when: creating a challenge by hand makes it appear at /demo/step-up/pending;
    responding emits a step_up_result event row."""
    from api import stepup
    demo_state.phone[tok("cust", "C-1042")] = "+91 98450 00000"
    req = StepUpRequest(case_id="case_manual", customer=tok("cust", "C-1042"), method_class="trusted", reason_event_id="evt_manual01")
    info = stepup.create_challenge(req, datetime.now(UTC), datetime.now(UTC))
    pend = app_client.get("/v1/demo/step-up/pending", params={"customer_ref": "C-1042", "channel": "phone"}).json()["challenge"]
    assert pend["challenge_id"] == info["challenge_id"]
    assert app_client.post(f"/v1/demo/step-up/{info['challenge_id']}/respond", json={"decision": "approve"}).json() == {"status": "passed"}
    drain(app_client)
    (res,) = q("SELECT data FROM events WHERE event_type = 'step_up_result'")
    assert res["data"]["payload"]["challenge_id"] == info["challenge_id"] and res["data"]["payload"]["result"] == "passed"
