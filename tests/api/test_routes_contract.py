"""Phase 0: every Section 9 route answers with its contract shape (fixture-backed stubs), plus health and WebSocket auth."""
from __future__ import annotations

import pytest
from starlette.websockets import WebSocketDisconnect

from api.schemas import AskResponse, AuditVerify, CaseDetail, CasesPage, DetectorInfo, Health, MetricsSummary, Timeline
from engine.contracts import (
    CONTRACT_VERSION,
    Decision,
    Explanation,
    FeedbackResult,
    GraphElements,
    ReplayResult,
    SimulationResult,
)


def test_health(client):
    r = client.get("/v1/health")
    assert r.status_code == 200
    h = Health.model_validate(r.json())
    assert h.db is True and h.pipeline_ready is True and h.contract_version == CONTRACT_VERSION


def test_case_routes_shapes(client, auth_headers, seeded):
    h = auth_headers("lead")
    page = CasesPage.model_validate(client.get("/v1/cases", headers=h).json())
    cid = page.items[0].case_id
    assert all(i.band == "CRITICAL" for i in CasesPage.model_validate(client.get("/v1/cases?band=CRITICAL", headers=h).json()).items)
    CaseDetail.model_validate(client.get(f"/v1/cases/{cid}", headers=h).json())
    Timeline.model_validate(client.get(f"/v1/cases/{cid}/timeline", headers=h).json())
    GraphElements.model_validate(client.get(f"/v1/cases/{cid}/graph?hops=2", headers=h).json())
    ex = Explanation.model_validate(client.get(f"/v1/cases/{cid}/explanation", headers=h).json())
    assert ex.case_id == cid and abs(ex.parts[-1].running_log_odds - ex.final_log_odds) < 1e-6
    rp = ReplayResult.model_validate(client.post(f"/v1/cases/{cid}/replay", json={"ablate": ["kyc"], "mode": "fused"}, headers=h).json())
    assert rp.ablated == ["kyc"]
    FeedbackResult.model_validate(client.post(f"/v1/cases/{cid}/feedback", json={"verdict": "CONFIRMED_FRAUD", "note": None}, headers=h).json())
    Decision.model_validate(client.post(f"/v1/cases/{cid}/actions", json={"actions": ["HOLD_OUTBOUND_PAYMENTS"], "reason": "x"}, headers=h).json())
    AskResponse.model_validate(client.post(f"/v1/cases/{cid}/ask", json={"question": "Why did you block this?"}, headers=h).json())


def test_unknown_case_is_404(client, auth_headers):
    r = client.get("/v1/cases/case_doesnotexist", headers=auth_headers())
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"


def test_bad_query_filter_is_422(client, auth_headers):
    r = client.get("/v1/cases?band=HIGH';DROP TABLE cases;--", headers=auth_headers())
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_FAILED"


def test_metrics_routes_shapes(client, auth_headers, seeded):
    h = auth_headers("lead")
    MetricsSummary.model_validate(client.get("/v1/metrics/summary", headers=h).json())
    sim = SimulationResult.model_validate(client.post("/v1/simulate", json={"medium": 0.3, "high": 0.6, "critical": 0.9}, headers=h).json())
    assert sim.thresholds.medium == 0.3
    dets = [DetectorInfo.model_validate(d) for d in client.get("/v1/detectors", headers=h).json()]
    assert {d.detector for d in dets} == {"txn", "behaviour", "auth", "kyc", "cyber", "netsec", "graph"}
    AuditVerify.model_validate(client.get("/v1/audit/verify", headers=h).json())


def test_websocket_requires_token(client):
    with client.websocket_connect("/v1/stream") as ws:
        ws.send_text('{"token": "bad"}')
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_text()
    assert exc.value.code == 4401


def test_websocket_accepts_valid_token(client, auth_headers):
    token = auth_headers()["Authorization"].split()[1]
    with client.websocket_connect("/v1/stream") as ws:
        ws.send_text(f'{{"token": "{token}"}}')
        ws.send_text("ping")
    assert client.app.state.broadcaster.count == 0      # removed again after disconnect


def test_error_body_shape(client):
    r = client.get("/v1/nope")
    assert r.status_code == 404
    assert set(r.json()["error"]) == {"code", "message", "request_id"}
    assert r.headers["x-request-id"] == r.json()["error"]["request_id"]
