"""PRD §12.4 end-to-end list (D1-P7, reviewed by Dev 2 at Checkpoint 2). Real detectors once Dev 2's engine is merged,
so P values may differ from the golden table; this test asserts structure, not exact numbers.

Runs the whole stack in-process: POST /v1/demo/reset, then POST /v1/demo/run/{scenario} (the autopilot plays signed
events and answers step-ups through the demo routes) and checks the outcome through the API.

Pipeline: engine.pipeline.Pipeline, or the dev stand-in when FM_DEV_PIPELINE=1 (CI runs it that way until the engine
lands). With the Phase 0 stub (no cases are ever produced) the test is skipped, not failed.
"""
from __future__ import annotations

import inspect
import time

import pytest

import engine.pipeline
from api.pipeline_factory import dev_pipeline_enabled
from engine.common.tokenize import tok
from engine.contracts import ACTION_SEVERITY, BAND_ORDER, SEVERITY_HOLD

PHASE0_STUB = "Phase 0 stub" in inspect.getsource(engine.pipeline)
pytestmark = pytest.mark.skipif(PHASE0_STUB and not dev_pipeline_enabled(),
                                reason="engine.pipeline is still the Phase 0 stub (set FM_DEV_PIPELINE=1 to run on the dev stand-in)")


@pytest.fixture
def stack(client, auth_headers):
    from api.pipeline_factory import make_pipeline
    client.app.state.pipeline = make_pipeline(client.app.state.store)
    client.app.state.pipeline.startup()
    admin = auth_headers("admin")
    assert client.post("/v1/demo/reset", headers=admin).status_code == 200
    return client, admin, auth_headers("analyst")


def play(client, admin, scenario: str, speed: float = 600, timeout: float = 120):
    r = client.post(f"/v1/demo/run/{scenario}", json={"speed": speed}, headers=admin)
    assert r.status_code == 200, r.text
    run_id, deadline = r.json()["run_id"], time.monotonic() + timeout
    while time.monotonic() < deadline:
        st, _ = client.app.state.runs[run_id]
        if st.status != "running":
            break
        time.sleep(0.2)
    client.portal.call(client.app.state.worker.drain)
    assert st.status == "done", st.log[-10:]
    return st


def test_midnight_ato_end_to_end(stack):
    client, admin, h = stack
    st = play(client, admin, "midnight_ato")
    posted = {e for ids in st.posted.values() for e in ids}
    items = client.get("/v1/cases?limit=200", headers=h).json()["items"]
    timelines = {i["case_id"]: client.get(f"/v1/cases/{i['case_id']}/timeline", headers=h).json() for i in items}
    holders = [cid for cid, tl in timelines.items() if any(e["event_id"] in posted for e in tl["evidence"])]

    # exactly one case holds all scenario evidence, anchored on Priya's cust token
    assert len(holders) == 1, holders
    cid = holders[0]
    case = client.get(f"/v1/cases/{cid}", headers=h).json()["case"]
    assert case["anchor_entity"] == tok("cust", "C-1042")
    # the final band is CRITICAL
    assert case["band"] == "CRITICAL"
    # the first decision with severity >= HOLD comes before the transaction evidence
    tl = timelines[cid]
    txn_ids = set(st.posted["transaction"])
    txn_ev = next(e for e in tl["evidence"] if e["event_id"] in txn_ids)
    first_hold = next(d for d in sorted(tl["decisions"], key=lambda d: d["created_at"])
                      if max(ACTION_SEVERITY[a] for a in d["actions"]) >= SEVERITY_HOLD)
    assert first_hold["created_at"] < txn_ev["ts"]
    # the transaction's payment outcome is blocked
    assert client.get(f"/v1/demo/payment-status/{next(iter(txn_ids))}").json() == {"outcome": "blocked"}
    # explanation parts sum to case.log_odds within 1e-6
    ex = client.get(f"/v1/cases/{cid}/explanation", headers=h).json()
    assert abs(ex["parts"][-1]["running_log_odds"] - case["log_odds"]) < 1e-6
    # replay without kyc has an EIP no earlier than the baseline EIP
    r = client.post(f"/v1/cases/{cid}/replay", json={"ablate": ["kyc"], "mode": "fused"}, headers=h).json()
    assert r["baseline_eip"] and (r["eip"] is None or r["eip"]["ts"] >= r["baseline_eip"]["ts"])
    # after the "Not me" event: CRITICAL via floor_CUSTOMER_DENIED, status INVESTIGATING
    assert ("phone", "denied_by_customer") in st.step_ups
    assert "floor_CUSTOMER_DENIED" in case["floors"] and case["status"] == "INVESTIGATING"
    # the audit chain is intact after the whole run
    assert client.get("/v1/audit/verify", headers=admin).json()["ok"] is True
    # Digital Twin: the case replayed into the virtual bank under every strategy
    twin = client.get(f"/v1/cases/{cid}/twin", headers=h).json()
    assert len(twin["steps"]) >= 7 and any(s["actor"] == "attacker" for s in twin["steps"])
    outcome = {o["policy_id"]: o for o in twin["policies"]}
    assert outcome["allow_all"]["money_lost_paise"] == 48_000_000
    assert outcome["fraudmesh"]["money_lost_paise"] == 0 and outcome["fraudmesh"]["money_protected_paise"] == 48_000_000
    assert twin["earliest_intervention"] is not None and twin["prediction"]["sample_size"] > 0
    ov = client.get("/v1/twin/overview", headers=h).json()
    assert ov["cases_by_band"]["CRITICAL"] >= 1 and any(c["case_id"] == cid for c in ov["hottest_cases"])


def test_benign_odd_never_exceeds_medium(stack):
    client, admin, h = stack
    play(client, admin, "benign_odd")
    priya = tok("cust", "C-1042")
    bands = []
    for item in client.get("/v1/cases?limit=200", headers=h).json()["items"]:
        if item["customer"] == priya:
            bands.append(item["band"])
            bands += [d["band"] for d in client.get(f"/v1/cases/{item['case_id']}/timeline", headers=h).json()["decisions"]]
    assert all(BAND_ORDER.index(b) <= BAND_ORDER.index("MEDIUM") for b in bands), bands
