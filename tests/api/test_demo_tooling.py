"""D1-P5: scenario source (fallback for ml.scenario), Suricata adapter, loader, demo reset, autopilot.

PRD §15.5 done-when: reset_demo finishes in under 4 minutes; the /demo Run button plays midnight_ato end to end and the
console shows the case building live (here: through the API with the dev stand-in pipeline, asserting the final case)."""
from __future__ import annotations

import json
import time
from datetime import timedelta

import pytest
from sqlalchemy import text

from api import loader, scenario_source
from api.adapters.suricata import eve_to_envelope, read_alerts
from api.db.session import get_engine
from api.demo_identities import demo_state
from api.dev_pipeline import ScriptedPipeline
from engine.common.tokenize import tok
from engine.contracts import Envelope

SAMPLE_EVE = "fixtures/api/ids_alerts_sample.jsonl"


def q(sql: str, **params):
    with get_engine().connect() as c:
        return c.execute(text(sql), params).mappings().all()


# ------------------------------------------------------------------ scenario source (§16.1 signatures)
@pytest.mark.parametrize("sid", scenario_source.SCENARIO_IDS)
def test_every_scenario_expands_to_valid_envelopes(sid):
    sc = scenario_source.load_scenario(str(scenario_source.scenario_path(sid)))
    assert sc.id == sid and sc.default_start.tzinfo is not None
    direct = scenario_source.expand(sc, sc.default_start, "direct")
    assert direct and all(isinstance(e, Envelope) for e in direct)
    assert [e.occurred_at for e in direct] == sorted(e.occurred_at for e in direct)
    for e in direct + scenario_source.preload_envelopes(sc, sc.default_start):
        Envelope.model_validate_json(e.model_dump_json())
    labels = scenario_source.labels_for(sc, direct)
    assert len(labels) == len(direct)


def test_midnight_ato_expansion_follows_section_12_2():
    sc = scenario_source.load_scenario(str(scenario_source.scenario_path("midnight_ato")))
    direct = scenario_source.expand(sc, sc.default_start, "direct")
    offs = [(e.event_type, int((e.occurred_at - sc.default_start).total_seconds())) for e in direct]
    assert offs == [("network_ids_alert", 0), ("login", 120), ("mfa_change", 300), ("step_up_result", 780), ("kyc_result", 790),
                    ("cloud_audit", 1140), ("payee_added", 1440), ("transaction", 1560), ("step_up_result", 1620)]
    assert {e.payload["challenge_id"] for e in direct if e.event_type == "step_up_result"} == {"chl_direct"}
    api_items = scenario_source.expand(sc, sc.default_start, "api")
    actions = [x for x in api_items if isinstance(x, scenario_source.StepUpAction)]
    assert [(a.channel, a.as_identity, a.decision) for a in actions] == [("app", "attacker", None), ("phone", "priya_phone", "deny")]
    assert scenario_source.seed_tokens(sc) == [tok("dev", "fp_mule_shared"), tok("acct", "A-MULE-01")]
    assert [e.subject.customer_ref for e in scenario_source.preload_envelopes(sc, sc.default_start)] == ["C-MULE-01", "C-RAVI-01", "C-1042"]
    assert scenario_source.scenario_path("../../etc/passwd") is None


# ------------------------------------------------------------------ Suricata adapter (§7.4)
def test_suricata_alert_maps_and_other_lines_are_skipped():
    envs, skipped = read_alerts(SAMPLE_EVE)
    assert skipped == 1 and len(envs) == 1
    e = envs[0]
    assert (e.event_type, e.source) == ("network_ids_alert", "network-ids")
    assert e.occurred_at.isoformat() == "2026-10-09T00:39:00+05:30"
    assert e.payload == {"src_ip": "185.220.101.7", "dest_ip": "10.0.1.20", "dest_port": 443, "signature_id": 9000001,
                         "signature": "FM LOCAL credential stuffing against /api/login",
                         "category": "Attempted User Privilege Gain", "severity": 2}
    assert eve_to_envelope(json.dumps({"event_type": "dns"})) is None
    z = json.loads(open(SAMPLE_EVE, encoding="utf-8").readline())
    z["timestamp"] = "2026-10-08T19:09:00Z"
    assert eve_to_envelope(json.dumps(z)).occurred_at.isoformat() == "2026-10-08T19:09:00+00:00"


def test_suricata_alert_ingests_signed(client):
    from scripts.sign import sign
    (e,), _ = read_alerts(SAMPLE_EVE)
    body = e.model_dump_json().encode()
    assert client.post("/v1/events", content=body, headers=sign("network-ids", body)).status_code == 202
    assert q("SELECT data->'payload'->>'src_ip' AS ip FROM events")[0]["ip"].startswith("ip:")


# ------------------------------------------------------------------ loader (--direct, --preload-only)
class CountingPipeline:
    def __init__(self):
        self.seen, self.seeds = [], []

    def process(self, ev):
        self.seen.append(ev.occurred_at)
        return []

    def set_seeds(self, ids, value=True):
        self.seeds += ids


def test_load_file_direct_inserts_labels_and_processes_in_order(tmp_path, client):
    sc = scenario_source.load_scenario(str(scenario_source.scenario_path("midnight_ato")))
    envs = list(reversed(scenario_source.expand(sc, sc.default_start, "direct")))          # out of order on disk
    labels = scenario_source.labels_for(sc, envs)
    (tmp_path / "ev.jsonl").write_text("\n".join(e.model_dump_json() for e in envs), encoding="utf-8")
    (tmp_path / "lb.jsonl").write_text("\n".join(lb.model_dump_json() for lb in labels), encoding="utf-8")
    p = CountingPipeline()
    rep = loader.load_file(tmp_path / "ev.jsonl", tmp_path / "lb.jsonl", client.app.state.store, p)
    assert (rep.events_read, rep.events_inserted, rep.labels, rep.processed, rep.errors) == (9, 9, 9, 9, 0)
    assert p.seen == sorted(p.seen)
    assert q("SELECT count(*) AS n FROM labels WHERE is_attack")[0]["n"] == 9
    rep = loader.load_file(tmp_path / "ev.jsonl", None, client.app.state.store, p)           # idempotent on event_id
    assert rep.events_inserted == 0


def test_load_preload_marks_seeds(client):
    store = client.app.state.store
    pipeline = ScriptedPipeline(store)
    pipeline.startup()
    sc = scenario_source.load_scenario(str(scenario_source.scenario_path("midnight_ato")))
    rep = loader.load_preload("midnight_ato", sc.default_start, store, pipeline)
    assert rep.events_inserted == 3 and rep.errors == 0
    assert store.list_fraud_seeds() == {tok("dev", "fp_mule_shared"), tok("acct", "A-MULE-01")}
    assert {r["is_attack"] for r in q("SELECT is_attack FROM labels")} == {False}


# ------------------------------------------------------------------ POST /v1/demo/reset
def test_demo_reset_is_admin_only_and_rebuilds_everything(client, auth_headers, seeded):
    assert client.post("/v1/demo/reset", headers=auth_headers("lead")).status_code == 403
    h = auth_headers("admin")
    t0 = time.monotonic()
    r = client.post("/v1/demo/reset", headers=h)
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert time.monotonic() - t0 < 240                                                       # PRD: under 4 minutes
    assert q("SELECT count(*) AS n FROM cases")[0]["n"] == 0                                 # runtime data truncated
    assert q("SELECT count(*) AS n FROM events")[0]["n"] == 3                                # midnight_ato preload only
    assert {r["user_id"] for r in q("SELECT user_id FROM users")} == {"usr_analyst", "usr_lead", "usr_admin"}
    assert {r["entity_id"] for r in q("SELECT entity_id FROM entities WHERE fraud_seed")} == {tok("dev", "fp_mule_shared"), tok("acct", "A-MULE-01")}
    priya = q("SELECT kind, device_token, enrolled_at FROM mfa_factors WHERE customer = :c ORDER BY kind", c=tok("cust", "C-1042"))
    assert [f["kind"] for f in priya] == ["device_push", "sms"] and priya[0]["device_token"] == tok("dev", "fp_priya_phone")
    assert q("SELECT count(*) AS n FROM detector_reliability")[0]["n"] == 7
    assert [r["action"] for r in q("SELECT action FROM audit_log ORDER BY seq")] [-1] == "DEMO_RESET"
    assert client.get("/v1/audit/verify", headers=auth_headers("lead")).json()["ok"] is True


# ------------------------------------------------------------------ POST /v1/demo/run/{scenario_id}
def _wait_run(client, run_id: str, timeout: float = 60) -> object:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        st, _ = client.app.state.runs[run_id]
        if st.status != "running":
            return st
        time.sleep(0.2)
    raise AssertionError(f"run {run_id} still running: {client.app.state.runs[run_id][0].log[-5:]}")


def test_autopilot_plays_midnight_ato_end_to_end(client, auth_headers):
    """The /demo Run button: reset, then midnight_ato at high speed through the real routes (dev stand-in engine)."""
    import api.pipeline_factory as factory
    from api.pipeline_factory import make_pipeline  # noqa: F401  (the reset route builds its pipeline from here)
    factory_make = factory.make_pipeline
    h = auth_headers("admin")
    try:
        factory.make_pipeline = lambda store: ScriptedPipeline(store)                         # what FM_DEV_PIPELINE=1 selects
        import api.routers.demo as demo_router
        demo_router.make_pipeline = factory.make_pipeline
        import api.demo_reset as demo_reset_mod
        demo_reset_mod.make_pipeline = factory.make_pipeline
        assert client.post("/v1/demo/reset", headers=h).status_code == 200
        assert client.post("/v1/demo/run/not_a_scenario", json={"speed": 8}, headers=h).status_code == 404
        r = client.post("/v1/demo/run/midnight_ato", json={"speed": 600}, headers=h)
        assert r.status_code == 200 and r.json()["run_id"].startswith("run_")
        st = _wait_run(client, r.json()["run_id"])
    finally:
        factory.make_pipeline = factory_make
        demo_router.make_pipeline = factory_make
        demo_reset_mod.make_pipeline = factory_make
    assert st.status == "done", st.log
    assert st.accepted == 7, st.log                                                          # 7 signed events; 2 step-ups via routes
    assert any("app OTP" in line and "passed" in line for line in st.log), st.log
    assert any("phone deny: denied_by_customer" in line for line in st.log), st.log
    client.portal.call(client.app.state.worker.drain)
    (case,) = client.get("/v1/cases", headers=auth_headers()).json()["items"]
    assert case["band"] == "CRITICAL" and case["payment_state"] == "blocked" and case["status"] == "INVESTIGATING"
    assert len(case["stages_reached"]) == 7 and case["p_attack"] == pytest.approx(0.997, abs=0.002)
    tl = client.get(f"/v1/cases/{case['case_id']}/timeline", headers=auth_headers()).json()
    assert len(tl["evidence"]) == 9 and sorted(c["status"] for c in tl["challenges"]) == ["denied_by_customer", "passed"]
    ts = [e["ts"] for e in tl["evidence"]]
    assert ts == sorted(ts)                                                                  # step-up results stay in scenario order
    starts = q("SELECT min(occurred_at) AS a, max(occurred_at) AS b FROM events WHERE source <> 'simulator'")[0]
    assert starts["b"] - starts["a"] >= timedelta(minutes=26)        # scenario timestamps (IDS at +0 ... transfer at +26 min), not compressed


def test_signed_mfa_change_routes_the_otp_to_the_new_number(client):
    """Autopilot events arrive signed at /v1/events, not via /demo/emit: the OTP must still reach the swapped number."""
    from scripts.sign import sign
    demo_state.reset()
    sc = scenario_source.load_scenario(str(scenario_source.scenario_path("midnight_ato")))
    mfa = next(e for e in scenario_source.expand(sc, sc.default_start, "api") if getattr(e, "event_type", "") == "mfa_change")
    body = mfa.model_dump_json().encode()
    assert client.post("/v1/events", content=body, headers=sign("demo-bank-web", body)).status_code == 202
    assert demo_state.phone[tok("cust", "C-1042")] == "+91 90000 11111"
    assert demo_state.last_context[tok("cust", "C-1042")]["device_id"] == "fp_attacker_01"


# ------------------------------------------------------------------ the §12.1 background inside a reset
def _background_reset(client, auth_headers, monkeypatch, tmp_path, days: str, customers: str) -> tuple[float, int, int]:
    import api.demo_reset as dr
    if not dr.generator_available():
        pytest.skip("ml/generator (Dev 2) is not merged on this branch")
    monkeypatch.setattr(dr, "BACKGROUND_ENABLED", True)
    monkeypatch.setattr(dr, "DATA", tmp_path)
    monkeypatch.setattr(dr, "BACKGROUND", tmp_path / "background.jsonl")
    monkeypatch.setattr(dr, "BACKGROUND_LABELS", tmp_path / "background_labels.jsonl")
    monkeypatch.setenv("FM_BG_DAYS", days)
    monkeypatch.setenv("FM_BG_CUSTOMERS", customers)
    t0 = time.monotonic()
    assert client.post("/v1/demo/reset", headers=auth_headers("admin")).status_code == 200
    seconds = time.monotonic() - t0
    n_bg = sum(1 for line in open(tmp_path / "background.jsonl", encoding="utf-8") if line.strip())
    n_bg_labels = sum(1 for line in open(tmp_path / "background_labels.jsonl", encoding="utf-8") if line.strip())
    return seconds, n_bg, n_bg_labels


def test_demo_reset_with_a_tiny_background(client, auth_headers, monkeypatch, tmp_path):
    """Same reset as the demo, with Dev 2's generator at 2 days x 50 customers: exact counts of what it loads."""
    seconds, n_bg, n_bg_labels = _background_reset(client, auth_headers, monkeypatch, tmp_path, "2", "50")
    assert n_bg > 0
    assert q("SELECT count(*) AS n FROM events")[0]["n"] == n_bg + 3                       # background + midnight_ato preload
    assert q("SELECT count(*) AS n FROM labels")[0]["n"] == n_bg_labels + 3
    customers = q("SELECT count(DISTINCT customer) AS n FROM events WHERE customer IS NOT NULL")[0]["n"]
    factors = q("SELECT kind, count(*) AS n FROM mfa_factors GROUP BY kind ORDER BY kind")
    assert factors == [{"kind": "device_push", "n": customers}, {"kind": "sms", "n": customers}]   # one sms + one push each
    assert {r["entity_id"] for r in q("SELECT entity_id FROM entities WHERE fraud_seed")} >= {tok("dev", "fp_mule_shared"),
                                                                                           tok("acct", "A-MULE-01")}
    assert seconds < 240


@pytest.mark.slow
def test_full_prd_reset_under_four_minutes(client, auth_headers, monkeypatch, tmp_path):
    """PRD §12.3 / §15.5: the full reset (14 d x 2000 customers, ~62k events through PgStore + the engine) < 240 s."""
    seconds, n_bg, _ = _background_reset(client, auth_headers, monkeypatch, tmp_path, "14", "2000")
    print(f"full PRD reset: {n_bg} background events in {seconds:.1f}s")
    assert n_bg > 50_000
    assert seconds < 240, f"full reset took {seconds:.0f}s (budget 240s)"
