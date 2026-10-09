"""Scenario loader / expander (PRD §12.2, §16.1) and the scenario data files."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import Envelope, Label, validate_payload
from ml.scenario import (
    DIRECT_CHALLENGE_ID,
    Scenario,
    StepUpAction,
    expand,
    labels_for,
    load_scenario,
    preload_envelopes,
    seed_tokens,
)

IST = timezone(timedelta(hours=5, minutes=30))
ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "scenarios"
MIDNIGHT = SCENARIOS / "midnight_ato.yaml"
ALL = ["midnight_ato", "mule_fanin", "benign_odd", "scam_app"]          # scam_app: DEV1 FW (test_scam_direct.py)


@pytest.fixture(scope="module")
def midnight() -> Scenario:
    return load_scenario(str(MIDNIGHT))


def _valid(e: Envelope) -> None:
    Envelope.model_validate_json(e.model_dump_json())
    validate_payload(e.event_type, e.payload)
    to_stored_event(e, e.occurred_at)


# ---------------------------------------------------------------------------- loading
@pytest.mark.parametrize("name", ALL)
def test_every_scenario_loads_and_expands_to_valid_envelopes(name):
    sc = load_scenario(str(SCENARIOS / f"{name}.yaml"))
    assert sc.id == name and sc.default_start.tzinfo is not None and isinstance(sc.raw, dict)
    envs = preload_envelopes(sc, sc.default_start) + expand(sc, sc.default_start, "direct")
    assert envs and all(isinstance(e, Envelope) for e in envs)
    for e in envs:
        _valid(e)
    assert len({e.event_id for e in envs}) == len(envs)


def test_midnight_header(midnight):
    assert midnight.default_start == datetime(2026, 10, 9, 0, 39, tzinfo=IST)
    assert set(midnight.raw["identities"]) == {"priya_phone", "attacker", "ravi", "mule"}


# ---------------------------------------------------------------------------- direct mode
def test_midnight_direct_mode_yields_nine_valid_envelopes(midnight):
    """§12.2 lists 7 typed steps + 2 step_up_respond steps = 9 Envelopes in direct mode.

    §16.1 says "10 Envelopes"; that count does not follow from §12.2 (see docs/CONTRACT_REQUESTS.md).
    """
    out = expand(midnight, midnight.default_start, "direct")
    assert len(out) == 9 and all(isinstance(e, Envelope) for e in out)
    assert [e.event_type for e in out] == ["network_ids_alert", "login", "mfa_change", "step_up_result", "kyc_result",
                                           "cloud_audit", "payee_added", "transaction", "step_up_result"]
    for e in out:
        _valid(e)


def test_midnight_timing_matches_the_golden_table(midnight):
    """occurred_at = start + at_min + 10 s × position among steps sharing that at_min (§12.2, §12.4 IST times)."""
    out = expand(midnight, midnight.default_start, "direct")
    assert [e.occurred_at.astimezone(IST).strftime("%H:%M:%S") for e in out] == [
        "00:39:00", "00:41:00", "00:44:00", "00:52:00", "00:52:10", "00:58:00", "01:03:00", "01:05:00", "01:06:00"]
    assert [e.occurred_at for e in out] == sorted(e.occurred_at for e in out)


def test_direct_step_up_result_envelopes(midnight):
    ups = [e for e in expand(midnight, midnight.default_start, "direct") if e.event_type == "step_up_result"]
    assert [e.payload for e in ups] == [
        {"method": "sms_otp", "result": "passed", "factor_age_h": 0.13, "challenge_id": DIRECT_CHALLENGE_ID},
        {"method": "device_push", "result": "denied_by_customer", "factor_age_h": 2160, "challenge_id": "chl_direct"}]
    assert all(e.source == "demo-bank-web" for e in ups)
    assert ups[0].context.device_id == "fp_attacker_01"                 # the responding device (as: attacker)
    assert ups[1].context.device_id == "fp_priya_phone"                 # as: priya_phone


def test_subject_and_context_come_from_the_identity(midnight):
    out = expand(midnight, midnight.default_start, "direct")
    ids, login, cloud = out[0], out[1], out[5]
    assert ids.subject.customer_ref is None and ids.context.ip is None                      # no `as`
    assert login.subject.customer_ref == "C-1042" and login.subject.account_ref == "A-88213"
    assert login.context.ip == "185.220.101.7" and login.context.device_id == "fp_attacker_01"
    assert login.context.asn == "AS64500 HostCo" and login.source == "demo-bank-web"
    assert cloud.source == "cloud-audit" and cloud.payload["target_customer"] == "C-1042"
    assert out[2].payload["new_phone"] == "+91 90000 11111"


def test_expand_rebases_to_any_start(midnight):
    start = datetime(2026, 12, 1, 9, 0, tzinfo=UTC)
    out = expand(midnight, start, "direct")
    assert out[0].occurred_at == start and out[-1].occurred_at == start + timedelta(minutes=27)
    with pytest.raises(ValueError):
        expand(midnight, datetime(2026, 12, 1, 9, 0), "direct")                             # naive start
    with pytest.raises(ValueError):
        expand(midnight, start, "replay")


def test_event_ids_are_fresh_and_valid(midnight):
    a = expand(midnight, midnight.default_start, "direct")
    b = expand(midnight, midnight.default_start, "direct")
    assert not {e.event_id for e in a} & {e.event_id for e in b}


# ---------------------------------------------------------------------------- api mode
def test_api_mode_keeps_step_up_actions(midnight):
    out = expand(midnight, midnight.default_start, "api")
    assert len(out) == 9
    actions = [x for x in out if isinstance(x, StepUpAction)]
    assert actions == [
        StepUpAction(at=datetime(2026, 10, 9, 0, 52, tzinfo=IST), channel="app", as_identity="attacker", decision=None,
                     direct_payload={"method": "sms_otp", "result": "passed", "factor_age_h": 0.13}),
        StepUpAction(at=datetime(2026, 10, 9, 1, 6, tzinfo=IST), channel="phone", as_identity="priya_phone",
                     decision="deny", direct_payload={"method": "device_push", "result": "denied_by_customer",
                                                      "factor_age_h": 2160})]
    assert [type(x).__name__ for x in out] == ["Envelope", "Envelope", "Envelope", "StepUpAction", "Envelope", "Envelope",
                                               "Envelope", "Envelope", "StepUpAction"]
    with pytest.raises(AttributeError):
        actions[0].channel = "phone"                                                       # frozen


# ---------------------------------------------------------------------------- preload, seeds, labels
def test_preload_and_seeds(midnight):
    pre = preload_envelopes(midnight, midnight.default_start)
    assert [(e.subject.customer_ref, e.occurred_at) for e in pre] == [
        ("C-MULE-01", midnight.default_start - timedelta(minutes=10080)),
        ("C-RAVI-01", midnight.default_start - timedelta(minutes=4320)),
        ("C-1042", midnight.default_start - timedelta(minutes=1440))]
    assert all(e.source == "simulator" and e.event_type == "login" for e in pre)
    assert seed_tokens(midnight) == [tok("dev", "fp_mule_shared"), tok("acct", "A-MULE-01")]


def test_labels_mark_steps_as_attack_and_preload_as_benign(midnight):
    pre = preload_envelopes(midnight, midnight.default_start)
    steps = expand(midnight, midnight.default_start + timedelta(hours=1), "direct")       # different starts are fine
    labels = labels_for(midnight, pre + steps)
    assert all(isinstance(lb, Label) for lb in labels)
    assert [lb.event_id for lb in labels] == [e.event_id for e in pre + steps]
    assert all(lb.scenario == "midnight_ato" for lb in labels)
    assert [(lb.is_attack, lb.attack_id) for lb in labels[:3]] == [(False, None)] * 3
    assert [(lb.is_attack, lb.attack_id) for lb in labels[3:]] == [(True, "atk_midnight_1")] * 9


def test_benign_scenario_labels_everything_benign():
    sc = load_scenario(str(SCENARIOS / "benign_odd.yaml"))
    envs = preload_envelopes(sc, sc.default_start) + expand(sc, sc.default_start, "direct")
    assert not any(lb.is_attack or lb.attack_id for lb in labels_for(sc, envs))


def test_labels_reject_foreign_envelopes(midnight):
    other = expand(load_scenario(str(SCENARIOS / "benign_odd.yaml")), midnight.default_start, "direct")
    with pytest.raises(ValueError):
        labels_for(midnight, other)


# ---------------------------------------------------------------------------- other scenario files
def test_mule_fanin_shape():
    sc = load_scenario(str(SCENARIOS / "mule_fanin.yaml"))
    out = expand(sc, sc.default_start, "direct")
    into_mule = [e for e in out if e.event_type == "transaction" and e.payload["payee_account"] == "A-MULE-02"]
    onward = [e for e in out if e.event_type == "transaction" and e.subject.customer_ref == "C-MULE-02"]
    assert len({e.subject.customer_ref for e in into_mule}) == 12
    assert max(e.occurred_at for e in into_mule) - min(e.occurred_at for e in into_mule) <= timedelta(hours=2)
    assert len(onward) == 1 and onward[0].occurred_at > max(e.occurred_at for e in into_mule)
    total = sum(e.payload["amount_paise"] for e in into_mule)
    assert onward[0].payload["amount_paise"] == pytest.approx(0.9 * total)
    assert all(lb.attack_id == "atk_mule_1" for lb in labels_for(sc, out))


def test_benign_odd_shape():
    sc = load_scenario(str(SCENARIOS / "benign_odd.yaml"))
    pre = preload_envelopes(sc, sc.default_start)
    out = expand(sc, sc.default_start, "direct")
    login, approve, txn = out
    assert login.context.city == "Mumbai" and login.context.device_id == "fp_priya_new_phone"
    assert approve.event_type == "step_up_result" and approve.payload["result"] == "passed"
    assert approve.payload["factor_age_h"] >= 72 and approve.context.device_id == "fp_priya_phone"   # trusted factor
    assert txn.payload["payee_account"] in {e.payload.get("payee_account") for e in pre if e.event_type == "payee_added"}
    assert sc.raw["steps"][1]["decision"] == "approve"


def test_ids_alerts_file_matches_the_suricata_mapping(midnight):
    """§7.4: EVE alert lines; other event_types are skipped by the adapter. The alert mirrors step at_min 0."""
    lines = [json.loads(x) for x in (SCENARIOS / "data" / "ids_alerts.jsonl").read_text().splitlines() if x.strip()]
    alerts = [x for x in lines if x["event_type"] == "alert"]
    assert alerts and any(x["event_type"] != "alert" for x in lines)
    step = midnight.raw["steps"][0]["payload"]
    for a in alerts:
        payload = {"src_ip": a["src_ip"], "dest_ip": a["dest_ip"], "dest_port": a["dest_port"],
                   **{k: a["alert"][k] for k in ("signature_id", "signature", "category", "severity")}}
        validate_payload("network_ids_alert", payload)
        assert datetime.fromisoformat(a["timestamp"]).utcoffset() is not None
    first = alerts[0]
    assert datetime.fromisoformat(first["timestamp"]) == midnight.default_start
    assert {k: first["alert"][k] for k in ("signature_id", "signature", "category", "severity")} == \
        {k: step[k] for k in ("signature_id", "signature", "category", "severity")}
    assert (first["src_ip"], first["dest_ip"], first["dest_port"]) == (step["src_ip"], step["dest_ip"], step["dest_port"])


# ---------------------------------------------------------------------------- validation
def _write(tmp_path, text: str) -> str:
    p = tmp_path / "s.yaml"
    p.write_text(text)
    return str(p)


BASE = """
id: t
default_start: "2026-10-09T00:00:00+05:30"
identities:
  a: {subject: {customer_ref: C-1}, context: {ip: 1.2.3.4, device_id: d1}}
"""


@pytest.mark.parametrize("body", [
    "steps:\n  - {at_min: 0, type: login, source: simulator, as: nobody, payload: {result: success, auth_method: password}}",
    "steps:\n  - {at_min: 0, type: login, source: simulator, as: a, payload: {result: maybe, auth_method: password}}",
    "steps:\n  - {at_min: 0, type: login, source: bank, as: a, payload: {result: success, auth_method: password}}",
    "steps:\n  - {at_min: 0, action: step_up_respond, channel: phone, as: a, direct_payload: {method: device_push, result: passed, factor_age_h: 1}}",
    "steps:\n  - {at_min: 0, action: step_up_respond, channel: app, as: a, direct_payload: {method: sms_otp, result: ok, factor_age_h: 1}}",
    "steps:\n  - {type: login, source: simulator, as: a, payload: {result: success, auth_method: password}}",
    "preload:\n  - {at_min: -5, type: login, source: simulator, as: a, payload: {result: success, auth_method: password}}\n"
    "steps:\n  - {at_min: 0, type: login, source: simulator, as: a, payload: {result: success, auth_method: password}}",
    "seeds: [{kind: nope, raw: x}]\nsteps: []",
])
def test_malformed_scenarios_are_rejected(tmp_path, body):
    with pytest.raises((ValueError, ValidationError)):
        load_scenario(_write(tmp_path, BASE + body))
