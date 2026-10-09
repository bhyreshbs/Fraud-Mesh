"""v3 phase 15: the Digital Twin scenario library (benchmark/twin_scenarios.py), played through the REAL engine.

Each scenario must meet its OWN expected behaviour (the checks next to it in SPECS), and attacks must come out TP,
benign scenarios TN. A scenario the engine does not handle yet is a strict xfail with the reason: the test asserts the
correct behaviour and starts failing (XPASS) the moment the gap is closed, so the marker has to be removed then.
"""
from __future__ import annotations

import pytest

from benchmark.twin_scenarios import SPECS, run_one

KNOWN_GAPS = {
    "session_replay_clone": (
        "a stolen session replayed with a PERFECTLY cloned device (same device id, platform, WebGL, screen, time zone) "
        "from a hosting network: SESSION_CONTEXT_CHANGE needs network AND device context to change "
        "(session_device.yaml), so only weak APP reasons fire and the transfer completes. Needs a session-level "
        "network-type escalation rule (mobile/residential -> hosting inside one session) or device-bound sessions."),
}

_results: dict[str, dict] = {}


def result(sid: str) -> dict:
    if sid not in _results:
        _results[sid] = run_one(next(s for s in SPECS if s.id == sid))
    return _results[sid]


def test_library_covers_the_fifteen_phase15_scenarios():
    assert [s.num for s in SPECS] == list(range(1, 16))
    assert len({s.id for s in SPECS}) == 15


@pytest.mark.parametrize("sid", [
    pytest.param(s.id, marks=pytest.mark.xfail(strict=True, reason=KNOWN_GAPS[s.id])) if s.id in KNOWN_GAPS else s.id
    for s in SPECS])
def test_scenario_meets_its_expected_behaviour(sid):
    r = result(sid)
    failed = [c["check"] for c in r["checks"] if not c["passed"]]
    assert not failed, f"{sid}: {failed} (peak {r['peak_band']}, reasons {r['reason_codes']}, payments {r['payments']})"
    assert r["outcome"] == ("TP" if r["is_attack"] else "TN")


def test_benign_scenarios_lose_no_money():
    for s in SPECS:
        if not s.is_attack:
            r = result(s.id)
            assert r["money"]["stopped_paise"] == 0, (s.id, r["payments"])


def test_app_and_remote_access_are_not_account_takeover_but_takeovers_are():
    assert result("scam_app")["case_kind"] == "app_scam"
    assert result("remote_access_demo")["case_kind"] != "account_takeover"
    for sid in ("midnight_ato", "residential_proxy_ato", "device_multi_account", "distributed_stuffing"):
        assert result(sid)["case_kind"] == "account_takeover", sid


def test_every_detection_is_explained_by_reason_codes():
    for s in SPECS:
        r = result(s.id)
        if r["detected_at_step"] is not None or r["first_intervention"]:
            assert r["reason_codes"] and r["detectors"], s.id


def test_feedback_burst_moves_reliability_but_stays_in_bounds():
    r = result("late_evidence_feedback")
    before, after = r["extra"]["reliability_before"], r["extra"]["reliability_after"]
    assert r["extra"]["reliability_in_bounds"]
    assert any(after[d] < before[d] for d in before)          # the wrong verdicts DID count, within the caps
