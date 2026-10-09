"""v3 phases 5, 6.1, 6.2, 11.1: geo-confidence, TZ_MISMATCH, DEVICE_INCONSISTENT, SESSION_CONTEXT_CHANGE, cold start."""
from __future__ import annotations

import pytest

from engine.contracts import Telemetry
from engine.detectors.auth import AuthDetector
from engine.detectors.behaviour import BehaviourDetector
from engine.features.features import FEATURE_NAMES, NONE_RECENT_MIN, FeatureWindows
from engine.graph.store import EntityGraph
from tests.engine.test_v3_net_common import cust, ev, feed, login, new_pipeline, reasons_in_case

REL = {d: (8.5, 1.5) for d in ("netsec", "behaviour", "auth", "kyc", "cyber", "graph", "txn")}
HOME = {"ip": "49.207.10.21", "asn": "AS24560 Airtel", "dev": "fp_phone"}
PHONE = {"platform": "Android", "webgl_renderer": "Adreno (TM) 640", "screen": "412x915"}
HIJACK = {"ip": "203.0.113.50", "asn": "AS64503 Cloud", "dev": "fp_evil", "coords": None,
          "platform": "Linux x86_64", "webgl_renderer": "Google SwiftShader", "screen": "1280x720"}


def history(fw: FeatureWindows, days: int = 8) -> None:
    for d in range(days):
        fw.update(login(d * 1440 + 600, **HOME, **PHONE))


def mfa(minutes, **kw):
    return ev("mfa_challenge", {"method": "device_push", "result": "passed"}, minutes, **kw)


# ---------------------------------------------------------------------------- features
def test_feature_names_extend_the_contract_order():
    f = FeatureWindows().compute(login(0))
    assert list(f) == FEATURE_NAMES
    for k in ("has_login_history", "geo_confidence_factor", "session_change", "acct_fail_1h"):
        assert k in f


def test_cold_start_is_explicit():
    fw = FeatureWindows()
    first = fw.compute(login(0, **HOME))
    assert first["has_login_history"] == 0 and first["hour_deviation"] == 0 and first["has_home_location"] == 0
    history(fw)
    later = fw.compute(login(9 * 1440 + 600, **HOME))
    assert later["has_login_history"] == 1 and later["has_home_location"] == 1 and later["past_logins_30d"] == 8


def test_wifi_to_mobile_with_the_same_device_is_not_a_session_change():
    fw = FeatureWindows()
    fw.update(login(0, session_id="S1", **HOME, **PHONE))
    f = fw.compute(mfa(5, session_id="S1", ip="49.36.128.10", asn="AS45609 Airtel Mobile", dev="fp_phone", **PHONE))
    assert f["session_seen"] == 1 and f["session_change"] == 0
    assert int(f["session_change_mask"]) & 1          # the ASN did change ...
    assert not int(f["session_change_mask"]) & 4      # ... but the device did not


def test_device_change_alone_is_not_a_session_change():
    fw = FeatureWindows()
    fw.update(login(0, session_id="S1", **HOME, **PHONE))
    f = fw.compute(mfa(5, session_id="S1", ip=HOME["ip"], asn=HOME["asn"], dev="fp_other", **PHONE))
    assert f["session_change"] == 0


def test_network_and_device_change_inside_a_session_is_flagged_once():
    fw = FeatureWindows()
    fw.update(login(0, session_id="S1", **HOME, **PHONE))
    e = mfa(5, session_id="S1", **HIJACK)
    f = fw.compute(e)
    assert f["session_change"] == 1
    assert int(f["session_change_mask"]) & 64         # now on hosting
    fw.update(e)
    again = fw.compute(mfa(6, session_id="S1", **HIJACK))
    assert again["session_change"] == 0               # same combination already reported


def test_session_expires_after_ttl():
    fw = FeatureWindows()
    fw.update(login(0, session_id="S1", **HOME, **PHONE))
    assert fw.compute(mfa(25 * 60, session_id="S1", **HIJACK))["session_seen"] == 0


@pytest.mark.parametrize("client,mask", [
    ({"platform": "Android", "telemetry": Telemetry(pointer_type="mouse")}, 1),
    ({"platform": "Win32", "webgl_renderer": "Adreno (TM) 640"}, 2),
    ({"platform": "Android", "webgl_renderer": "NVIDIA GeForce RTX 3060"}, 4),
    ({"platform": "Linux x86_64", "webgl_renderer": "Google SwiftShader"}, 8),
    ({"platform": "iPhone", "screen": "2560x1440"}, 16),
    ({"platform": "Android", "webgl_renderer": "Adreno (TM) 640", "screen": "412x915",
      "telemetry": Telemetry(pointer_type="touch")}, 0),
    ({}, 0),
])
def test_device_inconsistency(client, mask):
    f = FeatureWindows().compute(login(0, **client))
    assert int(f["device_inconsistency_mask"]) == mask


def test_platform_change_inside_a_session_is_inconsistent():
    fw = FeatureWindows()
    fw.update(login(0, session_id="S9", platform="Android"))
    assert int(fw.compute(mfa(1, session_id="S9", platform="Win32"))["device_inconsistency_mask"]) & 32


def test_tz_mismatch_compares_utc_offsets():
    same = FeatureWindows().compute(login(0, ip="49.207.10.21", browser_timezone="Asia/Calcutta"))   # alias, +05:30
    other = FeatureWindows().compute(login(0, ip="185.220.101.7", browser_timezone="Asia/Kolkata"))  # ip: Europe/Berlin
    unknown_ip = FeatureWindows().compute(login(0, ip="8.8.4.4", browser_timezone="Asia/Kolkata"))
    assert (same["tz_mismatch"], other["tz_mismatch"], unknown_ip["tz_mismatch"]) == (0, 1, 0)


# ---------------------------------------------------------------------------- detectors
def feats(**kw):
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    f.update(amount_to_median_30d=1.0, minutes_since_payee_added=NONE_RECENT_MIN, minutes_since_new_device=NONE_RECENT_MIN,
             minutes_since_mfa_change=NONE_RECENT_MIN, past_logins_30d=20.0, has_login_history=1.0, has_home_location=1.0,
             geo_confidence_factor=1.0)
    f.update(kw)
    return f


def test_impossible_travel_is_down_weighted_on_anonymisers():
    det = BehaviourDetector()
    plain = det.score(login(0, enrich=False), feats(travel_speed_kmh=2000), EntityGraph(), REL)
    vpn = det.score(login(0, ip="192.0.2.4"), feats(travel_speed_kmh=2000, geo_confidence_factor=0.3), EntityGraph(), REL)
    assert plain[0].p == pytest.approx(det.cal["IMPOSSIBLE_TRAVEL"]) or plain[0].p > det.cal["IMPOSSIBLE_TRAVEL"]
    assert vpn[0].p < plain[0].p
    assert "geo confidence" in vpn[0].reasons[0].detail


def test_far_from_home_is_down_weighted_on_anonymisers():
    det = BehaviourDetector()
    near_p = det.predict(feats(km_from_home=0.0))[0]
    far = det.score(login(0, enrich=False), feats(km_from_home=1500.0), EntityGraph(), REL)
    far_vpn = det.score(login(0, ip="192.0.2.4"), feats(km_from_home=1500.0, geo_confidence_factor=0.3), EntityGraph(), REL)
    p_far = far[0].p if far else near_p
    p_vpn = far_vpn[0].p if far_vpn else near_p
    assert p_vpn <= p_far
    assert near_p <= p_vpn + 1e-12


def test_vpn_alone_raises_nothing():
    det = BehaviourDetector()
    assert det.score(login(0, ip="192.0.2.4"), feats(geo_confidence_factor=0.3), EntityGraph(), REL) == []


def test_weak_rules_on_logins():
    det = BehaviourDetector()
    out = det.score(login(0, ip="185.220.101.7", browser_timezone="Asia/Kolkata"),
                    feats(tz_mismatch=1.0, device_inconsistency=1.0, device_inconsistency_mask=8.0), EntityGraph(), REL)
    codes = [r.code for r in out[0].reasons]
    assert "TZ_MISMATCH" in codes and "DEVICE_INCONSISTENT" in codes
    assert out[0].p <= 0.05                                    # weak: never a block on its own


def test_auth_session_change_is_standalone_device_inconsistency_is_not():
    det = AuthDetector()
    e = mfa(1, session_id="S1", **HIJACK)
    hit = det.score(e, feats(session_change=1.0, session_change_mask=float(1 | 4 | 64)), EntityGraph(), REL)
    assert hit and hit[0].reasons[0].code == "SESSION_CONTEXT_CHANGE" and hit[0].attack_technique == "T1539"
    assert hit[0].p == pytest.approx(0.08)
    assert det.score(e, feats(device_inconsistency=2.0, device_inconsistency_mask=9.0), EntityGraph(), REL) == []
    step_up = ev("step_up_result", {"challenge_id": "ch_1", "method": "device_push", "result": "passed", "factor_age_h": 2000}, 1, session_id="S1")
    out = det.score(step_up, feats(session_change=1.0, session_change_mask=5.0), EntityGraph(), REL)
    assert [r.code for r in out[0].reasons] == ["STEP_UP_PASSED_TRUSTED"]


# ---------------------------------------------------------------------------- pipeline: cookie theft, re-scoring
def _victim_history(store, pipe):
    feed(store, pipe, [login(d * 1440 + 600, **HOME, **PHONE) for d in range(8)])


def test_stolen_session_without_a_login_raises_evidence_and_rescores_the_case():
    store, pipe = new_pipeline()
    _victim_history(store, pipe)
    t = 8 * 1440 + 600
    feed(store, pipe, [login(t, session_id="S-live", **HOME, **PHONE)])
    # earlier the same morning: password guessing on the account from rotating ips opened a (LOW) case
    guesses = [login(t + 1 + i, result="failure", ip=f"198.18.{i}.9", dev=f"fp_bot{i}", asn="AS1", coords=None)
               for i in range(5)]
    feed(store, pipe, guesses)
    (case,) = [c for c in store.list_cases()]
    assert "ACCOUNT_DISTRIBUTED_FAILURES" in reasons_in_case(store, case.case_id)
    before = case.p_attack
    # the stolen cookie is replayed from a cloud host on another device: no login, straight to an mfa challenge
    feed(store, pipe, [mfa(t + 20, session_id="S-live", **HIJACK)])
    after = store.get_case(case.case_id)
    assert "SESSION_CONTEXT_CHANGE" in reasons_in_case(store, case.case_id)
    assert after.p_attack > before


def test_same_events_without_a_session_raise_no_session_evidence():
    store, pipe = new_pipeline()
    _victim_history(store, pipe)
    t = 8 * 1440 + 600
    feed(store, pipe, [login(t, **HOME, **PHONE), mfa(t + 20, **HIJACK)])
    assert all("SESSION_CONTEXT_CHANGE" not in reasons_in_case(store, c.case_id) for c in store.list_cases())


# ---------------------------------------------------------------------------- v3 twin/perf: hijack straight to a payee
def _session_evidence(store, event_id):
    return [(c, e) for c in store.list_cases() for e in store.list_evidence(c.case_id)
            if e.event_id == event_id and any(r.code == "SESSION_CONTEXT_CHANGE" for r in e.reasons)]


def test_stolen_session_straight_to_payee_added_joins_the_victims_case():
    """The cookie is replayed from a new network AND a new device, with no login and no MFA event: the hijacker's
    first action is adding a payee. The auth detector now evaluates its session rules on payee_added."""
    store, pipe = new_pipeline()
    _victim_history(store, pipe)
    t = 8 * 1440 + 600
    feed(store, pipe, [login(t, session_id="S-live", **HOME, **PHONE)])
    guesses = [login(t + 1 + i, result="failure", ip=f"198.18.{i}.9", dev=f"fp_bot{i}", asn="AS1", coords=None)
               for i in range(5)]
    feed(store, pipe, guesses)
    (case,) = store.list_cases()
    before = case.p_attack
    payee = ev("payee_added", {"payee_account": "A-HIJACK-9", "payee_name_match": True, "nickname": "rent"}, t + 20,
               session_id="S-live", **HIJACK)
    feed(store, pipe, [payee])
    hits = _session_evidence(store, payee.event_id)
    assert [c.case_id for c, _ in hits] == [case.case_id]                # joined the victim's existing case
    assert hits[0][0].customer == cust("C-1")
    e = hits[0][1]
    assert e.detector == "auth" and e.stage == "S2_CONTROL_TAKEOVER" and e.attack_technique == "T1539"
    assert {r.code for r in e.reasons} <= {"SESSION_CONTEXT_CHANGE", "DEVICE_INCONSISTENT"}
    assert store.get_case(case.case_id).p_attack > before


def test_stolen_session_straight_to_payee_added_opens_a_case_on_the_victim():
    store, pipe = new_pipeline()
    _victim_history(store, pipe)
    t = 8 * 1440 + 600
    feed(store, pipe, [login(t, session_id="S-live", **HOME, **PHONE)])
    assert store.list_cases() == []
    payee = ev("payee_added", {"payee_account": "A-HIJACK-9", "payee_name_match": True}, t + 20, session_id="S-live", **HIJACK)
    feed(store, pipe, [payee])
    hits = _session_evidence(store, payee.event_id)
    assert len(hits) == 1 and hits[0][0].customer == cust("C-1")


def test_session_only_types_without_a_session_change_raise_no_auth_evidence():
    store, pipe = new_pipeline()
    _victim_history(store, pipe)
    t = 8 * 1440 + 600
    feed(store, pipe, [login(t, session_id="S-ok", **HOME, **PHONE),
                       ev("payee_added", {"payee_account": "A-OK-1", "payee_name_match": True}, t + 5,
                          session_id="S-ok", **HOME, **PHONE),
                       ev("transaction", {"amount_paise": 150000, "payee_account": "A-OK-1", "channel": "UPI"}, t + 6,
                          session_id="S-ok", **HOME, **PHONE)])
    assert all(e.detector != "auth" for c in store.list_cases() for e in store.list_evidence(c.case_id))
