"""Detector unit tests (PRD §10.4): each rule, the emission threshold, reliability, entities and degraded modes."""
from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone

import pytest

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import Envelope
from engine.detectors import models as models_mod
from engine.detectors.auth import AuthDetector
from engine.detectors.base import DETECTOR_HANDLES, reliability
from engine.detectors.behaviour import BehaviourDetector
from engine.detectors.cyber import CyberDetector
from engine.detectors.graph_det import GraphDetector
from engine.detectors.kyc import KycDetector
from engine.detectors.netsec import NetsecDetector
from engine.detectors.registry import default_detectors
from engine.detectors.txn import TxnDetector
from engine.features.features import FEATURE_NAMES, NONE_RECENT_MIN
from engine.graph.store import EntityGraph
from engine.store_memory import RELIABILITY_SEED

T0 = datetime(2026, 10, 9, 0, 39, tzinfo=timezone(timedelta(hours=5, minutes=30)))
REL = dict(RELIABILITY_SEED)
_n = 0


def ev(event_type, payload, cust="C-1042", acct="A-88213", ip="185.220.101.7", dev="fp_attacker_01", source="demo-bank-web"):
    global _n
    _n += 1
    env = Envelope(event_id=f"evt_det{_n:08d}", event_type=event_type, source=source, occurred_at=T0,
                   subject={"customer_ref": cust, "account_ref": acct}, context={"ip": ip, "device_id": dev},
                   payload=payload)
    return to_stored_event(env, T0)


def feats(**kw) -> dict:
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    f.update(amount_to_median_30d=1.0, minutes_since_payee_added=NONE_RECENT_MIN, minutes_since_new_device=NONE_RECENT_MIN,
             minutes_since_mfa_change=NONE_RECENT_MIN, past_logins_30d=20.0)
    f.update(kw)
    return f


G = EntityGraph()


def test_registry_order_and_handles():
    dets = default_detectors()
    assert [d.id for d in dets] == ["netsec", "behaviour", "auth", "kyc", "cyber", "graph", "txn"]
    assert all(d.handles == DETECTOR_HANDLES[d.id] for d in dets)


def test_reliability_is_floored():
    assert reliability(REL, "txn") == pytest.approx(0.85)
    assert reliability({"cyber": (1, 9)}, "cyber") == 0.2


# ---------------------------------------------------------------------------- netsec
IDS = {"src_ip": "185.220.101.7", "dest_ip": "10.0.1.20", "dest_port": 443, "signature_id": 9000001,
       "signature": "FM LOCAL credential stuffing against /api/login", "category": "Attempted User Privilege Gain", "severity": 2}


def test_netsec_ids_alert():
    (e,) = NetsecDetector().score(ev("network_ids_alert", IDS, cust=None, acct=None, ip=None, dev=None, source="network-ids"),
                                  feats(), G, REL)
    assert (e.detector, e.family, e.stage, e.p, e.reliability) == ("netsec", "cyber", "S0_RECON", 0.03, 0.5)
    assert e.attack_technique == "T1110.004" and e.reasons[0].code == "IDS_SEV2"
    assert e.entities == [tok("ip", "185.220.101.7")]


def test_netsec_severities_and_threshold():
    d = NetsecDetector()
    sev1 = d.score(ev("network_ids_alert", {**IDS, "severity": 1, "signature_id": 1}, cust=None, acct=None, ip=None, dev=None,
                      source="network-ids"), feats(), G, REL)
    assert sev1[0].p == 0.05 and sev1[0].attack_technique is None                       # unmapped SID
    assert d.score(ev("network_ids_alert", {**IDS, "severity": 3}, cust=None, acct=None, ip=None, dev=None,
                      source="network-ids"), feats(), G, REL) == []                      # 0.015 < 0.02
    assert d.score(ev("login", {"result": "failure", "auth_method": "password"}), feats(), G, REL) == []


# ---------------------------------------------------------------------------- auth
def test_mfa_changed_after_new_device():
    mfa = ev("mfa_change", {"factor": "sms", "action": "replace", "new_phone": "+91 90000 11111"})
    (e,) = AuthDetector().score(mfa, feats(minutes_since_new_device=3), G, REL)
    assert (e.stage, e.p, e.attack_technique, e.reasons[0].code) == ("S2_CONTROL_TAKEOVER", 0.06, "T1556.006",
                                                                     "MFA_CHANGED_AFTER_NEW_DEVICE")
    assert AuthDetector().score(mfa, feats(minutes_since_new_device=61), G, REL) == []


@pytest.mark.parametrize("result,age,code,p", [
    ("passed", 0.13, "STEP_UP_PASSED_WITH_FRESH_FACTOR", 0.08),
    ("passed", 2160, "STEP_UP_PASSED_TRUSTED", 0.003),
    ("failed", 2160, "STEP_UP_FAILED_OR_TIMEOUT", 0.05),
    ("timeout", 100, "STEP_UP_FAILED_OR_TIMEOUT", 0.05),
    ("denied_by_customer", 2160, "CUSTOMER_DENIED", 0.01),
])
def test_step_up_results(result, age, code, p):
    su = ev("step_up_result", {"challenge_id": "chl_direct", "method": "device_push", "result": result, "factor_age_h": age})
    (e,) = AuthDetector().score(su, feats(), G, REL)
    assert e.reasons[0].code == code and e.p == pytest.approx(p)


def test_step_up_failed_with_fresh_factor_is_not_a_rule():
    su = ev("step_up_result", {"challenge_id": "chl_direct", "method": "sms_otp", "result": "failed", "factor_age_h": 1})
    assert AuthDetector().score(su, feats(), G, REL) == []


def test_recent_sim_swap():
    assert AuthDetector().score(ev("sim_signal", {"sim_change_age_h": 5}), feats(), G, REL)[0].reasons[0].code == "RECENT_SIM_SWAP"
    assert AuthDetector().score(ev("sim_signal", {"sim_change_age_h": 80}), feats(), G, REL) == []


# ---------------------------------------------------------------------------- kyc
def test_kyc_rules_one_item_highest_p_all_reasons():
    k = {"liveness_score": 0.38, "face_match_score": 0.6, "doc_tamper_score": 0.7, "injection_suspected": True,
         "reason": "re_verification"}
    (e,) = KycDetector().score(ev("kyc_result", k), feats(), G, REL)
    assert e.p == 0.12 and [r.code for r in e.reasons] == ["INJECTION_SUSPECTED", "LOW_LIVENESS", "DOC_TAMPER", "LOW_FACE_MATCH"]
    assert e.stage == "S3_IDENTITY_MANIPULATION"
    ok = {**k, "liveness_score": 0.94, "face_match_score": 0.9, "doc_tamper_score": 0.1, "injection_suspected": False}
    assert KycDetector().score(ev("kyc_result", ok), feats(), G, REL) == []


# ---------------------------------------------------------------------------- cyber
def cloud(action, src_ip="185.220.101.7", actor_type="support_console"):
    return ev("cloud_audit", {"actor_type": actor_type, "actor_identity": "svc-support-07", "action": action,
                              "target_customer": "C-1042", "src_ip": src_ip, "result": "success"},
              cust=None, acct=None, ip=None, dev=None, source="cloud-audit")


def test_cyber_limit_raise_from_untrusted_ip():
    (e,) = CyberDetector().score(cloud("UpdateTransferLimit"), feats(), G, REL)
    assert (e.stage, e.p, e.attack_technique) == ("S4_ESCALATION", 0.04, "T1098")
    assert set(e.entities) == {tok("cid", "svc-support-07"), tok("ip", "185.220.101.7"), tok("cust", "C-1042")}
    assert CyberDetector().score(cloud("UpdateTransferLimit", src_ip="10.0.4.7"), feats(), G, REL) == []   # corporate


def test_cyber_mfa_reset_and_bulk_reads():
    (e,) = CyberDetector().score(cloud("ResetCustomerMfa"), feats(), G, REL)
    assert e.stage == "S2_CONTROL_TAKEOVER" and e.reasons[0].code == "mfa_reset_by_support_untrusted_ip"
    read = cloud("ReadCustomerProfile", src_ip="10.0.4.7")
    (bulk,) = CyberDetector().score(read, feats(cid_profile_reads_10m=20), G, REL)
    assert bulk.stage == "S0_RECON" and bulk.attack_technique == "T1530"
    assert CyberDetector().score(read, feats(cid_profile_reads_10m=19), G, REL) == []


# ---------------------------------------------------------------------------- graph
def _graph_with_mule():
    g = EntityGraph()
    for cust, acct in (("C-RAVI-01", "A-RAVI-778"), ("C-MULE-01", "A-MULE-01")):
        g.apply(ev("login", {"result": "success", "auth_method": "password"}, cust=cust, acct=acct, ip="103.21.4.9",
                   dev="fp_mule_shared"))
    g.set_seeds([tok("dev", "fp_mule_shared"), tok("acct", "A-MULE-01")])
    return g


def test_graph_seed_distances():
    g, d = _graph_with_mule(), GraphDetector()
    (e,) = d.score(ev("payee_added", {"payee_account": "A-RAVI-778", "nickname": "Rent"}), feats(), g, REL)
    assert (e.p, e.reasons[0].code, e.stage, e.attack_technique) == (0.10, "SEED_DISTANCE_1", "S5_POSITIONING", "T1657")
    (zero,) = d.score(ev("payee_added", {"payee_account": "A-MULE-01", "nickname": "x"}), feats(), g, REL)
    assert zero.reasons[0].code == "SEED_DISTANCE_0" and zero.p == 0.30
    assert d.score(ev("payee_added", {"payee_account": "A-UNKNOWN", "nickname": "x"}), feats(), g, REL) == []


def test_graph_transactions_only_to_payees_not_just_added():
    g, d = _graph_with_mule(), GraphDetector()
    t = ev("transaction", {"amount_paise": 100, "payee_account": "A-RAVI-778", "channel": "UPI"})
    assert d.score(t, feats(payee_is_new=1.0), g, REL) == []
    assert d.score(t, feats(payee_is_new=0.0), g, REL)[0].reasons[0].code == "SEED_DISTANCE_1"


def test_graph_weak_single_path_is_capped():
    g = EntityGraph()
    g.apply(ev("login", {"result": "success", "auth_method": "password"}, cust="C-X", acct="A-X", ip="103.40.1.9", dev="fp_x"))
    g.apply(ev("login", {"result": "success", "auth_method": "password"}, cust="C-Y", acct="A-Y", ip="103.40.1.10", dev="fp_y"))
    g.set_seeds([tok("dev", "fp_y")])                                   # A-X → fp_x → ip (0.5) → fp_y: 3 hops, weak
    (e,) = GraphDetector().score(ev("payee_added", {"payee_account": "A-X", "nickname": "x"}), feats(), g, REL)
    assert [r.code for r in e.reasons] == ["SEED_DISTANCE_3", "WEAK_PATH_CAP"] and e.p == 0.02


# ---------------------------------------------------------------------------- behaviour
LOGIN = {"result": "success", "auth_method": "password+otp"}


def test_behaviour_flags_new_device_and_asn():
    (e,) = BehaviourDetector().score(ev("login", LOGIN), feats(device_first_seen=1, asn_first_seen=1, hour_deviation=4.7), G, REL)
    assert e.stage == "S1_INITIAL_ACCESS" and e.attack_technique == "T1078" and e.p > 0.5
    assert {r.code for r in e.reasons} == {"NEW_DEVICE", "NEW_ASN"} and not e.degraded


def test_behaviour_ordinary_login_is_not_emitted():
    assert BehaviourDetector().score(ev("login", LOGIN), feats(hour_deviation=0.5), G, REL) == []
    assert BehaviourDetector().score(ev("login", {"result": "failure", "auth_method": "password"}),
                                     feats(device_first_seen=1, asn_first_seen=1), G, REL) == []


def test_behaviour_cold_start_uses_the_population_rate():
    d = BehaviourDetector()
    p, _ = d.predict(feats(device_first_seen=1, asn_first_seen=1, hour_deviation=5))
    assert p > 0.02
    assert d.score(ev("login", LOGIN), feats(device_first_seen=1, asn_first_seen=1, hour_deviation=5, past_logins_30d=4),
                   G, REL) == []                                         # COLD_START p = 0.01 < 0.02


# ---------------------------------------------------------------------------- txn
TXN = {"amount_paise": 48_000_000, "payee_account": "A-RAVI-778", "channel": "IMPS"}
ATO_TXN = feats(log_amount=13.08, amount_to_median_30d=60, payee_is_new=1, minutes_since_payee_added=2,
                minutes_since_new_device=24, hour_deviation=4.9)


def test_txn_model_scores_an_ato_transfer_with_shap():
    (e,) = TxnDetector().score(ev("transaction", TXN), ATO_TXN, G, REL)
    assert e.stage == "S6_MONETIZATION" and e.p > 0.5 and e.amount_paise == 48_000_000 and not e.degraded
    assert len(e.shap) == 5 and 1 <= len(e.reasons) <= 3
    assert all(abs(a.shap) >= abs(b.shap) for a, b in zip(e.shap, e.shap[1:], strict=False))
    assert e.detector_version.startswith("txn_v1:")


def test_txn_ordinary_payment_is_not_emitted():
    # A customer with login history paying a usual amount to a known payee, a little off their usual hour.
    assert TxnDetector().score(ev("transaction", {**TXN, "amount_paise": 750_000}),
                               feats(log_amount=8.9, amount_to_median_30d=0.9, hour_deviation=1.5), G, REL) == []


def test_txn_payment_from_a_dormant_account_is_weak_evidence():
    # No login in 30 days (hour_deviation is exactly 0 only then): the model trained with IEEE-CIS learned that a payment
    # with no prior session is riskier. Alone it stays far below MEDIUM (fusion caps one item at +3 x reliability).
    (e,) = TxnDetector().score(ev("transaction", {**TXN, "amount_paise": 750_000}),
                               feats(log_amount=8.9, amount_to_median_30d=0.9, hour_deviation=0.0), G, REL)
    assert 0.02 <= e.p < 0.5


@pytest.fixture
def broken_model_dir(tmp_path, monkeypatch):
    for f in ("manifest.json", "txn_v1.joblib", "behaviour_v1.joblib"):
        shutil.copy(models_mod.model_dir() / f, tmp_path / f)
    (tmp_path / "txn_v1.joblib").write_bytes((tmp_path / "txn_v1.joblib").read_bytes() + b"tampered")
    (tmp_path / "behaviour_v1.joblib").unlink()
    monkeypatch.setattr(models_mod, "model_dir", lambda: tmp_path)
    return tmp_path


def test_txn_degraded_mode_on_sha_mismatch(broken_model_dir):
    d = TxnDetector()
    assert d.model is None and "sha256 mismatch" in d.version
    (e,) = d.score(ev("transaction", TXN), ATO_TXN, G, REL)
    assert e.degraded and e.p == 0.15 and e.reasons[0].code == "DEGRADED_HIGH" and e.shap is None
    assert d.score(ev("transaction", TXN), feats(amount_to_median_30d=2), G, REL) == []   # DEGRADED_LOW 0.005


def test_behaviour_without_artifact_is_cold_start(broken_model_dir):
    d = BehaviourDetector()
    assert d.model is None and "missing" in d.version
    assert d.score(ev("login", LOGIN), feats(device_first_seen=1, asn_first_seen=1), G, REL) == []
