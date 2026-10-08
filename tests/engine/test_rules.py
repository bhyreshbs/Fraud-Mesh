"""PayPal-derived rules (PRD §16.4), each with a short synthetic event sequence through the real Pipeline."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import Envelope
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from ml.scenario import expand, load_scenario, preload_envelopes, seed_tokens

IST = timezone(timedelta(hours=5, minutes=30))
T0 = datetime(2026, 10, 9, 0, 0, tzinfo=IST)
BLR, MUMBAI = (12.9716, 77.5946), (19.076, 72.8777)
PAYPAL_CODES = {"IMPOSSIBLE_TRAVEL", "PROFILE_CHANGE_AFTER_NEW_DEVICE", "MFA_FAIL_THEN_PASS", "PUSH_SPAM",
                "CREDENTIAL_STUFFING_IP", "STRUCTURING", "PAYEE_NAME_MISMATCH", "MULE_FLOW"}


class Sim:
    """Feeds raw envelopes through a fresh Pipeline + MemoryStore and keeps every update."""

    def __init__(self) -> None:
        self.store = MemoryStore()
        self.pipe = Pipeline(self.store)
        self.pipe.startup()
        self.n = 0
        self.updates: list = []

    def send(self, event_type, payload, minutes, cust="C-1", acct="A-1", ip="49.207.10.21", dev="fp_home", asn="AS24560 Airtel",
             coords=BLR, source="demo-bank-web"):
        self.n += 1
        ctx = {"ip": ip, "device_id": dev, "asn": asn}
        if coords:
            ctx.update(lat=coords[0], lon=coords[1])
        env = Envelope(event_id=f"evt_rule{self.n:08d}", event_type=event_type, source=source,
                       occurred_at=T0 + timedelta(minutes=minutes), subject={"customer_ref": cust, "account_ref": acct},
                       context=ctx, payload=payload)
        ev = to_stored_event(env, env.occurred_at)
        self.store.insert_event(ev)
        out = self.pipe.process(ev)
        self.updates.append(out)
        return out

    def history(self, cust="C-1", acct="A-1", days=6, **kw):
        """Ordinary 20:00 logins on earlier days, so the customer is not cold-start."""
        for d in range(days, 0, -1):
            self.send("login", {"result": "success", "auth_method": "password+otp"}, -d * 24 * 60 - 4 * 60, cust=cust,
                      acct=acct, **kw)

    def evidence(self, code=None):
        out = [e for c in self.store.list_cases() for e in self.store.list_evidence(c.case_id)]
        return [e for e in out if code is None or any(r.code == code for r in e.reasons)]


def login(sim, minutes, result="success", **kw):
    return sim.send("login", {"result": result, "auth_method": "password" if result == "failure" else "password+otp"},
                    minutes, **kw)


def test_impossible_travel():
    sim = Sim()
    sim.history()
    login(sim, 0)                                                     # Bengaluru
    login(sim, 20, coords=MUMBAI)                                     # 845 km in 20 min
    (e,) = sim.evidence("IMPOSSIBLE_TRAVEL")
    assert e.detector == "behaviour" and e.p >= 0.08 and e.reasons[0].code == "IMPOSSIBLE_TRAVEL"
    calm = Sim()
    calm.history()
    login(calm, 0)
    login(calm, 60 * 20, coords=MUMBAI)                               # 845 km in 20 h is fine
    assert calm.evidence("IMPOSSIBLE_TRAVEL") == []


def test_profile_change_after_new_device():
    sim = Sim()
    sim.history()
    login(sim, 0, dev="fp_new", ip="185.220.101.7", asn="AS64500 HostCo", coords=None)
    sim.send("profile_change", {"field": "email"}, 10, dev="fp_new", ip="185.220.101.7", coords=None)
    (e,) = sim.evidence("PROFILE_CHANGE_AFTER_NEW_DEVICE")
    assert (e.detector, e.stage, e.attack_technique) == ("auth", "S2_CONTROL_TAKEOVER", "T1098")
    later = Sim()
    later.history()
    later.send("profile_change", {"field": "address"}, 0)              # from the old device
    assert later.evidence("PROFILE_CHANGE_AFTER_NEW_DEVICE") == []


def test_mfa_fail_then_pass():
    sim = Sim()
    for i, result in enumerate(["failed", "failed", "passed"]):
        sim.send("mfa_challenge", {"method": "sms_otp", "result": result}, i * 4)
    (e,) = sim.evidence("MFA_FAIL_THEN_PASS")
    assert e.attack_technique == "T1111" and e.event_id == "evt_rule00000003"
    once = Sim()
    once.send("mfa_challenge", {"method": "sms_otp", "result": "failed"}, 0)
    once.send("mfa_challenge", {"method": "sms_otp", "result": "passed"}, 3)
    assert once.evidence("MFA_FAIL_THEN_PASS") == []


def test_push_spam():
    sim = Sim()
    for i, result in enumerate(["ignored", "failed", "ignored"]):
        sim.send("mfa_challenge", {"method": "device_push", "result": result}, i * 3)
    (e,) = sim.evidence("PUSH_SPAM")
    assert e.attack_technique == "T1621" and e.event_id == "evt_rule00000003"
    two = Sim()
    for i in range(2):
        two.send("mfa_challenge", {"method": "device_push", "result": "ignored"}, i * 3)
    two.send("mfa_challenge", {"method": "device_push", "result": "ignored"}, 15)   # first one is now > 10 min old
    assert two.evidence("PUSH_SPAM") == []


def test_credential_stuffing_ip_gives_one_evidence_item_and_a_captcha():
    sim = Sim()
    for i in range(10):                                               # 10 customers, 1 IP, within 60 min
        login(sim, i * 6, result="failure", cust=f"C-{i}", acct=f"A-{i}", ip="91.200.12.7", dev=f"fp_bot{i}", coords=None)
    for i in range(10, 13):                                           # more victims within the same hour
        login(sim, 55 + i, result="failure", cust=f"C-{i}", acct=f"A-{i}", ip="91.200.12.7", dev=f"fp_bot{i}", coords=None)
    (e,) = sim.evidence("CREDENTIAL_STUFFING_IP")
    assert e.entities == [tok("ip", "91.200.12.7")] and e.detector == "netsec" and e.stage == "S0_RECON"
    assert e.event_id == "evt_rule00000010"                            # the 10th customer's failure
    (case,) = sim.store.list_cases()
    (d,) = sim.store.list_decisions(case.case_id)
    assert d.actions == ["CAPTCHA_CHALLENGE"] and d.policy_rule == "credential_stuffing" and case.band == "LOW"
    for i in range(13, 23):                                           # a new wave more than an hour later
        login(sim, 130 + i, result="failure", cust=f"C-{i}", acct=f"A-{i}", ip="91.200.12.7", dev=f"fp_bot{i}", coords=None)
    assert len(sim.evidence("CREDENTIAL_STUFFING_IP")) == 2


def test_nine_customers_is_not_stuffing():
    sim = Sim()
    for i in range(9):
        login(sim, i * 6, result="failure", cust=f"C-{i}", acct=f"A-{i}", ip="91.200.12.7", dev=f"fp_bot{i}", coords=None)
    assert sim.evidence() == []


def test_structuring_three_transfers_of_4_9_lakh():
    sim = Sim()
    sim.history()
    sim.send("payee_added", {"payee_account": "A-GOLD-1", "payee_name_match": True, "nickname": "Gold"}, -3 * 24 * 60)
    for i in range(3):
        sim.send("transaction", {"amount_paise": 49_000_000 - i * 50_000, "payee_account": "A-GOLD-1", "channel": "NEFT"},
                 i * 90)
    hits = sim.evidence("STRUCTURING")
    assert hits and all(e.detector == "txn" and e.p >= 0.12 for e in hits)
    assert hits[-1].event_id == "evt_rule00000010"                     # the third transfer
    assert all(e.reasons[0].code == "STRUCTURING" for e in hits)


def test_one_near_limit_transfer_is_not_structuring():
    sim = Sim()
    sim.history()
    sim.send("payee_added", {"payee_account": "A-GOLD-1", "payee_name_match": True, "nickname": "Gold"}, -3 * 24 * 60)
    sim.send("transaction", {"amount_paise": 49_000_000, "payee_account": "A-GOLD-1", "channel": "NEFT"}, 0)
    sim.send("transaction", {"amount_paise": 30_000_000, "payee_account": "A-GOLD-1", "channel": "NEFT"}, 60)
    assert sim.evidence("STRUCTURING") == []


def test_payee_name_mismatch():
    sim = Sim()
    sim.send("payee_added", {"payee_account": "A-X1", "payee_name_match": False, "nickname": "Rent"}, 0)
    (e,) = sim.evidence("PAYEE_NAME_MISMATCH")
    assert e.detector == "graph" and e.p == pytest.approx(0.03) and e.stage == "S5_POSITIONING"
    ok = Sim()
    ok.send("payee_added", {"payee_account": "A-X1", "payee_name_match": True, "nickname": "Rent"}, 0)
    ok.send("payee_added", {"payee_account": "A-X2", "nickname": "Rent"}, 1)          # None is not a mismatch
    assert ok.evidence() == []


def test_mule_flow_by_fan_in():
    sim = Sim()
    for i in range(5):
        sim.send("transaction", {"amount_paise": 2_500_000, "payee_account": "A-MULE-9", "channel": "IMPS"}, i * 10,
                 cust=f"C-{i}", acct=f"A-{i}", ip=f"49.207.{20 + i}.5", dev=f"fp_{i}")
    assert sim.evidence("MULE_FLOW") == []                             # fan-in reaches 5 only after the 5th
    sim.send("payee_added", {"payee_account": "A-MULE-9", "nickname": "Refund"}, 60, cust="C-9", acct="A-9",
             ip="49.207.40.5", dev="fp_9")
    (e,) = sim.evidence("MULE_FLOW")
    assert e.detector == "graph" and e.p == pytest.approx(0.03) and "fan-in 5" in e.reasons[0].detail


def test_mule_flow_by_pass_through_and_multiplier():
    sim = Sim()
    sim.send("transaction", {"amount_paise": 10_000_000, "payee_account": "A-PASS", "channel": "IMPS"}, 0,
             cust="C-1", acct="A-1")
    sim.send("transaction", {"amount_paise": 9_500_000, "payee_account": "A-ELSEWHERE", "channel": "IMPS"}, 30,
             cust="C-PASS", acct="A-PASS", ip="49.207.50.5", dev="fp_pass")
    sim.send("payee_added", {"payee_account": "A-PASS", "payee_name_match": False, "nickname": "x"}, 60, cust="C-2",
             acct="A-2", ip="49.207.51.5", dev="fp_2")
    (e,) = sim.evidence("MULE_FLOW")
    assert {r.code for r in e.reasons} == {"PAYEE_NAME_MISMATCH", "MULE_FLOW"}
    assert e.p == pytest.approx(0.045)                                 # max(0·1.5, 0.03) then ×1.5


def test_mule_fanin_scenario_flags_the_mule_in_one_case():
    sc = load_scenario(str(Path(__file__).resolve().parents[2] / "scenarios" / "mule_fanin.yaml"))
    sim = Sim()
    for e in preload_envelopes(sc, sc.default_start) + expand(sc, sc.default_start, "direct"):
        ev = to_stored_event(e, e.occurred_at)
        sim.store.insert_event(ev)
        sim.pipe.process(ev)
    flows = sim.evidence("MULE_FLOW")
    assert len(flows) >= 6                                             # every sender from the 6th on
    owners = {c.case_id for c in sim.store.list_cases() for e in sim.store.list_evidence(c.case_id)
              if any(r.code == "MULE_FLOW" for r in e.reasons)}
    assert len(owners) == 1                                            # one case per attack


def test_rules_do_not_touch_the_midnight_path():
    """§16.4: the PayPal-derived rules must not change the Midnight ATO path."""
    sc = load_scenario(str(Path(__file__).resolve().parents[2] / "scenarios" / "midnight_ato.yaml"))
    sim = Sim()
    for e in preload_envelopes(sc, sc.default_start):
        ev = to_stored_event(e, e.occurred_at)
        sim.store.insert_event(ev)
        sim.pipe.process(ev)
    sim.pipe.set_seeds(seed_tokens(sc))
    for e in expand(sc, sc.default_start, "direct"):
        ev = to_stored_event(e, e.occurred_at)
        sim.store.insert_event(ev)
        sim.pipe.process(ev)
    codes = {r.code for e in sim.evidence() for r in e.reasons}
    assert not codes & PAYPAL_CODES, codes & PAYPAL_CODES


def two_day_ato(sim: Sim) -> list[str]:
    """Day 1: takeover (new-device login, then an SMS-number change → S2). Day 2, 30 h later: weak KYC and a big
    transfer to a fresh payee. Returns the case id of every update."""
    att = {"ip": "185.220.101.7", "dev": "fp_attacker_01", "asn": "AS64500 HostCo", "coords": None}
    sim.history()
    out = []
    out += sim.send("login", {"result": "success", "auth_method": "password+otp"}, 41, **att)
    out += sim.send("mfa_change", {"factor": "sms", "action": "replace", "new_phone": "+91 90000 11111"}, 44, **att)
    day2 = 30 * 60 + 44
    out += sim.send("kyc_result", {"liveness_score": 0.35, "face_match_score": 0.8, "doc_tamper_score": 0.1,
                                   "injection_suspected": False, "reason": "re_verification"}, day2, **att)
    out += sim.send("payee_added", {"payee_account": "A-NEWPAYEE-1", "nickname": "Loan"}, day2 + 5, **att)
    out += sim.send("transaction", {"amount_paise": 45_000_000, "payee_account": "A-NEWPAYEE-1", "channel": "IMPS"},
                    day2 + 8, **att)
    return [u.case.case_id for u in out]


def test_sticky_two_day_ato_stays_one_case():
    sim = Sim()
    ids = two_day_ato(sim)
    assert len(ids) >= 4 and len(set(ids)) == 1
    case = sim.store.get_case(ids[0])
    assert case.customer == tok("cust", "C-1") and "S2_CONTROL_TAKEOVER" in case.stages and "S6_MONETIZATION" in case.stages


def test_without_sticky_the_second_day_would_open_a_new_case(monkeypatch):
    from engine.cases import joiner
    monkeypatch.setattr(joiner, "STICKY_ENABLED", False)
    assert len(set(two_day_ato(Sim()))) == 2
