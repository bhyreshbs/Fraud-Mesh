"""v3 phase 10: insider rules in the cyber detector (rules/insider.yaml). A trusted corporate IP never whitelists them."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import Envelope
from engine.detectors.cyber import CyberDetector
from engine.graph.store import EntityGraph
from tests.engine.test_v3_graph_mule import codes_for, play, step_cases

IST = timezone(timedelta(hours=5, minutes=30))
T0 = datetime(2026, 10, 9, 14, 0, tzinfo=IST)                 # office hours
REL = {"cyber": (5.0, 5.0)}


def _ev(event_type, payload, at, cust=None, dev=None, ip=None, source="demo-bank-web", n=[0]):
    n[0] += 1
    env = Envelope(event_id=f"evt_v3ins{n[0]:08d}", event_type=event_type, source=source, occurred_at=at,
                   subject={"customer_ref": cust, "account_ref": f"A-{cust}"} if cust else {},
                   context={"device_id": dev, "ip": ip} if dev else {}, payload=payload)
    return to_stored_event(env, at)


def _login(cust, dev, at):
    return _ev("login", {"result": "success", "auth_method": "password+otp"}, at, cust=cust, dev=dev, ip="49.207.77.1")


def _cloud(action, cust, at, ip="10.0.4.7", actor="svc-support-21"):
    return _ev("cloud_audit", {"actor_type": "support_console", "actor_identity": actor, "action": action,
                               "target_customer": cust, "src_ip": ip, "result": "success"}, at, source="cloud-audit")


def _score(graph, ev):
    graph.apply(ev)
    return CyberDetector().score(ev, {"cid_profile_reads_10m": 0}, graph, REL)


def test_trusted_ip_does_not_whitelist_a_change_right_after_a_new_device_login():
    g = EntityGraph()
    g.apply(_login("C-INS1", "fp_old", T0 - timedelta(days=10)))
    g.apply(_login("C-INS1", "fp_new", T0 - timedelta(minutes=20)))
    (e,) = _score(g, _cloud("UpdateTransferLimit", "C-INS1", T0))          # 10.0.4.7 is a corporate IP
    assert [r.code for r in e.reasons] == ["INSIDER_CHANGE_AFTER_NEW_DEVICE_LOGIN"]
    assert (e.stage, e.p, e.attack_technique) == ("S4_ESCALATION", 0.04, "T1098")
    assert tok("cust", "C-INS1") in e.entities


def test_no_new_device_no_insider_hit_and_reads_are_not_sensitive():
    g = EntityGraph()
    g.apply(_login("C-INS2", "fp_old2", T0 - timedelta(days=10)))
    assert _score(g, _cloud("UpdateTransferLimit", "C-INS2", T0)) == []    # corporate IP, no new device: nothing
    g.apply(_login("C-INS2", "fp_new2", T0 - timedelta(minutes=5)))
    assert _score(g, _cloud("ReadCustomerProfile", "C-INS2", T0)) == []    # not a sensitive action
    # a first-ever device (no established one) is a new customer, not a takeover sign
    g.apply(_login("C-INS3", "fp_only3", T0 - timedelta(minutes=5)))
    assert _score(g, _cloud("ResetCustomerMfa", "C-INS3", T0)) == []


def test_repeated_sensitive_actions_and_off_hours_corroboration():
    g = EntityGraph()
    for i in range(2):
        _score(g, _cloud("ReadCustomerProfile", f"C-R{i}", T0 + timedelta(minutes=i), actor="svc-support-31"))
    (e,) = _score(g, _cloud("UnlockAccount", "C-R9", T0 + timedelta(minutes=5), actor="svc-support-31"))
    assert [r.code for r in e.reasons] == ["INSIDER_REPEATED_SENSITIVE_ACTIONS"] and e.p == 0.03
    night = datetime(2026, 10, 9, 23, 30, tzinfo=IST)
    g2 = EntityGraph()
    assert _score(g2, _cloud("UpdateTransferLimit", "C-N1", night)) == []   # off hours alone never fires
    g2.apply(_login("C-N1", "fp_n_old", night - timedelta(days=3)))
    g2.apply(_login("C-N1", "fp_n_new", night - timedelta(minutes=30)))
    (e2,) = _score(g2, _cloud("UpdateTransferLimit", "C-N1", night))
    assert {r.code for r in e2.reasons} == {"INSIDER_CHANGE_AFTER_NEW_DEVICE_LOGIN", "INSIDER_SENSITIVE_OFF_HOURS"}


def test_untrusted_ip_rule_keeps_its_p_stage_and_order_when_insider_rules_also_fire():
    g = EntityGraph()
    g.apply(_login("C-INS4", "fp_old4", T0 - timedelta(days=10)))
    g.apply(_login("C-INS4", "fp_new4", T0 - timedelta(minutes=10)))
    (e,) = _score(g, _cloud("UpdateTransferLimit", "C-INS4", T0, ip="185.220.101.7"))
    assert [r.code for r in e.reasons][0] == "cloud_limit_raise_untrusted_ip"
    assert (e.stage, e.p) == ("S4_ESCALATION", 0.04)
    assert "INSIDER_CHANGE_AFTER_NEW_DEVICE_LOGIN" in {r.code for r in e.reasons}


def test_insider_trusted_network_scenario():
    store, _, steps, _ = play("insider_trusted_network")
    codes = codes_for(store, steps)
    assert {"INSIDER_CHANGE_AFTER_NEW_DEVICE_LOGIN", "INSIDER_REPEATED_SENSITIVE_ACTIONS",
            "INSIDER_SENSITIVE_OFF_HOURS"} <= codes
    assert not {"cloud_limit_raise_untrusted_ip", "mfa_reset_by_support_untrusted_ip"} & codes   # the IP is trusted
    anita = tok("cust", "C-ANITA-01")
    cloud = [s for s in steps if s.event_type == "cloud_audit" and s.payload["target_customer"] == anita]
    owners = {c.case_id for c in step_cases(store, cloud) if anita in c.entities}
    assert len(owners) == 1
