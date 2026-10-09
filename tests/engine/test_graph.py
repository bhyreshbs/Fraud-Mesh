"""Entity graph (PRD §7.1, §10.2) and the D2-P1 graph acceptance checks (§16.1)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import Envelope
from engine.graph.resolve import CGNAT_FILE, cgnat_tokens, edges_for_event, load_cgnat_networks
from engine.graph.store import EntityGraph
from engine.store_memory import MemoryStore
from ml.scenario import load_scenario, preload_envelopes, seed_tokens

T0 = datetime(2026, 10, 9, 0, 39, tzinfo=timezone(timedelta(hours=5, minutes=30)))
CGNAT_IP = "49.36.128.77"                      # inside 49.36.128.0/24, listed in cgnat.txt
_n = 0


def env(event_type: str, payload: dict, *, cust=None, acct=None, ip=None, dev=None, at=T0, source="simulator"):
    global _n
    _n += 1
    e = Envelope(event_id=f"evt_graph{_n:08d}", event_type=event_type, source=source, occurred_at=at,
                 subject={"customer_ref": cust, "account_ref": acct}, context={"ip": ip, "device_id": dev},
                 payload=payload)
    return to_stored_event(e, at)


def login(cust, acct, ip, dev, at=T0, result="success"):
    return env("login", {"result": result, "auth_method": "password"}, cust=cust, acct=acct, ip=ip, dev=dev, at=at)


def edge_set(edges):
    return {(e.edge_type, e.src, e.dst, e.confidence) for e in edges}


def apply_all(graph: EntityGraph, store: MemoryStore, events):
    for ev in events:
        store.upsert_edges(graph.apply(ev))


# ---------------------------------------------------------------------------- §7.1 edge table
def test_login_edges():
    ev = login("C-1", "A-1", "103.21.4.9", "fp_1")
    assert edge_set(edges_for_event(ev)) == {
        ("LOGGED_IN_FROM", tok("acct", "A-1"), tok("dev", "fp_1"), 0.9),
        ("CONNECTED_VIA", tok("dev", "fp_1"), tok("ip", "103.21.4.9"), 0.5),
        ("OWNS", tok("cust", "C-1"), tok("acct", "A-1"), 1.0)}
    (e,) = [e for e in edges_for_event(ev) if e.edge_type == "OWNS"]
    assert e.count == 1 and e.source_event_ids == [ev.event_id] and e.first_seen == e.last_seen == ev.occurred_at


def test_failed_login_creates_no_identity_link():
    ev = login("C-1", "A-1", "103.21.4.9", "fp_1", result="failure")
    assert {e.edge_type for e in edges_for_event(ev)} == {"CONNECTED_VIA", "OWNS"}


def test_mfa_change_edges():
    ev = env("mfa_change", {"factor": "sms", "action": "replace", "new_phone": "+91 90000 11111"},
             cust="C-1042", ip="185.220.101.7", dev="fp_attacker_01")
    phone = tok("phone", "9000011111")
    assert edge_set(edges_for_event(ev)) == {("RESET", tok("dev", "fp_attacker_01"), phone, 0.9),
                                             ("HAS_PHONE", tok("cust", "C-1042"), phone, 1.0)}


def test_payee_and_transaction_edges():
    added = env("payee_added", {"payee_account": "A-RAVI-778", "payee_name_match": True, "nickname": "Rent"},
                cust="C-1042", acct="A-88213", ip="185.220.101.7", dev="fp_attacker_01")
    sent = env("transaction", {"amount_paise": 48000000, "payee_account": "a-ravi-778 ", "channel": "IMPS"},
               cust="C-1042", acct="A-88213", ip="185.220.101.7", dev="fp_attacker_01")
    payee = tok("acct", "A-RAVI-778")                  # acct normalisation: trim, upper-case
    assert edge_set(edges_for_event(added)) == {("ADDED_PAYEE", tok("acct", "A-88213"), payee, 0.9)}
    assert edge_set(edges_for_event(sent)) == {("SENT", tok("acct", "A-88213"), payee, 1.0)}


def test_cloud_audit_edges():
    ev = env("cloud_audit", {"actor_type": "support_console", "actor_identity": "svc-support-07",
                             "action": "UpdateTransferLimit", "target_customer": "C-1042", "src_ip": "185.220.101.7",
                             "result": "success"}, source="cloud-audit")
    cid = tok("cid", "svc-support-07")
    assert edge_set(edges_for_event(ev)) == {("ACTED_FROM", cid, tok("ip", "185.220.101.200"), 0.7),   # same /24
                                             ("ACCESSED", cid, tok("cust", "C-1042"), 0.8)}


@pytest.mark.parametrize("event_type,payload", [
    ("network_ids_alert", {"src_ip": "185.220.101.7", "dest_ip": "10.0.1.20", "dest_port": 443, "signature_id": 9000001,
                           "signature": "x", "category": "y", "severity": 2}),
    ("kyc_result", {"liveness_score": 0.38, "face_match_score": 0.81, "doc_tamper_score": 0.12,
                    "injection_suspected": False, "reason": "re_verification"}),
    ("step_up_result", {"challenge_id": "chl_direct", "method": "sms_otp", "result": "passed", "factor_age_h": 0.13}),
    ("mfa_challenge", {"method": "device_push", "result": "failed"}),
    ("sim_signal", {"sim_change_age_h": 3}),
    ("profile_change", {"field": "email"}),
])
def test_events_without_edges(event_type, payload):
    ev = env(event_type, payload, cust="C-1042", ip="185.220.101.7", dev="fp_attacker_01")
    assert edges_for_event(ev) == []


def test_network_ids_alert_only_entity_is_its_src_ip_token():
    ev = env("network_ids_alert", {"src_ip": "185.220.101.7", "dest_ip": "10.0.1.20", "dest_port": 443,
                                   "signature_id": 9000001, "signature": "x", "category": "y", "severity": 2},
             source="network-ids")
    assert ev.entity_tokens == [tok("ip", "185.220.101.7")]
    assert ev.payload["dest_ip"] == "10.0.1.20"                          # not tokenized
    assert EntityGraph().apply(ev) == []


# ---------------------------------------------------------------------------- upsert, rebuild
def test_graph_merge_matches_store_upsert():
    g, store = EntityGraph(), MemoryStore()
    apply_all(g, store, [login("C-1", "A-1", "103.21.4.9", "fp_1", at=T0),
                         login("C-1", "A-1", "103.21.4.9", "fp_1", at=T0 + timedelta(hours=1))])
    assert sorted(g.edges(), key=lambda e: (e.src, e.dst, e.edge_type)) == store.load_edges()
    e = g.get_edge(tok("acct", "A-1"), tok("dev", "fp_1"), "LOGGED_IN_FROM")
    assert e.count == 2 and e.first_seen == T0 and e.last_seen == T0 + timedelta(hours=1)
    rebuilt = EntityGraph()
    rebuilt.load(store.load_edges(), store.list_fraud_seeds())
    assert sorted(rebuilt.edges(), key=lambda e: (e.src, e.dst, e.edge_type)) == store.load_edges()


def test_reverse_direction_edges_are_kept_apart():
    g, store = EntityGraph(), MemoryStore()
    a, b = tok("acct", "A-1"), tok("acct", "A-2")
    apply_all(g, store, [env("transaction", {"amount_paise": 100, "payee_account": "A-2", "channel": "UPI"}, acct="A-1"),
                         env("transaction", {"amount_paise": 100, "payee_account": "A-1", "channel": "UPI"}, acct="A-2")])
    assert g.get_edge(a, b, "SENT").count == 1 and g.get_edge(b, a, "SENT").count == 1
    assert len(store.load_edges()) == 2


# ---------------------------------------------------------------------------- SHARES_DEVICE
def test_shares_device_links_two_customers_on_one_device():
    g, store = EntityGraph(), MemoryStore()
    apply_all(g, store, [login("C-1", "A-1", "103.21.4.9", "fp_shared", at=T0)])
    new = g.apply(login("C-2", "A-2", "103.21.4.9", "fp_shared", at=T0 + timedelta(days=3)))
    shares = [e for e in new if e.edge_type == "SHARES_DEVICE"]
    c1, c2 = sorted((tok("cust", "C-1"), tok("cust", "C-2")))
    assert [(e.src, e.dst, e.confidence) for e in shares] == [(c1, c2, 0.9)]


def test_shares_device_needs_both_logins_within_30_days():
    g = EntityGraph()
    g.apply(login("C-1", "A-1", "103.21.4.9", "fp_shared", at=T0))
    new = g.apply(login("C-2", "A-2", "103.21.4.9", "fp_shared", at=T0 + timedelta(days=31)))
    assert not [e for e in new if e.edge_type == "SHARES_DEVICE"]


# ---------------------------------------------------------------------------- CGNAT
def test_cgnat_file_parses_and_includes_the_test_ip():
    nets = load_cgnat_networks(CGNAT_FILE)
    assert nets and all(n.prefixlen in (24, 64) for n in nets)
    assert tok("ip", CGNAT_IP) in cgnat_tokens(nets)


def test_cgnat_connected_via_has_zero_confidence():
    g = EntityGraph()
    new = g.apply(login("C-1", "A-1", CGNAT_IP, "fp_1"))
    (cv,) = [e for e in new if e.edge_type == "CONNECTED_VIA"]
    assert cv.confidence == 0.0
    assert g.is_excluded(tok("ip", CGNAT_IP))


def test_a_cgnat_ip_links_nobody():
    """§16.1: two unrelated customers behind one carrier NAT stay unlinked, even next to a fraud seed."""
    g = EntityGraph()
    g.apply(login("C-1", "A-1", CGNAT_IP, "fp_one"))
    g.apply(login("C-2", "A-2", "49.36.128.12", "fp_two"))             # same CGNAT /24
    g.set_seeds([tok("dev", "fp_two")])
    ip = tok("ip", CGNAT_IP)
    for cust, acct, dev in (("C-1", "A-1", "fp_one"), ("C-2", "A-2", "fp_two")):
        for start in (tok("cust", cust), tok("acct", acct), tok("dev", dev)):
            reach = g.neighbours_within(start, hops=5, min_conf=0.0)
            assert ip not in reach
            assert not {tok("cust", "C-1"), tok("cust", "C-2")} - {start} <= set(reach)
    assert g.seed_distance(tok("acct", "A-1"), max_hops=6) is None
    assert g.seed_distance(tok("acct", "A-2")) == (1, [tok("acct", "A-2"), tok("dev", "fp_two")])
    assert not [e for e in g.edges() if e.edge_type == "SHARES_DEVICE"]


def test_the_same_ip_outside_cgnat_does_link():
    g = EntityGraph()
    g.apply(login("C-1", "A-1", "103.21.4.9", "fp_one"))
    g.apply(login("C-2", "A-2", "103.21.4.10", "fp_two"))
    assert tok("dev", "fp_two") in g.neighbours_within(tok("dev", "fp_one"), hops=2)


# ---------------------------------------------------------------------------- exclusions, searches
def test_hub_device_is_excluded_and_creates_no_shares_device():
    g = EntityGraph()
    for i in range(21):
        new = g.apply(login(f"C-{i}", f"A-{i}", f"103.30.{i}.9", "fp_kiosk", at=T0 + timedelta(minutes=i)))
    hub = tok("dev", "fp_kiosk")
    assert g.is_hub(hub) and g.is_excluded(hub)
    assert not [e for e in new if e.edge_type == "SHARES_DEVICE"]       # the 21st customer adds none
    assert tok("acct", "A-1") not in g.neighbours_within(tok("acct", "A-0"), hops=3)


def test_twenty_customers_is_not_a_hub():
    g = EntityGraph()
    for i in range(20):
        g.apply(login(f"C-{i}", f"A-{i}", f"103.30.{i}.9", "fp_family"))
    assert not g.is_hub(tok("dev", "fp_family"))


def test_cloud_identities_are_excluded():
    g = EntityGraph()
    g.apply(env("cloud_audit", {"actor_type": "support_console", "actor_identity": "svc-support-07", "action": "X",
                                "target_customer": "C-1", "src_ip": "185.220.101.7", "result": "success"},
                source="cloud-audit"))
    assert g.is_excluded(tok("cid", "svc-support-07"))
    assert g.neighbours_within(tok("cust", "C-1"), hops=3, min_conf=0.0) == {}


def test_neighbours_within_respects_hops_and_min_conf():
    g = EntityGraph()
    g.apply(login("C-1", "A-1", "103.21.4.9", "fp_1"))
    acct = tok("acct", "A-1")
    assert g.neighbours_within(acct, hops=1) == {tok("cust", "C-1"): 1, tok("dev", "fp_1"): 1}
    assert g.neighbours_within(acct, hops=2)[tok("ip", "103.21.4.9")] == 2      # CONNECTED_VIA 0.5 >= 0.5
    assert tok("ip", "103.21.4.9") not in g.neighbours_within(acct, hops=2, min_conf=0.6)
    assert g.neighbours_within("acct:unknown0000000") == {}


def test_seed_distance_is_zero_for_a_seed_and_none_without_one():
    g = EntityGraph()
    g.apply(login("C-1", "A-1", "103.21.4.9", "fp_1"))
    acct = tok("acct", "A-1")
    assert g.seed_distance(acct) is None
    g.set_seeds([acct])
    assert g.seed_distance(acct) == (0, [acct])
    assert g.seed_distance(tok("ip", "103.21.4.9")) == (2, [tok("ip", "103.21.4.9"), tok("dev", "fp_1"), acct])
    assert g.seed_distance(tok("ip", "103.21.4.9"), max_hops=1) is None


# ---------------------------------------------------------------------------- D2-P1 acceptance
def _midnight_graph():
    sc = load_scenario(str(Path(__file__).resolve().parents[2] / "scenarios" / "midnight_ato.yaml"))
    g, store = EntityGraph(), MemoryStore()
    for e in preload_envelopes(sc, sc.default_start):
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        store.upsert_edges(g.apply(ev))
    seeds = seed_tokens(sc)
    store.set_fraud_seeds(seeds)
    g.set_seeds(seeds)
    return g, store


def test_payee_a_ravi_778_is_at_seed_distance_1_after_preload_and_seeds():
    g, store = _midnight_graph()
    ravi, shared = tok("acct", "A-RAVI-778"), tok("dev", "fp_mule_shared")
    assert g.seed_distance(ravi) == (1, [ravi, shared])
    rebuilt = EntityGraph()                                              # Pipeline.startup path
    rebuilt.load(store.load_edges(), store.list_fraud_seeds())
    assert rebuilt.seed_distance(ravi) == (1, [ravi, shared])
    c_ravi, c_mule = sorted((tok("cust", "C-RAVI-01"), tok("cust", "C-MULE-01")))
    assert g.get_edge(c_ravi, c_mule, "SHARES_DEVICE") is not None
    assert g.seed_distance(tok("acct", "A-88213")) is None              # Priya is not linked to the mule ring
