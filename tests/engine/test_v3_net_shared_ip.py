"""v3 phases 4.1-4.3: shared-IP classifier, distributed credential stuffing, carrier-IP regression."""
from __future__ import annotations

from datetime import timedelta

from engine.common.tokenize import tok
from engine.detectors.base import make_evidence
from engine.features.identity_windows import BoundedWindows, IdentityWindows
from engine.graph.shared_ip import SharedIpClassifier, SharedIpConfig
from engine.graph.store import EntityGraph
from tests.engine.test_v3_net_common import (
    T0,
    band_rank,
    cust,
    ev,
    feed,
    login,
    new_pipeline,
    reasons_in_case,
)

CARRIER_IP = "117.200.45.10"          # carrier-style egress, deliberately NOT in cgnat.txt
CARRIER_TOK = tok("ip", CARRIER_IP)


# ---------------------------------------------------------------------------- 4.1 classifier
def test_ip_becomes_shared_with_device_diversity_and_expires():
    c = SharedIpClassifier(SharedIpConfig(min_devices=3, min_accounts=99, min_sessions=99, min_client_profiles=99))
    for i in range(3):
        c.observe(login(i, cust=f"C-{i}", acct=f"A-{i}", dev=f"fp_{i}", ip=CARRIER_IP))
    assert c.is_shared(CARRIER_TOK)
    assert c.counts(CARRIER_TOK)["devices"] == 3
    c.observe(login(25 * 60, cust="C-9", acct="A-9", dev="fp_9", ip="8.8.4.4"))       # 25 h later, elsewhere
    assert not c.is_shared(CARRIER_TOK)                                              # recomputed, not permanent


def test_failed_logins_do_not_count_as_shared_accounts():
    c = SharedIpClassifier(SharedIpConfig(min_devices=99, min_accounts=3))
    for i in range(5):
        c.observe(login(i, result="failure", cust=f"C-{i}", acct=f"A-{i}", dev="fp_bot", ip=CARRIER_IP))
    assert not c.is_shared(CARRIER_TOK)


def test_classifier_memory_is_bounded():
    c = SharedIpClassifier(SharedIpConfig(max_ips=50, max_values_per_dim=4))
    for i in range(200):
        c.observe(login(i, dev=f"fp_{i}", ip=f"60.{i // 250}.{i % 250}.1"))
    for i in range(20):
        c.observe(login(300 + i, dev=f"fp_x{i}", ip=CARRIER_IP))
    assert len(c) == 50 and c.counts(CARRIER_TOK)["devices"] == 4


def test_graph_gives_shared_ip_edges_zero_confidence_and_excludes_it():
    g = EntityGraph()
    g.shared_ip = SharedIpClassifier(SharedIpConfig(min_devices=3))
    for i in range(4):
        g.apply(login(i, cust=f"C-{i}", acct=f"A-{i}", dev=f"fp_{i}", ip=CARRIER_IP))
    assert g.is_excluded(CARRIER_TOK)
    late = g.get_edge(tok("dev", "fp_3"), CARRIER_TOK, "CONNECTED_VIA")
    early = g.get_edge(tok("dev", "fp_0"), CARRIER_TOK, "CONNECTED_VIA")
    assert late.confidence == 0.0 and early.confidence == 0.5
    assert CARRIER_TOK not in g.neighbours_within(tok("dev", "fp_0"), 2, 0.5)


def test_restart_reseeds_device_diversity_from_edges():
    g = EntityGraph()
    for i in range(9):
        g.apply(login(i, cust=f"C-{i}", acct=f"A-{i}", dev=f"fp_{i}", ip=CARRIER_IP))
    g2 = EntityGraph()
    g2.load(g.edges(), [])
    assert g2.is_excluded(CARRIER_TOK)


# ---------------------------------------------------------------------------- 4.2 identity windows
def test_bounded_windows_drop_old_keys_and_values():
    w = BoundedWindows(timedelta(hours=1), max_keys=3, max_values=2)
    for i in range(5):
        for j in range(4):
            w.add(f"k{i}", T0 + timedelta(minutes=j), j)
    assert len(w) == 3 and w.values("k4", T0 + timedelta(minutes=5)) == [2, 3]


def test_account_distributed_failures_fire_once_per_window():
    iw = IdentityWindows()
    seen = []
    for i in range(8):
        e = login(i, result="failure", ip=f"60.1.{i}.1", dev=f"fp_r{i}")
        f = iw.compute(e)
        seen.append(iw.rule_hits(f)["ACCOUNT_DISTRIBUTED_FAILURES"] and not f["acct_distributed_flagged"])
        iw.update(e)
    assert seen == [False] * 4 + [True] + [False] * 3


def test_device_multi_account_and_global_spike():
    iw = IdentityWindows()
    for i in range(40):                       # 40 accounts, one device, 40 failures in 10 min (no baseline)
        e = login(i * 0.2, result="failure", cust=f"C-{i}", acct=f"A-{i}", dev="fp_spray", ip=f"60.2.{i}.1")
        f = iw.compute(e)
        iw.update(e)
    assert f["dev_accounts_1h"] == 40 and f["global_fail_10m"] == 40 and f["global_spike_active"] == 1
    assert f["dev_multi_flagged"] == 1 and f["global_spike_flagged"] == 1


# ---------------------------------------------------------------------------- 4.3 regression through the pipeline
USERS = [f"C-CARR{i:02d}" for i in range(30)]


def carrier_traffic(days: int = 6, users: list[str] = USERS) -> list:
    """30 genuine customers, each on their own phone, all behind one carrier ip; a few mistyped passwords."""
    out = []
    for d in range(days):
        for i, u in enumerate(users):
            t = d * 1440 + 8 * 60 + i * 20                      # each user keeps their own time of day
            kw = {"cust": u, "acct": f"A-{u}", "dev": f"fp_{u}", "ip": CARRIER_IP, "asn": "AS45609 Airtel Mobile"}
            if (i + d) % 7 == 0:
                out.append(login(t - 1, result="failure", **kw))
            out.append(login(t, session_id=f"s-{u}-{d}", **kw))
            out.append(ev("transaction", {"amount_paise": 50_000 + i * 100, "payee_account": f"A-PAY-{u}",
                                          "channel": "UPI"}, t + 3, session_id=f"s-{u}-{d}", **kw))
    return out


def legit_cases(store):
    ours = {cust(u) for u in USERS}
    return [c for c in store.list_cases() if ours & set(c.entities)], ours


def test_thirty_users_behind_one_carrier_ip_are_not_flagged_or_linked():
    store, pipe = new_pipeline()
    feed(store, pipe, carrier_traffic())
    assert pipe.graph.shared_ip.is_shared(CARRIER_TOK)
    cases, ours = legit_cases(store)
    for c in cases:
        assert c.band == "LOW", (c.band, reasons_in_case(store, c.case_id))
        assert len(ours & set(c.entities)) <= 1                 # never a cross-user case
    for u in USERS[:5]:
        linked = pipe.graph.neighbours_within(tok("dev", f"fp_{u}"), 2, 0.5)      # dev -> ip -> other devices?
        assert CARRIER_TOK not in linked
        assert not ({tok("dev", f"fp_{v}") for v in USERS} - {tok("dev", f"fp_{u}")}) & set(linked)
        e = make_evidence("behaviour", "test", login(7 * 1440, cust=u, acct=f"A-{u}", dev=f"fp_{u}", ip=CARRIER_IP),
                          "S1_INITIAL_ACCESS", 0.05, {}, [])
        tokens = set(pipe.joiner.join_tokens(e))
        assert CARRIER_TOK not in tokens and not ({cust(v) for v in USERS} - {cust(u)}) & tokens


def test_control_without_the_classifier_the_carrier_ip_links_strangers():
    store, pipe = new_pipeline()
    big = 10 ** 6
    pipe.graph.shared_ip = SharedIpClassifier(SharedIpConfig(min_devices=big, min_accounts=big, min_sessions=big,
                                                             min_client_profiles=big))
    feed(store, pipe, carrier_traffic(days=1, users=USERS[:12]))   # 12 customers: below the §10.2 hub rule (> 20)
    linked = pipe.graph.neighbours_within(tok("dev", f"fp_{USERS[0]}"), 2, 0.5)
    assert CARRIER_TOK in linked and tok("dev", f"fp_{USERS[1]}") in linked


def test_with_the_classifier_twelve_users_are_not_linked_below_the_hub_rule():
    store, pipe = new_pipeline()
    feed(store, pipe, carrier_traffic(days=1, users=USERS[:12]))
    assert pipe.graph.shared_ip.is_shared(CARRIER_TOK) and not pipe.graph.is_hub(CARRIER_TOK)
    linked = pipe.graph.neighbours_within(tok("dev", f"fp_{USERS[0]}"), 2, 0.5)
    assert CARRIER_TOK not in linked and tok("dev", f"fp_{USERS[1]}") not in linked


def test_coordinated_attack_on_the_same_carrier_ip_is_detected():
    store, pipe = new_pipeline()
    feed(store, pipe, carrier_traffic())
    t = 6 * 1440 + 2 * 60
    attack = []
    for k, u in enumerate(USERS[:6]):                           # one device walks through six accounts
        for j in range(2):
            attack.append(login(t + k * 2 + j * 0.5, result="failure", cust=u, acct=f"A-{u}", dev="fp_evil",
                                ip=CARRIER_IP, asn="AS45609 Airtel Mobile"))
    victim = USERS[5]
    attack.append(login(t + 15, cust=victim, acct=f"A-{victim}", dev="fp_evil", ip=CARRIER_IP, asn="AS45609 Airtel Mobile"))
    attack.append(ev("mfa_change", {"factor": "sms", "action": "replace", "new_phone": "+91 90000 22222"}, t + 18,
                     cust=victim, acct=None, dev="fp_evil", ip=CARRIER_IP, asn="AS45609 Airtel Mobile"))
    feed(store, pipe, attack)
    evil = tok("dev", "fp_evil")
    (case,) = [c for c in store.list_cases() if evil in c.entities]
    codes = reasons_in_case(store, case.case_id)
    assert "DEVICE_MULTI_ACCOUNT_FAILURES" in codes and "MFA_CHANGED_AFTER_NEW_DEVICE" in codes
    assert cust(victim) in case.entities
    assert band_rank(case.band) >= band_rank("MEDIUM")
    others, ours = legit_cases(store)
    for c in others:                                            # bystanders on the same ip stay out
        if c.case_id != case.case_id:
            assert c.band == "LOW"
    assert ours & set(case.entities) <= {cust(u) for u in USERS[:6]}


def test_attack_rotating_across_many_ips_is_detected():
    store, pipe = new_pipeline()
    t = 600.0
    rotating = [login(t + i * 3, result="failure", cust="C-VIC", acct="A-VIC", dev=f"fp_r{i}", ip=f"60.3.{i}.7",
                      asn="AS64500 HostCo", coords=None) for i in range(6)]
    slow = [login(t + i * 180, result="failure", cust="C-SLOW", acct="A-SLOW", dev="fp_slow", ip=f"60.4.{i}.7",
                  asn="AS64500 HostCo", coords=None) for i in range(6)]
    feed(store, pipe, rotating + slow)
    vic = [c for c in store.list_cases() if cust("C-VIC") in c.entities]
    slw = [c for c in store.list_cases() if cust("C-SLOW") in c.entities]
    assert vic and "ACCOUNT_DISTRIBUTED_FAILURES" in reasons_in_case(store, vic[0].case_id)
    assert slw and "ACCOUNT_LOW_SLOW_FAILURES" in reasons_in_case(store, slw[0].case_id)


def test_password_spray_triggers_the_global_spike():
    store, pipe = new_pipeline()
    spray = [login(600 + i * 0.2, result="failure", cust=f"C-SP{i}", acct=f"A-SP{i}", dev=f"fp_sp{i}", ip=f"60.5.{i}.7",
                   coords=None) for i in range(40)]
    feed(store, pipe, spray)
    codes = set().union(*(reasons_in_case(store, c.case_id) for c in store.list_cases()))
    assert "GLOBAL_LOGIN_FAILURE_SPIKE" in codes
    assert all(c.band == "LOW" for c in store.list_cases())     # a spike alone never blocks anyone
