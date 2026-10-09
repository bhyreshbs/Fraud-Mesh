"""v3 phase 9: seed-independent mule detection and safe joining through payees (engine/graph/mule.py, the graph
detector, engine/cases/joiner.py), with the real detectors after a background, plus focused graph-level tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import Envelope, Reason
from engine.detectors.base import make_evidence
from engine.detectors.graph_det import GraphDetector
from engine.features.graph_features import GRAPH_FEATURE_NAMES, graph_features
from engine.graph.mule import MuleAnalytics, decayed_weight, load_config
from engine.graph.pagerank import ppr_proximity
from engine.graph.reputation import PayeeReputation
from engine.pipeline import Pipeline
from engine.policy.policy import Policy, load_rules
from engine.store_memory import MemoryStore
from ml.generator.run import generate
from ml.scenario import expand, labels_for, load_scenario, preload_envelopes, seed_tokens

ROOT = Path(__file__).resolve().parents[2]
IST = timezone(timedelta(hours=5, minutes=30))
MULE_CODES = {"MULE_FAN_IN_NEW_ACCOUNT", "MULE_PASS_THROUGH", "MULE_FAN_OUT", "MULE_DORMANT_ACTIVATED",
              "MULE_RAPID_HOPS", "MULE_RING"}


def play(name: str, policy_path: Path | None = None, background: bool = True, preload: bool = True):
    """(store, pipeline, step events, updates) for a scenario in direct mode, after a 60-customer background."""
    sc = load_scenario(str(ROOT / "scenarios" / f"{name}.yaml"))
    store = MemoryStore()
    pipe = Pipeline(store)
    if policy_path is not None:
        pipe.policy = Policy(store, rules=load_rules(policy_path))
    pipe.startup()
    bg, bg_labels = (generate(days=14, customers=60, seed=7, end=sc.default_start - timedelta(minutes=10))
                     if background else ([], []))
    pre = preload_envelopes(sc, sc.default_start) if preload else []
    envs = expand(sc, sc.default_start, "direct")
    store.save_labels(bg_labels + labels_for(sc, pre) + labels_for(sc, envs))
    for e in bg + pre:
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        pipe.process(ev)
    pipe.set_seeds(seed_tokens(sc))
    steps, updates = [], []
    for e in envs:
        ev = to_stored_event(e, e.occurred_at)
        store.insert_event(ev)
        steps.append(ev)
        updates.append(pipe.process(ev))
    return store, pipe, steps, updates


def step_cases(store, steps):
    ids = {s.event_id for s in steps}
    return [c for c in store.list_cases() if any(e.event_id in ids for e in store.list_evidence(c.case_id))]


def codes_for(store, steps) -> set[str]:
    ids = {s.event_id for s in steps}
    return {r.code for c in store.list_cases() for e in store.list_evidence(c.case_id) if e.event_id in ids
            for r in e.reasons}


# ---------------------------------------------------------------------------- scenarios
@pytest.fixture(scope="module")
def ring():
    return play("mule_ring_noseed")


def test_new_mule_ring_without_seeds_is_detected(ring):
    store, pipe, steps, _ = ring
    assert pipe.graph.seeds == set()                                       # nothing is a known seed
    codes = codes_for(store, steps)
    assert {"MULE_RING", "MULE_PASS_THROUGH", "MULE_RAPID_HOPS"} <= codes
    assert not any(c.startswith("SEED_DISTANCE") for c in codes)


def test_ring_is_one_case_and_its_onward_transfers_are_stopped(ring):
    store, _, steps, updates = ring
    cases = step_cases(store, steps)
    assert len(cases) == 1                                                 # 7 victims, 3 ring accounts, 1 collector
    case = cases[0]
    assert {tok("acct", f"A-RING-0{i}") for i in (1, 2, 3)} | {tok("acct", "A-COLL-01")} <= set(case.entities)
    onward = [u for s, us in zip(steps, updates, strict=True) for u in us
              if s.event_type == "transaction" and s.payload["payee_account"] == tok("acct", "A-COLL-01")]
    assert onward and all(u.payment_outcome in ("held", "blocked") for u in onward)


def test_popular_merchant_legit_volume_creates_no_mule_signal_or_link():
    store, pipe, steps, updates = play("popular_merchant_legit")
    grocer = tok("acct", "A-GROCER-77")
    assert PayeeReputation(pipe.graph).is_reputable(grocer, steps[-1].occurred_at)
    assert not (codes_for(store, steps) & (MULE_CODES | {"MULE_FLOW", "APP_SCAM_WARNING", "APP_SCAM_COOLING_OFF"}))
    for c in step_cases(store, steps):
        assert sum(t.startswith("cust:") for t in c.entities) == 1          # no case chains two shoppers
    assert all(u.case.band == "LOW" for us in updates for u in us)


def test_mule_fanin_is_still_one_case():
    store, _, steps, _ = play("mule_fanin")
    mule = tok("acct", "A-MULE-02")
    owners = {c.case_id for c in step_cases(store, steps) if mule in c.entities}
    assert len(owners) == 1


# ---------------------------------------------------------------------------- focused graph-level worlds
T0 = datetime(2026, 10, 9, 10, 0, tzinfo=IST)


class FlagDayX:
    """Test detector: txn evidence (p 0.05) for every transaction at or after T0, so each payer has a case."""
    id = "txn"
    handles = frozenset({"transaction"})

    def score(self, event, feats, graph, rel):
        if event.occurred_at < T0:
            return []
        return [make_evidence("txn", "test", event, "S6_MONETIZATION", 0.05, rel, [Reason(code="TEST_FLAG")],
                              amount_paise=event.payload["amount_paise"])]


class World:
    def __init__(self, detectors=None) -> None:
        self.store = MemoryStore()
        self.pipe = Pipeline(self.store, detectors=detectors if detectors is not None else [GraphDetector(), FlagDayX()])
        self.pipe.startup()
        self.n = 0

    def send(self, event_type, payload, at, who, dev=None):
        self.n += 1
        env = Envelope(event_id=f"evt_v3m{self.n:08d}", event_type=event_type, source="simulator", occurred_at=at,
                       subject={"customer_ref": f"C-{who}", "account_ref": f"A-{who}"},
                       context={"ip": f"49.{100 + self.n % 100}.{self.n // 100}.5", "device_id": dev or f"fp_{who}"},
                       payload=payload)
        ev = to_stored_event(env, at)
        self.store.insert_event(ev)
        return self.pipe.process(ev)

    def pay(self, who, payee, at, amount=1_500_000, dev=None):
        return self.send("transaction", {"amount_paise": amount, "payee_account": payee, "channel": "IMPS"}, at, who, dev)

    def login(self, who, at, dev=None):
        return self.send("login", {"result": "success", "auth_method": "password+otp"}, at, who, dev)

    def codes(self) -> set[str]:
        return {r.code for c in self.store.list_cases() for e in self.store.list_evidence(c.case_id) for r in e.reasons}

    def cases_with(self, token) -> list:
        return [c for c in self.store.list_cases() if token in c.entities]


def test_rapid_pass_through_is_flagged_on_the_mule_and_on_the_next_hop():
    w = World()
    w.login("MULE7", T0 - timedelta(days=2))
    for i in range(3):
        w.login(f"V{i}", T0 - timedelta(days=20))
        w.pay(f"V{i}", "A-MULE7", T0 + timedelta(minutes=5 * i))
    w.pay("MULE7", "A-NEXT7", T0 + timedelta(minutes=25), amount=4_000_000)
    prof = MuleAnalytics(w.pipe.graph).profile(tok("acct", "A-MULE7"), T0 + timedelta(minutes=26))
    assert prof.new_money_payers_window == 3 and prof.pass_through_min == pytest.approx(15.0)
    assert prof.new_beneficiaries_window == 1
    assert "MULE_PASS_THROUGH" in w.codes()
    sig = MuleAnalytics(w.pipe.graph).signals(tok("acct", "A-NEXT7"), T0 + timedelta(minutes=26))
    assert ("MULE_RAPID_HOPS" in {c for c, _ in sig})
    f = graph_features(w.pipe.graph, tok("acct", "A-MULE7"), T0 + timedelta(minutes=26))
    assert list(f) == GRAPH_FEATURE_NAMES and f["pass_through_min"] == pytest.approx(15.0)


def test_fan_out_ring_on_a_shared_device():
    w = World()
    for k in range(3):                                                     # 3 accounts, one controlling phone
        w.login(f"R{k}", T0 - timedelta(days=3), dev="fp_ctrl")
    for i in range(4):
        w.login(f"P{i}", T0 - timedelta(days=20))
    for i in range(4):
        w.pay(f"P{i}", f"A-R{i % 3}", T0 + timedelta(minutes=3 * i))
    assert "MULE_RING" in w.codes()
    assert MuleAnalytics(w.pipe.graph).ring(tok("acct", "A-R0"), T0 + timedelta(minutes=12)) == (3, 4)
    for j in range(3):                                                     # the hub account fans the money out
        w.pay("R0", f"A-OUT{j}", T0 + timedelta(minutes=20 + j))
    assert "MULE_FAN_OUT" in w.codes()


def test_unknown_dormant_account_suddenly_receiving_is_flagged():
    w = World()
    w.login("OLD1", T0 - timedelta(days=90))                               # opened, then idle for 90 days
    for i in range(3):
        w.login(f"D{i}", T0 - timedelta(days=20))
    for i in range(3):
        w.pay(f"D{i}", "A-OLD1", T0 + timedelta(minutes=10 * i))
    prof = MuleAnalytics(w.pipe.graph).profile(tok("acct", "A-OLD1"), T0 + timedelta(minutes=30))
    assert prof.dormant_activated and prof.account_age_days > 89
    assert "MULE_DORMANT_ACTIVATED" in w.codes()


def test_young_unknown_mule_account_gets_fan_in_signal_and_one_case():
    w = World()
    for i in range(4):
        w.login(f"Y{i}", T0 - timedelta(days=20))
    for i in range(4):
        w.pay(f"Y{i}", "A-UNKNOWN9", T0 + timedelta(minutes=10 * i))
    assert "MULE_FAN_IN_NEW_ACCOUNT" in w.codes()
    assert len(w.cases_with(tok("acct", "A-UNKNOWN9"))) == 1                 # suspicious bridge: victims joined


def test_popular_not_yet_reputable_payee_makes_no_false_links():
    """An established account with long-standing payers but too many newer ones to be reputable (share < 50%): before
    v3 the joiner chained every flagged payer through it; safe joining needs a suspicious bridge or two bridges."""
    w = World()
    for i in range(12):
        w.login(f"Q{i}", T0 - timedelta(days=60))
    for i in range(4):                                                     # 4 long-standing payers (60 days)
        w.pay(f"Q{i}", "A-TUTOR2", T0 - timedelta(days=59 - i))
    for i in range(4, 12):                                                 # 8 newer payers, one every half day
        w.pay(f"Q{i}", "A-TUTOR2", T0 - timedelta(days=5) + timedelta(hours=12 * (i - 4)))
    payee = tok("acct", "A-TUTOR2")
    rep = PayeeReputation(w.pipe.graph)
    assert not rep.is_reputable(payee, T0)                                  # not reputable ...
    for i in range(12):
        w.pay(f"Q{i}", "A-TUTOR2", T0 + timedelta(minutes=7 * i))
    day_x = [c for c in w.store.list_cases() if c.opened_at >= T0]
    assert len(day_x) == 12                                                # ... yet no chaining: one case per payer
    assert all(sum(t.startswith("cust:") for t in c.entities) == 1 for c in day_x)
    assert not (w.codes() & MULE_CODES)


def test_two_shared_payees_are_two_independent_links():
    """Two customers who both pay the same two established payees (not reputable: too many newer payers; not
    suspicious: long-standing payers, no mule signal) are joined: two independent shared entities."""
    w = World()
    for who in ("TA", "TB"):
        w.login(who, T0 - timedelta(days=60))
    for k, payee in enumerate(("A-LAND1", "A-SCHOOL1")):
        tag = payee[2:]
        for i in range(3):                                                 # other long-standing payers
            w.login(f"{tag}O{i}", T0 - timedelta(days=60))
            w.pay(f"{tag}O{i}", payee, T0 - timedelta(days=50 - i))
        for who in ("TA", "TB"):
            w.pay(who, payee, T0 - timedelta(days=40 - k))
        for j in range(6):                                                 # newer payers: share of tenured < 50 %
            w.login(f"{tag}N{j}", T0 - timedelta(days=30))
            w.pay(f"{tag}N{j}", payee, T0 - timedelta(days=5) + timedelta(hours=12 * j))
        assert not PayeeReputation(w.pipe.graph).is_reputable(tok("acct", payee), T0)
    w.pay("TA", "A-LAND1", T0)
    w.pay("TA", "A-SCHOOL1", T0 + timedelta(minutes=1))
    w.pay("TB", "A-LAND1", T0 + timedelta(minutes=2))
    joined = [c for c in w.store.list_cases() if c.opened_at >= T0 and tok("cust", "C-TB") in c.entities]
    assert len(joined) == 1 and tok("cust", "C-TA") in joined[0].entities


def test_decay_and_pagerank_helpers():
    w = World()
    for i in range(3):
        w.login(f"K{i}", T0 - timedelta(days=20))
        w.pay(f"K{i}", "A-HOT1", T0 + timedelta(minutes=i))
    g = w.pipe.graph
    d = next(iter(g.g.get_edge_data(tok("acct", "A-K0"), tok("acct", "A-HOT1")).values()))
    cfg = load_config()
    assert decayed_weight(d, d["last_seen"], cfg.decay_half_life_h) == pytest.approx(d["confidence"])
    assert decayed_weight(d, d["last_seen"] + timedelta(hours=cfg.decay_half_life_h), cfg.decay_half_life_h) \
        == pytest.approx(d["confidence"] / 2)
    # the payer next to a mule-signalled account gets PPR mass; an unrelated token gets none
    assert ppr_proximity(g, tok("acct", "A-K0"), T0 + timedelta(minutes=3), cfg) > 0
    assert ppr_proximity(g, tok("acct", "A-NOBODY"), T0, cfg) == 0.0
    assert cfg.pagerank["enabled"] is False                                 # off by default (see mule.yaml)
