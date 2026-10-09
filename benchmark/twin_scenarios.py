"""v3 phase 15: the Digital Twin scenario library, played end to end through the REAL engine.

Each of the 15 scenarios is played in direct mode, as tests/engine/test_midnight_direct.py does:
    MemoryStore + Pipeline (real detectors, fusion, joiner, policy) + 14 days of seed-7 generator background (60
    customers) + the scenario's preload + its fraud seeds + its steps.
Every event is enriched exactly like the API does at ingestion (api/enrichment.py: network type of the RAW ip, then
tokenization), so VPN / hosting / carrier classifications reach the detectors as they would in production.
Scenarios 3 (30 genuine users behind one carrier ip) and 5 (distributed credential stuffing across rotating ips) are
multi-customer traffic and are generated here instead of in a YAML file.

Per scenario the runner records: expected behaviour, detection stage, final band, detectors and reason codes, the
FP / FN outcome, time to detection, every payment's intervention, the money outcome and the Digital Twin's case_kind,
then checks the scenario's own expected behaviour. A failed check is reported as a GAP, never hidden.

Twin numbers are SYNTHETIC: the scenarios, the background and the twin's transition table are generated data. They
show what this engine does on these inputs; they are not evidence of real-world detection rates.

Usage:
    python -m benchmark.twin_scenarios                    # writes benchmark/twin_scenarios.json + docs/V3_SCENARIOS.md
    python -m benchmark.twin_scenarios --only benign_vpn --no-write
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from api.enrichment import enrich
from engine.common.ids import new_id
from engine.common.tokenize import to_stored_event
from engine.contracts import ACTION_SEVERITY, BAND_ORDER, SEVERITY_HOLD, Envelope, Label, StoredEvent
from engine.feedback import apply_feedback_with_provenance, reliabilities
from engine.fusion.v3_core import load_v3_core
from engine.graph.resolve import kind_of
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from engine.twin.build import twin_case
from ml.generator.run import generate
from ml.scenario import expand, labels_for, load_scenario, preload_envelopes, seed_tokens

ROOT = Path(__file__).resolve().parents[1]
OUT_JSON = ROOT / "benchmark" / "twin_scenarios.json"
OUT_DOC = ROOT / "docs" / "V3_SCENARIOS.md"
BACKGROUND_DAYS, BACKGROUND_CUSTOMERS, BACKGROUND_SEED = 14, 60, 7
IST = timezone(timedelta(hours=5, minutes=30))
HIGH = BAND_ORDER.index("HIGH")
FEEDBACK_BURST = 12                     # scenario 14: wrong FALSE_POSITIVE verdicts fired after the steps


# ---------------------------------------------------------------------------- playing
@dataclass
class Played:
    store: MemoryStore
    pipe: Pipeline
    steps: list[StoredEvent]
    updates: list[list]                 # CaseUpdates per step, in step order
    start: datetime
    labels: dict[str, Label]
    extra: dict[str, Any] = field(default_factory=dict)


def stored(env: Envelope) -> StoredEvent:
    """API ingestion order: enrich the raw ip, then tokenize (api/routers/ingest.py accept_envelope)."""
    env2, network = enrich(env)
    return to_stored_event(env2, env2.occurred_at, network=network)


def _engine(start: datetime, background: bool) -> tuple[MemoryStore, Pipeline, list[Label]]:
    store = MemoryStore()
    pipe = Pipeline(store)
    pipe.startup()
    labels: list[Label] = []
    if background:
        envs, labels = generate(days=BACKGROUND_DAYS, customers=BACKGROUND_CUSTOMERS, seed=BACKGROUND_SEED,
                                end=start - timedelta(minutes=10))
        for e in envs:
            ev = stored(e)
            store.insert_event(ev)
            pipe.process(ev)
    return store, pipe, labels


def play_yaml(path: Path) -> Played:
    sc = load_scenario(str(path))
    start = sc.default_start
    store, pipe, bg_labels = _engine(start, background=True)
    pre = preload_envelopes(sc, start)
    store.save_labels(bg_labels + labels_for(sc, pre))
    for e in pre:
        ev = stored(e)
        store.insert_event(ev)
        pipe.process(ev)
    pipe.set_seeds(seed_tokens(sc))
    envs = [e for e in expand(sc, start, "direct")]
    store.save_labels(labels_for(sc, envs))
    steps, updates = [], []
    for e in envs:                      # ARRIVAL order (late_evidence_feedback lists delayed events last)
        ev = stored(e)
        store.insert_event(ev)
        steps.append(ev)
        updates.append(pipe.process(ev))
    return Played(store, pipe, steps, updates, start, store.get_labels())


def _env(event_type: str, at: datetime, cust: str, acct: str | None, ip: str, dev: str, asn: str, payload: dict,
         **ctx) -> Envelope:
    subject = {"customer_ref": cust, **({"account_ref": acct} if acct else {})}
    return Envelope(event_id=new_id("evt"), event_type=event_type, source="demo-bank-web", occurred_at=at,
                    schema_version="1.1", subject=subject, context={"ip": ip, "device_id": dev, "asn": asn, **ctx},
                    payload=payload)


def play_generated(scenario_id: str, build: Callable[[datetime], tuple[list[Envelope], list[Envelope], bool]],
                   start: datetime) -> Played:
    """build(start) -> (preload envelopes, step envelopes, is_attack). Steps are labelled with the attack flag."""
    store, pipe, bg_labels = _engine(start, background=True)
    pre, envs, is_attack = build(start)
    attack_id = f"atk_{scenario_id}" if is_attack else None
    store.save_labels(bg_labels + [Label(event_id=e.event_id, scenario=scenario_id, is_attack=False) for e in pre]
                      + [Label(event_id=e.event_id, scenario=scenario_id, attack_id=attack_id, is_attack=is_attack)
                         for e in envs])
    for e in sorted(pre, key=lambda x: x.occurred_at):
        ev = stored(e)
        store.insert_event(ev)
        pipe.process(ev)
    steps, updates = [], []
    for e in sorted(envs, key=lambda x: x.occurred_at):
        ev = stored(e)
        store.insert_event(ev)
        steps.append(ev)
        updates.append(pipe.process(ev))
    return Played(store, pipe, steps, updates, start, store.get_labels())


CARRIER_IP, CARRIER_ASN = "117.200.45.10", "AS45609 Airtel Mobile"        # carrier-style egress, not in cgnat.txt
CARRIER_USERS = [f"C-CARR{i:02d}" for i in range(30)]


def build_shared_ip(start: datetime) -> tuple[list[Envelope], list[Envelope], bool]:
    """Scenario 3: 30 genuine customers, each on their own phone, all behind one carrier ip, for six days (the last
    day is the scenario's steps). A few mistyped passwords. Nobody here is an attacker."""
    pre, steps = [], []
    day0 = start - timedelta(days=5)
    for d in range(6):
        for i, u in enumerate(CARRIER_USERS):
            t = day0 + timedelta(days=d, minutes=i * 20)
            kw = {"cust": u, "acct": f"A-{u}", "ip": CARRIER_IP, "dev": f"fp_{u}", "asn": CARRIER_ASN}
            out = steps if d == 5 else pre
            if (i + d) % 7 == 0:
                out.append(_env("login", t - timedelta(minutes=1), payload={"result": "failure", "auth_method": "password"}, **kw))
            out.append(_env("login", t, payload={"result": "success", "auth_method": "password"}, session_id=f"s-{u}-{d}", **kw))
            out.append(_env("transaction", t + timedelta(minutes=3), session_id=f"s-{u}-{d}",
                            payload={"amount_paise": 50_000 + i * 100, "payee_account": f"A-PAY-{u}", "channel": "UPI"}, **kw))
    return pre, steps, False


def build_distributed_stuffing(start: datetime) -> tuple[list[Envelope], list[Envelope], bool]:
    """Scenario 5: distributed credential stuffing. A botnet tries Priya's password from eight different devices on
    eight rotating cloud ips (no ip sees more than one attempt, so per-ip rules stay quiet), gets in on the ninth,
    adds a payee and sends ₹2,20,000."""
    vic = {"cust": "C-1042", "acct": "A-88213"}
    steps = []
    for i in range(8):
        steps.append(_env("login", start + timedelta(minutes=i * 1.5), ip=f"185.220.101.{60 + i}", dev=f"fp_botnet_{i}",
                          asn="AS64500 HostCo", payload={"result": "failure", "auth_method": "password"}, **vic))
    t = start + timedelta(minutes=14)
    kw = {"ip": "185.220.101.90", "dev": "fp_botnet_9", "asn": "AS64500 HostCo", **vic}
    steps.append(_env("login", t, payload={"result": "success", "auth_method": "password+otp"}, **kw))
    steps.append(_env("payee_added", t + timedelta(minutes=4),
                      payload={"payee_account": "A-STUFF-MULE-5", "payee_name_match": True, "nickname": "Rent"}, **kw))
    steps.append(_env("transaction", t + timedelta(minutes=6),
                      payload={"amount_paise": 22_000_000, "payee_account": "A-STUFF-MULE-5", "channel": "IMPS"}, **kw))
    return [], steps, True


# ---------------------------------------------------------------------------- measuring
def _owners(store: MemoryStore, ev: StoredEvent) -> set[str]:
    return {c.case_id for c in store.list_cases() for e in store.list_evidence(c.case_id) if e.event_id == ev.event_id}


def scenario_cases(p: Played) -> list:
    ids: set[str] = set()
    for s, us in zip(p.steps, p.updates, strict=True):
        ids |= {u.case.case_id for u in us} | _owners(p.store, s)
    return [c for c in (p.store.get_case(i) for i in sorted(ids)) if c is not None]


def payments(p: Played) -> list[dict]:
    out = []
    for s, us in zip(p.steps, p.updates, strict=True):
        if s.event_type != "transaction":
            continue
        outcome = next((u.payment_outcome for u in us if u.payment_outcome), None) or "completed"
        out.append({"at_min": round((s.occurred_at - p.start).total_seconds() / 60, 1), "amount_paise": s.payload["amount_paise"],
                    "outcome": outcome, "is_attack": bool(p.labels.get(s.event_id) and p.labels[s.event_id].is_attack)})
    return out


def first_high(p: Played) -> tuple[int | None, Any]:
    for i, us in enumerate(p.updates):
        for u in us:
            if BAND_ORDER.index(u.case.band) >= HIGH:
                return i, u
    return None, None


def first_intervention(p: Played, cases: list) -> Any:
    decisions = [d for c in cases for d in p.store.list_decisions(c.case_id)
                 if max((ACTION_SEVERITY[a] for a in d.actions), default=0) >= SEVERITY_HOLD]
    return min(decisions, key=lambda d: d.created_at) if decisions else None


def customers_in(case) -> int:
    return sum(1 for t in case.entities if kind_of(t) == "cust")


def measure(p: Played) -> dict:
    cases = scenario_cases(p)
    codes = sorted({r.code for c in cases for e in p.store.list_evidence(c.case_id) for r in e.reasons})
    detectors = sorted({e.detector for c in cases for e in p.store.list_evidence(c.case_id) if e.contribution > 0})
    max_band = max((c.band for c in cases), key=BAND_ORDER.index, default="LOW")
    peak_band = max((u.case.band for us in p.updates for u in us), key=BAND_ORDER.index, default="LOW")
    i, u = first_high(p)
    pays = payments(p)
    first_step = p.steps[0].occurred_at if p.steps else p.start
    hold = first_intervention(p, cases)
    main = max(cases, key=lambda c: (BAND_ORDER.index(c.band), c.p_attack), default=None)
    kind = None
    if main is not None:
        try:
            kind = twin_case(p.store, main.case_id, graph=p.pipe.graph, labels=p.labels).case_kind
        except Exception as e:  # noqa: BLE001 - the twin must never break the benchmark; record why
            kind = f"error: {type(e).__name__}"
    return {
        "events": len(p.steps),
        "cases": len(cases),
        "max_customers_in_one_case": max((customers_in(c) for c in cases), default=0),
        "final_band": max_band,
        "peak_band": peak_band,
        "final_p_attack": round(main.p_attack, 4) if main else None,
        "patterns": sorted({h for c in cases for h in c.pattern_hits}),
        "detectors": detectors,
        "reason_codes": codes,
        "detected_at_step": i,
        "detection_event": p.steps[i].event_type if i is not None else None,
        "detection_stage": (u.case.current_stage if u is not None else None),
        "time_to_detection_min": (round((p.steps[i].occurred_at - first_step).total_seconds() / 60, 1) if i is not None else None),
        "first_intervention": ({"policy_rule": hold.policy_rule, "actions": hold.actions,
                                "at_min": round((hold.created_at - p.start).total_seconds() / 60, 1)} if hold else None),
        "payments": pays,
        "money": {
            "attempted_paise": sum(x["amount_paise"] for x in pays),
            "completed_paise": sum(x["amount_paise"] for x in pays if x["outcome"] == "completed"),
            "stopped_paise": sum(x["amount_paise"] for x in pays if x["outcome"] != "completed"),
        },
        "final_payment_state": main.payment_state if main else "normal",
        "case_kind": kind,
    }


# ---------------------------------------------------------------------------- the library
@dataclass(frozen=True)
class Spec:
    num: int
    id: str
    title: str
    is_attack: bool
    expected: str
    play: Callable[[], Played]
    checks: Callable[[dict, Played], list[tuple[str, bool]]]
    source: str


def _yaml(name: str) -> Callable[[], Played]:
    return lambda: play_yaml(ROOT / "scenarios" / f"{name}.yaml")


def _attack_payments_stopped(m: dict) -> bool:
    attack_pays = [x for x in m["payments"] if x["is_attack"]]
    return bool(attack_pays) and all(x["outcome"] != "completed" for x in attack_pays)


def _no_intervention(m: dict) -> bool:
    return m["first_intervention"] is None and all(x["outcome"] == "completed" for x in m["payments"])


def _band_at_most(m: dict, band: str) -> bool:
    return BAND_ORDER.index(m["peak_band"]) <= BAND_ORDER.index(band)


def _check_late_feedback(m: dict, p: Played) -> list[tuple[str, bool]]:
    pays = m["payments"]
    held_at_transfer = bool(pays) and pays[0]["outcome"] in ("held", "blocked")
    blocked_after_late = p.extra.get("state_after_late") == "blocked"
    bounds_ok = p.extra.get("reliability_in_bounds", False)
    return [("transfer held when it is made", held_at_transfer),
            ("late cloud/KYC evidence blocks the held case", blocked_after_late),
            (f"{FEEDBACK_BURST} wrong FALSE_POSITIVE verdicts keep every reliability inside its bounds", bounds_ok)]


def play_late_feedback() -> Played:
    p = play_yaml(ROOT / "scenarios" / "late_evidence_feedback.yaml")
    cases = scenario_cases(p)
    main = max(cases, key=lambda c: (BAND_ORDER.index(c.band), c.p_attack))
    p.extra["state_after_late"] = main.payment_state
    cfg = load_v3_core()["feedback"]
    lo, hi = float(cfg["reliability_min"]), float(cfg["reliability_max"])
    before = reliabilities(p.store)
    ts = main.last_event_ts
    for k in range(FEEDBACK_BURST):    # a poisoning burst: the same wrong verdict, a minute apart
        apply_feedback_with_ts(p, main.case_id, ts + timedelta(minutes=k + 1))
    after = reliabilities(p.store)
    # a detector that started inside the bounds must stay inside; one already outside must not move further out
    p.extra["reliability_in_bounds"] = all(
        (lo - 1e-9 <= after[d] <= hi + 1e-9) if lo <= before.get(d, after[d]) <= hi
        else abs(after[d] - before[d]) < 1e-9 or (after[d] - before[d]) * (before[d] - (lo + hi) / 2) < 0
        for d in after)
    p.extra["reliability_before"] = {d: round(v, 4) for d, v in before.items()}
    p.extra["reliability_after"] = {d: round(v, 4) for d, v in after.items()}
    return p


def apply_feedback_with_ts(p: Played, case_id: str, ts: datetime) -> None:
    apply_feedback_with_provenance(p.store, p.pipe, case_id, "FALSE_POSITIVE", "twin-poison", feedback_ts=ts,
                                   source="twin_scenarios")


def _check_appsec(m: dict, p: Played) -> list[tuple[str, bool]]:
    verbatim = all(p.store.get_event(s.event_id) is not None and p.store.get_event(s.event_id).payload == s.payload
                   for s in p.steps) if hasattr(p.store, "get_event") else len(p.steps) == 4
    return [("every event processed (no exception)", m["events"] == 4),
            ("payloads stored verbatim as data", verbatim),
            ("no hold or block", _no_intervention(m)),
            ("nothing above MEDIUM", _band_at_most(m, "MEDIUM"))]


SPECS: list[Spec] = [
    Spec(1, "midnight_ato", "ATO with a new payee (PRD Midnight)", True,
         "attacker's transfers never complete", _yaml("midnight_ato"),
         lambda m, p: [("detected (HIGH or above)", m["detected_at_step"] is not None),
                       ("every attacker transfer held or blocked", _attack_payments_stopped(m))],
         "scenarios/midnight_ato.yaml"),
    Spec(2, "structuring_split", "Transaction structuring", True,
         "held by the second near-limit transfer; the third never completes", _yaml("structuring_split"),
         lambda m, p: [("STRUCTURING evidence", "STRUCTURING" in m["reason_codes"]),
                       ("second transfer held or blocked", len(m["payments"]) >= 2 and m["payments"][1]["outcome"] != "completed"),
                       ("third transfer does not complete", len(m["payments"]) >= 3 and m["payments"][2]["outcome"] != "completed")],
         "scenarios/structuring_split.yaml"),
    Spec(3, "shared_ip_30", "30 genuine users behind one carrier IP", False,
         "no case above LOW, no cross-user case, no payment stopped",
         lambda: play_generated("shared_ip_30", build_shared_ip, datetime(2026, 10, 9, 8, 0, tzinfo=IST)),
         lambda m, p: [("no case above LOW", _band_at_most(m, "LOW")),
                       ("no case links two customers", m["max_customers_in_one_case"] <= 1),
                       ("no payment held or blocked", _no_intervention(m))],
         "generated (benchmark/twin_scenarios.py build_shared_ip)"),
    Spec(4, "device_multi_account", "Same device attacking multiple accounts", True,
         "device flagged; the takeover transfer does not complete", _yaml("device_multi_account"),
         lambda m, p: [("DEVICE_MULTI_ACCOUNT_FAILURES", "DEVICE_MULTI_ACCOUNT_FAILURES" in m["reason_codes"]),
                       ("takeover transfer held or blocked", _attack_payments_stopped(m))],
         "scenarios/device_multi_account.yaml"),
    Spec(5, "distributed_stuffing", "Distributed credential stuffing across rotating IPs", True,
         "account-centric failures detected; the takeover transfer does not complete",
         lambda: play_generated("distributed_stuffing", build_distributed_stuffing, datetime(2026, 10, 9, 3, 20, tzinfo=IST)),
         lambda m, p: [("ACCOUNT_DISTRIBUTED_FAILURES", "ACCOUNT_DISTRIBUTED_FAILURES" in m["reason_codes"]),
                       ("takeover transfer held or blocked", _attack_payments_stopped(m))],
         "generated (benchmark/twin_scenarios.py build_distributed_stuffing)"),
    Spec(6, "benign_vpn", "Benign commercial VPN", False,
         "no hold or block, nothing above MEDIUM", _yaml("benign_vpn"),
         lambda m, p: [("no hold or block", _no_intervention(m)), ("nothing above MEDIUM", _band_at_most(m, "MEDIUM"))],
         "scenarios/benign_vpn.yaml"),
    Spec(7, "residential_proxy_ato", "Residential-proxy account takeover", True,
         "payee after the account change escalates; the transfer is held", _yaml("residential_proxy_ato"),
         lambda m, p: [("detected (HIGH or above)", m["detected_at_step"] is not None),
                       ("transfer held or blocked", _attack_payments_stopped(m))],
         "scenarios/residential_proxy_ato.yaml"),
    Spec(8, "session_replay_clone", "Stolen-session replay with a cloned device", True,
         "transfer from a hijacked session on a hosting network does not complete", _yaml("session_replay_clone"),
         lambda m, p: [("transfer held or blocked", _attack_payments_stopped(m))],
         "scenarios/session_replay_clone.yaml"),
    Spec(9, "scam_app", "Authorised push payment (APP) scam", True,
         "first transfer held; the twin classifies an APP scam, not a takeover", _yaml("scam_app"),
         lambda m, p: [("first transfer held", bool(m["payments"]) and m["payments"][0]["outcome"] != "completed"),
                       ("case_kind app_scam", m["case_kind"] == "app_scam")],
         "scenarios/scam_app.yaml"),
    Spec(10, "remote_access_demo", "Remote-access control of a legitimate device", True,
         "transfer held; kept apart from account takeover", _yaml("remote_access_demo"),
         lambda m, p: [("transfer held or blocked", _attack_payments_stopped(m)),
                       ("not classified as account takeover", m["case_kind"] != "account_takeover")],
         "scenarios/remote_access_demo.yaml"),
    Spec(11, "mule_ring_noseed", "New mule ring without known seeds", True,
         "ring detected from money-flow shape alone", _yaml("mule_ring_noseed"),
         lambda m, p: [("MULE_* evidence without seeds", any(c.startswith("MULE_") for c in m["reason_codes"])),
                       ("detected (HIGH or above)", m["detected_at_step"] is not None)],
         "scenarios/mule_ring_noseed.yaml"),
    Spec(12, "popular_merchant_legit", "Popular merchant, legitimate high volume", False,
         "no MULE_* reason, no cross-customer case, nothing above LOW", _yaml("popular_merchant_legit"),
         lambda m, p: [("no MULE_* reason", not any(c.startswith("MULE_") for c in m["reason_codes"])),
                       ("no case links two customers", m["max_customers_in_one_case"] <= 1),
                       ("nothing above LOW", _band_at_most(m, "LOW"))],
         "scenarios/popular_merchant_legit.yaml"),
    Spec(13, "insider_trusted_network", "Insider abuse through a trusted network", True,
         "insider rules fire despite the trusted source IP", _yaml("insider_trusted_network"),
         lambda m, p: [("INSIDER_CHANGE_AFTER_NEW_DEVICE_LOGIN", "INSIDER_CHANGE_AFTER_NEW_DEVICE_LOGIN" in m["reason_codes"]),
                       ("INSIDER_REPEATED_SENSITIVE_ACTIONS", "INSIDER_REPEATED_SENSITIVE_ACTIONS" in m["reason_codes"])],
         "scenarios/insider_trusted_network.yaml"),
    Spec(14, "late_evidence_feedback", "Delayed events and feedback poisoning", True,
         "held at the transfer, blocked by late evidence; a wrong-verdict burst stays inside reliability bounds",
         play_late_feedback, _check_late_feedback, "scenarios/late_evidence_feedback.yaml"),
    Spec(15, "appsec_payloads", "SQL-injection / XSS strings as event data", False,
         "processed and stored verbatim as data; no hold", _yaml("appsec_payloads"), _check_appsec,
         "scenarios/appsec_payloads.yaml"),
]


def run_one(spec: Spec) -> dict:
    t0 = time.perf_counter()
    p = spec.play()
    m = measure(p)
    checks = [{"check": name, "passed": bool(ok)} for name, ok in spec.checks(m, p)]
    passed = all(c["passed"] for c in checks)
    stopped_attack = _attack_payments_stopped(m) if any(x["is_attack"] for x in m["payments"]) else None
    if spec.is_attack:
        outcome = "TP" if (m["detected_at_step"] is not None or stopped_attack or m["first_intervention"]) else "FN"
    else:
        outcome = "FP" if (BAND_ORDER.index(m["peak_band"]) >= HIGH or not _no_intervention(m)) else "TN"
    return {"num": spec.num, "id": spec.id, "title": spec.title, "is_attack": spec.is_attack, "source": spec.source,
            "expected": spec.expected, "outcome": outcome, "passed": passed, "checks": checks, **m,
            **({"extra": p.extra} if p.extra else {}), "seconds": round(time.perf_counter() - t0, 1)}


# ---------------------------------------------------------------------------- reporting
def _inr(paise: int) -> str:
    rupees = paise // 100
    s = str(rupees)
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        head = ",".join([head[max(0, i - 2):i] for i in range(len(head), 0, -2)][::-1])
        s = f"{head},{tail}"
    return f"₹{s}"


def markdown(results: list[dict], meta: dict) -> str:
    rows = []
    for r in results:
        money = r["money"]
        counts: dict[str, int] = {}
        for x in r["payments"]:
            counts[x["outcome"]] = counts.get(x["outcome"], 0) + 1
        pay = ", ".join(f"{n} {o}" for o, n in counts.items()) or "—"
        rows.append(f"| {r['num']} | {r['title']} | {'attack' if r['is_attack'] else 'benign'} | {r['outcome']} | "
                    f"{'pass' if r['passed'] else '**GAP**'} | {r['peak_band']} | "
                    f"{r['detection_stage'] or '—'} | {r['time_to_detection_min'] if r['time_to_detection_min'] is not None else '—'} | "
                    f"{pay} | {_inr(money['stopped_paise'])} / {_inr(money['attempted_paise'])} | {r['case_kind'] or '—'} |")
    gaps = [r for r in results if not r["passed"]]
    detail = []
    for r in results:
        detail.append(f"### {r['num']}. {r['title']} (`{r['id']}`)\n")
        detail.append(f"- Source: `{r['source']}`")
        detail.append(f"- Expected: {r['expected']}")
        detail.append(f"- Result: **{r['outcome']}**, {'all checks pass' if r['passed'] else 'GAP'}; peak band {r['peak_band']}, "
                      f"final band {r['final_band']}, p(attack) {r['final_p_attack']}")
        for c in r["checks"]:
            detail.append(f"  - [{'x' if c['passed'] else ' '}] {c['check']}")
        if r["detected_at_step"] is not None:
            detail.append(f"- Detection: step {r['detected_at_step']} ({r['detection_event']}), stage {r['detection_stage']}, "
                          f"{r['time_to_detection_min']} min after the first step")
        else:
            detail.append("- Detection: never reached HIGH")
        fi = r["first_intervention"]
        detail.append(f"- First intervention: {fi['policy_rule']} {fi['actions']} at minute {fi['at_min']}" if fi else "- First intervention: none")
        pays = ", ".join(_inr(x["amount_paise"]) + " " + x["outcome"] for x in r["payments"]) or "none"
        detail.append(f"- Payments: {pays}")
        detail.append(f"- Detectors: {', '.join(r['detectors']) or 'none'}")
        detail.append(f"- Reason codes: {', '.join(r['reason_codes']) or 'none'}")
        detail.append(f"- Patterns: {', '.join(r['patterns']) or 'none'}; cases {r['cases']}; twin case_kind `{r['case_kind']}`")
        if r.get("extra", {}).get("reliability_after"):
            detail.append(f"- Reliability before the burst: {r['extra']['reliability_before']}")
            detail.append(f"- Reliability after {FEEDBACK_BURST} wrong verdicts: {r['extra']['reliability_after']}")
        detail.append("")
    n_pass = sum(r["passed"] for r in results)
    return "\n".join([
        "# FraudMesh v3: Digital Twin scenario library (Phase 15)",
        "",
        f"Generated by `python -m benchmark.twin_scenarios` on {meta['generated']} (engine contract {meta['contract']}). "
        f"Raw results: `benchmark/twin_scenarios.json`.",
        "",
        "**These are synthetic results.** Every scenario, the 14-day background (generator seed "
        f"{BACKGROUND_SEED}, {BACKGROUND_CUSTOMERS} customers) and the twin's stage-transition table are generated data. "
        "They show what this engine does on these inputs. They are not real-world detection rates and must not be "
        "presented as a comparison with commercial products.",
        "",
        "How each scenario is played: direct mode through the real `Pipeline` and `MemoryStore` (real detectors, fusion, "
        "joiner and policy), every event enriched like the API does (`api/enrichment.py`), background first, then the "
        "preload and seeds, then the steps in arrival order.",
        "",
        f"**{n_pass} of {len(results)} scenarios meet every expected-behaviour check.**"
        + (f" Gaps: {', '.join(r['id'] for r in gaps)} (see below; tracked as strict xfails in "
           "`tests/engine/test_v3_twin_scenarios.py`)." if gaps else ""),
        "",
        "| # | Scenario | Kind | Outcome | Checks | Peak band | Detection stage | Min to HIGH | Payments | Stopped / attempted | Twin case_kind |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
        *rows,
        "",
        "Outcome: TP = attack detected or its money stopped; FN = attack missed; TN = benign left alone; "
        "FP = benign case reached HIGH or a benign payment was stopped.",
        "",
        "## Per scenario",
        "",
        *detail,
    ])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", nargs="*", help="scenario ids to run (default: all 15)")
    ap.add_argument("--no-write", action="store_true", help="print a summary only; do not write the JSON / markdown")
    args = ap.parse_args(argv)
    specs = [s for s in SPECS if not args.only or s.id in args.only]
    results = []
    for s in specs:
        r = run_one(s)
        results.append(r)
        print(f"{s.num:2d} {s.id:24s} {r['outcome']} {'pass' if r['passed'] else 'GAP '} peak={r['peak_band']:8s} "
              f"pays={[x['outcome'] for x in r['payments']]} kind={r['case_kind']} ({r['seconds']}s)", flush=True)
    from engine.contracts import CONTRACT_VERSION
    meta = {"generated": datetime.now(IST).strftime("%Y-%m-%d %H:%M IST"), "contract": CONTRACT_VERSION,
            "background": {"days": BACKGROUND_DAYS, "customers": BACKGROUND_CUSTOMERS, "seed": BACKGROUND_SEED},
            "synthetic": True}
    if not args.no_write and not args.only:
        OUT_JSON.write_text(json.dumps({"meta": meta, "scenarios": results}, indent=2, default=str) + "\n", encoding="utf-8")
        OUT_DOC.write_text(markdown(results, meta) + "\n", encoding="utf-8")
        print(f"wrote {OUT_JSON.relative_to(ROOT)} and {OUT_DOC.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
