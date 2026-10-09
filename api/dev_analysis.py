"""DEV-ONLY stand-ins for engine.api replay_case / explain_case / simulate_policy (PRD §10.9, §10.10), used by
api/dev_pipeline.ScriptedPipeline when FM_DEV_PIPELINE=1. Dev 2's engine/replay and engine/explain replace them.

Everything is recomputed from stored evidence (p, reliability, ts, stage, family, reasons) — models are never re-run:
  fused   : after each item, re-run fusion (family discount), patterns, floors, bands and policy incrementally
  siloed  : judge each item alone — SILOED_ALERT if p >= 0.5, BLOCK only for txn evidence with p >= 0.5
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import timedelta, timezone

from sqlalchemy import text

from api.db import session
from engine.common.ids import new_id
from engine.common.settings import settings
from engine.common.tokenize import tok
from engine.contracts import (
    ACTION_SEVERITY,
    BAND_ORDER,
    SEVERITY_HOLD,
    BandThresholds,
    Evidence,
    Explanation,
    ExplanationPart,
    NarrativeSentence,
    ReplayPoint,
    ReplayResult,
    SimulationResult,
)

BASE = settings.base_rate
POLICY = [("critical", "CRITICAL", ["BLOCK_PENDING_PAYMENTS", "FREEZE_NEW_PAYEES", "REVOKE_SESSIONS", "OPEN_CASE_P1"]),
          ("high", "HIGH", ["HOLD_OUTBOUND_PAYMENTS", "STEP_UP_TRUSTED_FACTOR", "OPEN_CASE_P2"]),
          ("medium", "MEDIUM", ["STEP_UP_ANY_FACTOR"]), ("low", "LOW", ["ALLOW"])]
PATTERNS = {"pat_ATO1": ("New-device login followed by an MFA or profile change", 0.5),
            "pat_CASE_IP_CLOUD": ("Cloud action from an IP already seen in this case", 0.3)}
FLOOR_MIN = {"floor_CUSTOMER_DENIED": "CRITICAL", "floor_SEED_PAYEE": "HIGH", "floor_THREE_STAGES": "MEDIUM"}
SEED_LINKED_PAYEES = {tok("acct", "A-RAVI-778"): tok("dev", "fp_mule_shared")}
REASON_TEXT = {
    "IDS_SEV1": "a severity-1 IDS alert", "IDS_SEV2": "credential stuffing (IDS severity 2)", "IDS_SEV3": "a low-severity IDS alert",
    "NEW_DEVICE": "a new device", "NEW_ASN": "a new network", "FAR_FROM_HOME": "far from home", "IMPOSSIBLE_TRAVEL": "an impossible-travel location",
    "MFA_CHANGED_AFTER_NEW_DEVICE": "the SMS factor was changed right after a new-device login",
    "PROFILE_CHANGE_AFTER_NEW_DEVICE": "the profile was changed right after a new-device login",
    "STEP_UP_PASSED_WITH_FRESH_FACTOR": "a step-up passed on a freshly changed factor",
    "STEP_UP_PASSED_TRUSTED": "a step-up passed on the trusted device", "STEP_UP_FAILED_OR_TIMEOUT": "a step-up failed or timed out",
    "CUSTOMER_DENIED": "the customer tapped Not me", "LOW_LIVENESS": "low liveness", "LOW_FACE_MATCH": "a low face match",
    "INJECTION_SUSPECTED": "a suspected camera injection", "DOC_TAMPER": "document tampering",
    "cloud_limit_raise_untrusted_ip": "a support-console identity raised the transfer limit from an untrusted IP",
    "SEED_DISTANCE_1": "is one hop from a confirmed mule", "SEED_DISTANCE_2": "is two hops from confirmed fraud",
    "PAYEE_NAME_MISMATCH": "does not match the account holder's name", "AMOUNT_HIGH_VS_MEDIAN": "amount far above usual",
    "NEW_PAYEE": "new payee", "PAYEE_FAN_IN": "many senders to this payee", "STRUCTURING": "split just under limits",
}
TEMPLATES = {
    "S0_RECON": "At {time} {reason_text} was seen from {ip_short}.",
    "S1_INITIAL_ACCESS": "At {time} a login succeeded from {reason_text}.",
    "S2_CONTROL_TAKEOVER": "At {time} {reason_text}.",
    "S3_IDENTITY_MANIPULATION": "At {time} a KYC check returned {reason_text}.",
    "S4_ESCALATION": "At {time} {reason_text} ({technique}).",
    "S5_POSITIONING": "At {time} a payee was added that {reason_text}.",
    "S6_MONETIZATION": "At {time} a transfer of Rs {amount} was attempted ({reason_text}).",
}


def logit(x: float) -> float:
    return math.log(x / (1 - x))


def sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def ell(e: Evidence) -> float:
    return e.reliability * max(-2.0, min(3.0, logit(e.p) - logit(BASE)))


def band_of(p: float, t: BandThresholds) -> str:
    return "CRITICAL" if p >= t.critical else "HIGH" if p >= t.high else "MEDIUM" if p >= t.medium else "LOW"


_IST = timezone(timedelta(hours=5, minutes=30))


def ist_hhmm(ts) -> str:
    return ts.astimezone(_IST).strftime("%H:%M")


def inr(paise: int) -> str:
    rupees = str(round(paise / 100))
    head, tail = rupees[:-3], rupees[-3:]
    groups = []
    while len(head) > 2:
        groups.insert(0, head[-2:])
        head = head[:-2]
    return ",".join(([head] if head else []) + groups + [tail]) if len(rupees) > 3 else rupees


@dataclass
class Step:
    ev: Evidence
    log_odds: float
    p: float
    band: str
    actions: list[str]
    severity: int
    patterns_added: list[str] = field(default_factory=list)
    floors_added: list[str] = field(default_factory=list)
    contributions: dict[str, float] = field(default_factory=dict)


def fused_steps(evidence: list[Evidence], t: BandThresholds | None = None, ablate: tuple[str, ...] = ()) -> list[Step]:
    """Incremental fused replay (§10.9) over evidence in (ts, evidence_id) order, skipping ablated detectors."""
    t = t or BandThresholds(medium=settings.band_medium, high=settings.band_high, critical=settings.band_critical)
    items = sorted((e for e in evidence if e.detector not in ablate), key=lambda e: (e.ts, e.evidence_id))
    out, seen, patterns, floors, stage_ts = [], [], [], [], {}
    for new in items:
        seen.append(new)
        by_fam: dict[str, list[Evidence]] = {}
        for e in seen:
            by_fam.setdefault(e.family, []).append(e)
        contrib = {}
        for fam_items in by_fam.values():
            for k, e in enumerate(sorted(fam_items, key=ell, reverse=True)):
                contrib[e.evidence_id] = ell(e) * (1.0 if k == 0 else 0.5)
        added_p, added_f = [], []
        if "pat_ATO1" not in patterns and new.stage == "S2_CONTROL_TAKEOVER" and ell(new) > 0 and any(
                e.stage == "S1_INITIAL_ACCESS" and ell(e) > 0 and timedelta(0) <= new.ts - e.ts <= timedelta(minutes=30) for e in seen):
            added_p.append("pat_ATO1")
        if "pat_CASE_IP_CLOUD" not in patterns and new.detector == "cyber":
            earlier = {x for e in seen if e is not new for x in e.entities if x.startswith("ip:")}
            if any(x in earlier for x in new.entities if x.startswith("ip:")):
                added_p.append("pat_CASE_IP_CLOUD")
        patterns += added_p
        if ell(new) > 0 and new.stage not in stage_ts:
            stage_ts[new.stage] = new.ts
        L = logit(BASE) + sum(contrib.values()) + sum(PATTERNS[p][1] for p in patterns)
        p = sigmoid(L)
        band = band_of(p, t)
        if any(r.code == "CUSTOMER_DENIED" for r in new.reasons) and "floor_CUSTOMER_DENIED" not in floors:
            added_f.append("floor_CUSTOMER_DENIED")
        if len({s for s, ts in stage_ts.items() if new.ts - ts <= timedelta(minutes=30)}) >= 3 and "floor_THREE_STAGES" not in floors:
            added_f.append("floor_THREE_STAGES")
        floors += added_f
        for f in floors:
            if BAND_ORDER.index(FLOOR_MIN[f]) > BAND_ORDER.index(band):
                band = FLOOR_MIN[f]
        actions = next(a for _, b, a in POLICY if BAND_ORDER.index(band) >= BAND_ORDER.index(b))
        out.append(Step(new, L, p, band, actions, max(ACTION_SEVERITY[a] for a in actions), added_p, added_f, contrib))
    return out


def _points_fused(steps: list[Step]) -> list[ReplayPoint]:
    return [ReplayPoint(ts=s.ev.ts, evidence_id=s.ev.evidence_id, p=s.p, band=s.band, actions=s.actions, severity=s.severity) for s in steps]


def _points_siloed(evidence: list[Evidence], ablate: tuple[str, ...]) -> list[ReplayPoint]:
    out = []
    for e in sorted((e for e in evidence if e.detector not in ablate), key=lambda e: (e.ts, e.evidence_id)):
        alert = e.p >= 0.5
        actions = ["BLOCK_PENDING_PAYMENTS"] if e.detector == "txn" and alert else ["ALLOW"]
        out.append(ReplayPoint(ts=e.ts, evidence_id=e.evidence_id, p=e.p, band="SILOED_ALERT" if alert else "SILOED_NONE",
                               actions=actions, severity=max(ACTION_SEVERITY[a] for a in actions)))
    return out


def _eip(points: list[ReplayPoint]) -> ReplayPoint | None:
    return next((pt for pt in points if pt.severity >= SEVERITY_HOLD), None)


def replay(store, case_id: str, ablate: list[str] | None = None, mode: str = "fused", save: bool = True) -> ReplayResult:
    case = store.get_case(case_id)
    if case is None:
        raise KeyError(case_id)
    evidence = store.list_evidence(case_id)
    ab = tuple(ablate or ())
    points = _points_fused(fused_steps(evidence, ablate=ab)) if mode == "fused" else _points_siloed(evidence, ab)
    eip = _eip(points)
    baseline_eip = _eip(_points_fused(fused_steps(evidence)))
    s6 = sorted((e for e in evidence if e.stage == "S6_MONETIZATION"), key=lambda e: e.ts)
    r = ReplayResult(
        replay_id=new_id("rep"), case_id=case_id, mode=mode, ablated=list(ab), timeline=points, eip=eip, baseline_eip=baseline_eip,
        lead_time_s=int((s6[0].ts - eip.ts).total_seconds()) if eip and s6 else None,
        lead_time_lost_s=int((eip.ts - baseline_eip.ts).total_seconds()) if eip and baseline_eip else None,
        money_protected_paise=sum(e.amount_paise or 0 for e in s6 if eip and e.ts >= eip.ts))
    if save:
        store.save_replay(r)
    return r


def _sentence(e: Evidence) -> str:
    reason_text = " and ".join(REASON_TEXT.get(r.code, r.code.replace("_", " ").lower()) for r in e.reasons)
    ip = next((x for x in e.entities if x.startswith("ip:")), "an unknown IP")
    return TEMPLATES[e.stage].format(time=ist_hhmm(e.ts), reason_text=reason_text, ip_short=f"IP {ip[-6:]}",
                                     technique=e.attack_technique or "no technique", amount=inr(e.amount_paise or 0))


def explain(store, case_id: str) -> Explanation:
    case = store.get_case(case_id)
    if case is None:
        raise KeyError(case_id)
    evidence = sorted(store.list_evidence(case_id), key=lambda e: (e.ts, e.evidence_id))
    steps = fused_steps(evidence)
    final = steps[-1].contributions if steps else {}
    parts = [ExplanationPart(part_id="prior", kind="prior", label=f"Base rate {BASE:.0%}", contribution=logit(BASE),
                             running_log_odds=logit(BASE), running_p=BASE)]
    run = logit(BASE)
    for s in steps:
        c = final.get(s.ev.evidence_id, 0.0)
        run += c
        parts.append(ExplanationPart(part_id=s.ev.evidence_id, kind="evidence", label=_sentence(s.ev)[9:].rstrip(".")[:90],
                                     detector=s.ev.detector, stage=s.ev.stage, contribution=c, running_log_odds=run,
                                     running_p=sigmoid(run), ts=s.ev.ts))
        for pid in s.patterns_added:                                # inserted right after the evidence that completed it
            run += PATTERNS[pid][1]
            parts.append(ExplanationPart(part_id=pid, kind="pattern", label=PATTERNS[pid][0], contribution=PATTERNS[pid][1],
                                         running_log_odds=run, running_p=sigmoid(run), ts=s.ev.ts))
        for fid in s.floors_added:                                  # zero-contribution marker where a floor applies
            parts.append(ExplanationPart(part_id=fid, kind="floor", label=f"Floor: minimum band {FLOOR_MIN[fid]}",
                                         contribution=0.0, running_log_odds=run, running_p=sigmoid(run), ts=s.ev.ts))
    narrative = []
    for s in steps:
        cites = [s.ev.evidence_id] + [p for p in s.patterns_added]
        narrative.append(NarrativeSentence(text=_sentence(s.ev)[:-1] + "".join(f" [{c}]" for c in cites) + ".", cites=cites))
    decisions = store.list_decisions(case_id)
    first_hold = next((d for d in decisions if max(ACTION_SEVERITY[a] for a in d.actions) >= SEVERITY_HOLD), None)
    if first_hold and decisions:
        last = decisions[-1]
        narrative.append(NarrativeSentence(
            text=(f"FraudMesh first intervened at {ist_hhmm(first_hold.created_at)} with {', '.join(first_hold.actions)} "
                  f"[{first_hold.decision_id}]; the case is now {case.band} [{last.decision_id}]."),
            cites=[first_hold.decision_id, last.decision_id]))
    seed_paths = [[payee, seed] for payee, seed in SEED_LINKED_PAYEES.items() if payee in case.entities]
    return Explanation(case_id=case_id, prior_log_odds=logit(BASE), parts=parts, final_log_odds=run, p_attack=sigmoid(run),
                       band=case.band, floors=case.floors, narrative=narrative,
                       shap_by_evidence={e.evidence_id: e.shap for e in evidence if e.shap}, seed_paths=seed_paths)


def simulate(store, t: BandThresholds) -> SimulationResult:
    """§10.9 simulate_policy: replay every case in fused mode with the given thresholds, then score against labels."""
    labels = store.get_labels()
    attack_of = {eid: lb.attack_id for eid, lb in labels.items() if lb.is_attack and lb.attack_id}
    with session.transaction() as c:
        ev_rows = c.execute(text("SELECT event_id, event_type, customer, occurred_at, (data->'payload'->>'amount_paise')::bigint AS amount "
                                 "FROM events")).mappings().all()
    last_ts: dict[str, object] = {}
    for r in ev_rows:
        a = attack_of.get(r["event_id"])
        if a and (a not in last_ts or r["occurred_at"] > last_ts[a]):
            last_ts[a] = r["occurred_at"]
    attack_customers = {r["customer"] for r in ev_rows if r["event_id"] in attack_of and r["customer"]}
    benign_customers = {r["customer"] for r in ev_rows if r["customer"]} - attack_customers
    caught, leads, money, flagged = set(), [], 0, set()
    txn_case_points: dict[str, list[ReplayPoint]] = {}
    for case in store.list_cases():
        evidence = store.list_evidence(case.case_id)
        points = _points_fused(fused_steps(evidence, t))
        if not points:
            continue
        attacks = {attack_of[e.event_id] for e in evidence if e.event_id in attack_of}
        eip = _eip(points)
        for a in attacks:
            if eip and eip.ts < last_ts[a]:
                caught.add(a)
                s6 = sorted((e for e in evidence if e.stage == "S6_MONETIZATION"), key=lambda e: e.ts)
                if s6:
                    leads.append(int((s6[0].ts - eip.ts).total_seconds()))
                money += sum(e.amount_paise or 0 for e in s6 if e.ts >= eip.ts)
        if case.customer in benign_customers and any(BAND_ORDER.index(pt.band) >= BAND_ORDER.index("HIGH") for pt in points):
            flagged.add(case.customer)
        for e in evidence:
            if e.detector == "txn":
                txn_case_points[e.event_id] = points
    legit = [r for r in ev_rows if r["event_type"] == "transaction" and r["event_id"] not in attack_of]
    stopped = 0
    for r in legit:
        pts = [pt for pt in txn_case_points.get(r["event_id"], []) if pt.ts <= r["occurred_at"]]
        stopped += bool(pts and max(pt.severity for pt in pts) >= SEVERITY_HOLD)
    return SimulationResult(thresholds=t, attacks_total=len(last_ts), attacks_caught=len(caught),
                            benign_customers_total=len(benign_customers), benign_customers_flagged=len(flagged),
                            legit_payments_total=len(legit), legit_payments_stopped=stopped, money_protected_paise=money,
                            median_lead_time_s=int(statistics.median(leads)) if leads else None)
