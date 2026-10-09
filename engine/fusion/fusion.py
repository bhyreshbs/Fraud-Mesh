"""Fusion (PRD §10.5).

    ℓ_i = r_i · clip(logit(p_i) − logit(π), −2, 3)
    within each family, items sorted by ℓ descending: the first counts fully, every other one half (δ = 1, then 0.5)
    L   = logit(π) + Σ δ_i ℓ_i + Σ b_k          P = 1 / (1 + e^(−L))

Bands use BandThresholds; floors are applied after banding and can only raise the band:
    floor_CUSTOMER_DENIED  any evidence with reason CUSTOMER_DENIED            → CRITICAL (and status INVESTIGATING)
    floor_SEED_PAYEE       graph evidence with seed distance 0 (SEED_DISTANCE_0) → HIGH
    floor_THREE_STAGES     3+ distinct stages reached within 30 minutes        → MEDIUM
v3 floors (engine/detectors/rules/v3_core.yaml `floors`; each one can be disabled there):
    floor_S2_THEN_NEW_PAYEE     a positive S2 item, then a positive S5 item (payee positioning) at most window_h (24 h,
                                inclusive) later, with no disarm reason (STEP_UP_PASSED_TRUSTED) at or after that S2
                                item                                                → HIGH
    floor_TXN_HIGH_CONFIDENCE   a txn item from the valid calibrated model (degraded false) with p >= min_p (0.90)
                                                                                    → HIGH
                                This is a model-confidence floor: it says the transaction model is very sure, not that
                                the case is structuring (or any other one typology).
FusionResult.floor_evidence names the evidence item that satisfied each v3 floor (the S5 / txn item) and floor_cause
says why, so the explanation's floor part can cite it; the policy's floor rules (policy.yaml floor_any) record the
floor as the decision's policy_rule.
v3 correlated evidence (v3_core.yaml `correlation`, OFF by default because it changes the PRD §12.4 golden values):
items in different families that carry a reason from one provenance group (e.g. NEW_DEVICE and
MFA_CHANGED_AFTER_NEW_DEVICE both derive from one new-device fact), share a customer token and lie within window_min
of each other count once: the strongest keeps its δ·ℓ, every other one is multiplied by the group's factor.

`fuse` is pure (a function of the evidence list), so live scoring, replay and the golden test share it.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from engine.common.settings import settings
from engine.contracts import BAND_ORDER, STAGE_ORDER, BandThresholds, Case, Evidence, StageHit, Store
from engine.fusion.patterns import Pattern, load_patterns
from engine.fusion.v3_core import load_v3_core
from engine.graph.resolve import kind_of

CLIP_LOW, CLIP_HIGH = -2.0, 3.0
SECOND_IN_FAMILY = 0.5
THREE_STAGES_WINDOW = timedelta(minutes=30)
FLOOR_CUSTOMER_DENIED = "floor_CUSTOMER_DENIED"
FLOOR_SEED_PAYEE = "floor_SEED_PAYEE"
FLOOR_THREE_STAGES = "floor_THREE_STAGES"
FLOOR_S2_THEN_NEW_PAYEE = "floor_S2_THEN_NEW_PAYEE"
FLOOR_TXN_HIGH_CONFIDENCE = "floor_TXN_HIGH_CONFIDENCE"
FLOOR_MIN_BAND = {FLOOR_CUSTOMER_DENIED: "CRITICAL", FLOOR_SEED_PAYEE: "HIGH", FLOOR_THREE_STAGES: "MEDIUM",
                  FLOOR_S2_THEN_NEW_PAYEE: "HIGH", FLOOR_TXN_HIGH_CONFIDENCE: "HIGH"}   # v3 bands: from the config
V3_FLOOR_CONFIG = {FLOOR_S2_THEN_NEW_PAYEE: "s2_then_new_payee", FLOOR_TXN_HIGH_CONFIDENCE: "txn_high_confidence"}
V3_FLOOR_LABEL = {FLOOR_S2_THEN_NEW_PAYEE: "Floor: a payee was positioned within {window_h:g} h of an account-control "
                                           "change → {min_band}",
                  FLOOR_TXN_HIGH_CONFIDENCE: "Floor: the transaction model is very confident (p ≥ {min_p:.2f}; model "
                                             "confidence, not proof of a typology) → {min_band}"}
REASON_CUSTOMER_DENIED = "CUSTOMER_DENIED"
REASON_SEED_DISTANCE_0 = "SEED_DISTANCE_0"     # graph detector reason for a payee that is itself a fraud seed
STAGE_S2, STAGE_S5 = "S2_CONTROL_TAKEOVER", "S5_POSITIONING"


def logit(x: float) -> float:
    return math.log(x / (1.0 - x))


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x)) if x >= 0 else math.exp(x) / (1.0 + math.exp(x))


def band_of(p: float, th: BandThresholds) -> str:
    if p >= th.critical:
        return "CRITICAL"
    if p >= th.high:
        return "HIGH"
    if p >= th.medium:
        return "MEDIUM"
    return "LOW"


def max_band(a: str, b: str) -> str:
    return a if BAND_ORDER.index(a) >= BAND_ORDER.index(b) else b


def default_thresholds() -> BandThresholds:
    return BandThresholds(medium=settings.band_medium, high=settings.band_high, critical=settings.band_critical)


def weight(ev: Evidence, base_rate: float) -> float:
    """ℓ for one evidence item."""
    return ev.reliability * min(CLIP_HIGH, max(CLIP_LOW, logit(ev.p) - logit(base_rate)))


@dataclass
class FusionResult:
    log_odds: float
    p_attack: float
    band: str                                   # after floors
    band_before_floors: str
    contributions: dict[str, float]             # evidence_id -> δ·ℓ (× correlation factor when that is enabled)
    pattern_hits: list[str]
    pattern_completed_by: dict[str, str]        # pattern id -> evidence_id that completed it
    pattern_bonus: dict[str, float]
    floors: list[str]                           # every floor whose condition holds
    floors_raising: list[str]                   # the floors that actually raised the band
    stages: dict[str, StageHit] = field(default_factory=dict)
    amount_at_risk_paise: int = 0
    floor_evidence: dict[str, str] = field(default_factory=dict)        # v3 floor id -> evidence_id that satisfied it
    floor_cause: dict[str, str] = field(default_factory=dict)           # v3 floor id -> "ev_S5 after ev_S2" etc.
    correlated: dict[str, tuple[str, str, float]] = field(default_factory=dict)  # evidence_id -> (group, kept, factor)


def ordered(evidence: list[Evidence]) -> list[Evidence]:
    return sorted(evidence, key=lambda e: (e.ts, e.evidence_id))


def stage_hits(evs: list[Evidence], contributions: dict[str, float]) -> dict[str, StageHit]:
    """§10.7: a stage is reached by the earliest evidence with a positive contribution at that stage."""
    hits: dict[str, StageHit] = {}
    for ev in evs:
        if contributions[ev.evidence_id] > 0 and ev.stage not in hits:
            hits[ev.stage] = StageHit(ts=ev.ts, evidence_id=ev.evidence_id)
    return {s: hits[s] for s in STAGE_ORDER if s in hits}


def _three_stages(hits: dict[str, StageHit]) -> bool:
    times = sorted(h.ts for h in hits.values())
    return any(times[i + 2] - times[i] <= THREE_STAGES_WINDOW for i in range(len(times) - 2))


def floor_min_band(floor_id: str, v3: dict[str, Any] | None = None) -> str:
    if floor_id in V3_FLOOR_CONFIG:
        return (load_v3_core() if v3 is None else v3)["floors"][V3_FLOOR_CONFIG[floor_id]]["min_band"]
    return FLOOR_MIN_BAND[floor_id]


def floor_label(floor_id: str, cause: str | None = None, v3: dict[str, Any] | None = None) -> str | None:
    """Explanation label of a v3 floor, citing the evidence that satisfied it; None for a PRD §10.5/§10.7 floor."""
    if floor_id not in V3_FLOOR_LABEL:
        return None
    cfg = (load_v3_core() if v3 is None else v3)["floors"][V3_FLOOR_CONFIG[floor_id]]
    label = V3_FLOOR_LABEL[floor_id].format(**cfg)
    return f"{label} [{cause}]" if cause else label


def _customers(ev: Evidence) -> set[str]:
    return {t for t in ev.entities if kind_of(t) == "cust"}


def correlation_discounts(evs: list[Evidence], contributions: dict[str, float], cfg: dict[str, Any]
                          ) -> dict[str, tuple[str, str, float]]:
    """v3 11.5: evidence_id -> (group id, evidence_id kept at full weight, factor) for every discounted item.
    Only positive items in DIFFERENT families that share a customer token within window_min are correlated (one family
    is already discounted by δ). Strongest first, ties by (ts, evidence_id), so the result is deterministic. An item is
    discounted at most once (by the first group, in config order, that pairs it)."""
    if not cfg.get("enabled"):
        return {}
    window = timedelta(minutes=float(cfg["window_min"]))
    out: dict[str, tuple[str, str, float]] = {}
    for g in cfg.get("groups") or []:
        codes = set(g["reasons"])
        members = [e for e in evs if e.evidence_id not in out and contributions[e.evidence_id] > 0
                   and any(r.code in codes for r in e.reasons)]
        kept: list[Evidence] = []
        for e in sorted(members, key=lambda e: (-contributions[e.evidence_id], e.ts, e.evidence_id)):
            partner = next((k for k in kept if k.family != e.family and _customers(k) & _customers(e)
                            and abs(k.ts - e.ts) <= window), None)
            if partner is None:
                kept.append(e)
            else:
                out[e.evidence_id] = (g["id"], partner.evidence_id, float(g["factor"]))
    return out


def s2_then_new_payee(evs: list[Evidence], contributions: dict[str, float], cfg: dict[str, Any]) -> tuple[str, str] | None:
    """(S5 evidence_id, S2 evidence_id): the first positive S5 item at most window_h (inclusive) after a positive S2
    item, with no disarm reason at or after that S2 item; None if there is none. Event time (evidence ts) only, so a
    late-arriving S2 item with an earlier ts still pairs with an S5 item that arrived first."""
    window, disarm = timedelta(hours=float(cfg["window_h"])), set(cfg.get("disarm_reasons") or ())
    s2s = [e for e in evs if e.stage == STAGE_S2 and contributions[e.evidence_id] > 0]
    if not s2s:
        return None
    disarms = [e.ts for e in evs if any(r.code in disarm for r in e.reasons)]
    for s5 in evs:
        if s5.stage != STAGE_S5 or contributions[s5.evidence_id] <= 0:
            continue
        for s2 in s2s:
            if s2.ts <= s5.ts <= s2.ts + window and not any(t >= s2.ts for t in disarms):
                return s5.evidence_id, s2.evidence_id
    return None


def fuse(evidence: list[Evidence], *, base_rate: float | None = None, thresholds: BandThresholds | None = None,
         patterns: tuple[Pattern, ...] | None = None, v3: dict[str, Any] | None = None) -> FusionResult:
    base_rate = settings.base_rate if base_rate is None else base_rate
    th = default_thresholds() if thresholds is None else thresholds
    pats = load_patterns() if patterns is None else patterns
    v3 = load_v3_core() if v3 is None else v3
    evs = ordered(evidence)
    ell = {e.evidence_id: weight(e, base_rate) for e in evs}

    by_family: dict[str, list[Evidence]] = defaultdict(list)
    for e in evs:
        by_family[e.family].append(e)
    contributions: dict[str, float] = {}
    for items in by_family.values():
        ranked = sorted(items, key=lambda e: (-ell[e.evidence_id], e.ts, e.evidence_id))
        for rank, e in enumerate(ranked):
            contributions[e.evidence_id] = (1.0 if rank == 0 else SECOND_IN_FAMILY) * ell[e.evidence_id]
    correlated = correlation_discounts(evs, contributions, v3["correlation"])
    for ev_id, (_, _, factor) in correlated.items():
        contributions[ev_id] *= factor

    completed: dict[str, str] = {}
    for pat in pats:
        if any(u in completed for u in pat.unless_patterns):
            continue
        by = pat.completed_by(evs, ell)
        if by is not None:
            completed[pat.id] = by
    bonus = {p.id: p.bonus for p in pats if p.id in completed}

    log_odds = logit(base_rate) + sum(contributions[e.evidence_id] for e in evs) + sum(bonus.values())
    p_attack = sigmoid(log_odds)
    band0 = band_of(p_attack, th)

    hits = stage_hits(evs, contributions)
    floors = []
    if any(r.code == REASON_CUSTOMER_DENIED for e in evs for r in e.reasons):
        floors.append(FLOOR_CUSTOMER_DENIED)
    if any(e.detector == "graph" and any(r.code == REASON_SEED_DISTANCE_0 for r in e.reasons) for e in evs):
        floors.append(FLOOR_SEED_PAYEE)
    if _three_stages(hits):
        floors.append(FLOOR_THREE_STAGES)
    floor_evidence: dict[str, str] = {}
    floor_cause: dict[str, str] = {}
    fcfg = v3["floors"]
    if fcfg["s2_then_new_payee"]["enabled"]:
        hit = s2_then_new_payee(evs, contributions, fcfg["s2_then_new_payee"])
        if hit is not None:
            floors.append(FLOOR_S2_THEN_NEW_PAYEE)
            floor_evidence[FLOOR_S2_THEN_NEW_PAYEE] = hit[0]
            floor_cause[FLOOR_S2_THEN_NEW_PAYEE] = f"{hit[0]} after {hit[1]}"
    tcfg = fcfg["txn_high_confidence"]
    if tcfg["enabled"]:
        top = next((e for e in evs if e.detector == "txn" and not e.degraded and e.p >= float(tcfg["min_p"])), None)
        if top is not None:
            floors.append(FLOOR_TXN_HIGH_CONFIDENCE)
            floor_evidence[FLOOR_TXN_HIGH_CONFIDENCE] = top.evidence_id
            floor_cause[FLOOR_TXN_HIGH_CONFIDENCE] = f"{top.evidence_id} p={top.p:.3f}"
    band, raising = band0, []
    for f in floors:
        need = floor_min_band(f, v3)
        if BAND_ORDER.index(need) > BAND_ORDER.index(band0):
            raising.append(f)
        band = max_band(band, need)

    amount = sum(e.amount_paise or 0 for e in evs if e.stage == "S6_MONETIZATION")
    return FusionResult(log_odds=log_odds, p_attack=p_attack, band=band, band_before_floors=band0,
                        contributions=contributions, pattern_hits=[p.id for p in pats if p.id in completed],
                        pattern_completed_by=completed, pattern_bonus=bonus, floors=floors, floors_raising=raising,
                        stages=hits, amount_at_risk_paise=amount, floor_evidence=floor_evidence,
                        floor_cause=floor_cause, correlated=correlated)


class Fusion:
    """Recomputes a case from all of its evidence and re-saves every evidence item's contribution."""

    def __init__(self, store: Store, base_rate: float | None = None, thresholds: BandThresholds | None = None) -> None:
        self.store = store
        self.base_rate = settings.base_rate if base_rate is None else base_rate
        self.thresholds = default_thresholds() if thresholds is None else thresholds
        self.patterns = load_patterns()
        self.v3 = load_v3_core()

    def recompute(self, case: Case) -> FusionResult:
        evidence = self.store.list_evidence(case.case_id)
        res = fuse(evidence, base_rate=self.base_rate, thresholds=self.thresholds, patterns=self.patterns, v3=self.v3)
        for ev in evidence:
            c = res.contributions[ev.evidence_id]
            if ev.contribution != c:
                ev.contribution = c
                self.store.save_evidence(ev, case.case_id)          # save_evidence upserts
        case.log_odds, case.p_attack, case.band = res.log_odds, res.p_attack, res.band
        case.pattern_hits, case.floors = res.pattern_hits, res.floors
        case.amount_at_risk_paise = res.amount_at_risk_paise
        if FLOOR_CUSTOMER_DENIED in res.floors and case.status == "OPEN":
            case.status = "INVESTIGATING"
        return res
