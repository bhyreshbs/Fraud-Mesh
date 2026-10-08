"""Fusion (PRD §10.5).

    ℓ_i = r_i · clip(logit(p_i) − logit(π), −2, 3)
    within each family, items sorted by ℓ descending: the first counts fully, every other one half (δ = 1, then 0.5)
    L   = logit(π) + Σ δ_i ℓ_i + Σ b_k          P = 1 / (1 + e^(−L))

Bands use BandThresholds; floors are applied after banding and can only raise the band:
    floor_CUSTOMER_DENIED  any evidence with reason CUSTOMER_DENIED            → CRITICAL (and status INVESTIGATING)
    floor_SEED_PAYEE       graph evidence with seed distance 0 (SEED_DISTANCE_0) → HIGH
    floor_THREE_STAGES     3+ distinct stages reached within 30 minutes        → MEDIUM

`fuse` is pure (a function of the evidence list), so live scoring, replay and the golden test share it.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from engine.common.settings import settings
from engine.contracts import BAND_ORDER, STAGE_ORDER, BandThresholds, Case, Evidence, StageHit, Store
from engine.fusion.patterns import Pattern, load_patterns

CLIP_LOW, CLIP_HIGH = -2.0, 3.0
SECOND_IN_FAMILY = 0.5
THREE_STAGES_WINDOW = timedelta(minutes=30)
FLOOR_CUSTOMER_DENIED = "floor_CUSTOMER_DENIED"
FLOOR_SEED_PAYEE = "floor_SEED_PAYEE"
FLOOR_THREE_STAGES = "floor_THREE_STAGES"
FLOOR_MIN_BAND = {FLOOR_CUSTOMER_DENIED: "CRITICAL", FLOOR_SEED_PAYEE: "HIGH", FLOOR_THREE_STAGES: "MEDIUM"}
REASON_CUSTOMER_DENIED = "CUSTOMER_DENIED"
REASON_SEED_DISTANCE_0 = "SEED_DISTANCE_0"     # graph detector reason for a payee that is itself a fraud seed


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
    contributions: dict[str, float]             # evidence_id -> δ·ℓ
    pattern_hits: list[str]
    pattern_completed_by: dict[str, str]        # pattern id -> evidence_id that completed it
    pattern_bonus: dict[str, float]
    floors: list[str]                           # every floor whose condition holds
    floors_raising: list[str]                   # the floors that actually raised the band
    stages: dict[str, StageHit] = field(default_factory=dict)
    amount_at_risk_paise: int = 0


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


def fuse(evidence: list[Evidence], *, base_rate: float | None = None, thresholds: BandThresholds | None = None,
         patterns: tuple[Pattern, ...] | None = None) -> FusionResult:
    base_rate = settings.base_rate if base_rate is None else base_rate
    th = default_thresholds() if thresholds is None else thresholds
    pats = load_patterns() if patterns is None else patterns
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

    completed: dict[str, str] = {}
    for pat in pats:
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
    band, raising = band0, []
    for f in floors:
        if BAND_ORDER.index(FLOOR_MIN_BAND[f]) > BAND_ORDER.index(band0):
            raising.append(f)
        band = max_band(band, FLOOR_MIN_BAND[f])

    amount = sum(e.amount_paise or 0 for e in evs if e.stage == "S6_MONETIZATION")
    return FusionResult(log_odds=log_odds, p_attack=p_attack, band=band, band_before_floors=band0,
                        contributions=contributions, pattern_hits=[p.id for p in pats if p.id in completed],
                        pattern_completed_by=completed, pattern_bonus=bonus, floors=floors, floors_raising=raising,
                        stages=hits, amount_at_risk_paise=amount)


class Fusion:
    """Recomputes a case from all of its evidence and re-saves every evidence item's contribution."""

    def __init__(self, store: Store, base_rate: float | None = None, thresholds: BandThresholds | None = None) -> None:
        self.store = store
        self.base_rate = settings.base_rate if base_rate is None else base_rate
        self.thresholds = default_thresholds() if thresholds is None else thresholds
        self.patterns = load_patterns()

    def recompute(self, case: Case) -> FusionResult:
        evidence = self.store.list_evidence(case.case_id)
        res = fuse(evidence, base_rate=self.base_rate, thresholds=self.thresholds, patterns=self.patterns)
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
