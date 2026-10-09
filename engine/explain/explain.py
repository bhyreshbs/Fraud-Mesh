"""Explanation (PRD §10.10): exact contributions (waterfall) + template narrative with citations.

parts = the prior, then one part per evidence item in time order with its final contribution; each pattern part
right after the evidence that completed it; a zero-contribution floor part right after the item at which that floor
first raised the band. running_log_odds accumulates, so the last value equals case.log_odds.
seed_paths = graph seed paths from the case's payee and device tokens (graph rebuilt from the store's edges).
"""
from __future__ import annotations

from engine.common.settings import settings
from engine.contracts import (
    Evidence,
    Explanation,
    ExplanationPart,
    ShapItem,
    Store,
)
from engine.explain.narrative import closing_sentence, evidence_sentence, reason_text
from engine.fusion.fusion import default_thresholds, floor_label, fuse, logit, ordered, sigmoid
from engine.fusion.patterns import load_patterns
from engine.graph.resolve import kind_of
from engine.graph.store import EntityGraph
from engine.policy.policy import severity

FLOOR_LABEL = {"floor_CUSTOMER_DENIED": "Floor: the customer said \"Not me\" → CRITICAL",
               "floor_SEED_PAYEE": "Floor: the payee is a confirmed fraud entity → HIGH",
               "floor_THREE_STAGES": "Floor: three attack stages within 30 minutes → MEDIUM"}
DETECTOR_LABEL = {"netsec": "Network IDS", "behaviour": "Login behaviour", "auth": "Account control", "kyc": "KYC",
                  "cyber": "Cloud audit", "graph": "Entity graph", "txn": "Transaction model"}


def _label(ev: Evidence) -> str:
    text = reason_text(ev)
    return f"{DETECTOR_LABEL.get(ev.detector, ev.detector)}: {text[0].upper() + text[1:] if text else ev.detector}"


def _floor_points(evs: list[Evidence], base_rate: float, th) -> dict[str, str]:
    """floor id → evidence_id of the item at which the floor first raised the band."""
    pats, out = load_patterns(), {}
    for k in range(1, len(evs) + 1):
        for f in fuse(evs[:k], base_rate=base_rate, thresholds=th, patterns=pats).floors_raising:
            out.setdefault(f, evs[k - 1].evidence_id)
    return out


def _payees(store: Store, evs: list[Evidence]) -> list[str]:
    out = []
    for ev in evs:
        if ev.detector in ("graph", "txn"):
            event = store.get_event(ev.event_id)
            payee = event.payload.get("payee_account") if event else None
            if payee and payee not in out:
                out.append(payee)
    return out


def seed_paths(store: Store, tokens: list[str]) -> list[list[str]]:
    if not tokens:
        return []
    graph = EntityGraph()
    graph.load(store.load_edges(), store.list_fraud_seeds())
    paths = []
    for t in tokens:
        hit = graph.seed_distance(t)
        if hit is not None and hit[1] not in paths:
            paths.append(hit[1])
    return paths


def explain_case(store: Store, case_id: str) -> Explanation:
    case = store.get_case(case_id)
    if case is None:
        raise KeyError(case_id)
    base_rate, th = settings.base_rate, default_thresholds()
    evs = ordered(store.list_evidence(case_id))
    res = fuse(evs, base_rate=base_rate, thresholds=th)
    prior = logit(base_rate)
    completed_by: dict[str, list[str]] = {}
    for pat_id, ev_id in res.pattern_completed_by.items():
        completed_by.setdefault(ev_id, []).append(pat_id)
    floors_at: dict[str, list[str]] = {}
    for floor_id, ev_id in _floor_points(evs, base_rate, th).items():
        if floor_id in res.floors:
            floors_at.setdefault(ev_id, []).append(floor_id)
    patterns = {p.id: p for p in load_patterns()}

    parts = [ExplanationPart(part_id="prior", kind="prior", label=f"Base rate {base_rate:.0%}", contribution=prior,
                             running_log_odds=prior, running_p=sigmoid(prior))]
    running = prior
    narrative = []
    for ev in evs:
        c = res.contributions[ev.evidence_id]
        running += c
        corr = res.correlated.get(ev.evidence_id)          # v3 11.5, only when correlation is enabled
        label = _label(ev) + (f" (correlated with {corr[1]} via {corr[0]}, ×{corr[2]:g})" if corr else "")
        parts.append(ExplanationPart(part_id=ev.evidence_id, kind="evidence", label=label, detector=ev.detector,
                                     stage=ev.stage, contribution=c, running_log_odds=running, running_p=sigmoid(running),
                                     ts=ev.ts))
        for pat_id in completed_by.get(ev.evidence_id, []):
            running += res.pattern_bonus[pat_id]
            parts.append(ExplanationPart(part_id=pat_id, kind="pattern", label=patterns[pat_id].label,
                                         contribution=res.pattern_bonus[pat_id], running_log_odds=running,
                                         running_p=sigmoid(running), ts=ev.ts))
        for floor_id in floors_at.get(ev.evidence_id, []):
            label = FLOOR_LABEL.get(floor_id) or floor_label(floor_id, res.floor_cause.get(floor_id)) or floor_id
            parts.append(ExplanationPart(part_id=floor_id, kind="floor", label=label, contribution=0.0,
                                         running_log_odds=running, running_p=sigmoid(running), ts=ev.ts))
        narrative.append(evidence_sentence(ev, completed_by.get(ev.evidence_id, [])))
    closing = closing_sentence(store.list_decisions(case_id), case.band, severity)
    if closing is not None:
        narrative.append(closing)

    shap: dict[str, list[ShapItem]] = {ev.evidence_id: ev.shap for ev in evs if ev.shap}
    tokens = _payees(store, evs) + sorted(t for t in case.entities if kind_of(t) == "dev")
    return Explanation(case_id=case_id, prior_log_odds=prior, parts=parts, final_log_odds=running, p_attack=sigmoid(running),
                       band=case.band, floors=list(case.floors), narrative=narrative, shap_by_evidence=shap,
                       seed_paths=seed_paths(store, tokens))

