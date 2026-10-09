"""Analyst feedback (PRD §10.11) → detector reliability, fraud seeds and case status.

    CONFIRMED_FRAUD  alpha += 1 for each detector with an evidence contribution > 0.5 in the case; seeds every case
                     entity of kind dev, ip, cid and every acct except the case customer's own (via pipeline.set_seeds);
                     status CONFIRMED_FRAUD; payment state unchanged
    FALSE_POSITIVE   beta += 1 for the same detectors; no seeds; status FALSE_POSITIVE; payment state normal
    INCONCLUSIVE     no change; status INVESTIGATING; payment state unchanged
A CUSTOMER_DENIED item never counts towards reliability (it carries no weight; the floor alone decides).
The FEEDBACK audit row is written by the API route, not here, so the hash chain gets exactly one row per feedback
(docs/CONTRACT_REQUESTS.md).

v3 core 11.4 — feedback-poisoning guards (engine/detectors/rules/v3_core.yaml `feedback`), all deterministic: time is
the feedback timestamp the caller passes (else the case's last event time), never the wall clock.
  decay       before an update, (alpha, beta) moves toward the PRD §8 prior by 0.5^(dt / half-life), dt = time since
              this detector's previous guarded update (needs a FeedbackGuard that remembers it; none → no decay)
  per update  each detector moves by at most max_update (the PRD unit step 1.0) per feedback
  per batch   the sum of a detector's moves within batch_window_h (by feedback time) is capped at max_batch
  bounds      an update never pushes alpha / (alpha + beta) above reliability_max or below reliability_min (it is
              shortened; a detector already outside the bounds is never pushed further out)
apply_feedback_with_provenance() also returns a provenance dict (who, when, source, which case evidence credited
which detector, requested vs applied deltas and why they were cut) for the API's FEEDBACK audit details.
The PRD §16.5 golden step (cyber 5/5 → 5/6 = 0.455 on one FALSE_POSITIVE) is inside every default bound.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from engine.contracts import DETECTOR_FAMILY, FeedbackResult, Store
from engine.fusion.v3_core import load_v3_core
from engine.graph.resolve import kind_of
from engine.graph.store import EntityGraph
from engine.store_memory import RELIABILITY_SEED, UNKNOWN_DETECTOR_SEED

CREDIT_MIN_CONTRIBUTION = 0.5
SEED_KINDS = frozenset({"dev", "ip", "cid"})
STATUS = {"CONFIRMED_FRAUD": "CONFIRMED_FRAUD", "FALSE_POSITIVE": "FALSE_POSITIVE", "INCONCLUSIVE": "INVESTIGATING"}


@dataclass
class FeedbackGuard:
    """Per-detector memory for decay and batch caps. Lives with the pipeline (attribute `feedback_guard`)."""
    last_update: dict[str, datetime] = field(default_factory=dict)
    history: dict[str, list[tuple[datetime, float]]] = field(default_factory=dict)   # detector -> (ts, |delta|)

    def used(self, detector: str, ts: datetime, window: timedelta) -> float:
        return sum(d for t, d in self.history.get(detector, []) if ts - window <= t <= ts)

    def record(self, detector: str, ts: datetime, delta: float, window: timedelta) -> None:
        self.last_update[detector] = max(ts, self.last_update.get(detector, ts))
        kept = [(t, d) for t, d in self.history.get(detector, []) if t >= ts - window]
        self.history[detector] = kept + [(ts, delta)]


def reliabilities(store: Store) -> dict[str, float]:
    rel = store.get_reliability()
    return {d: (rel[d][0] / (rel[d][0] + rel[d][1])) for d in DETECTOR_FAMILY if d in rel}


def credited_evidence(store: Store, case_id: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in store.list_evidence(case_id):
        if e.contribution > CREDIT_MIN_CONTRIBUTION and not any(r.code == "CUSTOMER_DENIED" for r in e.reasons):
            out.setdefault(e.detector, []).append(e.evidence_id)
    return dict(sorted(out.items()))


def credited_detectors(store: Store, case_id: str) -> list[str]:
    return list(credited_evidence(store, case_id))


def bounded_delta(a: float, b: float, d_alpha: float, d_beta: float, rmin: float, rmax: float) -> tuple[float, float]:
    """Shorten a non-negative (d_alpha, d_beta) step so alpha / (alpha + beta) stays within [rmin, rmax]."""
    if d_alpha > 0:                       # (a + x) / (a + x + b) <= rmax  ⇔  x <= rmax·b / (1 − rmax) − a
        d_alpha = min(d_alpha, max(0.0, rmax * b / (1 - rmax) - a)) if rmax < 1 else d_alpha
    if d_beta > 0:                        # a / (a + b + y) >= rmin  ⇔  y <= a / rmin − a − b
        d_beta = min(d_beta, max(0.0, a / rmin - a - b)) if rmin > 0 else d_beta
    return d_alpha, d_beta


def _guarded_update(store: Store, detector: str, d_alpha: float, d_beta: float, ts: datetime, cfg: dict[str, Any],
                    guard: FeedbackGuard | None) -> dict[str, Any]:
    a, b = store.get_reliability().get(detector, RELIABILITY_SEED.get(detector, UNKNOWN_DETECTOR_SEED))
    rec: dict[str, Any] = {"before": [a, b], "requested": [d_alpha, d_beta], "cut_by": []}
    decay = [0.0, 0.0]
    last = guard.last_update.get(detector) if guard is not None else None
    if last is not None and ts > last and cfg["decay_half_life_days"]:
        f = 0.5 ** ((ts - last) / timedelta(days=float(cfg["decay_half_life_days"])))
        a0, b0 = RELIABILITY_SEED.get(detector, UNKNOWN_DETECTOR_SEED)
        decay = [(a0 + (a - a0) * f) - a, (b0 + (b - b0) * f) - b]
        a, b = a + decay[0], b + decay[1]
    step = max(d_alpha, d_beta)
    if step > float(cfg["max_update"]):
        scale = float(cfg["max_update"]) / step
        d_alpha, d_beta = d_alpha * scale, d_beta * scale
        rec["cut_by"].append("max_update")
    window = timedelta(hours=float(cfg["batch_window_h"]))
    room = max(0.0, float(cfg["max_batch"]) - (guard.used(detector, ts, window) if guard is not None else 0.0))
    if max(d_alpha, d_beta) > room:
        scale = room / max(d_alpha, d_beta)
        d_alpha, d_beta = d_alpha * scale, d_beta * scale
        rec["cut_by"].append("max_batch")
    bounded = bounded_delta(a, b, d_alpha, d_beta, float(cfg["reliability_min"]), float(cfg["reliability_max"]))
    if bounded != (d_alpha, d_beta):
        rec["cut_by"].append("reliability_bounds")
    d_alpha, d_beta = bounded
    total = (decay[0] + d_alpha, decay[1] + d_beta)
    if total != (0.0, 0.0):
        store.add_reliability(detector, total[0], total[1])
    if guard is not None:
        guard.record(detector, ts, max(d_alpha, d_beta), window)
    rec.update(decay=decay, applied=[d_alpha, d_beta], after=[a + d_alpha, b + d_beta])
    return rec


def apply_feedback_with_provenance(store: Store, pipeline: Any, case_id: str, verdict: str, analyst: str, *,
                                   feedback_ts: datetime | None = None, source: str | None = None,
                                   guard: FeedbackGuard | None = None, cfg: dict[str, Any] | None = None
                                   ) -> tuple[FeedbackResult, dict[str, Any]]:
    """apply_feedback plus a provenance dict for the FEEDBACK audit row. `guard` defaults to
    pipeline.feedback_guard when the pipeline carries one."""
    if verdict not in STATUS:
        raise ValueError(f"unknown verdict {verdict!r}")
    case = store.get_case(case_id)
    if case is None:
        raise KeyError(case_id)
    cfg = load_v3_core()["feedback"] if cfg is None else cfg
    if guard is None:
        guard = getattr(pipeline, "feedback_guard", None)
    ts = feedback_ts or case.last_event_ts
    with store.transaction():
        before = reliabilities(store)
        credited = credited_evidence(store, case_id)
        seeds: list[str] = []
        updates: dict[str, Any] = {}
        if verdict == "CONFIRMED_FRAUD":
            for d in credited:
                updates[d] = _guarded_update(store, d, 1.0, 0.0, ts, cfg, guard)
            graph: EntityGraph | None = getattr(pipeline, "graph", None)
            if graph is None:
                graph = EntityGraph()
                graph.load(store.load_edges(), store.list_fraud_seeds())
            own = graph.accounts_of(case.customer) if case.customer else set()
            existing = store.list_fraud_seeds()
            seeds = sorted(t for t in case.entities
                           if (kind_of(t) in SEED_KINDS or (kind_of(t) == "acct" and t not in own)) and t not in existing)
            if seeds:
                if pipeline is not None:
                    pipeline.set_seeds(seeds, True)
                else:
                    store.set_fraud_seeds(seeds, True)
        elif verdict == "FALSE_POSITIVE":
            for d in credited:
                updates[d] = _guarded_update(store, d, 0.0, 1.0, ts, cfg, guard)
            case.payment_state = "normal"
        case.status = STATUS[verdict]
        store.save_case(case)
        after = reliabilities(store)
    provenance = {"case_id": case_id, "verdict": verdict, "analyst": analyst, "source": source or "analyst",
                  "feedback_ts": ts.isoformat(), "credited_evidence": credited, "updates": updates,
                  "guards": dict(cfg), "guard_state": "pipeline" if guard is not None else "none (no decay, batch = this call)"}
    return (FeedbackResult(case_id=case_id, verdict=verdict, reliability_before=before, reliability_after=after,
                           seeds_added=seeds, status_after=case.status), provenance)


def apply_feedback(store: Store, pipeline: Any, case_id: str, verdict: str, analyst: str) -> FeedbackResult:
    return apply_feedback_with_provenance(store, pipeline, case_id, verdict, analyst)[0]
