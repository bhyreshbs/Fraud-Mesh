"""Analyst feedback (PRD §10.11) → detector reliability, fraud seeds and case status.

    CONFIRMED_FRAUD  alpha += 1 for each detector with an evidence contribution > 0.5 in the case; seeds every case
                     entity of kind dev, ip, cid and every acct except the case customer's own (via pipeline.set_seeds);
                     status CONFIRMED_FRAUD; payment state unchanged
    FALSE_POSITIVE   beta += 1 for the same detectors; no seeds; status FALSE_POSITIVE; payment state normal
    INCONCLUSIVE     no change; status INVESTIGATING; payment state unchanged
A CUSTOMER_DENIED item never counts towards reliability (it carries no weight; the floor alone decides).
The FEEDBACK audit row is written by the API route, not here, so the hash chain gets exactly one row per feedback
(docs/CONTRACT_REQUESTS.md).
"""
from __future__ import annotations

from typing import Any

from engine.contracts import DETECTOR_FAMILY, FeedbackResult, Store
from engine.graph.resolve import kind_of
from engine.graph.store import EntityGraph

CREDIT_MIN_CONTRIBUTION = 0.5
SEED_KINDS = frozenset({"dev", "ip", "cid"})
STATUS = {"CONFIRMED_FRAUD": "CONFIRMED_FRAUD", "FALSE_POSITIVE": "FALSE_POSITIVE", "INCONCLUSIVE": "INVESTIGATING"}


def reliabilities(store: Store) -> dict[str, float]:
    rel = store.get_reliability()
    return {d: (rel[d][0] / (rel[d][0] + rel[d][1])) for d in DETECTOR_FAMILY if d in rel}


def credited_detectors(store: Store, case_id: str) -> list[str]:
    return sorted({e.detector for e in store.list_evidence(case_id) if e.contribution > CREDIT_MIN_CONTRIBUTION
                   and not any(r.code == "CUSTOMER_DENIED" for r in e.reasons)})


def apply_feedback(store: Store, pipeline: Any, case_id: str, verdict: str, analyst: str) -> FeedbackResult:
    if verdict not in STATUS:
        raise ValueError(f"unknown verdict {verdict!r}")
    case = store.get_case(case_id)
    if case is None:
        raise KeyError(case_id)
    with store.transaction():
        before = reliabilities(store)
        detectors = credited_detectors(store, case_id)
        seeds: list[str] = []
        if verdict == "CONFIRMED_FRAUD":
            for d in detectors:
                store.add_reliability(d, 1.0, 0.0)
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
            for d in detectors:
                store.add_reliability(d, 0.0, 1.0)
            case.payment_state = "normal"
        case.status = STATUS[verdict]
        store.save_case(case)
        after = reliabilities(store)
    return FeedbackResult(case_id=case_id, verdict=verdict, reliability_before=before, reliability_after=after,
                          seeds_added=seeds, status_after=case.status)
