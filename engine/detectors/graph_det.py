"""graph detector (PRD §10.4): where the money is going, stage S5, T1657.

Handles payee_added, and transactions to a payee with no payee_added in the last 24 h. p comes from the payee's
seed distance: 0 → SEED_DISTANCE_0 (the payee is itself a fraud seed; triggers floor_SEED_PAYEE), 1/2/3 →
SEED_DISTANCE_1/_2/_3. If only one shortest path exists and its weakest edge has confidence < 0.7, p is capped at
WEAK_PATH_CAP. p is capped at CAP. PAYEE_NAME_MISMATCH and MULE_FLOW are PayPal-derived rules added in D2-P4.
"""
from __future__ import annotations

from typing import Any

from engine.contracts import Evidence, Reason, StoredEvent
from engine.detectors.base import load_calibration, make_evidence, should_emit
from engine.graph.store import EntityGraph

VERSION = "graph-1"
MAX_HOPS = 3
WEAK_EDGE = 0.7


class GraphDetector:
    id = "graph"
    handles = frozenset({"payee_added", "transaction"})

    def __init__(self) -> None:
        self.cal = load_calibration()["graph"]

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        payee = event.payload.get("payee_account")
        if not payee or (event.event_type == "transaction" and feats.get("payee_is_new")):
            return []                                  # a transaction right after payee_added was scored at the add
        paths = graph.seed_paths(payee, MAX_HOPS, limit=2)
        if not paths:
            return []
        dist = len(paths[0]) - 1
        code = f"SEED_DISTANCE_{dist}"
        p = self.cal[code]
        reasons = [Reason(code=code, detail=" > ".join(paths[0]))]
        if dist > 0 and len(paths) == 1 and graph.path_min_confidence(paths[0]) < WEAK_EDGE:
            p = min(p, self.cal["WEAK_PATH_CAP"])
            reasons.append(Reason(code="WEAK_PATH_CAP", detail=f"weakest edge {graph.path_min_confidence(paths[0]):.2f}"))
        p = min(p, self.cal["CAP"])
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, VERSION, event, "S5_POSITIONING", p, rel, reasons, technique="T1657")]
