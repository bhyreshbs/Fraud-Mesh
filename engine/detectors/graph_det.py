"""graph detector (PRD §10.4): where the money is going, stage S5, T1657.

Handles payee_added, and transactions to a payee with no payee_added in the last 24 h. p comes from the payee's
seed distance: 0 → SEED_DISTANCE_0 (the payee is itself a fraud seed; triggers floor_SEED_PAYEE), 1/2/3 →
SEED_DISTANCE_1/_2/_3. If only one shortest path exists and its weakest edge has confidence < 0.7, p is capped at
WEAK_PATH_CAP. p is capped at CAP.
PayPal-derived (D2-P4): PAYEE_NAME_MISMATCH (payee_name_match == false) and MULE_FLOW (the payee's fan-in >= 5
distinct senders in 24 h, or its own outbound ÷ inbound in 24 h within 0.8–1.2) each multiply p by 1.5 with a
minimum of 0.03, so either one alone emits evidence even without a seed path.
"""
from __future__ import annotations

from typing import Any

from engine.contracts import Evidence, Reason, StoredEvent
from engine.detectors.base import load_calibration, make_evidence, should_emit
from engine.graph.store import EntityGraph

VERSION = "graph-1"
MAX_HOPS = 3
WEAK_EDGE = 0.7
RULE_FACTOR, RULE_MIN_P = 1.5, 0.03
MULE_FAN_IN = 5
PASS_THROUGH = (0.8, 1.2)


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
        p, reasons = 0.0, []
        if paths:
            dist = len(paths[0]) - 1
            code = f"SEED_DISTANCE_{dist}"
            p = self.cal[code]
            reasons.append(Reason(code=code, detail=" > ".join(paths[0])))
            if dist > 0 and len(paths) == 1 and graph.path_min_confidence(paths[0]) < WEAK_EDGE:
                p = min(p, self.cal["WEAK_PATH_CAP"])
                reasons.append(Reason(code="WEAK_PATH_CAP", detail=f"weakest edge {graph.path_min_confidence(paths[0]):.2f}"))
        for code, detail in self._rules(event, feats):
            p = max(p * RULE_FACTOR, RULE_MIN_P)
            reasons.append(Reason(code=code, detail=detail))
        if not reasons:
            return []
        p = min(p, self.cal["CAP"])
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, VERSION, event, "S5_POSITIONING", p, rel, reasons, technique="T1657")]

    @staticmethod
    def _rules(event: StoredEvent, feats: dict[str, Any]) -> list[tuple[str, str]]:
        out = []
        if event.event_type == "payee_added" and event.payload.get("payee_name_match") is False:
            out.append(("PAYEE_NAME_MISMATCH", "the payee name does not match the account"))
        fan_in, ratio = feats.get("payee_fan_in_24h", 0), feats.get("payee_passthrough_24h", 0)
        if fan_in >= MULE_FAN_IN or PASS_THROUGH[0] <= ratio <= PASS_THROUGH[1]:
            out.append(("MULE_FLOW", f"fan-in {fan_in:.0f} senders, pass-through {ratio:.2f} in 24 h"))
        return out
