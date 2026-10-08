"""The detector interface (PRD §10.1, §10.4).

Pipeline.process calls, for every detector in DETECTORS_IN_ORDER whose `handles` contains the event type,
`score(event, feats, graph, rel)` and collects the returned Evidence. `feats` are the event's features computed from
state BEFORE the event (§10.3), `graph` is the EntityGraph after the event's edges were applied, and `rel` is the
reliability snapshot {detector: (alpha, beta)} taken once per process() call.
"""
from __future__ import annotations

from typing import Any, Protocol

from engine.contracts import Evidence, StoredEvent
from engine.graph.store import EntityGraph

DETECTOR_ORDER: tuple[str, ...] = ("netsec", "behaviour", "auth", "kyc", "cyber", "graph", "txn")
RELIABILITY_FLOOR = 0.2
# §10.4 "Handles" column: the event types each detector scores.
DETECTOR_HANDLES: dict[str, frozenset[str]] = {
    "netsec": frozenset({"network_ids_alert", "login"}),
    "behaviour": frozenset({"login"}),
    "auth": frozenset({"mfa_change", "mfa_challenge", "sim_signal", "profile_change", "step_up_result"}),
    "kyc": frozenset({"kyc_result"}),
    "cyber": frozenset({"cloud_audit"}),
    "graph": frozenset({"payee_added", "transaction"}),
    "txn": frozenset({"transaction"}),
}


class Detector(Protocol):
    id: str
    handles: frozenset[str]

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]: ...


def reliability(rel: dict[str, tuple[float, float]], detector: str) -> float:
    """alpha / (alpha + beta) from the snapshot, floored at 0.2 (§10.4)."""
    a, b = rel.get(detector, (1.0, 1.0))
    return max(RELIABILITY_FLOOR, a / (a + b)) if a + b > 0 else RELIABILITY_FLOOR
