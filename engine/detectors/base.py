"""The detector interface (PRD §10.1, §10.4).

Pipeline.process calls, for every detector in DETECTORS_IN_ORDER whose `handles` contains the event type,
`score(event, feats, graph, rel)` and collects the returned Evidence. `feats` are the event's features computed from
state BEFORE the event (§10.3), `graph` is the EntityGraph after the event's edges were applied, and `rel` is the
reliability snapshot {detector: (alpha, beta)} taken once per process() call.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

from engine.common.ids import new_id
from engine.contracts import DETECTOR_FAMILY, Evidence, Reason, ShapItem, StoredEvent
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


# ---------------------------------------------------------------------------- shared helpers
RULES_DIR = Path(__file__).resolve().parent / "rules"
EMIT_MIN_P = 0.02                                   # emit only when p >= 0.02 ...
ALWAYS_EMIT = frozenset({"STEP_UP_PASSED_TRUSTED", "CUSTOMER_DENIED"})   # ... except these (§10.4)
P_MIN, P_MAX = 1e-4, 1 - 1e-4                       # Evidence.p is strictly inside (0, 1)


@lru_cache(maxsize=4)
def load_calibration(path: str | Path = RULES_DIR / "calibration.json") -> dict[str, dict[str, float]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def clamp_p(p: float) -> float:
    return min(P_MAX, max(P_MIN, float(p)))


def should_emit(p: float, reasons: list[Reason]) -> bool:
    return p >= EMIT_MIN_P or any(r.code in ALWAYS_EMIT for r in reasons)


def make_evidence(detector: str, version: str, event: StoredEvent, stage: str, p: float, rel: dict[str, tuple[float, float]],
                  reasons: list[Reason], technique: str | None = None, entities: list[str] | None = None,
                  shap: list[ShapItem] | None = None, amount_paise: int | None = None, degraded: bool = False) -> Evidence:
    return Evidence(evidence_id=new_id("ev"), event_id=event.event_id, detector=detector, detector_version=version,
                    family=DETECTOR_FAMILY[detector], stage=stage, attack_technique=technique, p=clamp_p(p),
                    reliability=reliability(rel, detector), entities=sorted(event.entity_tokens if entities is None else entities),
                    reasons=reasons, shap=shap, amount_paise=amount_paise, degraded=degraded, ts=event.occurred_at)


def best_rule(hits: list[tuple[str, float, str | None, str | None]]) -> tuple[float, list[Reason], str | None, str | None]:
    """Several rules of one detector fired on one event: one evidence item with the highest p and all reasons.
    hits = [(reason_code, p, technique, detail)]; returns (p, reasons, technique of the top rule, its code)."""
    top = max(hits, key=lambda h: h[1])
    reasons = [Reason(code=c, detail=d) for c, _, _, d in sorted(hits, key=lambda h: -h[1])]
    return top[1], reasons, top[2], top[0]
