"""kyc detector (PRD §10.4): re-verification results, stage S3.
LOW_LIVENESS (< 0.5), LOW_FACE_MATCH (< 0.7), DOC_TAMPER (> 0.5), INJECTION_SUSPECTED; one evidence item with the
highest p and every reason that fired."""
from __future__ import annotations

from typing import Any

from engine.contracts import Evidence, StoredEvent
from engine.detectors.base import best_rule, load_calibration, make_evidence, should_emit
from engine.graph.store import EntityGraph

VERSION = "kyc-1"


class KycDetector:
    id = "kyc"
    handles = frozenset({"kyc_result"})

    def __init__(self) -> None:
        self.cal = load_calibration()["kyc"]

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        p_, c, hits = event.payload, self.cal, []
        if p_["liveness_score"] < 0.5:
            hits.append(("LOW_LIVENESS", c["LOW_LIVENESS"], None, f"liveness_score={p_['liveness_score']}"))
        if p_["face_match_score"] < 0.7:
            hits.append(("LOW_FACE_MATCH", c["LOW_FACE_MATCH"], None, f"face_match_score={p_['face_match_score']}"))
        if p_["doc_tamper_score"] > 0.5:
            hits.append(("DOC_TAMPER", c["DOC_TAMPER"], None, f"doc_tamper_score={p_['doc_tamper_score']}"))
        if p_["injection_suspected"]:
            hits.append(("INJECTION_SUSPECTED", c["INJECTION_SUSPECTED"], None, None))
        if not hits:
            return []
        p, reasons, _, _ = best_rule(hits)
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, VERSION, event, "S3_IDENTITY_MANIPULATION", p, rel, reasons)]
