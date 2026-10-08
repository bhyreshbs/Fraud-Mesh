"""behaviour detector (PRD §10.4): successful logins, stage S1, T1078.

Logistic regression on device_first_seen, asn_first_seen, km_from_home/1000, hour_deviation/12, failed_logins_1h,
isotonic-calibrated (ml/artifacts/behaviour_v1.joblib). Reasons: the top 2 terms by coefficient × value.
Customers with fewer than 5 past logins get COLD_START and the population rate. Without a valid artifact every
login is treated as COLD_START and marked degraded. IMPOSSIBLE_TRAVEL is a PayPal-derived rule added in D2-P4.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from engine.contracts import Evidence, Reason, StoredEvent
from engine.detectors.base import load_calibration, make_evidence, should_emit
from engine.detectors.models import load_artifact
from engine.graph.store import EntityGraph

ARTIFACT = "behaviour_v1.joblib"
BEHAVIOUR_FEATURES = ["device_first_seen", "asn_first_seen", "km_from_home", "hour_deviation", "failed_logins_1h"]
SCALE = {"km_from_home": 1000.0, "hour_deviation": 12.0}
REASON_CODES = {"device_first_seen": "NEW_DEVICE", "asn_first_seen": "NEW_ASN", "km_from_home": "FAR_FROM_HOME",
                "hour_deviation": "ODD_HOUR", "failed_logins_1h": "FAILED_LOGINS"}
COLD_START_LOGINS = 5


def behaviour_vector(feats: dict[str, Any]) -> list[float]:
    return [float(feats[f]) / SCALE.get(f, 1.0) for f in BEHAVIOUR_FEATURES]


class BehaviourDetector:
    id = "behaviour"
    handles = frozenset({"login"})

    def __init__(self, artifact: dict | None = None) -> None:
        self.cal = load_calibration()["behaviour"]
        if artifact is None:
            artifact, info = load_artifact(ARTIFACT)
            self.version = f"behaviour_v1:{info[:12]}" if artifact is not None else f"behaviour-degraded:{info}"
        else:
            self.version = "behaviour_v1:injected"
        self.model = artifact

    def predict(self, feats: dict[str, Any]) -> tuple[float, list[Reason]]:
        x = np.array([behaviour_vector(feats)])
        raw = float(self.model["model"].predict_proba(x)[0, 1])
        p = float(self.model["calibrator"].predict([raw])[0])
        terms = sorted(zip(BEHAVIOUR_FEATURES, self.model["model"].coef_[0] * x[0], strict=True), key=lambda t: -t[1])
        reasons = [Reason(code=REASON_CODES[f], detail=f"{f}={feats[f]:.2f}") for f, v in terms[:2] if v > 0]
        return p, reasons

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        if event.payload.get("result") != "success":
            return []
        degraded = self.model is None
        if degraded or feats["past_logins_30d"] < COLD_START_LOGINS:
            p, reasons = self.cal["COLD_START"], [Reason(code="COLD_START", detail=f"{feats['past_logins_30d']:.0f} past logins")]
        else:
            p, reasons = self.predict(feats)
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, self.version, event, "S1_INITIAL_ACCESS", p, rel, reasons, technique="T1078",
                              degraded=degraded)]
