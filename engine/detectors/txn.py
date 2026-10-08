"""txn detector (PRD §10.4): transactions, stage S6.

LightGBM on TXN_FEATURES + isotonic calibration (ml/artifacts/txn_v1.joblib). The top 5 SHAP values (LightGBM's
TreeSHAP, pred_contrib) are stored; reasons come from the top 3 positive ones. Degraded mode when the artifact is
missing or its SHA-256 does not match the manifest: p = DEGRADED_HIGH when amount_to_median_30d > 5 and the payee
is new, else DEGRADED_LOW; degraded = true. Sets amount_paise. STRUCTURING is a PayPal-derived rule added in D2-P4.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from engine.contracts import Evidence, Reason, ShapItem, StoredEvent
from engine.detectors.base import load_calibration, make_evidence, should_emit
from engine.detectors.models import load_artifact
from engine.features.features import TXN_FEATURES
from engine.graph.store import EntityGraph

ARTIFACT = "txn_v1.joblib"
SHAP_TOP = 5
REASON_TOP = 3
REASON_CODES = {"log_amount": "AMOUNT_HIGH", "amount_to_median_30d": "AMOUNT_HIGH_VS_MEDIAN",
                "txn_count_1h": "TXN_VELOCITY_1H", "txn_sum_24h_paise": "TXN_SUM_24H", "payee_is_new": "NEW_PAYEE",
                "minutes_since_payee_added": "PAYEE_RECENTLY_ADDED", "payee_fan_in_24h": "PAYEE_FAN_IN",
                "payee_sum_24h_paise": "PAYEE_SUM_24H", "near_limit_count_24h": "NEAR_LIMIT_AMOUNTS",
                "hour_deviation": "ODD_HOUR", "minutes_since_new_device": "RECENT_NEW_DEVICE"}


class TxnDetector:
    id = "txn"
    handles = frozenset({"transaction"})

    def __init__(self, artifact: dict | None = None) -> None:
        self.cal = load_calibration()["txn"]
        if artifact is None:
            artifact, info = load_artifact(ARTIFACT)
            self.version = f"txn_v1:{info[:12]}" if artifact is not None else f"txn-degraded:{info}"
        else:
            self.version = "txn_v1:injected"
        self.model = artifact

    def predict(self, feats: dict[str, Any]) -> tuple[float, list[ShapItem], list[Reason]]:
        x = np.array([[float(feats[f]) for f in TXN_FEATURES]])
        booster = self.model["booster"]
        raw = float(booster.predict(x)[0])
        p = float(self.model["calibrator"].predict([raw])[0])
        contrib = booster.predict(x, pred_contrib=True)[0][:-1]            # last column is the bias
        ranked = sorted(zip(TXN_FEATURES, x[0], contrib, strict=True), key=lambda t: -abs(t[2]))
        shap = [ShapItem(feature=f, value=float(v), shap=float(s)) for f, v, s in ranked[:SHAP_TOP]]
        positive = [t for t in sorted(ranked, key=lambda t: -t[2]) if t[2] > 0][:REASON_TOP]
        reasons = [Reason(code=REASON_CODES[f], detail=f"{f}={v:g}") for f, v, _ in positive]
        return p, shap, reasons

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        amount = int(event.payload["amount_paise"])
        if self.model is None:
            high = feats["amount_to_median_30d"] > 5 and feats["payee_is_new"]
            p = self.cal["DEGRADED_HIGH"] if high else self.cal["DEGRADED_LOW"]
            shap, reasons, degraded = None, [Reason(code="DEGRADED_HIGH" if high else "DEGRADED_LOW")], True
        else:
            (p, shap, reasons), degraded = self.predict(feats), False
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, self.version, event, "S6_MONETIZATION", p, rel, reasons, shap=shap,
                              amount_paise=amount, degraded=degraded)]
