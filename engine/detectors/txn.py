"""txn detector (PRD §10.4): transactions, stage S6.

LightGBM on TXN_FEATURES + isotonic calibration (ml/artifacts/txn_v1.joblib). The top 5 SHAP values (LightGBM's
TreeSHAP, pred_contrib) are stored; reasons come from the top 3 positive ones. Degraded mode when the artifact is
missing or its SHA-256 does not match the manifest: p = DEGRADED_HIGH when amount_to_median_30d > 5 and the payee
is new, else DEGRADED_LOW; degraded = true. Sets amount_paise.
STRUCTURING (PayPal-derived, D2-P4): near_limit_count_24h >= 2 sets p = max(p, STRUCTURING_FLOOR), degraded too.
v3 core (3.2b): the rule reads the event-time customer+payee windows (engine/features/txn_windows.py) and adds a
"split over the limit" case (p = max(p, split_p), engine/detectors/rules/v3_core.yaml `structuring`); see
structuring(). These are rule-side features: TXN_FEATURES (the model input) is unchanged. A very confident model
score (p >= 0.90) is turned into a HIGH band by fusion's floor_TXN_HIGH_CONFIDENCE, not here.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from engine.contracts import Evidence, Reason, ShapItem, StoredEvent
from engine.detectors.base import load_calibration, make_evidence, should_emit
from engine.detectors.models import load_artifact
from engine.features.features import TXN_FEATURES
from engine.fusion.v3_core import load_v3_core
from engine.graph.store import EntityGraph

ARTIFACT = "txn_v1.joblib"
SHAP_TOP = 5
REASON_TOP = 3
STRUCTURING_MIN = 2
REASON_CODES = {"log_amount": "AMOUNT_HIGH", "amount_to_median_30d": "AMOUNT_HIGH_VS_MEDIAN",
                "txn_count_1h": "TXN_VELOCITY_1H", "txn_sum_24h_paise": "TXN_SUM_24H", "payee_is_new": "NEW_PAYEE",
                "minutes_since_payee_added": "PAYEE_RECENTLY_ADDED", "payee_fan_in_24h": "PAYEE_FAN_IN",
                "payee_sum_24h_paise": "PAYEE_SUM_24H", "near_limit_count_24h": "NEAR_LIMIT_AMOUNTS",
                "hour_deviation": "ODD_HOUR", "minutes_since_new_device": "RECENT_NEW_DEVICE"}


def structuring(feats: dict[str, Any], cfg: dict[str, Any]) -> tuple[float, str] | None:
    """(p floor beyond STRUCTURING_FLOOR, reason detail) when the STRUCTURING rule fires, else None.

    Uses the v3 event-time customer+payee windows (tw_*, engine/features/txn_windows.py: deduplicated by event_id,
    late events placed by event time) when present, else the PRD §10.3 near_limit_count_24h. Fires at min_near_limit
    near-limit transfers to one payee in 24 h (including this one). "Split over the limit": at least
    split_min_same_limit of them sit under the SAME limit L and the 24 h total to the payee reaches L — the amount the
    customer avoided sending in one transfer — which raises p to split_p."""
    count = feats.get("tw_near_limit_count_24h", feats.get("near_limit_count_24h", 0.0))
    if count < float(cfg.get("min_near_limit", STRUCTURING_MIN)):
        return None
    same, lim = feats.get("tw_near_limit_same_limit_max_24h", 0.0), feats.get("tw_near_limit_limit_paise", 0.0)
    total = feats.get("tw_pair_sum_24h_paise", 0.0)
    detail = f"{count:.0f} transfers just under a limit in 24 h"
    if "tw_pair_sum_24h_paise" in feats:
        detail += (f"; {same:.0f} under Rs {lim / 100:,.0f}, Rs {total / 100:,.0f} to this payee in 24 h, "
                   f"{feats.get('tw_pair_count_1h', 0):.0f} in the last hour, {feats.get('tw_near_limit_rate_per_h', 0):.2f}/h")
    if lim and same >= float(cfg["split_min_same_limit"]) and total >= lim:
        return float(cfg["split_p"]), detail + " (split over the limit)"
    return 0.0, detail


class TxnDetector:
    id = "txn"
    handles = frozenset({"transaction"})

    def __init__(self, artifact: dict | None = None, cfg: dict[str, Any] | None = None) -> None:
        self.cal = load_calibration()["txn"]
        self.cfg = load_v3_core()["structuring"] if cfg is None else cfg
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
        hit = structuring(feats, self.cfg)
        if hit is not None:
            floor, detail = hit
            p = max(p, self.cal["STRUCTURING_FLOOR"], floor)
            reasons = [Reason(code="STRUCTURING", detail=detail)] + reasons
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, self.version, event, "S6_MONETIZATION", p, rel, reasons, shap=shap,
                              amount_paise=amount, degraded=degraded)]
