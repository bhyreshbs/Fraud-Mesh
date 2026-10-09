"""behaviour detector (PRD §10.4): successful logins, stage S1, T1078.

Logistic regression on device_first_seen, asn_first_seen, km_from_home/1000, hour_deviation/12, failed_logins_1h,
isotonic-calibrated (ml/artifacts/behaviour_v1.joblib). Reasons: the top 2 terms by coefficient × value.
Customers with fewer than 5 past logins get COLD_START and the population rate. Without a valid artifact every
login is treated as COLD_START and marked degraded.
IMPOSSIBLE_TRAVEL (PayPal-derived, D2-P4): travel_speed_kmh > 900 sets p = max(p, calibration value), cold start
included.

v3 additions (all neutral when the 1.1.0 fields are absent, so direct-mode replays and golden fixtures are unchanged):
  cold start (11.1)   the model is only called with a login history (past_logins_30d >= 5, so has_login_history = 1);
                      without a known home location (has_home_location = 0) km_from_home is "unknown", never a
                      measured zero, and FAR_FROM_HOME cannot be a reason.
  geo confidence (5)  for logins from hosting / vpn / tor (or unknown with low confidence) the model sees
                      km_from_home × geo_confidence_factor and the IMPOSSIBLE_TRAVEL floor is multiplied by it
                      (engine/detectors/rules/network_intel.yaml). A VPN alone never raises p.
  TZ_MISMATCH (5)     browser and ip time zones differ: weak rule, p = network_intel.yaml tz_mismatch.p.
  DEVICE_INCONSISTENT (6.1)   platform / pointer / WebGL / screen contradictions (session_device.yaml).
  SESSION_CONTEXT_CHANGE (6.2) network AND device context changed inside one session (session_device.yaml).
  SHARED_IP (4.1)     context-only reason (no p) when the login's ip is currently shared (engine/graph/shared_ip.py).
The rules combine with the model as p = max(model p, rule p), reasons ordered by p; rule reasons follow the model's.
"""
from __future__ import annotations

from typing import Any

import numpy as np

from engine.contracts import Evidence, Reason, StoredEvent
from engine.detectors.base import load_calibration, make_evidence, should_emit
from engine.detectors.models import load_artifact
from engine.features.network import DEVICE_FLAGS, SESSION_FLAGS, describe, load_session_device_config
from engine.graph.store import EntityGraph
from engine.netintel.intel import load_intel_config

ARTIFACT = "behaviour_v1.joblib"
BEHAVIOUR_FEATURES = ["device_first_seen", "asn_first_seen", "km_from_home", "hour_deviation", "failed_logins_1h"]
SCALE = {"km_from_home": 1000.0, "hour_deviation": 12.0}
REASON_CODES = {"device_first_seen": "NEW_DEVICE", "asn_first_seen": "NEW_ASN", "km_from_home": "FAR_FROM_HOME",
                "hour_deviation": "ODD_HOUR", "failed_logins_1h": "FAILED_LOGINS"}
COLD_START_LOGINS = 5
IMPOSSIBLE_KMH = 900.0


def behaviour_vector(feats: dict[str, Any]) -> list[float]:
    return [float(feats[f]) / SCALE.get(f, 1.0) for f in BEHAVIOUR_FEATURES]


def network_rules(event: StoredEvent, feats: dict[str, Any], with_tz: bool = True) -> list[tuple[str, float, str]]:
    """(code, p, detail) for the v3 client/network rules shared by behaviour (logins) and auth (session events)."""
    sd, out = load_session_device_config(), []
    if with_tz and feats.get("tz_mismatch"):
        out.append(("TZ_MISMATCH", float(load_intel_config()["tz_mismatch"]["p"]),
                    f"browser {event.browser_timezone} vs ip {event.ip_timezone}"))
    n = int(feats.get("device_inconsistency", 0) or 0)
    if n:
        c = sd["device_consistency"]
        out.append(("DEVICE_INCONSISTENT", float(c["p_many"] if n >= 2 else c["p_one"]),
                    describe(feats.get("device_inconsistency_mask", 0), DEVICE_FLAGS)))
    if feats.get("session_change"):
        s, mask = sd["session"], int(feats.get("session_change_mask", 0) or 0)
        out.append(("SESSION_CONTEXT_CHANGE", float(s["p_anonymiser"] if mask & 64 else s["p"]),
                    describe(mask, SESSION_FLAGS)))
    return out


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
        geo = float(feats.get("geo_confidence_factor", 1.0) or 1.0)
        if degraded or feats["past_logins_30d"] < COLD_START_LOGINS:
            p, reasons = self.cal["COLD_START"], [Reason(code="COLD_START", detail=f"{feats['past_logins_30d']:.0f} past logins")]
        else:
            # km_from_home is 0 exactly when no home location is known (has_home_location = 0), which the model was
            # trained with; FAR_FROM_HOME needs a positive term, so an unknown home never becomes a reason.
            model_feats = feats if geo >= 1.0 else {**feats, "km_from_home": feats["km_from_home"] * geo}
            p, reasons = self.predict(model_feats)
            if geo < 1.0:
                reasons = [r.model_copy(update={"detail": f"{r.detail} (geo confidence x{geo:g}: {event.network_type})"})
                           if r.code == "FAR_FROM_HOME" else r for r in reasons]
        if feats["travel_speed_kmh"] > IMPOSSIBLE_KMH:
            p = max(p, self.cal["IMPOSSIBLE_TRAVEL"] * geo)
            detail = f"{feats['travel_speed_kmh']:.0f} km/h" + (f" (geo confidence x{geo:g}: {event.network_type})" if geo < 1.0 else "")
            reasons = [Reason(code="IMPOSSIBLE_TRAVEL", detail=detail)] + reasons
        extra = sorted(network_rules(event, feats), key=lambda h: -h[1])
        if extra:
            p = max(p, extra[0][1])
            reasons = reasons + [Reason(code=c, detail=d) for c, _, d in extra]
        if not should_emit(p, reasons):
            return []
        if event.ip and graph.shared_ip.is_shared(event.ip):
            reasons = reasons + [Reason(code="SHARED_IP", detail=graph.shared_ip.describe(event.ip))]
        return [make_evidence(self.id, self.version, event, "S1_INITIAL_ACCESS", p, rel, reasons, technique="T1078",
                              degraded=degraded)]
