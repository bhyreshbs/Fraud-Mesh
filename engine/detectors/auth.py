"""auth detector (PRD §10.4): account-control signals, stage S2.

Rules here: MFA_CHANGED_AFTER_NEW_DEVICE (mfa_change with minutes_since_new_device <= 60, T1556.006),
RECENT_SIM_SWAP (sim_signal age < 72 h, T1451), and the step-up results:
  STEP_UP_PASSED_WITH_FRESH_FACTOR   passed, factor_age_h < 72                 (T1556.006)
  STEP_UP_FAILED_OR_TIMEOUT          failed or timeout, factor_age_h >= 72
  STEP_UP_PASSED_TRUSTED             passed, factor_age_h >= 72, p 0.003 → negative evidence, always emitted
  CUSTOMER_DENIED                    denied_by_customer, p = BASE_RATE, always emitted (triggers a floor)
PROFILE_CHANGE_AFTER_NEW_DEVICE, MFA_FAIL_THEN_PASS and PUSH_SPAM are PayPal-derived rules added in D2-P4.
"""
from __future__ import annotations

from typing import Any

from engine.common.settings import settings
from engine.contracts import Evidence, StoredEvent
from engine.detectors.base import best_rule, load_calibration, make_evidence, should_emit
from engine.graph.store import EntityGraph

VERSION = "auth-1"
NEW_DEVICE_WINDOW_MIN = 60
TRUSTED_FACTOR_AGE_H = 72
SIM_SWAP_H = 72


class AuthDetector:
    id = "auth"
    handles = frozenset({"mfa_change", "mfa_challenge", "sim_signal", "profile_change", "step_up_result"})

    def __init__(self, base_rate: float | None = None) -> None:
        self.cal = load_calibration()["auth"]
        self.base_rate = settings.base_rate if base_rate is None else base_rate

    def rules(self, event: StoredEvent, feats: dict[str, Any]) -> list[tuple[str, float, str | None, str | None]]:
        p_, c, hits = event.payload, self.cal, []
        t = event.event_type
        if t == "mfa_change" and feats.get("minutes_since_new_device", 1e9) <= NEW_DEVICE_WINDOW_MIN:
            hits.append(("MFA_CHANGED_AFTER_NEW_DEVICE", c["MFA_CHANGED_AFTER_NEW_DEVICE"], "T1556.006",
                         f"{p_.get('factor')} {p_.get('action')}, {feats['minutes_since_new_device']:.0f} min after a new device"))
        elif t == "sim_signal" and float(p_["sim_change_age_h"]) < SIM_SWAP_H:
            hits.append(("RECENT_SIM_SWAP", c["RECENT_SIM_SWAP"], "T1451", f"sim_change_age_h={p_['sim_change_age_h']}"))
        elif t == "step_up_result":
            age, result = float(p_["factor_age_h"]), p_["result"]
            detail = f"{p_['method']} {result}, factor_age_h={age:g}"
            if result == "denied_by_customer":
                hits.append(("CUSTOMER_DENIED", self.base_rate, None, detail))
            elif result == "passed" and age < TRUSTED_FACTOR_AGE_H:
                hits.append(("STEP_UP_PASSED_WITH_FRESH_FACTOR", c["STEP_UP_PASSED_WITH_FRESH_FACTOR"], "T1556.006", detail))
            elif result == "passed":
                hits.append(("STEP_UP_PASSED_TRUSTED", c["STEP_UP_PASSED_TRUSTED"], None, detail))
            elif age >= TRUSTED_FACTOR_AGE_H:
                hits.append(("STEP_UP_FAILED_OR_TIMEOUT", c["STEP_UP_FAILED_OR_TIMEOUT"], None, detail))
        return hits

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        hits = self.rules(event, feats)
        if not hits:
            return []
        p, reasons, technique, _ = best_rule(hits)
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, VERSION, event, "S2_CONTROL_TAKEOVER", p, rel, reasons, technique=technique)]
