"""APP (authorised push payment) scam assessment (v3 phase 7): is the genuine customer being manipulated into paying?

An account takeover is an attacker in the customer's session; an APP scam is the customer, on their own device, paying
a fraudster they were talked into trusting. Identity signals cannot see it, so this looks at the payment itself:

    customer side   first payment to this payee; amount vs the customer's 30-day median; recent security changes
    payee side      account age; fan-in from unrelated customers in 24 h; seed-independent mule signals; an external
                    payee / mobile-number risk report (optional provider, off by default)
    session         contract 1.1.0 Telemetry: pasted payee details, a rushed payment screen, and the demo-only
                    active_call_demo / remote_access_demo indicators (simulated; never claimed as real detection)

Inputs are the event, its §10.3 features (state before the event) and the graph (after the event's edges), so the
assessment needs no state of its own. Weights and thresholds: engine/detectors/rules/app_scam.yaml.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from engine.contracts import StoredEvent
from engine.graph.mule import MuleAnalytics
from engine.graph.reputation import PayeeReputation
from engine.graph.store import EntityGraph

CONFIG_FILE = Path(__file__).resolve().parents[1] / "detectors" / "rules" / "app_scam.yaml"
WARNING, COOLING_OFF = "APP_SCAM_WARNING", "APP_SCAM_COOLING_OFF"


@dataclass(frozen=True)
class AppScamConfig:
    warn_at: float
    cooling_off_at: float
    evidence_p: float
    weights: dict
    amount_high_x: float
    amount_very_high_x: float
    young_payee_days: float
    fan_in_min: int
    fan_in_burst: int
    security_change_h: float
    rushed_dwell_s: float
    provider_min_score: float
    ato_new_device_h: float


@lru_cache(maxsize=4)
def load_config(path: str | Path = CONFIG_FILE) -> AppScamConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return AppScamConfig(**{k: raw[k] for k in AppScamConfig.__dataclass_fields__})


@dataclass(frozen=True)
class PayeeRiskSignal:
    """What an external payee / mobile-number risk provider says about a payee token (api/payee_risk.py)."""
    score: float                 # 0..1
    reports: int = 0
    source: str = "unknown"


# payee token, event time -> signal or None. The engine never calls a network service itself: the API injects a lookup.
PayeeRiskLookup = Callable[[str, datetime], PayeeRiskSignal | None]


@dataclass
class AppScamAssessment:
    score: float = 0.0
    indicators: list[tuple[str, str]] = field(default_factory=list)
    level: str | None = None     # None | APP_SCAM_WARNING | APP_SCAM_COOLING_OFF

    def reasons(self) -> list[tuple[str, str]]:
        """The level reason first (policy keys on it), then every indicator."""
        if self.level is None:
            return []
        return [(self.level, f"APP-scam score {self.score:.2f}")] + self.indicators


class AppScamAssessor:
    def __init__(self, config: AppScamConfig | None = None) -> None:
        self.cfg = load_config() if config is None else config

    def assess(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
               payee_risk: PayeeRiskLookup | None = None) -> AppScamAssessment:
        out = AppScamAssessment()
        if event.event_type != "transaction":
            return out
        payee = event.payload.get("payee_account")
        if not payee:
            return out
        c, w, now = self.cfg, self.cfg.weights, event.occurred_at
        if float(feats.get("minutes_since_new_device", 1e9)) < c.ato_new_device_h * 60:
            return out                             # a device new to the customer: the account-takeover path, not APP

        def add(code: str, detail: str) -> None:
            out.score += float(w.get(code, 0.0))
            out.indicators.append((code, detail))

        sent = graph.get_edge(event.account, payee, "SENT") if event.account else None
        if sent is not None and sent.count <= 1:
            add("APP_FIRST_PAYMENT_TO_PAYEE", "first transfer to this payee")
        ratio = float(feats.get("amount_to_median_30d", 1.0) or 1.0)
        if ratio >= c.amount_very_high_x:
            add("APP_AMOUNT_FAR_ABOVE_BASELINE", f"{ratio:.0f}x the customer's 30-day median")
        elif ratio >= c.amount_high_x:
            add("APP_AMOUNT_ABOVE_BASELINE", f"{ratio:.1f}x the customer's 30-day median")
        reputable = PayeeReputation(graph).is_reputable(payee, now)
        if not reputable:
            prof = MuleAnalytics(graph).profile(payee, now)
            if prof is not None and prof.account_age_days < c.young_payee_days:
                add("APP_YOUNG_PAYEE_ACCOUNT", f"payee account first seen {prof.account_age_days:.1f} days ago")
            fan_in = int(feats.get("payee_fan_in_24h", 0) or 0)
            if fan_in >= c.fan_in_burst:
                add("APP_PAYEE_FAN_IN_BURST", f"{fan_in} other customers paid this payee in 24 h")
            elif fan_in >= c.fan_in_min:
                add("APP_PAYEE_FAN_IN_UNRELATED", f"{fan_in} other customers paid this payee in 24 h")
            mule = MuleAnalytics(graph).signals(payee, now)
            if mule:
                add("APP_PAYEE_MULE_SIGNAL", f"payee shows {mule[0][0]}")
        if payee_risk is not None:
            sig = payee_risk(payee, now)
            if sig is not None and sig.score >= c.provider_min_score:
                add("APP_PAYEE_REPORTED", f"{sig.source}: risk {sig.score:.2f}, {sig.reports} reports")
        minutes = c.security_change_h * 60
        if (float(feats.get("minutes_since_mfa_change", 1e9)) < minutes
                or float(feats.get("minutes_since_new_device", 1e9)) < minutes):
            add("APP_RECENT_SECURITY_CHANGE", f"MFA change or new device within {c.security_change_h:.0f} h")
        # (a new device within ato_new_device_h never reaches here: see the ATO check above)
        t = event.telemetry
        if t is not None:
            if t.paste_in_sensitive_field:
                add("APP_PASTED_PAYEE_DETAILS", "payee details were pasted, not typed")
            if t.payment_screen_dwell_s is not None and t.payment_screen_dwell_s < c.rushed_dwell_s:
                add("APP_RUSHED_PAYMENT", f"payment screen confirmed in {t.payment_screen_dwell_s:.0f} s")
            if t.active_call_demo:
                add("APP_ACTIVE_CALL_DEMO", "simulated: a call was active during the payment (demo-only indicator)")
            if t.remote_access_demo:
                add("APP_REMOTE_ACCESS_DEMO", "simulated: remote-access app active (demo-only indicator)")
        out.score = round(out.score, 4)
        if out.score >= c.cooling_off_at:
            out.level = COOLING_OFF
        elif out.score >= c.warn_at:
            out.level = WARNING
        return out
