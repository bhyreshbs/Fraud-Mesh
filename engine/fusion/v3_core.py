"""v3 core detection configuration (engine/detectors/rules/v3_core.yaml).

One YAML file holds the constants for the v3 Phase 3 / Phase 11 rules: the S2→new-payee and txn model-confidence
floors (fusion), the structuring rolling windows (features, txn detector), correlated-evidence discounts (fusion),
late-evidence escalation (policy) and the feedback-poisoning guards (feedback). `load_v3_core()` returns the parsed
file merged over DEFAULTS, so a missing key always has a value and tests can pass a partial dict through `merged()`.
"""
from __future__ import annotations

import copy
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

V3_CORE_FILE = Path(__file__).resolve().parents[1] / "detectors" / "rules" / "v3_core.yaml"

DEFAULTS: dict[str, Any] = {
    "floors": {
        "s2_then_new_payee": {"enabled": True, "window_h": 24, "min_band": "HIGH",
                              "disarm_reasons": ["STEP_UP_PASSED_TRUSTED"]},
        "txn_high_confidence": {"enabled": True, "min_p": 0.90, "min_band": "HIGH",
                                "disarm_reasons": ["STEP_UP_PASSED_TRUSTED"]},
    },
    "structuring": {"limits_paise": [10_000_000, 20_000_000, 50_000_000], "near_fraction": 0.95, "window_h": 24,
                    "velocity_window_h": 1, "late_tolerance_h": 24, "min_near_limit": 2, "split_min_same_limit": 2,
                    "split_p": 0.30},
    "correlation": {"enabled": False, "window_min": 60, "groups": []},
    "late_evidence": {"enabled": True, "detectors": ["cyber", "auth", "kyc"], "min_band": "HIGH",
                      "min_contribution": 0.0,
                      "exclude_reasons": ["STEP_UP_PASSED_WITH_FRESH_FACTOR", "STEP_UP_FAILED_OR_TIMEOUT",
                                          "STEP_UP_PASSED_TRUSTED", "CUSTOMER_DENIED"]},
    "feedback": {"reliability_min": 0.20, "reliability_max": 0.95, "max_update": 1.0, "max_batch": 3.0,
                 "batch_window_h": 24, "decay_half_life_days": 30},
}


def _merge(base: dict[str, Any], over: dict[str, Any] | None) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else copy.deepcopy(v)
    return out


def merged(overrides: dict[str, Any] | None = None, base: dict[str, Any] | None = None) -> dict[str, Any]:
    """DEFAULTS (or `base`) with `overrides` merged in, key by key."""
    return _merge(DEFAULTS if base is None else base, overrides)


@lru_cache(maxsize=4)
def _load(path: str) -> dict[str, Any]:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}
    return merged(raw or {})


def load_v3_core(path: str | Path = V3_CORE_FILE) -> dict[str, Any]:
    """The parsed config merged over DEFAULTS. Callers must not mutate it (it is cached)."""
    return _load(str(path))
