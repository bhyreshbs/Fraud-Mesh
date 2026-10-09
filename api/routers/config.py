"""GET /v1/engine/config (analyst+, read-only): the engine's live configuration for the Detection Engine and Settings
screens. Band thresholds, base rate, policy.yaml rules, patterns.yaml sequence patterns, the model manifest (headline
and per-dataset test metrics) and the Digital Twin forecast source. Nothing here can be changed through the API: policy
and patterns are reviewed files, and model artifacts are verified against their SHA-256 before use."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.security import Principal, require_role
from engine.common.settings import settings
from engine.contracts import CONTRACT_VERSION
from engine.detectors.models import load_manifest
from engine.fusion.patterns import load_patterns
from engine.policy.policy import load_rules
from engine.twin.predict import load as load_transitions

router = APIRouter(tags=["config"])


@router.get("/v1/engine/config")
async def engine_config(p: Principal = Depends(require_role("analyst"))) -> dict:
    twin = load_transitions()
    return {
        "contract_version": CONTRACT_VERSION,
        "demo_mode": settings.demo_mode,
        "base_rate": settings.base_rate,
        "thresholds": {"medium": settings.band_medium, "high": settings.band_high, "critical": settings.band_critical},
        "policy_rules": [{"id": r.id, "band": r.band, "reason_any": sorted(r.reason_any), "actions": list(r.actions)}
                         for r in load_rules()],
        "patterns": [{"id": pt.id, "label": pt.label, "bonus": pt.bonus, "sequence": list(pt.sequence),
                      "within_min": int(pt.within.total_seconds() // 60) if pt.within else None,
                      "when_detector": pt.when_detector, "shared_kind": pt.shared_kind} for pt in load_patterns()],
        "models": load_manifest().get("artifacts", []),
        "twin_forecast": {"source": twin.get("source"), "attacks": twin.get("attacks", 0)},
    }
