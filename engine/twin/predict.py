"""Attack progression forecast (Digital Twin phase 3): first-order transitions between kill-chain stages, learned from
labelled attacks (ml/train_twin.py -> ml/artifacts/twin_transitions.json). Probabilities, not guarantees: they describe
how the training attacks progressed, with the sample size shown next to every forecast.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from engine.contracts import STAGE_ORDER
from engine.detectors.models import model_dir
from engine.twin.models import NextStage, Prediction

FILE = "twin_transitions.json"
GOAL = "S6_MONETIZATION"

# event type -> stage, the same mapping the detectors use (PRD §10.4 stage column); cloud actions by rule
EVENT_STAGE = {"network_ids_alert": "S0_RECON", "login": "S1_INITIAL_ACCESS", "mfa_change": "S2_CONTROL_TAKEOVER",
               "mfa_challenge": "S2_CONTROL_TAKEOVER", "sim_signal": "S2_CONTROL_TAKEOVER",
               "profile_change": "S2_CONTROL_TAKEOVER", "kyc_result": "S3_IDENTITY_MANIPULATION",
               "payee_added": "S5_POSITIONING", "transaction": "S6_MONETIZATION"}
CLOUD_STAGE = {"UpdateTransferLimit": "S4_ESCALATION", "ReadCustomerProfile": "S0_RECON", "ResetCustomerMfa": "S2_CONTROL_TAKEOVER"}


def stage_of(event_type: str, payload: dict) -> str | None:
    if event_type == "cloud_audit":
        return CLOUD_STAGE.get(payload.get("action", ""))
    if event_type == "login" and payload.get("result") == "failure":
        return "S0_RECON"
    return EVENT_STAGE.get(event_type)


@lru_cache(maxsize=4)
def load(directory: str | None = None) -> dict:
    path = Path(directory) if directory else model_dir()
    try:
        return json.loads((path / FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"transitions": {}, "attacks": 0}


def _probs(table: dict, stage: str) -> dict[str, float]:
    row = table.get(stage, {})
    total = sum(v["count"] for v in row.values())
    return {t: v["count"] / total for t, v in row.items()} if total else {}


def p_reach(table: dict, stage: str, goal: str = GOAL, iterations: int = 200) -> float:
    """P(the attack eventually reaches `goal` from `stage`), solving the absorbing chain by value iteration."""
    if stage == goal:
        return 1.0
    v = dict.fromkeys(STAGE_ORDER, 0.0)
    v[goal] = 1.0
    for _ in range(iterations):
        v = {s: 1.0 if s == goal else sum(p * v.get(t, 0.0) for t, p in _probs(table, s).items()) for s in STAGE_ORDER}
    return v.get(stage, 0.0)


def minutes_to(table: dict, stage: str, goal: str = GOAL) -> float | None:
    """Median minutes along the most likely path from `stage` to `goal` (no stage revisited)."""
    total, here, seen = 0.0, stage, {stage}
    while here != goal:
        options = [(p, t) for t, p in _probs(table, here).items() if t not in seen]
        if not options:
            return None
        _, nxt = max(options)
        total += table[here][nxt].get("median_minutes") or 0.0
        here = nxt
        seen.add(nxt)
    return round(total, 1)


def predict(stage: str | None, directory: str | None = None) -> Prediction:
    data = load(directory)
    table, n = data.get("transitions", {}), int(data.get("attacks", 0))
    note = (f"Learned from {n} labelled attacks ({data.get('source', 'training data')}). "
            "A forecast of how similar attacks progressed, not a guarantee.")
    if stage is None or not table:
        return Prediction(from_stage=stage, next_stages=[], p_reach_monetization=None,
                          expected_minutes_to_monetization=None, sample_size=n, note=note)
    nxt = sorted(_probs(table, stage).items(), key=lambda kv: -kv[1])[:3]
    return Prediction(
        from_stage=stage,
        next_stages=[NextStage(stage=t, probability=round(p, 3), median_minutes=table[stage][t].get("median_minutes"))
                     for t, p in nxt],
        p_reach_monetization=round(p_reach(table, stage), 3),
        expected_minutes_to_monetization=0.0 if stage == GOAL else minutes_to(table, stage),
        sample_size=n, note=note)
