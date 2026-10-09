"""Graph features of one account (v3 phase 9.1), as a flat dict for explanations, tests and offline analysis.

These are NOT part of the §10.3 FEATURE_NAMES vector (the txn model and the feature-parity test keep that vector
exactly as it is); the graph detector reads the same values through engine/graph/mule.py. Everything is computed from
graph edges at the given event time, so a restarted engine (graph rebuilt from the edges table) returns the same.
"""
from __future__ import annotations

from datetime import datetime

from engine.graph.mule import MuleAnalytics, MuleConfig
from engine.graph.store import EntityGraph

GRAPH_FEATURE_NAMES = ["account_age_days", "payers", "unique_payers_24h", "new_payers_24h", "beneficiaries",
                       "new_beneficiaries_24h", "inflow_outflow_ratio", "pass_through_min", "dormant_activated",
                       "decayed_fan_in"]
NO_PASS_THROUGH = -1.0


def graph_features(graph: EntityGraph, acct: str, now: datetime, config: MuleConfig | None = None) -> dict[str, float]:
    """GRAPH_FEATURE_NAMES for an acct token (all zeros, pass_through_min -1, for an unknown token)."""
    f = dict.fromkeys(GRAPH_FEATURE_NAMES, 0.0)
    f["pass_through_min"] = NO_PASS_THROUGH
    prof = MuleAnalytics(graph, config).profile(acct, now)
    if prof is None:
        return f
    f.update(account_age_days=prof.account_age_days, payers=float(prof.payers),
             unique_payers_24h=float(prof.unique_payers_window), new_payers_24h=float(prof.new_payers_window),
             beneficiaries=float(prof.beneficiaries), new_beneficiaries_24h=float(prof.new_beneficiaries_window),
             inflow_outflow_ratio=prof.inflow_outflow_ratio,
             pass_through_min=prof.pass_through_min if prof.pass_through_min is not None else NO_PASS_THROUGH,
             dormant_activated=float(prof.dormant_activated), decayed_fan_in=prof.decayed_fan_in)
    return f
