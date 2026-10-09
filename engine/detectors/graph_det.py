"""graph detector (PRD §10.4): where the money is going, stage S5, T1657.

Handles payee_added, and transactions to a payee with no payee_added in the last 24 h. p comes from the payee's
seed distance: 0 → SEED_DISTANCE_0 (the payee is itself a fraud seed; triggers floor_SEED_PAYEE), 1/2/3 →
SEED_DISTANCE_1/_2/_3. If only one shortest path exists and its weakest edge has confidence < 0.7, p is capped at
WEAK_PATH_CAP. p is capped at CAP.
PayPal-derived (D2-P4): PAYEE_NAME_MISMATCH (payee_name_match == false) and MULE_FLOW (the payee's fan-in >= 5
distinct senders in 24 h, or its own outbound ÷ inbound in 24 h within 0.8–1.2) each multiply p by 1.5 with a
minimum of 0.03, so either one alone emits evidence even without a seed path.
Payee reputation (DEV1 FW, pending Dev 2 review): MULE_FLOW does not fire for a reputable payee
(engine/graph/reputation.py: an established account with long-standing payers, no pass-through and no seed nearby),
e.g. a landlord paid by many tenants on the same day. PAYEE_NAME_MISMATCH and seed distance are unchanged.

v3 (phases 7 and 9.1), all in the one evidence item per event (several rules → one item, §10.4):
  - Seed-independent mule signals on the payee (engine/graph/mule.py, rules/mule.yaml): MULE_FAN_IN_NEW_ACCOUNT,
    MULE_PASS_THROUGH, MULE_FAN_OUT, MULE_DORMANT_ACTIVATED, MULE_RAPID_HOPS, MULE_RING. Never for a reputable payee.
  - On every transaction (also one to a payee added < 24 h ago): the SENDER account's own pass-through / fan-out shape
    (a mule moving fresh money on), as MULE_PASS_THROUGH / MULE_FAN_OUT.
  - On every transaction: the APP-scam assessment (engine/features/app_scam.py, rules/app_scam.yaml), reason
    APP_SCAM_WARNING or APP_SCAM_COOLING_OFF plus its APP_* indicators, with a small p (it picks an intervention).
  Each of these sets p = max(p, its p); they never multiply.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from engine.contracts import Evidence, Reason, StoredEvent
from engine.detectors.base import load_calibration, make_evidence, should_emit
from engine.features.app_scam import AppScamAssessor, PayeeRiskLookup
from engine.graph.mule import MuleAnalytics
from engine.graph.mule import load_config as load_mule_config
from engine.graph.pagerank import ppr_proximity
from engine.graph.reputation import PayeeReputation
from engine.graph.store import EntityGraph

VERSION = "graph-2"
MAX_HOPS = 3
WEAK_EDGE = 0.7
RULE_FACTOR, RULE_MIN_P = 1.5, 0.03
MULE_FAN_IN = 5
PASS_THROUGH = (0.8, 1.2)


class GraphDetector:
    id = "graph"
    handles = frozenset({"payee_added", "transaction"})

    def __init__(self, payee_risk: PayeeRiskLookup | None = None) -> None:
        self.cal = load_calibration()["graph"]
        self.mule_cfg = load_mule_config()
        self.app = AppScamAssessor()
        self.payee_risk = payee_risk            # optional external provider (api/payee_risk.py); off by default

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        payee = event.payload.get("payee_account")
        if not payee:
            return []
        p, reasons = 0.0, []
        now = event.occurred_at
        mule = MuleAnalytics(graph, self.mule_cfg)
        rep_cache: list[bool] = []

        def reputable() -> bool:                       # asked lazily, at most once
            if not rep_cache:
                rep_cache.append(PayeeReputation(graph).is_reputable(payee, now))
            return rep_cache[0]

        if not (event.event_type == "transaction" and feats.get("payee_is_new")):
            # the payee itself (a transaction right after payee_added was scored at the add)
            paths = graph.seed_paths(payee, MAX_HOPS, limit=2)
            if paths:
                dist = len(paths[0]) - 1
                code = f"SEED_DISTANCE_{dist}"
                p = self.cal[code]
                reasons.append(Reason(code=code, detail=" > ".join(paths[0])))
                if dist > 0 and len(paths) == 1 and graph.path_min_confidence(paths[0]) < WEAK_EDGE:
                    p = min(p, self.cal["WEAK_PATH_CAP"])
                    reasons.append(Reason(code="WEAK_PATH_CAP", detail=f"weakest edge {graph.path_min_confidence(paths[0]):.2f}"))
            for code, detail in self._rules(event, feats, reputable):
                p = max(p * RULE_FACTOR, RULE_MIN_P)
                reasons.append(Reason(code=code, detail=detail))
            if not reputable():
                p = self._add_mule(p, reasons, mule.signals(payee, now))
                ppr = self.mule_cfg.pagerank or {}
                if ppr.get("enabled"):
                    s = ppr_proximity(graph, payee, now, self.mule_cfg)
                    if s >= float(ppr.get("min_score", 1.0)):
                        p = max(p, float(ppr.get("p", 0.03)))
                        reasons.append(Reason(code="MULE_PPR_PROXIMITY", detail=f"personalized PageRank {s:.3f}"))
        if event.event_type == "transaction":
            if event.account:
                seen = {r.code for r in reasons}
                sender = [(c, f"sender: {d}") for c, d in mule.signals(event.account, now, as_sender=True)
                          if c not in seen]
                p = self._add_mule(p, reasons, sender)
            app = self.app.assess(event, feats, graph, self.payee_risk)
            for code, detail in app.reasons():
                reasons.append(Reason(code=code, detail=detail))
            if app.level is not None:
                p = max(p, self.app.cfg.evidence_p)
        if not reasons:
            return []
        p = min(p, self.cal["CAP"])
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, VERSION, event, "S5_POSITIONING", p, rel, reasons, technique="T1657")]

    def _add_mule(self, p: float, reasons: list[Reason], signals: list[tuple[str, str]]) -> float:
        for code, detail in signals:
            p = max(p, float(self.mule_cfg.p.get(code, 0.0)))
            reasons.append(Reason(code=code, detail=detail))
        return p

    @staticmethod
    def _rules(event: StoredEvent, feats: dict[str, Any],
               reputable: Callable[[], bool] = lambda: False) -> list[tuple[str, str]]:
        out = []
        if event.event_type == "payee_added" and event.payload.get("payee_name_match") is False:
            out.append(("PAYEE_NAME_MISMATCH", "the payee name does not match the account"))
        fan_in, ratio = feats.get("payee_fan_in_24h", 0), feats.get("payee_passthrough_24h", 0)
        if (fan_in >= MULE_FAN_IN or PASS_THROUGH[0] <= ratio <= PASS_THROUGH[1]) and not reputable():
            out.append(("MULE_FLOW", f"fan-in {fan_in:.0f} senders, pass-through {ratio:.2f} in 24 h"))
        return out
