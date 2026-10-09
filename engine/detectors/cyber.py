"""cyber detector (PRD §10.4): Sigma-style rules from cyber_rules.yaml over cloud_audit events.

`match` keys compare to payload fields, plus src_ip_untrusted (src_ip outside corporate_ranges.txt; the payload
holds an ip token, so the ranges are tokenized the same way) and reads_10m_gte (feature cid_profile_reads_10m).
Each rule carries its own stage and technique; several hits give one evidence item at the top rule's stage.
Entities: the cid, ip and target cust tokens.

v3 insider rules (phase 10, rules/insider.yaml, p values there): INSIDER_CHANGE_AFTER_NEW_DEVICE_LOGIN,
INSIDER_REPEATED_SENSITIVE_ACTIONS, INSIDER_SENSITIVE_OFF_HOURS. They read the graph (the target customer's
LOGGED_IN_FROM edges, the identity's ACCESSED edges) at the event's time and never look at src_ip: a trusted corporate
IP is where a request came from, not an authorisation. They are evaluated after cyber_rules.yaml, so on a tie the
existing rule stays the top rule (its p, stage and technique).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from engine.contracts import STAGE_ORDER, Evidence, StoredEvent
from engine.detectors.base import RULES_DIR, best_rule, load_calibration, make_evidence, should_emit
from engine.graph.resolve import cgnat_tokens, load_cgnat_networks
from engine.graph.store import EntityGraph

VERSION = "cyber-1"
SPECIAL_KEYS = frozenset({"src_ip_untrusted", "reads_10m_gte"})


@dataclass(frozen=True)
class CyberRule:
    id: str
    title: str
    stage: str
    technique: str | None
    match: tuple[tuple[str, Any], ...]

    def matches(self, payload: dict, feats: dict[str, Any], corporate: frozenset[str]) -> bool:
        for key, want in self.match:
            if key == "src_ip_untrusted":
                if (payload.get("src_ip") not in corporate) != bool(want):
                    return False
            elif key == "reads_10m_gte":
                if feats.get("cid_profile_reads_10m", 0) < want:
                    return False
            elif payload.get(key) != want:
                return False
        return True


@lru_cache(maxsize=2)
def load_rules(path: str | Path = RULES_DIR / "cyber_rules.yaml") -> tuple[CyberRule, ...]:
    out = []
    for r in yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []:
        if r["stage"] not in STAGE_ORDER:
            raise ValueError(f"cyber rule {r['id']}: unknown stage {r['stage']}")
        out.append(CyberRule(id=r["id"], title=r["title"], stage=r["stage"], technique=r.get("technique"),
                             match=tuple(sorted((r.get("match") or {}).items()))))
    return tuple(out)


@lru_cache(maxsize=2)
def corporate_tokens(path: str | Path = RULES_DIR / "corporate_ranges.txt") -> frozenset[str]:
    return cgnat_tokens(load_cgnat_networks(path))


IST = timezone(timedelta(hours=5, minutes=30))


@lru_cache(maxsize=2)
def load_insider(path: str | Path = RULES_DIR / "insider.yaml") -> dict:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    for r in raw.get("rules", []):
        if r["stage"] not in STAGE_ORDER:
            raise ValueError(f"insider rule {r['id']}: unknown stage {r['stage']}")
    return raw


class InsiderRules:
    """Staff-abuse rules over cloud_audit (rules/insider.yaml). Graph-derived, so a restarted engine answers the same."""

    def __init__(self, config: dict | None = None) -> None:
        self.cfg = load_insider() if config is None else config
        self.sensitive = frozenset(self.cfg.get("sensitive_actions") or ())
        self.rules = {r["id"]: r for r in self.cfg.get("rules", [])}

    def hits(self, event: StoredEvent, graph: EntityGraph) -> list[tuple[str, str, str, str | None, float]]:
        """[(rule id, title, stage, technique, p)] in insider.yaml order."""
        p = event.payload
        if p.get("action") not in self.sensitive or p.get("result") == "failure":
            return []
        now, c = event.occurred_at, self.cfg
        fired = set()
        cust = p.get("target_customer")
        if cust and self.new_device_login(graph, cust, now):
            fired.add("INSIDER_CHANGE_AFTER_NEW_DEVICE_LOGIN")
        cid = p.get("actor_identity")
        if cid and cid in graph.g:
            since = now - timedelta(minutes=c["repeated_window_min"])
            touched = {other for other, keyed in graph.g.adj[cid].items() for d in keyed.values()
                       if d["edge_type"] == "ACCESSED" and d["first_seen"] <= now and d["last_seen"] >= since}
            if len(touched) >= c["repeated_min_customers"]:
                fired.add("INSIDER_REPEATED_SENSITIVE_ACTIONS")
        hour = now.astimezone(IST).hour
        if fired and (hour >= c["off_hours_start"] or hour < c["off_hours_end"]):    # corroborating only, never alone
            fired.add("INSIDER_SENSITIVE_OFF_HOURS")
        return [(rid, r["title"], r["stage"], r.get("technique"), float(r["p"]))
                for rid, r in self.rules.items() if rid in fired]

    def new_device_login(self, graph: EntityGraph, cust: str, now) -> bool:
        """The customer's account logged in from a device first seen within new_device_window_min, while the customer
        already had a device older than established_device_h."""
        c = self.cfg
        recent = now - timedelta(minutes=c["new_device_window_min"])
        established = now - timedelta(hours=c["established_device_h"])
        new, old = False, False
        for acct in graph.accounts_of(cust):
            for keyed in graph.g.adj[acct].values():
                for d in keyed.values():
                    if d["edge_type"] != "LOGGED_IN_FROM" or d["first_seen"] > now:
                        continue
                    if d["first_seen"] >= recent:
                        new = True
                    elif d["first_seen"] <= established:
                        old = True
        return new and old


class CyberDetector:
    id = "cyber"
    handles = frozenset({"cloud_audit"})

    def __init__(self) -> None:
        self.cal = load_calibration()["cyber"]
        self.rules = load_rules()
        self.corporate = corporate_tokens()
        self.insider = InsiderRules()

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        fired = [r for r in self.rules if r.matches(event.payload, feats, self.corporate)]
        hits = [(r.id, self.cal[r.id], r.technique, r.title) for r in fired]
        stage = {r.id: r.stage for r in fired}
        for rid, title, rstage, technique, p_rule in self.insider.hits(event, graph):
            hits.append((rid, p_rule, technique, title))
            stage[rid] = rstage
        if not hits:
            return []
        p, reasons, technique, top = best_rule(hits)
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, VERSION, event, stage[top], p, rel, reasons, technique=technique)]
