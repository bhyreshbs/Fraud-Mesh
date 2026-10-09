"""cyber detector (PRD §10.4): Sigma-style rules from cyber_rules.yaml over cloud_audit events.

`match` keys compare to payload fields, plus src_ip_untrusted (src_ip outside corporate_ranges.txt; the payload
holds an ip token, so the ranges are tokenized the same way) and reads_10m_gte (feature cid_profile_reads_10m).
Each rule carries its own stage and technique; several hits give one evidence item at the top rule's stage.
Entities: the cid, ip and target cust tokens.
"""
from __future__ import annotations

from dataclasses import dataclass
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


class CyberDetector:
    id = "cyber"
    handles = frozenset({"cloud_audit"})

    def __init__(self) -> None:
        self.cal = load_calibration()["cyber"]
        self.rules = load_rules()
        self.corporate = corporate_tokens()

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        fired = [r for r in self.rules if r.matches(event.payload, feats, self.corporate)]
        if not fired:
            return []
        stage = {r.id: r.stage for r in fired}
        p, reasons, technique, top = best_rule([(r.id, self.cal[r.id], r.technique, r.title) for r in fired])
        if not should_emit(p, reasons):
            return []
        return [make_evidence(self.id, VERSION, event, stage[top], p, rel, reasons, technique=technique)]
