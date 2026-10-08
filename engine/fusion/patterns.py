"""Sequence patterns (PRD §10.5), loaded from patterns.yaml.

Two pattern shapes exist:
  sequence + within_min      evidence of the later stage follows evidence of the earlier stage within N minutes
  when_detector + shares_entity_kind_with_earlier_evidence
                             evidence of that detector shares an entity of that kind with an earlier evidence item
Only evidence with a positive weight counts, the same rule that marks stages (§10.7). A match reports the
evidence item that completed it, which the explanation (§10.10) places the pattern part after.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from pathlib import Path

import yaml

from engine.contracts import STAGE_ORDER, Evidence
from engine.graph.resolve import kind_of

PATTERNS_FILE = Path(__file__).resolve().parent / "patterns.yaml"


@dataclass(frozen=True)
class Pattern:
    id: str
    label: str
    bonus: float
    sequence: tuple[str, ...] = ()
    within: timedelta | None = None
    when_detector: str | None = None
    shared_kind: str | None = None

    def completed_by(self, ordered: list[Evidence], weight: dict[str, float]) -> str | None:
        """evidence_id of the item that first completes this pattern in `ordered`, or None."""
        live = [e for e in ordered if weight[e.evidence_id] > 0]
        if self.sequence:
            return self._sequence(live)
        return self._shared_entity(live)

    def _sequence(self, live: list[Evidence]) -> str | None:
        # Each step must follow an earlier hit of the previous step within `within` (§10.5 uses two-stage sequences).
        hits: dict[int, list[Evidence]] = {}
        for ev in live:
            for step, stage in enumerate(self.sequence):
                if ev.stage != stage:
                    continue
                if step == 0:
                    hits.setdefault(0, []).append(ev)
                    continue
                before = [p for p in hits.get(step - 1, []) if p is not ev and p.ts <= ev.ts
                          and (self.within is None or ev.ts - p.ts <= self.within)]
                if before:
                    hits.setdefault(step, []).append(ev)
                    if step == len(self.sequence) - 1:
                        return ev.evidence_id
        return None

    def _shared_entity(self, live: list[Evidence]) -> str | None:
        seen: set[str] = set()
        for ev in live:
            mine = {t for t in ev.entities if kind_of(t) == self.shared_kind}
            if (self.when_detector is None or ev.detector == self.when_detector) and mine & seen:
                return ev.evidence_id
            seen |= mine
        return None


def _parse(item: dict) -> Pattern:
    if "sequence" in item:
        seq = tuple(item["sequence"])
        if len(seq) < 2 or any(s not in STAGE_ORDER for s in seq):
            raise ValueError(f"pattern {item.get('id')}: sequence must list 2+ stages from STAGE_ORDER")
        within = timedelta(minutes=item["within_min"]) if item.get("within_min") is not None else None
        return Pattern(id=item["id"], label=item["label"], bonus=float(item["bonus"]), sequence=seq, within=within)
    if "shares_entity_kind_with_earlier_evidence" in item:
        return Pattern(id=item["id"], label=item["label"], bonus=float(item["bonus"]),
                       when_detector=item.get("when_detector"), shared_kind=item["shares_entity_kind_with_earlier_evidence"])
    raise ValueError(f"pattern {item.get('id')}: unknown shape")


@lru_cache(maxsize=8)
def load_patterns(path: str | Path = PATTERNS_FILE) -> tuple[Pattern, ...]:
    items = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    patterns = tuple(_parse(i) for i in items)
    if len({p.id for p in patterns}) != len(patterns):
        raise ValueError("duplicate pattern id in patterns.yaml")
    return patterns
