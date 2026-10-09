"""Sequence patterns (PRD §10.5), loaded from patterns.yaml.

Two pattern shapes exist:
  sequence + within_min      evidence of the later stage follows evidence of the earlier stage within N minutes
  when_detector + shares_entity_kind_with_earlier_evidence
                             evidence of that detector shares an entity of that kind with an earlier evidence item
Only evidence with a positive weight counts, the same rule that marks stages (§10.7). A match reports the
evidence item that completed it, which the explanation (§10.10) places the pattern part after.

Two optional sequence conditions (DEV1 FW, pending Dev 2 review; used by pat_APP_SCAM1 only):
  first_reason_any    the evidence matching the FIRST stage of the sequence must carry one of these reason codes
  absent_stages       no live evidence of these stages anywhere in the case (e.g. an APP scam has no S2 takeover;
                      a case with S2 evidence is an account takeover and pat_ATO1 covers it)
Two optional keys (v3 core, used by pat_ATO2 only):
  total_within_min    the whole chain (first step to last step) must fit in N minutes; `within_min` still bounds each
                      step against the previous one
  unless_patterns     the pattern is not evaluated when one of these (earlier in the file) already matched the case,
                      so one sequence is not rewarded twice (pat_ATO2 extends pat_ATO1's S1 → S2 link to S5)
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
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
    first_reason_any: frozenset[str] = frozenset()
    absent_stages: frozenset[str] = frozenset()
    total_within: timedelta | None = None
    unless_patterns: tuple[str, ...] = ()

    def completed_by(self, ordered: list[Evidence], weight: dict[str, float]) -> str | None:
        """evidence_id of the item that first completes this pattern in `ordered`, or None."""
        live = [e for e in ordered if weight[e.evidence_id] > 0]
        if self.absent_stages and any(e.stage in self.absent_stages for e in live):
            return None
        if self.sequence:
            return self._sequence(live)
        return self._shared_entity(live)

    def _sequence(self, live: list[Evidence]) -> str | None:
        # Each step must follow an earlier hit of the previous step within `within` (§10.5 uses two-stage sequences).
        # Each hit remembers the latest possible chain start, for total_within (unused by two-stage patterns).
        hits: dict[int, list[tuple[Evidence, datetime]]] = {}
        for ev in live:
            for step, stage in enumerate(self.sequence):
                if ev.stage != stage:
                    continue
                if step == 0:
                    if not self.first_reason_any or any(r.code in self.first_reason_any for r in ev.reasons):
                        hits.setdefault(0, []).append((ev, ev.ts))
                    continue
                before = [start for p, start in hits.get(step - 1, []) if p is not ev and p.ts <= ev.ts
                          and (self.within is None or ev.ts - p.ts <= self.within)
                          and (self.total_within is None or ev.ts - start <= self.total_within)]
                if before:
                    hits.setdefault(step, []).append((ev, max(before)))
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
        absent = frozenset(item.get("absent_stages") or ())
        if any(s not in STAGE_ORDER for s in absent):
            raise ValueError(f"pattern {item.get('id')}: absent_stages must list stages from STAGE_ORDER")
        total = timedelta(minutes=item["total_within_min"]) if item.get("total_within_min") is not None else None
        return Pattern(id=item["id"], label=item["label"], bonus=float(item["bonus"]), sequence=seq, within=within,
                       first_reason_any=frozenset(item.get("first_reason_any") or ()), absent_stages=absent,
                       total_within=total, unless_patterns=tuple(item.get("unless_patterns") or ()))
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
    for i, p in enumerate(patterns):                 # fuse() evaluates in file order, so references must point back
        earlier = {q.id for q in patterns[:i]}
        if any(u not in earlier for u in p.unless_patterns):
            raise ValueError(f"pattern {p.id}: unless_patterns must name patterns listed before it")
    return patterns
