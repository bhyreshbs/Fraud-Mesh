"""Stage machine (PRD §10.7): case.stages[stage] = StageHit(ts, evidence_id) the first time evidence with a positive
contribution reaches that stage. Evidence with zero or negative contribution never marks a stage."""
from __future__ import annotations

from engine.contracts import STAGE_ORDER, Case, Evidence, StageHit


class Stages:
    def update(self, case: Case, ev: Evidence) -> bool:
        """Mark ev.stage if this is its first positive evidence. Returns True when a stage was newly reached."""
        if ev.contribution <= 0 or ev.stage in case.stages:
            return False
        case.stages[ev.stage] = StageHit(ts=ev.ts, evidence_id=ev.evidence_id)
        case.stages = {s: case.stages[s] for s in STAGE_ORDER if s in case.stages}
        return True
