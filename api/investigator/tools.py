"""Investigator AI tools (PRD §15.6 task 1): six read-only tools bound server-side to one case.

Each tool records the IDs it returned (the only citations the validator accepts) and every number the templates print
goes through a fmt_* helper that records its text, so the validator can drop any sentence with a number that did not
come from a tool output. Nothing here writes, except run_replay which saves its ReplayResult like the Replay tab does.
"""
from __future__ import annotations

from datetime import timedelta, timezone

from api import engine_calls
from engine.contracts import Case, CaseSummary, Decision, Evidence, ReplayResult, summarize

IST = timezone(timedelta(hours=5, minutes=30))


class CaseTools:
    def __init__(self, app, case: Case) -> None:
        self.app, self.case, self.store = app, case, app.state.store
        self.ids: set[str] = {case.case_id}
        self.numbers: set[str] = set()
        self._timeline: tuple[list[Evidence], list[Decision]] | None = None

    # ------------------------------------------------------------ the six tools
    def get_case_summary(self) -> CaseSummary:
        return summarize(self.case)

    def get_timeline(self) -> tuple[list[Evidence], list[Decision]]:
        if self._timeline is None:
            ev, dec = self.store.list_evidence(self.case.case_id), self.store.list_decisions(self.case.case_id)
            self.ids |= {e.evidence_id for e in ev} | {d.decision_id for d in dec}
            self._timeline = (ev, dec)
        return self._timeline

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        ev = next((e for e in self.get_timeline()[0] if e.evidence_id == evidence_id), None)
        if ev:
            self.ids.add(ev.evidence_id)
        return ev

    def get_entity_paths(self) -> list[list[str]]:
        paths = engine_calls.explain_sync(self.app, self.case.case_id).seed_paths
        self.ids |= {t for path in paths for t in path}
        return paths

    def run_replay(self, ablate: list[str] | None = None, mode: str = "fused") -> ReplayResult:
        r = engine_calls.replay_sync(self.app, self.case.case_id, list(ablate or []), mode)
        self.ids.add(r.replay_id)
        self.ids |= {pt.evidence_id for pt in (r.eip, r.baseline_eip) if pt}
        return r

    def get_policy_rule(self, decision_id: str) -> Decision | None:
        d = next((x for x in self.get_timeline()[1] if x.decision_id == decision_id), None)
        if d:
            self.ids.add(d.decision_id)
        return d

    # ------------------------------------------------------------ formatting that records the printed numbers
    def _rec(self, s: str) -> str:
        self.numbers.add(s)
        return s

    def fmt_pct(self, p: float) -> str:
        return self._rec(f"{p * 100:.1f}") + "%"

    def fmt_signed(self, x: float) -> str:
        return ("+" if x >= 0 else "-") + self._rec(f"{abs(x):.2f}")

    def fmt_int(self, n: int) -> str:
        return self._rec(str(int(n)))

    def fmt_time(self, ts) -> str:
        return self._rec(ts.astimezone(IST).strftime("%H:%M")) + " IST"

    def fmt_inr(self, paise: int) -> str:
        rupees = str(round(paise / 100))
        head, tail, groups = rupees[:-3], rupees[-3:], []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        text = ",".join(([head] if head else []) + groups + [tail]) if len(rupees) > 3 else rupees
        return "₹" + self._rec(text)
