"""Case joiner (PRD §10.6).

1. E = the evidence's entities of kind cust/acct/dev/ip/phone, minus excluded nodes (hubs, CGNAT IPs; §10.2).
2. X = E plus graph.neighbours_within(e, 2, 0.5) for each e in E, capped at 200 tokens.
3. C = store.find_open_cases(X, since = ev.ts − 72 h).
4. Keep a candidate if last_event_ts ≥ ev.ts − 6 h, or (sticky rule) it has the evidence's customer and has reached
   S2 or later (the sticky 72 h rule for customers past S2, F7).
5. No candidate: drop the evidence if ev.p ≤ BASE_RATE, else open a case anchored on the evidence's cust token,
   or else on its first entity in sorted order.
6. One candidate: attach. Several: merge into the one with the highest p_attack (ties: oldest opened_at),
   audit CASE_MERGED.
7. Re-anchor a case whose anchor is not a cust token when the evidence carries one, audit CASE_REANCHORED.
8. Add all of the evidence's entities to the case; last_event_ts = updated_at = ev.ts; save_evidence.

Payee reputation (DEV1 FW, pending Dev 2 review): in steps 1–2 a reputable payee account (engine/graph/reputation.py)
is treated like an excluded node, for joining only: it is neither a join token nor walked through. Accounts owned by
the evidence's own customer are never skipped. A popular legitimate payee then no longer chains its unrelated payers'
cases, while a young mule account (mule_fanin) still joins its victims into one case. The case still lists the payee
among its entities (step 8), and seed-distance searches are unchanged.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

from engine.common.ids import new_id
from engine.common.settings import settings
from engine.contracts import STAGE_ORDER, Case, CaseStatus, Evidence, Store
from engine.graph.reputation import PayeeReputation
from engine.graph.resolve import kind_of
from engine.graph.store import EntityGraph

JOIN_KINDS = frozenset({"cust", "acct", "dev", "ip", "phone"})
NEIGHBOUR_HOPS = 2
NEIGHBOUR_MIN_CONF = 0.5
MAX_JOIN_TOKENS = 200
LOOKBACK = timedelta(hours=72)
JOIN_WINDOW = timedelta(hours=6)
STICKY_ENABLED = True           # PRD §16.4: same customer, S2 or later, within 72 h
STICKY_FROM_STAGE = "S2_CONTROL_TAKEOVER"
PAYMENT_ORDER = ("normal", "held", "blocked")
STATUS_RANK: dict[str, int] = {"OPEN": 0, "INVESTIGATING": 1}


def customer_of(ev: Evidence) -> str | None:
    custs = sorted(t for t in ev.entities if kind_of(t) == "cust")
    return custs[0] if custs else None


class Joiner:
    def __init__(self, store: Store, graph: EntityGraph, base_rate: float | None = None,
                 reputation: PayeeReputation | None = None) -> None:
        self.store = store
        self.graph = graph
        self.base_rate = settings.base_rate if base_rate is None else base_rate
        self.reputation = PayeeReputation(graph) if reputation is None else reputation

    # ------------------------------------------------------------------ steps 1–4
    def reputable_payee_skip(self, ev: Evidence) -> Callable[[str], bool]:
        """skip(token) for this evidence: a reputable payee account that the evidence's customer does not own.
        Answers are cached for the call, since one join walk may meet the same account several times."""
        own: set[str] = set()
        for t in ev.entities:
            if kind_of(t) == "cust":
                own |= self.graph.accounts_of(t)
        cache: dict[str, bool] = {}

        def skip(token: str) -> bool:
            if kind_of(token) != "acct" or token in own:
                return False
            if token not in cache:
                cache[token] = self.reputation.is_reputable(token, ev.ts)
            return cache[token]
        return skip

    def join_tokens(self, ev: Evidence) -> list[str]:
        skip = self.reputable_payee_skip(ev)
        base = sorted({t for t in ev.entities
                       if kind_of(t) in JOIN_KINDS and not self.graph.is_excluded(t) and not skip(t)})
        out: dict[str, int] = dict.fromkeys(base, 0)
        for t in base:
            for n, d in self.graph.neighbours_within(t, NEIGHBOUR_HOPS, NEIGHBOUR_MIN_CONF, skip=skip).items():
                out[n] = min(out.get(n, d), d)
        ranked = sorted(out, key=lambda t: (out[t], t))         # the evidence's own tokens first, then nearest
        return ranked[:MAX_JOIN_TOKENS]

    def _sticky(self, case: Case, ev: Evidence) -> bool:
        if not STICKY_ENABLED:
            return False
        reached_s2 = any(STAGE_ORDER.index(s) >= STAGE_ORDER.index(STICKY_FROM_STAGE) for s in case.stages)
        return case.customer is not None and case.customer == customer_of(ev) and reached_s2

    def candidates(self, ev: Evidence) -> list[Case]:
        tokens = self.join_tokens(ev)
        if not tokens:
            return []
        found = self.store.find_open_cases(tokens, since=ev.ts - LOOKBACK)
        return [c for c in found if c.last_event_ts >= ev.ts - JOIN_WINDOW or self._sticky(c, ev)]

    # ------------------------------------------------------------------ steps 5–8
    def attach(self, ev: Evidence) -> Case | None:
        cands = self.candidates(ev)
        if not cands:
            if ev.p <= self.base_rate:
                return None
            case = self._open(ev)
        elif len(cands) == 1:
            case = cands[0]
        else:
            case = self._merge(cands, ev)
        self._reanchor(case, ev)
        case.entities = sorted(set(case.entities) | set(ev.entities))
        case.last_event_ts = case.updated_at = max(case.last_event_ts, ev.ts)
        self.store.save_case(case)                              # the evidence row references the case
        self.store.save_evidence(ev, case.case_id)
        return case

    def _open(self, ev: Evidence) -> Case:
        cust = customer_of(ev)
        if cust is None and not ev.entities:
            raise ValueError(f"evidence {ev.evidence_id} has no entities to anchor a case on")
        anchor = cust if cust is not None else sorted(ev.entities)[0]
        return Case(case_id=new_id("case"), anchor_entity=anchor, customer=cust, opened_at=ev.ts, updated_at=ev.ts,
                    last_event_ts=ev.ts)

    def _merge(self, cands: list[Case], ev: Evidence) -> Case:
        keep = sorted(cands, key=lambda c: (-c.p_attack, c.opened_at, c.case_id))[0]
        for drop in cands:
            if drop.case_id == keep.case_id:
                continue
            keep.entities = sorted(set(keep.entities) | set(drop.entities))
            for stage, hit in drop.stages.items():
                if stage not in keep.stages or hit.ts < keep.stages[stage].ts:
                    keep.stages[stage] = hit
            keep.stages = {s: keep.stages[s] for s in STAGE_ORDER if s in keep.stages}
            keep.opened_at = min(keep.opened_at, drop.opened_at)
            keep.last_event_ts = max(keep.last_event_ts, drop.last_event_ts)
            keep.payment_state = max(keep.payment_state, drop.payment_state, key=PAYMENT_ORDER.index)
            keep.status = self._merged_status(keep.status, drop.status)
            if keep.customer is None and drop.customer is not None:
                keep.customer = drop.customer
            self.store.merge_cases(keep.case_id, drop.case_id)
            self.store.append_audit("engine", "CASE_MERGED", keep.case_id,
                                    {"dropped": drop.case_id, "evidence_id": ev.evidence_id})
        return keep

    @staticmethod
    def _merged_status(a: CaseStatus, b: CaseStatus) -> CaseStatus:
        return a if STATUS_RANK.get(a, 0) >= STATUS_RANK.get(b, 0) else b

    def _reanchor(self, case: Case, ev: Evidence) -> None:
        cust = customer_of(ev)
        if kind_of(case.anchor_entity) == "cust" or cust is None:
            return
        old = case.anchor_entity
        case.anchor_entity, case.customer = cust, cust
        self.store.append_audit("engine", "CASE_REANCHORED", case.case_id,
                                {"from": old, "to": cust, "evidence_id": ev.evidence_id})
