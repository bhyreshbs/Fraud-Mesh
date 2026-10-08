"""MemoryStore(Store): the in-memory Store for engine tests and the benchmark (PRD §3, §5).

Mirrors api/store_pg.py:PgStore row for row: the same upsert rules (§8), the same orderings, and the same
two non-protocol helpers (insert_event, save_labels). Every model is copied on the way in and out, so callers
can never mutate stored state without a save, exactly as with a database.
"""
from __future__ import annotations

import copy
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import datetime

from engine.contracts import Case, Decision, Edge, Evidence, Label, ReplayResult, StoredEvent

# PRD §8: the detector_reliability seed rows.
RELIABILITY_SEED: dict[str, tuple[float, float]] = {
    "txn": (17.0, 3.0), "behaviour": (6.0, 4.0), "auth": (7.0, 3.0), "kyc": (6.0, 4.0),
    "cyber": (5.0, 5.0), "netsec": (5.0, 5.0), "graph": (8.0, 2.0)}
UNKNOWN_DETECTOR_SEED = (1.0, 1.0)      # same fallback as PgStore for a detector §8 does not list
MAX_SOURCE_EVENT_IDS = 50
OPEN_STATUSES = frozenset({"OPEN", "INVESTIGATING"})


class MemoryStore:
    """Implements engine.contracts.Store in memory."""

    def __init__(self, reliability: dict[str, tuple[float, float]] | None = None) -> None:
        self._events: dict[str, StoredEvent] = {}
        self._event_order: list[StoredEvent] | None = []
        self._edges: dict[tuple[str, str, str], Edge] = {}
        self._entities: dict[str, bool] = {}                       # token -> fraud_seed
        self._cases: dict[str, Case] = {}
        self._case_entities: dict[str, set[str]] = {}
        self._evidence: dict[str, tuple[str, Evidence]] = {}       # evidence_id -> (case_id, evidence)
        self._decisions: dict[str, Decision] = {}
        self._reliability: dict[str, tuple[float, float]] = dict(RELIABILITY_SEED if reliability is None else reliability)
        self._labels: dict[str, Label] = {}
        self._replays: dict[str, ReplayResult] = {}
        self.audit_log: list[dict] = []

    # ------------------------------------------------------------ transactions
    def transaction(self) -> AbstractContextManager[None]:
        """A no-op (PRD §5 allows it): each call below is already applied atomically."""
        @contextmanager
        def _tx() -> Iterator[None]:
            yield None
        return _tx()

    # ------------------------------------------------------------ events
    def insert_event(self, ev: StoredEvent) -> bool:
        """Not part of the Store protocol (same helper as PgStore). False means the event_id already exists."""
        if ev.event_id in self._events:
            return False
        self._events[ev.event_id] = ev.model_copy(deep=True)
        self._event_order = None
        return True

    def iter_events(self, since: datetime | None = None) -> Iterator[StoredEvent]:
        if self._event_order is None:
            self._event_order = sorted(self._events.values(), key=lambda e: (e.occurred_at, e.event_id))
        for ev in list(self._event_order):
            if since is None or ev.occurred_at >= since:
                yield ev.model_copy(deep=True)

    def get_event(self, event_id: str) -> StoredEvent | None:
        ev = self._events.get(event_id)
        return ev.model_copy(deep=True) if ev is not None else None

    # ------------------------------------------------------------ graph
    def upsert_edges(self, edges: list[Edge]) -> None:
        for e in edges:
            self._entities.setdefault(e.src, False)
            self._entities.setdefault(e.dst, False)
            key = (e.src, e.dst, e.edge_type)
            old = self._edges.get(key)
            if old is None:
                new = e.model_copy(deep=True)
                new.source_event_ids = new.source_event_ids[:MAX_SOURCE_EVENT_IDS]
            else:   # §8: ON CONFLICT DO UPDATE — first_seen is kept, count + 1
                new = old.model_copy(update={
                    "last_seen": max(old.last_seen, e.last_seen),
                    "count": old.count + 1,
                    "confidence": max(old.confidence, e.confidence),
                    "source_event_ids": (old.source_event_ids + list(e.source_event_ids))[:MAX_SOURCE_EVENT_IDS],
                })
            self._edges[key] = new

    def load_edges(self) -> list[Edge]:
        return [self._edges[k].model_copy(deep=True) for k in sorted(self._edges)]

    def list_fraud_seeds(self) -> set[str]:
        return {t for t, seed in self._entities.items() if seed}

    def set_fraud_seeds(self, entity_ids: list[str], value: bool = True) -> None:
        for t in entity_ids:
            self._entities[t] = value

    # ------------------------------------------------------------ cases, evidence, decisions
    def find_open_cases(self, entity_ids: list[str], since: datetime) -> list[Case]:
        ids = set(entity_ids)
        if not ids:
            return []
        return [self._cases[cid].model_copy(deep=True) for cid in sorted(self._cases)
                if self._cases[cid].status in OPEN_STATUSES
                and self._cases[cid].last_event_ts >= since
                and self._case_entities.get(cid, set()) & ids]

    def get_case(self, case_id: str) -> Case | None:
        c = self._cases.get(case_id)
        return c.model_copy(deep=True) if c is not None else None

    def list_cases(self) -> list[Case]:
        ordered = sorted(sorted(self._cases.values(), key=lambda c: c.case_id), key=lambda c: c.updated_at, reverse=True)
        return [c.model_copy(deep=True) for c in ordered]

    def save_case(self, case: Case) -> None:
        self._cases[case.case_id] = case.model_copy(deep=True)
        self._case_entities[case.case_id] = set(case.entities)

    def merge_cases(self, keep_id: str, drop_id: str) -> None:
        for eid, (cid, ev) in list(self._evidence.items()):
            if cid == drop_id:
                self._evidence[eid] = (keep_id, ev)
        for did, d in list(self._decisions.items()):
            if d.case_id == drop_id:
                self._decisions[did] = d.model_copy(update={"case_id": keep_id})
        self._cases.pop(drop_id, None)
        self._case_entities.pop(drop_id, None)

    def save_evidence(self, ev: Evidence, case_id: str) -> None:
        if case_id not in self._cases:      # the evidence table references cases(case_id)
            raise KeyError(f"save_evidence: unknown case {case_id}")
        self._evidence[ev.evidence_id] = (case_id, ev.model_copy(deep=True))

    def list_evidence(self, case_id: str) -> list[Evidence]:
        items = [ev for cid, ev in self._evidence.values() if cid == case_id]
        return [ev.model_copy(deep=True) for ev in sorted(items, key=lambda e: (e.ts, e.evidence_id))]

    def save_decision(self, d: Decision) -> None:
        if d.case_id not in self._cases:    # the decisions table references cases(case_id)
            raise KeyError(f"save_decision: unknown case {d.case_id}")
        self._decisions[d.decision_id] = d.model_copy(deep=True)

    def list_decisions(self, case_id: str) -> list[Decision]:
        items = [d for d in self._decisions.values() if d.case_id == case_id]
        return [d.model_copy(deep=True) for d in sorted(items, key=lambda d: (d.created_at, d.decision_id))]

    # ------------------------------------------------------------ learning, labels, replays, audit
    def get_reliability(self) -> dict[str, tuple[float, float]]:
        return dict(self._reliability)

    def add_reliability(self, detector: str, d_alpha: float, d_beta: float) -> None:
        a, b = self._reliability.get(detector, RELIABILITY_SEED.get(detector, UNKNOWN_DETECTOR_SEED))
        self._reliability[detector] = (a + d_alpha, b + d_beta)

    def get_labels(self) -> dict[str, Label]:
        return {k: v.model_copy() for k, v in self._labels.items()}

    def save_labels(self, labels: list[Label]) -> None:
        """Not part of the Store protocol (same helper as PgStore): first write wins, like ON CONFLICT DO NOTHING."""
        for lb in labels:
            self._labels.setdefault(lb.event_id, lb.model_copy())

    def save_replay(self, r: ReplayResult) -> None:
        self._replays[r.replay_id] = r.model_copy(deep=True)

    def get_replay(self, replay_id: str) -> ReplayResult | None:
        r = self._replays.get(replay_id)
        return r.model_copy(deep=True) if r is not None else None

    def append_audit(self, actor: str, action: str, object_id: str, details: dict) -> None:
        self.audit_log.append({"seq": len(self.audit_log) + 1, "actor": actor, "action": action,
                               "object_id": object_id, "details": copy.deepcopy(details)})
