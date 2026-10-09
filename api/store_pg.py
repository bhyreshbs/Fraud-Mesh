"""PgStore(Store) — PRD §5 Store protocol over the §8 schema.

Every engine object is stored whole as JSONB (`model_dump(mode="json")`) and read back with `model_validate`,
so the database can never drift from engine/contracts.py.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from contextvars import ContextVar
from datetime import datetime

from sqlalchemy import text

from api import audit
from api.db import session
from engine.contracts import Case, Decision, Edge, Evidence, Label, ReplayResult, StoredEvent

RELIABILITY_SEED: dict[str, tuple[float, float]] = {
    "txn": (17, 3), "behaviour": (6, 4), "auth": (7, 3), "kyc": (6, 4), "cyber": (5, 5), "netsec": (5, 5), "graph": (8, 2)}


# Inside store.transaction(), save_evidence() calls are buffered and written as one multi-row upsert at commit (§10.5
# re-saves every evidence row of a case on each update; one statement per row would dominate per-event latency).
# Reads of evidence flush the buffer first, so callers observe exactly the same state as with immediate writes.
_pending_evidence: ContextVar[dict[str, dict] | None] = ContextVar("fm_pending_evidence", default=None)
_EVIDENCE_UPSERT = text(
    "INSERT INTO evidence (evidence_id, case_id, event_id, detector, ts, data) "
    "VALUES (:id, :case, :evt, :det, :ts, CAST(:data AS jsonb)) "
    "ON CONFLICT (evidence_id) DO UPDATE SET case_id = EXCLUDED.case_id, detector = EXCLUDED.detector, "
    "ts = EXCLUDED.ts, data = EXCLUDED.data")


def _csv(tokens) -> str:
    """Entity tokens (kind:base32, never a comma) as one comma-joined string for string_to_array() in SQL: far cheaper
    than letting the driver serialise a Python list into a Postgres array on every event."""
    return ",".join(sorted(tokens))


def _j(model) -> str:
    return json.dumps(model.model_dump(mode="json"))


def _kind(token: str) -> str:
    return token.split(":", 1)[0]


_EDGES_UPSERT = text(                                            # entities + edges in one statement (one round trip)
    "WITH e AS (SELECT * FROM jsonb_to_recordset(CAST(:edges AS jsonb)) AS x(src text, dst text, edge_type text, "
    "             confidence real, first_seen timestamptz, last_seen timestamptz, count int, source_event_ids text[])), "
    "ent AS (INSERT INTO entities (entity_id, kind) SELECT t, split_part(t, ':', 1) FROM (SELECT src AS t FROM e UNION SELECT dst FROM e) u "
    "        ON CONFLICT (entity_id) DO NOTHING) "
    "INSERT INTO edges (src, dst, edge_type, confidence, first_seen, last_seen, count, source_event_ids) "
    "SELECT src, dst, edge_type, confidence, first_seen, last_seen, count, source_event_ids FROM e "
    "ON CONFLICT (src, dst, edge_type) DO UPDATE SET "
    "last_seen = GREATEST(edges.last_seen, EXCLUDED.last_seen), "
    "count = edges.count + 1, "
    "confidence = GREATEST(edges.confidence, EXCLUDED.confidence), "
    "source_event_ids = (edges.source_event_ids || EXCLUDED.source_event_ids)[1:50]")


class PgStore:
    """Implements engine.contracts.Store. Every method joins the caller's transaction() if one is open."""

    def __init__(self) -> None:
        self._reliability: dict[str, tuple[float, float]] | None = None   # cached; only add_reliability / reset change it

    def clear_caches(self) -> None:
        """Call after anything outside this store rewrites detector_reliability (e.g. the demo reset)."""
        self._reliability = None

    # ------------------------------------------------------------ transactions
    def transaction(self) -> AbstractContextManager[None]:
        @contextmanager
        def _tx() -> Iterator[None]:
            if _pending_evidence.get() is not None:              # nested: the outermost store transaction flushes
                with session.transaction():
                    yield None
                return
            token = _pending_evidence.set({})
            try:
                with session.transaction() as c:
                    yield None
                    self._flush_evidence(c)                      # same transaction: commits together or not at all
            finally:
                _pending_evidence.reset(token)
        return _tx()

    @staticmethod
    def _flush_evidence(c) -> None:
        buf = _pending_evidence.get()
        if buf:
            c.execute(_EVIDENCE_UPSERT, list(buf.values()))
            buf.clear()

    # ------------------------------------------------------------ events
    def insert_event(self, ev: StoredEvent) -> bool:
        """Not part of the Store protocol: ingestion's INSERT … ON CONFLICT DO NOTHING. False means duplicate."""
        with session.transaction() as c:
            row = c.execute(text(
                "INSERT INTO events (event_id, event_type, source, occurred_at, received_at, customer, entity_tokens, data) "
                "VALUES (:id, :et, :src, :occ, :rec, :cust, :toks, CAST(:data AS jsonb)) "
                "ON CONFLICT (event_id) DO NOTHING RETURNING event_id"),
                {"id": ev.event_id, "et": ev.event_type, "src": ev.source, "occ": ev.occurred_at, "rec": ev.received_at,
                 "cust": ev.customer, "toks": ev.entity_tokens, "data": _j(ev)}).first()
        return row is not None

    def insert_events_bulk(self, events: list[StoredEvent]) -> int:
        """Not part of the Store protocol: bulk ingestion for scripts/load.py --direct. Returns rows inserted."""
        if not events:
            return 0
        with session.transaction() as c:
            before = c.execute(text("SELECT count(*) FROM events")).scalar()
            c.execute(text(
                "INSERT INTO events (event_id, event_type, source, occurred_at, received_at, customer, entity_tokens, data) "
                "VALUES (:id, :et, :src, :occ, :rec, :cust, :toks, CAST(:data AS jsonb)) ON CONFLICT (event_id) DO NOTHING"),
                [{"id": e.event_id, "et": e.event_type, "src": e.source, "occ": e.occurred_at, "rec": e.received_at,
                  "cust": e.customer, "toks": e.entity_tokens, "data": _j(e)} for e in events])
            return c.execute(text("SELECT count(*) FROM events")).scalar() - before

    def iter_events(self, since: datetime | None = None) -> Iterator[StoredEvent]:
        sql = "SELECT data FROM events" + (" WHERE occurred_at >= :since" if since else "") + " ORDER BY occurred_at, event_id"
        with session.transaction() as c:
            result = c.execution_options(stream_results=True, yield_per=2000).execute(text(sql), {"since": since})
            for (data,) in result:
                yield StoredEvent.model_validate(data)

    def get_event(self, event_id: str) -> StoredEvent | None:
        with session.transaction() as c:
            data = c.execute(text("SELECT data FROM events WHERE event_id = :id"), {"id": event_id}).scalar()
        return StoredEvent.model_validate(data) if data is not None else None

    # ------------------------------------------------------------ graph
    def _ensure_entities(self, c, tokens: set[str]) -> None:
        if tokens:
            c.execute(text("INSERT INTO entities (entity_id, kind) SELECT t, split_part(t, ':', 1) FROM unnest(CAST(:t AS text[])) AS t "
                           "ON CONFLICT (entity_id) DO NOTHING"), {"t": sorted(tokens)})

    def upsert_edges(self, edges: list[Edge]) -> None:
        if not edges:
            return
        keys = [(e.src, e.dst, e.edge_type) for e in edges]
        if len(set(keys)) != len(keys):                          # same edge twice in one call: apply one by one
            for e in edges:
                self.upsert_edges([e])
            return
        payload = json.dumps([{"src": e.src, "dst": e.dst, "edge_type": e.edge_type, "confidence": e.confidence,
                               "first_seen": e.first_seen.isoformat(), "last_seen": e.last_seen.isoformat(),
                               "count": e.count, "source_event_ids": e.source_event_ids} for e in edges])
        with session.transaction() as c:
            c.execute(_EDGES_UPSERT, {"edges": payload})

    def load_edges(self) -> list[Edge]:
        with session.transaction() as c:
            rows = c.execute(text("SELECT src, dst, edge_type, confidence, first_seen, last_seen, count, source_event_ids "
                                  "FROM edges ORDER BY src, dst, edge_type")).mappings().all()
        return [Edge(src=r["src"], dst=r["dst"], edge_type=r["edge_type"], confidence=round(float(r["confidence"]), 6),
                     first_seen=r["first_seen"], last_seen=r["last_seen"], count=r["count"],
                     source_event_ids=list(r["source_event_ids"])) for r in rows]

    def list_fraud_seeds(self) -> set[str]:
        with session.transaction() as c:
            return set(c.execute(text("SELECT entity_id FROM entities WHERE fraud_seed")).scalars().all())

    def set_fraud_seeds(self, entity_ids: list[str], value: bool = True) -> None:
        if not entity_ids:
            return
        with session.transaction() as c:
            c.execute(text("INSERT INTO entities (entity_id, kind, fraud_seed) "
                           "SELECT t, split_part(t, ':', 1), :v FROM unnest(CAST(:t AS text[])) AS t "
                           "ON CONFLICT (entity_id) DO UPDATE SET fraud_seed = EXCLUDED.fraud_seed, updated_at = now()"),
                      {"t": sorted(set(entity_ids)), "v": value})

    # ------------------------------------------------------------ cases, evidence, decisions
    def find_open_cases(self, entity_ids: list[str], since: datetime) -> list[Case]:
        if not entity_ids:
            return []
        with session.transaction() as c:
            rows = c.execute(text(
                "SELECT c.data FROM cases c WHERE c.status IN ('OPEN','INVESTIGATING') AND c.last_event_ts >= :since "
                "AND EXISTS (SELECT 1 FROM case_entities ce WHERE ce.case_id = c.case_id AND ce.entity_id = ANY(string_to_array(:ids, ','))) "
                "ORDER BY c.case_id"), {"since": since, "ids": _csv(entity_ids)}).scalars().all()
        return [Case.model_validate(d) for d in rows]

    def get_case(self, case_id: str) -> Case | None:
        with session.transaction() as c:
            data = c.execute(text("SELECT data FROM cases WHERE case_id = :id"), {"id": case_id}).scalar()
        return Case.model_validate(data) if data is not None else None

    def list_cases(self) -> list[Case]:
        with session.transaction() as c:
            rows = c.execute(text("SELECT data FROM cases ORDER BY updated_at DESC, case_id")).scalars().all()
        return [Case.model_validate(d) for d in rows]

    def save_case(self, case: Case) -> None:
        with session.transaction() as c:
            c.execute(text(
                "INSERT INTO cases (case_id, status, band, p_attack, customer, last_event_ts, updated_at, data) "
                "VALUES (:id, :st, :band, :p, :cust, :last, :upd, CAST(:data AS jsonb)) "
                "ON CONFLICT (case_id) DO UPDATE SET status = EXCLUDED.status, band = EXCLUDED.band, "
                "p_attack = EXCLUDED.p_attack, customer = EXCLUDED.customer, last_event_ts = EXCLUDED.last_event_ts, "
                "updated_at = EXCLUDED.updated_at, data = EXCLUDED.data"),
                {"id": case.case_id, "st": case.status, "band": case.band, "p": case.p_attack, "cust": case.customer,
                 "last": case.last_event_ts, "upd": case.updated_at, "data": _j(case)})
            c.execute(text(                                             # one statement: drop stale entities, add new ones
                "WITH del AS (DELETE FROM case_entities WHERE case_id = :id AND NOT (entity_id = ANY(string_to_array(:t, ',')))) "
                "INSERT INTO case_entities (case_id, entity_id) SELECT :id, t FROM unnest(string_to_array(:t, ',')) AS t "
                "ON CONFLICT DO NOTHING"), {"id": case.case_id, "t": _csv(set(case.entities))})

    def merge_cases(self, keep_id: str, drop_id: str) -> None:
        with session.transaction() as c:
            self._flush_evidence(c)
            c.execute(text("UPDATE evidence SET case_id = :keep WHERE case_id = :drop"), {"keep": keep_id, "drop": drop_id})
            c.execute(text("UPDATE decisions SET case_id = :keep, data = jsonb_set(data, '{case_id}', to_jsonb(CAST(:keep AS text))) "
                           "WHERE case_id = :drop"), {"keep": keep_id, "drop": drop_id})
            # API-side rows that name the case: feedback has a foreign key (an INCONCLUSIVE verdict leaves the case open,
            # so it can be merged later, and the DELETE below would fail); the others would silently become orphans.
            for table in ("feedback", "step_up_challenges", "payment_outcomes", "replays"):
                c.execute(text(f"UPDATE {table} SET case_id = :keep WHERE case_id = :drop"), {"keep": keep_id, "drop": drop_id})
            c.execute(text("DELETE FROM cases WHERE case_id = :drop"), {"drop": drop_id})

    def save_evidence(self, ev: Evidence, case_id: str) -> None:
        params = {"id": ev.evidence_id, "case": case_id, "evt": ev.event_id, "det": ev.detector, "ts": ev.ts, "data": _j(ev)}
        buf = _pending_evidence.get()
        if buf is not None:                                      # inside store.transaction(): written at commit
            buf[ev.evidence_id] = params
            return
        with session.transaction() as c:
            c.execute(_EVIDENCE_UPSERT, params)

    def list_evidence(self, case_id: str) -> list[Evidence]:
        with session.transaction() as c:
            self._flush_evidence(c)
            rows = c.execute(text("SELECT data FROM evidence WHERE case_id = :id ORDER BY ts, evidence_id"),
                             {"id": case_id}).scalars().all()
        return [Evidence.model_validate(d) for d in rows]

    def save_decision(self, d: Decision) -> None:
        with session.transaction() as c:
            c.execute(text(
                "INSERT INTO decisions (decision_id, case_id, trigger_event_id, created_at, data) "
                "VALUES (:id, :case, :trig, :at, CAST(:data AS jsonb)) "
                "ON CONFLICT (decision_id) DO UPDATE SET case_id = EXCLUDED.case_id, data = EXCLUDED.data"),
                {"id": d.decision_id, "case": d.case_id, "trig": d.trigger_event_id, "at": d.created_at, "data": _j(d)})

    def list_decisions(self, case_id: str) -> list[Decision]:
        with session.transaction() as c:
            rows = c.execute(text("SELECT data FROM decisions WHERE case_id = :id ORDER BY created_at, decision_id"),
                             {"id": case_id}).scalars().all()
        return [Decision.model_validate(d) for d in rows]

    # ------------------------------------------------------------ learning, labels, replays, audit
    def get_reliability(self) -> dict[str, tuple[float, float]]:
        """The engine reads this on every event; it only changes through add_reliability (feedback) or a reset."""
        if self._reliability is None:
            with session.transaction() as c:
                rows = c.execute(text("SELECT detector, alpha, beta FROM detector_reliability")).all()
            self._reliability = {d: (float(a), float(b)) for d, a, b in rows}
        return dict(self._reliability)

    def add_reliability(self, detector: str, d_alpha: float, d_beta: float) -> None:
        a0, b0 = RELIABILITY_SEED.get(detector, (1.0, 1.0))
        with session.transaction() as c:
            c.execute(text("INSERT INTO detector_reliability (detector, alpha, beta) VALUES (:d, :a, :b) "
                           "ON CONFLICT (detector) DO NOTHING"), {"d": detector, "a": a0, "b": b0})
            c.execute(text("UPDATE detector_reliability SET alpha = alpha + :da, beta = beta + :db, updated_at = now() "
                           "WHERE detector = :d"), {"d": detector, "da": d_alpha, "db": d_beta})
        self._reliability = None

    def get_labels(self) -> dict[str, Label]:
        with session.transaction() as c:
            rows = c.execute(text("SELECT event_id, scenario, is_attack, attack_id FROM labels")).mappings().all()
        return {r["event_id"]: Label(**r) for r in rows}

    def save_labels(self, labels: list[Label]) -> None:
        """Not part of the Store protocol: used by scripts/load.py."""
        if not labels:
            return
        with session.transaction() as c:
            c.execute(text("INSERT INTO labels (event_id, scenario, is_attack, attack_id) VALUES (:e, :s, :a, :id) "
                           "ON CONFLICT (event_id) DO NOTHING"),
                      [{"e": lb.event_id, "s": lb.scenario, "a": lb.is_attack, "id": lb.attack_id} for lb in labels])

    def save_replay(self, r: ReplayResult) -> None:
        with session.transaction() as c:
            c.execute(text("INSERT INTO replays (replay_id, case_id, data) VALUES (:id, :case, CAST(:data AS jsonb)) "
                           "ON CONFLICT (replay_id) DO UPDATE SET data = EXCLUDED.data"),
                      {"id": r.replay_id, "case": r.case_id, "data": _j(r)})

    def append_audit(self, actor: str, action: str, object_id: str, details: dict) -> None:
        with session.transaction() as c:
            audit.append_audit(c, actor, action, object_id, details)
