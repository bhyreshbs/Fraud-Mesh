"""Demo baseline: a snapshot of the runtime tables kept inside Postgres (schema demo_baseline), so a live demo can be
undone in seconds instead of rebuilding 14 days of history (PRD §12.3 reset, ~9 min on a laptop).

  save_baseline()     copy every runtime table except users into demo_baseline.* (and record when)
  restore_baseline()  replace the runtime tables with the snapshot: everything that happened after the snapshot
                      (a live demo case, its events, evidence, decisions, payments, step-ups, audit rows) is gone,
                      everything before it (the background and benchmark cases) is back exactly as it was
  demo_case_ids()     cases created or updated after the snapshot: the live demo

users is never copied or restored, so signed-in sessions survive. Owner role only (the app role cannot truncate
audit_log). The caller rebuilds the in-memory Pipeline afterwards, as after a full reset.
"""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import text

from api.db.session import admin_engine

SCHEMA = "demo_baseline"
# insert order respects foreign keys (events before evidence, cases before case rows, mfa_factors before step-ups)
TABLES = ["events", "entities", "edges", "cases", "case_entities", "evidence", "decisions", "payment_outcomes",
          "mfa_factors", "step_up_challenges", "labels", "replays", "feedback", "detector_reliability", "audit_log", "payment_rail"]


def save_baseline() -> dict:
    counts = {}
    with admin_engine().begin() as c:
        c.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
        c.execute(text(f"CREATE SCHEMA {SCHEMA}"))
        for t in TABLES:
            c.execute(text(f"CREATE TABLE {SCHEMA}.{t} AS TABLE public.{t}"))
            counts[t] = c.execute(text(f"SELECT count(*) FROM {SCHEMA}.{t}")).scalar()
        c.execute(text(f"CREATE TABLE {SCHEMA}._meta (saved_at timestamptz NOT NULL, counts jsonb NOT NULL)"))
        c.execute(text(f"INSERT INTO {SCHEMA}._meta VALUES (now(), CAST(:c AS jsonb))"), {"c": json.dumps(counts)})
    return info() or {}


def info() -> dict | None:
    with admin_engine().connect() as c:
        exists = c.execute(text("SELECT 1 FROM information_schema.tables WHERE table_schema = :s AND table_name = '_meta'"),
                           {"s": SCHEMA}).scalar()
        if not exists:
            return None
        saved_at, counts = c.execute(text(f"SELECT saved_at, counts FROM {SCHEMA}._meta")).one()
    return {"saved_at": saved_at.isoformat(), "counts": counts}


def restore_baseline() -> dict:
    if info() is None:
        raise LookupError("no demo baseline saved")
    t0 = datetime.now()
    with admin_engine().begin() as c:
        c.execute(text("TRUNCATE " + ", ".join(TABLES) + " RESTART IDENTITY"))
        saved = set(c.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = :s"),
                              {"s": SCHEMA}).scalars())
        for t in TABLES:
            if t in saved:                       # a snapshot saved before a newer table (e.g. payment_rail) restores it empty
                c.execute(text(f"INSERT INTO public.{t} SELECT * FROM {SCHEMA}.{t}"))
        c.execute(text("SELECT setval(pg_get_serial_sequence('audit_log', 'seq'), GREATEST((SELECT max(seq) FROM audit_log), 1))"))
    return {"seconds": round((datetime.now() - t0).total_seconds(), 1), **(info() or {})}


def demo_case_ids() -> list[str]:
    """Cases that are not in the snapshot, or changed after it (the live demo), most recent first."""
    if info() is None:
        return []
    with admin_engine().connect() as c:
        return list(c.execute(text(
            f"SELECT c.case_id FROM cases c LEFT JOIN {SCHEMA}.cases b ON b.case_id = c.case_id "
            f"WHERE b.case_id IS NULL OR c.updated_at > (SELECT saved_at FROM {SCHEMA}._meta) "
            "ORDER BY c.updated_at DESC")).scalars())
