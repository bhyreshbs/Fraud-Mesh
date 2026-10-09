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
          "mfa_factors", "step_up_challenges", "labels", "replays", "feedback", "detector_reliability", "audit_log"]


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


SERIAL_COLUMNS = {"audit_log": "seq", "feedback": "feedback_id"}      # RESTART IDENTITY resets these to 1


def restore_baseline() -> dict:
    """Also archives the audit rows written after the snapshot into demo_baseline.audit_archive and returns what was
    removed (count, last seq and row_hash before the restore), so the caller's DEMO_RESET_LIVE audit row records it:
    a live reset rolls the audit chain back to the snapshot, and that must not be invisible."""
    if info() is None:
        raise LookupError("no demo baseline saved")
    t0 = datetime.now()
    with admin_engine().begin() as c:
        snap_max = c.execute(text(f"SELECT coalesce(max(seq), 0) FROM {SCHEMA}.audit_log")).scalar()
        head = c.execute(text("SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1")).first()
        c.execute(text(f"CREATE TABLE IF NOT EXISTS {SCHEMA}.audit_archive AS TABLE public.audit_log WITH NO DATA"))
        removed = c.execute(text(f"INSERT INTO {SCHEMA}.audit_archive SELECT * FROM audit_log WHERE seq > :m"), {"m": snap_max}).rowcount
        c.execute(text("TRUNCATE " + ", ".join(TABLES) + " RESTART IDENTITY"))
        for t in TABLES:
            c.execute(text(f"INSERT INTO public.{t} SELECT * FROM {SCHEMA}.{t}"))
        for t, col in SERIAL_COLUMNS.items():
            c.execute(text(f"SELECT setval(pg_get_serial_sequence('{t}', '{col}'), GREATEST((SELECT max({col}) FROM {t}), 1))"))
    audit_removed = {"rows": removed, "archived_to": f"{SCHEMA}.audit_archive",
                     "last_seq_before": head.seq if head else None, "last_row_hash_before": head.row_hash if head else None}
    return {"seconds": round((datetime.now() - t0).total_seconds(), 1), "audit_removed": audit_removed, **(info() or {})}


def demo_case_ids() -> list[str]:
    """Cases that are not in the snapshot, or changed after it (the live demo), most recent first."""
    if info() is None:
        return []
    with admin_engine().connect() as c:
        return list(c.execute(text(
            f"SELECT c.case_id FROM cases c LEFT JOIN {SCHEMA}.cases b ON b.case_id = c.case_id "
            f"WHERE b.case_id IS NULL OR c.updated_at > (SELECT saved_at FROM {SCHEMA}._meta) "
            "ORDER BY c.updated_at DESC")).scalars())
