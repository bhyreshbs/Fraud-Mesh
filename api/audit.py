"""Hash-chained audit log (PRD §8, §15.4): row_hash = sha256(prev_hash || canonical_json(actor, action, object_id, details, ts)).

append_audit() serialises writers with a transaction-scoped advisory lock instead of SELECT … FOR UPDATE: the app
role has INSERT + SELECT only on audit_log (migration 0002_roles), and FOR UPDATE would need UPDATE privilege.
verify_chain() recomputes every row in seq order and reports the first row whose link or hash does not match.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import Connection, text

from api import crypto_box

GENESIS = "0" * 64
_LOCK_KEY = 0x464D4155  # serialises appends even while the table is still empty


def canonical_json(actor: str, action: str, object_id: str, details: dict, ts: datetime) -> str:
    return json.dumps({"actor": actor, "action": action, "object_id": object_id, "details": details,
                       "ts": ts.astimezone(UTC).isoformat()},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def row_hash(prev_hash: str, actor: str, action: str, object_id: str, details: dict, ts: datetime) -> str:
    return hashlib.sha256((prev_hash + canonical_json(actor, action, object_id, details, ts)).encode()).hexdigest()


def append_audit(conn: Connection, actor: str, action: str, object_id: str, details: dict) -> None:
    """Must run inside a transaction; the advisory lock keeps the chain linear across concurrent writers.
    Two statements: the lock, then one INSERT … SELECT that reads the chain head and lets Postgres compute
    sha256(prev_hash || canonical_json) — the same bytes row_hash() hashes in Python, which verify_chain() recomputes."""
    conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_KEY})
    ts = datetime.now(UTC)
    details = crypto_box.redact_audit(action, details)        # encryption on: SHA-256 of analyst free text, not the text
    details = json.loads(json.dumps(details, default=str))     # exactly what jsonb hands back on verify
    canon = canonical_json(actor, action, object_id, details, ts)
    conn.execute(text(
        "INSERT INTO audit_log (ts, actor, action, object_id, details, prev_hash, row_hash) "
        "SELECT :ts, :actor, :action, :oid, CAST(:details AS jsonb), h.prev, "
        "       encode(sha256(convert_to(h.prev || :canon, 'UTF8')), 'hex') "
        "FROM (SELECT coalesce((SELECT row_hash FROM audit_log ORDER BY seq DESC LIMIT 1), :genesis) AS prev) h"),
        {"ts": ts, "actor": actor, "action": action, "oid": object_id, "details": json.dumps(details),
         "canon": canon, "genesis": GENESIS})


def verify_chain(conn: Connection) -> tuple[bool, int, int | None]:
    """Returns (ok, rows checked, seq of the first broken row or None)."""
    prev, rows = GENESIS, 0
    result = conn.execution_options(stream_results=True, yield_per=5000).execute(text(
        "SELECT seq, ts, actor, action, object_id, details, prev_hash, row_hash FROM audit_log ORDER BY seq"))
    for r in result:
        rows += 1
        if r.prev_hash != prev or r.row_hash != row_hash(prev, r.actor, r.action, r.object_id, r.details, r.ts):
            return False, rows, r.seq
        prev = r.row_hash
    return True, rows, None
