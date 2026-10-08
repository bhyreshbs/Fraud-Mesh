"""Hash-chained audit log (PRD §8): row_hash = sha256(prev_hash || canonical_json(actor, action, object_id, details, ts))."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import Connection, text

GENESIS = "0" * 64
_LOCK_KEY = 0x464D4155  # serialises appends even while the table is still empty


def canonical_json(actor: str, action: str, object_id: str, details: dict, ts: datetime) -> str:
    return json.dumps({"actor": actor, "action": action, "object_id": object_id, "details": details,
                       "ts": ts.astimezone(UTC).isoformat()},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def row_hash(prev_hash: str, actor: str, action: str, object_id: str, details: dict, ts: datetime) -> str:
    return hashlib.sha256((prev_hash + canonical_json(actor, action, object_id, details, ts)).encode()).hexdigest()


def append_audit(conn: Connection, actor: str, action: str, object_id: str, details: dict) -> None:
    """Must run inside a transaction; locks the chain head so the chain stays linear."""
    conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_KEY})
    prev = conn.execute(text("SELECT row_hash FROM audit_log ORDER BY seq DESC LIMIT 1 FOR UPDATE")).scalar() or GENESIS
    ts = datetime.now(UTC)
    details = json.loads(json.dumps(details, default=str))     # exactly what jsonb hands back on verify
    h = row_hash(prev, actor, action, object_id, details, ts)
    conn.execute(text("INSERT INTO audit_log (ts, actor, action, object_id, details, prev_hash, row_hash) "
                      "VALUES (:ts, :actor, :action, :oid, CAST(:details AS jsonb), :prev, :h)"),
                 {"ts": ts, "actor": actor, "action": action, "oid": object_id,
                  "details": json.dumps(details), "prev": prev, "h": h})
