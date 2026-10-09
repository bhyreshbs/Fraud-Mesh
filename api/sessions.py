"""Server-side sessions and rotating refresh tokens (v3 phase 6.3; tables in migration 0004_auth_sessions).

A sign-in creates one session (a refresh-token family). The refresh token is 256 bits from secrets.token_urlsafe and is
stored only as its SHA-256; the access token (15 min, api/security.py) carries the session id as `sid`, and every
authenticated request checks that the session is still live (cached for FM_SESSION_CHECK_TTL_S, default 5 s;
revocation in this process clears the cache entry at once).

refresh(token)            single use: the presented token is marked used and a new one is issued in the same
                          transaction (row lock, so two concurrent refreshes cannot both win).
reuse detection           a used token presented again more than REUSE_GRACE_S after its rotation revokes the whole
                          session (both the thief's and the user's copies stop working) and writes a
                          SESSION_REUSE_DETECTED audit row. Inside the grace window (two tabs racing on one cookie)
                          it is just refused, without revoking: the racing request gets nothing an attacker could use.
privilege change          if the user's role or queues changed since the session was issued, refresh revokes the
                          session and issues a NEW session (new sid), so access tokens carrying the old role die now.
                          on_privilege_change(user_id) revokes all of a user's sessions immediately (call it from any
                          code that changes a user's role or queues).
expiry                    idle: REFRESH_TTL_S (8 h) since the last refresh; absolute: FM_SESSION_MAX_AGE_S (24 h)
                          since sign-in, whatever happens.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from api import audit
from api.db import session as db

REFRESH_TTL_S = 8 * 3600                 # idle timeout (unchanged from the in-memory store it replaces)
REUSE_GRACE_S = 10
SYSTEM_ACTOR = "system:sessions"


def max_age_s() -> int:
    return int(os.getenv("FM_SESSION_MAX_AGE_S", str(24 * 3600)))


def check_ttl_s() -> float:
    return float(os.getenv("FM_SESSION_CHECK_TTL_S", "5"))


class SessionError(Exception):
    """reason: missing | expired | revoked | reused | superseded | user_gone"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Issued:
    session_id: str
    user_id: str
    role: str
    queues: tuple[str, ...]
    refresh_token: str
    cookie_max_age: int


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _new_sid() -> str:
    return "ses_" + secrets.token_hex(16)


def _now() -> datetime:
    return datetime.now(UTC)


# ------------------------------------------------------------------ liveness cache (the per-request sid check)
_cache: dict[str, tuple[bool, float]] = {}
_cache_lock = threading.Lock()
_CACHE_MAX = 10_000


def _forget(*sids: str) -> None:
    with _cache_lock:
        for s in sids:
            _cache.pop(s, None)


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def is_active(sid: str | None) -> bool:
    if not sid:
        return False
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(sid)
    if hit is not None and now - hit[1] < check_ttl_s():
        return hit[0]
    with db.transaction() as c:
        active = c.execute(text("SELECT 1 FROM auth_sessions WHERE session_id = :s AND revoked_at IS NULL "
                                "AND expires_at > now()"), {"s": sid}).first() is not None
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            _cache.clear()
        _cache[sid] = (active, now)
    return active


# ------------------------------------------------------------------ create / rotate / revoke
def _insert_token(c, sid: str, now: datetime, expires_at: datetime) -> tuple[str, int]:
    token = secrets.token_urlsafe(32)
    idle_exp = min(now + timedelta(seconds=REFRESH_TTL_S), expires_at)
    c.execute(text("INSERT INTO auth_refresh_tokens (token_hash, session_id, created_at, expires_at) "
                   "VALUES (:h, :s, :now, :exp)"), {"h": token_hash(token), "s": sid, "now": now, "exp": idle_exp})
    c.execute(text("UPDATE auth_sessions SET last_used_at = :now, idle_expires_at = :exp WHERE session_id = :s"),
              {"now": now, "exp": idle_exp, "s": sid})
    return token, max(1, int((idle_exp - now).total_seconds()))


def create_session(user_id: str, role: str, queues: tuple[str, ...] | list[str], *, user_agent: str | None = None,
                   provider: str = "local", rotated_from: str | None = None) -> Issued:
    now = _now()
    sid = _new_sid()
    expires_at = now + timedelta(seconds=max_age_s())
    with db.transaction() as c:
        c.execute(text("INSERT INTO auth_sessions (session_id, user_id, role, queues, provider, user_agent, created_at, "
                       "last_used_at, idle_expires_at, expires_at, rotated_from) "
                       "VALUES (:s, :u, :r, :q, :p, :ua, :now, :now, :now, :exp, :rf)"),
                  {"s": sid, "u": user_id, "r": role, "q": list(queues), "p": provider,
                   "ua": (user_agent or "")[:256] or None, "now": now, "exp": expires_at, "rf": rotated_from})
        token, max_age = _insert_token(c, sid, now, expires_at)
        c.execute(text("DELETE FROM auth_sessions WHERE expires_at < :cut"), {"cut": now - timedelta(days=1)})   # prune
    return Issued(sid, user_id, role, tuple(queues), token, max_age)


def _revoke(c, sid: str, reason: str) -> bool:
    n = c.execute(text("UPDATE auth_sessions SET revoked_at = now(), revoked_reason = :r "
                       "WHERE session_id = :s AND revoked_at IS NULL"), {"s": sid, "r": reason}).rowcount
    return n > 0


def refresh(token: str) -> Issued:
    """Rotate a refresh token. Raises SessionError; the caller turns every reason into the same 401."""
    if not token or len(token) > 256:
        raise SessionError("missing")
    now = _now()
    outcome, issued = "", None
    with db.transaction() as c:
        row = c.execute(text(
            "SELECT t.token_hash, t.expires_at AS token_exp, t.used_at, s.session_id, s.user_id, s.role, s.queues, "
            "       s.provider, s.user_agent, s.expires_at, s.revoked_at, u.role AS user_role, u.queues AS user_queues "
            "FROM auth_refresh_tokens t JOIN auth_sessions s ON s.session_id = t.session_id "
            "LEFT JOIN users u ON u.user_id = s.user_id "
            "WHERE t.token_hash = :h FOR UPDATE OF t, s"), {"h": token_hash(token)}).mappings().first()
        if row is None:
            raise SessionError("missing")
        sid = row["session_id"]
        if row["revoked_at"] is not None:
            raise SessionError("revoked")
        if row["used_at"] is not None:
            if now - row["used_at"] <= timedelta(seconds=REUSE_GRACE_S):
                raise SessionError("superseded")          # a racing request with the same cookie: nothing revoked
            _revoke(c, sid, "refresh_token_reuse")        # committed below, then refused
            audit.append_audit(c, SYSTEM_ACTOR, "SESSION_REUSE_DETECTED", row["user_id"],
                               {"session_id": sid, "action": "session revoked"})
            outcome = "reused"
        elif row["expires_at"] <= now or row["token_exp"] <= now:
            raise SessionError("expired")
        elif row["user_role"] is None:
            _revoke(c, sid, "user_gone")
            outcome = "user_gone"
        else:
            c.execute(text("UPDATE auth_refresh_tokens SET used_at = :now WHERE token_hash = :h"),
                      {"now": now, "h": row["token_hash"]})
            if row["user_role"] != row["role"] or list(row["user_queues"]) != list(row["queues"]):
                _revoke(c, sid, "privilege_change")
                audit.append_audit(c, SYSTEM_ACTOR, "SESSION_ROTATED", row["user_id"],
                                   {"old_session_id": sid, "reason": "privilege_change", "role": row["user_role"]})
                outcome = "rotate"
            else:
                token_new, max_age = _insert_token(c, sid, now, row["expires_at"])
                issued = Issued(sid, row["user_id"], row["role"], tuple(row["queues"]), token_new, max_age)
                outcome = "ok"
    if outcome in ("reused", "user_gone"):
        _forget(sid)
        raise SessionError(outcome)
    if outcome == "rotate":                               # privilege change: a brand-new session (new sid)
        _forget(sid)
        return create_session(row["user_id"], row["user_role"], tuple(row["user_queues"]), user_agent=row["user_agent"],
                              provider=row["provider"], rotated_from=sid)
    assert issued is not None
    return issued


def session_of_refresh(token: str | None) -> str | None:
    if not token or len(token) > 256:
        return None
    with db.transaction() as c:
        return c.execute(text("SELECT session_id FROM auth_refresh_tokens WHERE token_hash = :h"),
                         {"h": token_hash(token)}).scalar()


def revoke_session(sid: str | None, reason: str) -> bool:
    if not sid:
        return False
    with db.transaction() as c:
        done = _revoke(c, sid, reason)
    _forget(sid)
    return done


def revoke_all_for_user(user_id: str, reason: str, actor: str | None = None) -> int:
    """Every live session of the user (all devices). Audited as SESSIONS_REVOKED."""
    with db.transaction() as c:
        sids = list(c.execute(text("UPDATE auth_sessions SET revoked_at = now(), revoked_reason = :r "
                                   "WHERE user_id = :u AND revoked_at IS NULL RETURNING session_id"),
                              {"u": user_id, "r": reason}).scalars())
        audit.append_audit(c, actor or SYSTEM_ACTOR, "SESSIONS_REVOKED", user_id, {"reason": reason, "count": len(sids)})
    _forget(*sids)
    return len(sids)


def on_privilege_change(user_id: str, actor: str | None = None) -> int:
    """Call after a user's role or queues change: their tokens must not keep the old privileges for up to 15 min."""
    return revoke_all_for_user(user_id, "privilege_change", actor)


def list_active(user_id: str) -> list[dict]:
    with db.transaction() as c:
        rows = c.execute(text("SELECT session_id, provider, user_agent, created_at, last_used_at, idle_expires_at, expires_at "
                              "FROM auth_sessions WHERE user_id = :u AND revoked_at IS NULL AND expires_at > now() "
                              "ORDER BY created_at DESC"), {"u": user_id}).mappings().all()
    return [dict(r) for r in rows]
