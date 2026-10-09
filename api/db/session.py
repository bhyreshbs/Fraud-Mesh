"""SQLAlchemy engines + a context variable holding the current connection, so PgStore.transaction() nests (PRD §15.1).

get_engine()   — what the API and PgStore use. Every new connection runs SET ROLE fm_app (migration 0002_roles) when
                 that role exists, so application code has INSERT + SELECT only on audit_log.
admin_engine() — the login role, for migrations-adjacent admin work (demo reset, tests). Never used by request handlers.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from sqlalchemy import Connection, Engine, create_engine, event, text

from engine.common.settings import settings

APP_ROLE = "fm_app"
_engine: Engine | None = None
_admin: Engine | None = None
_current: ContextVar[Connection | None] = ContextVar("fm_current_connection", default=None)


def _use_app_role(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    try:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (APP_ROLE,))
        if cur.fetchone():
            cur.execute(f"SET ROLE {APP_ROLE}")
    finally:
        cur.close()
    dbapi_conn.commit()                      # keep the session-level SET ROLE past SQLAlchemy's reset-on-return


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        # no pool_pre_ping: it costs a round trip per checkout (per event); recycle instead, and SQLAlchemy discards
        # connections that fail with a disconnect error.
        _engine = create_engine(settings.database_url, pool_recycle=1800, pool_size=10, max_overflow=10)
        event.listen(_engine, "connect", _use_app_role)
    return _engine


def admin_engine() -> Engine:
    global _admin
    if _admin is None:
        _admin = create_engine(settings.database_url, pool_pre_ping=True, pool_size=2, max_overflow=2)
    return _admin


@contextmanager
def transaction() -> Iterator[Connection]:
    """Open one transaction; any transaction() inside it (same thread/task) reuses the same connection."""
    conn = _current.get()
    if conn is not None:
        yield conn
        return
    with get_engine().begin() as conn:
        token = _current.set(conn)
        try:
            yield conn
        finally:
            _current.reset(token)


def db_ok() -> bool:
    try:
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
