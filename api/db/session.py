"""SQLAlchemy engine + a context variable holding the current connection, so PgStore.transaction() nests (PRD §15.1)."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from sqlalchemy import Connection, Engine, create_engine, text

from engine.common.settings import settings

_engine: Engine | None = None
_current: ContextVar[Connection | None] = ContextVar("fm_current_connection", default=None)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=10, max_overflow=10)
    return _engine


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
