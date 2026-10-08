"""Time-windowed state for the §10.3 features: small per-key histories pruned by event time (never the wall clock)."""
from __future__ import annotations

from collections import deque
from collections.abc import Hashable
from datetime import datetime, timedelta
from typing import Any


class Window:
    """(ts, value) items for one key, oldest first, keeping only the last `span` of event time."""

    __slots__ = ("items", "span")

    def __init__(self, span: timedelta) -> None:
        self.span = span
        self.items: deque[tuple[datetime, Any]] = deque()

    def add(self, ts: datetime, value: Any = None) -> None:
        self.items.append((ts, value))

    def prune(self, now: datetime) -> None:
        cutoff = now - self.span
        while self.items and self.items[0][0] < cutoff:
            self.items.popleft()

    def since(self, now: datetime, span: timedelta) -> list[Any]:
        """Values with ts in [now − span, now] (span may be shorter than the window's own)."""
        cutoff = now - span
        return [v for ts, v in self.items if cutoff <= ts <= now]


class Windows:
    """A dict of Windows keyed by anything hashable, all with the same span."""

    def __init__(self, span: timedelta) -> None:
        self.span = span
        self._w: dict[Hashable, Window] = {}

    def get(self, key: Hashable, now: datetime) -> Window | None:
        w = self._w.get(key)
        if w is not None:
            w.prune(now)
        return w

    def add(self, key: Hashable, ts: datetime, value: Any = None) -> None:
        w = self._w.get(key)
        if w is None:
            w = self._w[key] = Window(self.span)
        w.prune(ts)
        w.add(ts, value)

    def values(self, key: Hashable, now: datetime, span: timedelta | None = None) -> list[Any]:
        w = self.get(key, now)
        return [] if w is None else w.since(now, span or self.span)

    def clear(self) -> None:
        self._w.clear()
