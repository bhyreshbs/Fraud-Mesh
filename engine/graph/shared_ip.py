"""Shared-IP classifier (v3 phase 4.1): which ip tokens are currently too diverse to be a strong joining key.

Carrier-grade NAT, offices, campuses and public Wi-Fi put many unrelated customers behind one address. cgnat.txt
lists known carrier ranges statically; this classifier finds the rest from traffic. Per ip token it keeps, for the
last `window_hours` of EVENT time (never the wall clock), the distinct devices, accounts (non-failed events only),
sessions and client profiles (platform | webgl_renderer, standing in for the user agent, which StoredEvent does not
keep). The ip is shared while any count reaches its threshold (engine/detectors/rules/shared_ip.yaml).

Effects (wired in engine/graph/store.py, kept small on purpose):
  - a CONNECTED_VIA edge created while the ip is shared gets confidence 0.0, like a CGNAT ip;
  - EntityGraph.is_excluded(ip) is true while the ip is shared, so it neither joins cases nor is walked.
Older 0.5 edges stay in the graph, but an excluded node is never walked, so they link nobody either. When the
diversity expires out of the window the ip is a normal joining key again. Shared IPs never block: they only stop
linking strangers, and detectors may report them as context.

Memory is bounded: at most max_ips ips (least recently seen dropped) and max_values_per_dim values per dimension.
After a restart (EntityGraph.load) device diversity is re-seeded from CONNECTED_VIA edges' last_seen; account,
session and profile diversity rebuild from new traffic.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path

import yaml

from engine.contracts import Edge, StoredEvent

CONFIG_FILE = Path(__file__).resolve().parents[1] / "detectors" / "rules" / "shared_ip.yaml"
DIMS = ("devices", "accounts", "sessions", "profiles")


@dataclass(frozen=True)
class SharedIpConfig:
    window_hours: float = 24
    min_devices: int = 8
    min_accounts: int = 6
    min_sessions: int = 20
    min_client_profiles: int = 8
    max_ips: int = 100_000
    max_values_per_dim: int = 256

    @property
    def window(self) -> timedelta:
        return timedelta(hours=self.window_hours)

    def threshold(self, dim: str) -> int:
        return {"devices": self.min_devices, "accounts": self.min_accounts, "sessions": self.min_sessions,
                "profiles": self.min_client_profiles}[dim]


@lru_cache(maxsize=4)
def load_shared_ip_config(path: str | Path = CONFIG_FILE) -> SharedIpConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return SharedIpConfig(**{k: raw[k] for k in SharedIpConfig.__dataclass_fields__ if k in raw})


class _IpState:
    __slots__ = ("seen", "checked_at", "shared")

    def __init__(self) -> None:
        self.seen: dict[str, OrderedDict[str, datetime]] = {d: OrderedDict() for d in DIMS}
        self.checked_at: datetime | None = None
        self.shared = False


class SharedIpClassifier:
    def __init__(self, config: SharedIpConfig | None = None) -> None:
        self.cfg = load_shared_ip_config() if config is None else config
        self._ips: OrderedDict[str, _IpState] = OrderedDict()
        self.now: datetime | None = None                # latest event time observed (the classifier's clock)

    def reset(self) -> None:
        self._ips.clear()
        self.now = None

    def __len__(self) -> int:
        return len(self._ips)

    # ------------------------------------------------------------------ observing
    def _advance(self, ts: datetime) -> None:
        if self.now is None or ts > self.now:
            self.now = ts

    def _state(self, ip: str) -> _IpState:
        st = self._ips.get(ip)
        if st is None:
            st = self._ips[ip] = _IpState()
            while len(self._ips) > self.cfg.max_ips:
                self._ips.popitem(last=False)
        else:
            self._ips.move_to_end(ip)
        return st

    def _add(self, st: _IpState, dim: str, value: str | None, ts: datetime) -> None:
        if not value:
            return
        d = st.seen[dim]
        if value in d:
            if ts <= d[value]:
                return
            d.move_to_end(value)
        d[value] = ts
        while len(d) > self.cfg.max_values_per_dim:
            d.popitem(last=False)
        st.checked_at = None

    @staticmethod
    def _profile(ev: StoredEvent) -> str | None:
        if not ev.platform and not ev.webgl_renderer:
            return None
        return f"{ev.platform or ''}|{ev.webgl_renderer or ''}"

    def observe(self, ev: StoredEvent) -> None:
        self._advance(ev.occurred_at)
        if not ev.ip:
            return
        st = self._state(ev.ip)
        ts = ev.occurred_at
        self._add(st, "devices", ev.device, ts)
        failed_login = ev.event_type == "login" and ev.payload.get("result") == "failure"
        if not failed_login:
            self._add(st, "accounts", ev.account, ts)
        self._add(st, "sessions", ev.session, ts)
        self._add(st, "profiles", self._profile(ev), ts)

    def seed_from_edges(self, edges: Iterable[Edge]) -> None:
        """Restart: device diversity from CONNECTED_VIA (dev -> ip) edges, at their last_seen."""
        for e in edges:
            if e.edge_type != "CONNECTED_VIA" or not e.dst.startswith("ip:"):
                continue
            self._advance(e.last_seen)
            self._add(self._state(e.dst), "devices", e.src, e.last_seen)

    # ------------------------------------------------------------------ queries
    def counts(self, ip: str | None) -> dict[str, int]:
        """Distinct values per dimension inside the window ending at the classifier's clock."""
        st = self._ips.get(ip) if ip else None
        if st is None or self.now is None:
            return dict.fromkeys(DIMS, 0)
        cutoff = self.now - self.cfg.window
        out = {}
        for dim in DIMS:
            d = st.seen[dim]
            while d and next(iter(d.values())) < cutoff:          # oldest first (insertion = recency order)
                d.popitem(last=False)
            out[dim] = len(d)
        return out

    def is_shared(self, ip: str | None) -> bool:
        if not ip or not ip.startswith("ip:"):
            return False
        st = self._ips.get(ip)
        if st is None:
            return False
        if st.checked_at != self.now:
            c = self.counts(ip)
            st.shared = any(c[d] >= self.cfg.threshold(d) for d in DIMS)
            st.checked_at = self.now
        return st.shared

    def weak_ips(self, ev: StoredEvent) -> frozenset[str]:
        """The event's ip when it is shared right now (for the CONNECTED_VIA confidence), else empty."""
        return frozenset({ev.ip}) if ev.ip and self.is_shared(ev.ip) else frozenset()

    def describe(self, ip: str | None) -> str:
        c = self.counts(ip)
        return (f"{c['devices']} devices, {c['accounts']} accounts, {c['sessions']} sessions, "
                f"{c['profiles']} client profiles on this ip in {self.cfg.window_hours:g} h")
