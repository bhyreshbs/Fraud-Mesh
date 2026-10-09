"""Identity windows for distributed credential stuffing (v3 phase 4.2). Plugged into FeatureWindows.

Same contract as engine/features/features.py: compute(ev) reads state built from EARLIER events only (plus "including
this one" counts, as for ip_failed_customers_1h), update(ev) then adds the event. Windows are event time only.
Thresholds and p values: engine/detectors/rules/cred_stuffing.yaml. Only login events are measured.

Features (all floats; 0 for non-login events):
  acct_fail_1h               failed logins on this account in window_min (incl. this one)
  acct_fail_sources_1h       distinct ip + device tokens behind them
  acct_fail_24h, acct_fail_ips_24h, acct_max_fail_per_ip_24h   the low-and-slow view over window_h
  dev_accounts_1h            distinct accounts attempted from this device (any result, incl. this one)
  dev_fail_1h                failed logins from this device (incl. this one)
  global_fail_10m            failed logins across all accounts in global window_min (incl. this one)
  global_fail_baseline_10m   average failures per global window over the prior baseline_h
  global_accounts_10m        distinct accounts with failures in the global window (account-targeting velocity)
  global_spike_active        1 if the global window is a spike right now
  *_flagged                  1 if that rule already fired for this key inside its window (fires once per window)
Memory is bounded: every map keeps at most max_keys keys (least recently updated dropped) and max_values_per_key
values per key; the global counter keeps one bucket per minute.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Hashable
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from engine.contracts import StoredEvent

CONFIG_FILE = Path(__file__).resolve().parents[1] / "detectors" / "rules" / "cred_stuffing.yaml"

IDENTITY_FEATURE_NAMES = [
    "acct_fail_1h", "acct_fail_sources_1h", "acct_distributed_flagged",
    "acct_fail_24h", "acct_fail_ips_24h", "acct_max_fail_per_ip_24h", "acct_lowslow_flagged",
    "dev_accounts_1h", "dev_fail_1h", "dev_multi_flagged",
    "global_fail_10m", "global_fail_baseline_10m", "global_accounts_10m", "global_spike_active", "global_spike_flagged",
]


@lru_cache(maxsize=4)
def load_stuffing_config(path: str | Path = CONFIG_FILE) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


class BoundedWindows:
    """key -> deque[(ts, value)] pruned to `span` of event time; at most max_keys keys (LRU) and max_values each."""

    def __init__(self, span: timedelta, max_keys: int, max_values: int) -> None:
        self.span, self.max_keys, self.max_values = span, max_keys, max_values
        self._w: OrderedDict[Hashable, deque[tuple[datetime, Any]]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._w)

    def _prune(self, d: deque, now: datetime) -> None:
        cutoff = now - self.span
        while d and d[0][0] < cutoff:
            d.popleft()

    def add(self, key: Hashable, ts: datetime, value: Any = None) -> None:
        d = self._w.get(key)
        if d is None:
            d = self._w[key] = deque()
            while len(self._w) > self.max_keys:
                self._w.popitem(last=False)
        else:
            self._w.move_to_end(key)
        self._prune(d, ts)
        d.append((ts, value))
        while len(d) > self.max_values:
            d.popleft()

    def values(self, key: Hashable, now: datetime) -> list[Any]:
        d = self._w.get(key)
        if d is None:
            return []
        cutoff = now - self.span
        return [v for ts, v in d if cutoff <= ts <= now]


class _Flags:
    """key -> when a rule last fired; a rule fires again only after `span`. Bounded like BoundedWindows."""

    def __init__(self, span: timedelta, max_keys: int) -> None:
        self.span, self.max_keys = span, max_keys
        self._at: OrderedDict[Hashable, datetime] = OrderedDict()

    def active(self, key: Hashable, now: datetime) -> bool:
        t = self._at.get(key)
        return t is not None and now - t < self.span

    def set(self, key: Hashable, now: datetime) -> None:
        if self.active(key, now):
            return
        self._at[key] = now
        self._at.move_to_end(key)
        while len(self._at) > self.max_keys:
            self._at.popitem(last=False)


class _GlobalFailures:
    """Per-minute buckets of failed-login counts and targeted accounts, kept for baseline_h + window."""

    def __init__(self, window: timedelta, baseline: timedelta, max_accounts: int) -> None:
        self.window, self.baseline, self.max_accounts = window, baseline, max_accounts
        self._b: deque[list] = deque()          # [minute, count, set(accounts)]

    @staticmethod
    def _minute(ts: datetime) -> datetime:
        return ts.replace(second=0, microsecond=0)

    def add(self, ts: datetime, account: str | None) -> None:
        m = self._minute(ts)
        if self._b and self._b[-1][0] == m:
            b = self._b[-1]
        else:
            # out-of-order events land in the newest bucket at or before their minute, or a new one at the end
            b = next((x for x in reversed(self._b) if x[0] == m), None)
            if b is None:
                b = [m, 0, set()]
                if not self._b or self._b[-1][0] < m:
                    self._b.append(b)
                else:
                    self._b.append(b)
                    self._b = deque(sorted(self._b, key=lambda x: x[0]))
        b[1] += 1
        if account and len(b[2]) < self.max_accounts:
            b[2].add(account)
        cutoff = self._minute(ts) - self.baseline - self.window
        while self._b and self._b[0][0] < cutoff:
            self._b.popleft()

    def measure(self, now: datetime) -> tuple[int, float, int]:
        """(failures in the window ending now, baseline average per window, distinct accounts in the window)."""
        w_start = self._minute(now) - self.window + timedelta(minutes=1)
        b_start = w_start - self.baseline
        in_w, in_base, accts = 0, 0, set()
        for m, n, a in self._b:
            if m > self._minute(now):
                continue
            if m >= w_start:
                in_w += n
                accts |= a
            elif m >= b_start:
                in_base += n
        windows = max(1.0, self.baseline / self.window)
        return in_w, in_base / windows, len(accts)


class IdentityWindows:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.cfg = load_stuffing_config() if config is None else config
        self.reset()

    def reset(self) -> None:
        c, mem = self.cfg, self.cfg.get("memory", {})
        mk, mv = int(mem.get("max_keys", 200_000)), int(mem.get("max_values_per_key", 512))
        self.w_ad = timedelta(minutes=float(c["account_distributed"]["window_min"]))
        self.w_ls = timedelta(hours=float(c["account_low_and_slow"]["window_h"]))
        self.w_dev = timedelta(minutes=float(c["device_multi_account"]["window_min"]))
        self.w_g = timedelta(minutes=float(c["global_spike"]["window_min"]))
        self._acct_fail = BoundedWindows(max(self.w_ad, self.w_ls), mk, mv)    # acct -> (ip, device)
        self._dev_attempts = BoundedWindows(self.w_dev, mk, mv)               # device -> (acct, failed)
        self._global = _GlobalFailures(self.w_g, timedelta(hours=float(c["global_spike"]["baseline_h"])), mv)
        self._f_ad = _Flags(self.w_ad, mk)
        self._f_ls = _Flags(self.w_ls, mk)
        self._f_dev = _Flags(self.w_dev, mk)
        self._f_g = _Flags(self.w_g, 1)

    @staticmethod
    def _acct(ev: StoredEvent) -> str | None:
        return ev.account or ev.customer

    # ------------------------------------------------------------------ measuring (shared by compute and update)
    def _measure(self, ev: StoredEvent, include: bool) -> dict[str, float]:
        f = dict.fromkeys(IDENTITY_FEATURE_NAMES, 0.0)
        if ev.event_type != "login":
            return f
        now, acct, failed = ev.occurred_at, self._acct(ev), ev.payload.get("result") == "failure"
        this_fail = include and failed
        if acct:
            items = self._acct_fail.values(acct, now)
            if this_fail:
                items = items + [(ev.ip, ev.device)]
            cut_ad = now - self.w_ad
            d = self._acct_fail._w.get(acct)
            recent_n = sum(1 for ts, _ in (d or ()) if cut_ad <= ts <= now) + int(this_fail)
            recent = items[len(items) - recent_n:] if recent_n else []
            f["acct_fail_1h"] = float(recent_n)
            f["acct_fail_sources_1h"] = float(len({ip for ip, _ in recent if ip} | {dv for _, dv in recent if dv}))
            per_ip: dict[str, int] = {}
            for ip, _ in items:
                if ip:
                    per_ip[ip] = per_ip.get(ip, 0) + 1
            f["acct_fail_24h"] = float(len(items))
            f["acct_fail_ips_24h"] = float(len(per_ip))
            f["acct_max_fail_per_ip_24h"] = float(max(per_ip.values(), default=0))
            f["acct_distributed_flagged"] = float(self._f_ad.active(acct, now))
            f["acct_lowslow_flagged"] = float(self._f_ls.active(acct, now))
        if ev.device:
            att = self._dev_attempts.values(ev.device, now)
            if include:
                att = att + [(acct, failed)]
            f["dev_accounts_1h"] = float(len({a for a, _ in att if a}))
            f["dev_fail_1h"] = float(sum(1 for _, x in att if x))
            f["dev_multi_flagged"] = float(self._f_dev.active(ev.device, now))
        n, base, accts = self._global.measure(now)
        if this_fail:
            n += 1
            accts += 1 if acct else 0                       # approximate: may double count a repeat account
        g = self.cfg["global_spike"]
        f["global_fail_10m"], f["global_fail_baseline_10m"], f["global_accounts_10m"] = float(n), base, float(accts)
        f["global_spike_active"] = float(n >= float(g["min_failures"]) and n >= float(g["ratio"]) * base
                                         and accts >= float(g["min_accounts"]))
        f["global_spike_flagged"] = float(self._f_g.active("global", now))
        return f

    # ------------------------------------------------------------------ rules (thresholds; used by netsec too)
    def rule_hits(self, f: dict[str, Any]) -> dict[str, bool]:
        c = self.cfg
        ad, ls, dm = c["account_distributed"], c["account_low_and_slow"], c["device_multi_account"]
        return {
            "ACCOUNT_DISTRIBUTED_FAILURES": f.get("acct_fail_1h", 0) >= ad["min_failures"]
            and f.get("acct_fail_sources_1h", 0) >= ad["min_sources"],
            "ACCOUNT_LOW_SLOW_FAILURES": f.get("acct_fail_24h", 0) >= ls["min_failures"]
            and f.get("acct_fail_ips_24h", 0) >= ls["min_ips"] and 0 < f.get("acct_max_fail_per_ip_24h", 0) <= ls["max_per_ip"],
            "DEVICE_MULTI_ACCOUNT_FAILURES": f.get("dev_accounts_1h", 0) >= dm["min_accounts"]
            and f.get("dev_fail_1h", 0) >= dm["min_failures"],
            "GLOBAL_LOGIN_FAILURE_SPIKE": bool(f.get("global_spike_active", 0)),
        }

    # ------------------------------------------------------------------ FeatureWindows hooks
    def compute(self, ev: StoredEvent) -> dict[str, float]:
        return self._measure(ev, include=True)

    def update(self, ev: StoredEvent) -> None:
        if ev.event_type != "login":
            return
        now, acct, failed = ev.occurred_at, self._acct(ev), ev.payload.get("result") == "failure"
        if failed:
            if acct:
                self._acct_fail.add(acct, now, (ev.ip, ev.device))
            self._global.add(now, acct)
        if ev.device:
            self._dev_attempts.add(ev.device, now, (acct, failed))
        if not failed:
            return
        hits = self.rule_hits(self._measure(ev, include=False))
        if acct and hits["ACCOUNT_DISTRIBUTED_FAILURES"]:
            self._f_ad.set(acct, now)
        if acct and hits["ACCOUNT_LOW_SLOW_FAILURES"]:
            self._f_ls.set(acct, now)
        if ev.device and hits["DEVICE_MULTI_ACCOUNT_FAILURES"]:
            self._f_dev.set(ev.device, now)
        if hits["GLOBAL_LOGIN_FAILURE_SPIKE"]:
            self._f_g.set("global", now)
