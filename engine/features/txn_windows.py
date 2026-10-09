"""Event-time rolling transfer features per customer + payee (v3 core 3.2b), for the STRUCTURING rule path.

These are rule-side features: they are NOT in TXN_FEATURES, so the trained txn model's input is unchanged. They are
added to the feature dict by FeatureWindows (engine/features/features.py) under the names in TXN_WINDOW_FEATURES.

Key      (who, payee) where who = the customer token, else the account token. Tokens carry their kind prefix
         ("cust:…", "acct:…"), so a customer and an unrelated account can never share a key, and two customers
         paying one payee are never merged.
Window   [t − window_h, t] in EVENT time, both ends inclusive (a transfer exactly 24 h earlier still counts);
         "including this one" for the current transaction, like the PRD §10.3 near_limit_count_24h.
Dedupe   by event_id: a re-delivered event is neither stored twice nor counted twice (its own stored copy is
         replaced by the current one in compute()).
Late     an out-of-order event is inserted at its event-time position, and its own features are computed from the
         transfers inside ITS window (later transfers are not counted). Items are kept for window_h + late_tolerance_h
         behind the newest event time seen, so an event up to late_tolerance_h late still sees its full window.
Near-limit  amount in [near_fraction · L, L) for any L in limits_paise (PRD §10.3: 0.95 and ₹1L / ₹2L / ₹5L).

  tw_pair_count_24h                  transfers customer → payee in the window, including this one
  tw_pair_sum_24h_paise              their total amount, including this one
  tw_pair_count_1h                   velocity: transfers in the last velocity_window_h, including this one
  tw_near_limit_count_24h            near-limit transfers in the window, including this one
  tw_near_limit_sum_24h_paise        their total amount
  tw_near_limit_same_limit_max_24h   the most near-limit transfers under ONE limit L (repeated near-threshold)
  tw_near_limit_limit_paise          that L (0 if none)
  tw_near_limit_rate_per_h           near-limit transfers per hour between the first one in the window and now
                                     (span floored at 1 h)
"""
from __future__ import annotations

from bisect import insort
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from engine.contracts import StoredEvent
from engine.fusion.v3_core import load_v3_core

TXN_WINDOW_FEATURES = ["tw_pair_count_24h", "tw_pair_sum_24h_paise", "tw_pair_count_1h", "tw_near_limit_count_24h",
                       "tw_near_limit_sum_24h_paise", "tw_near_limit_same_limit_max_24h", "tw_near_limit_limit_paise",
                       "tw_near_limit_rate_per_h"]


def near_limit_of(amount: int, limits: Sequence[int], fraction: float) -> int | None:
    """The smallest limit L with fraction·L <= amount < L, or None."""
    return next((lim for lim in sorted(limits) if fraction * lim <= amount < lim), None)


class TxnWindows:
    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        c = load_v3_core()["structuring"] if cfg is None else cfg
        self.limits = tuple(int(x) for x in c["limits_paise"])
        self.fraction = float(c["near_fraction"])
        self.window = timedelta(hours=float(c["window_h"]))
        self.velocity = timedelta(hours=float(c["velocity_window_h"]))
        self.keep = self.window + timedelta(hours=float(c["late_tolerance_h"]))
        self.reset()

    def reset(self) -> None:
        self._pairs: dict[tuple[str, str], list[tuple[datetime, str, int]]] = {}   # sorted by (ts, event_id)
        self._seen: dict[str, tuple[tuple[str, str], datetime]] = {}                # event_id -> (key, ts)
        self._newest: datetime | None = None

    @staticmethod
    def key(ev: StoredEvent) -> tuple[str, str] | None:
        who = ev.customer or ev.account
        payee = ev.payload.get("payee_account") if ev.event_type == "transaction" else None
        return (who, payee) if who and payee else None

    def compute(self, ev: StoredEvent) -> dict[str, float]:
        f = dict.fromkeys(TXN_WINDOW_FEATURES, 0.0)
        k = self.key(ev)
        if k is None:
            return f
        now, amount = ev.occurred_at, int(ev.payload["amount_paise"])
        items = [(ts, a) for ts, eid, a in self._pairs.get(k, ()) if now - self.window <= ts <= now and eid != ev.event_id]
        items.append((now, amount))
        near = [(ts, a, lim) for ts, a in items if (lim := near_limit_of(a, self.limits, self.fraction)) is not None]
        f["tw_pair_count_24h"] = float(len(items))
        f["tw_pair_sum_24h_paise"] = float(sum(a for _, a in items))
        f["tw_pair_count_1h"] = float(sum(1 for ts, _ in items if ts >= now - self.velocity))
        f["tw_near_limit_count_24h"] = float(len(near))
        f["tw_near_limit_sum_24h_paise"] = float(sum(a for _, a, _ in near))
        if near:
            per_limit: dict[int, int] = {}
            for _, _, lim in near:
                per_limit[lim] = per_limit.get(lim, 0) + 1
            best = max(sorted(per_limit), key=lambda lim: per_limit[lim])
            f["tw_near_limit_same_limit_max_24h"] = float(per_limit[best])
            f["tw_near_limit_limit_paise"] = float(best)
            span_h = max(1.0, (now - min(ts for ts, _, _ in near)).total_seconds() / 3600)
            f["tw_near_limit_rate_per_h"] = len(near) / span_h
        return f

    def update(self, ev: StoredEvent) -> None:
        k = self.key(ev)
        if k is None or ev.event_id in self._seen:
            return
        ts = ev.occurred_at
        insort(self._pairs.setdefault(k, []), (ts, ev.event_id, int(ev.payload["amount_paise"])))
        self._seen[ev.event_id] = (k, ts)
        if self._newest is None or ts > self._newest:
            self._newest = ts
        self._prune(k)

    def _prune(self, k: tuple[str, str]) -> None:
        """Drop this key's items older than newest − (window + late tolerance); forget their event ids."""
        cutoff = self._newest - self.keep
        items = self._pairs[k]
        drop = 0
        while drop < len(items) and items[drop][0] < cutoff:
            self._seen.pop(items[drop][1], None)
            drop += 1
        if drop:
            del items[:drop]
        if not items:
            del self._pairs[k]
