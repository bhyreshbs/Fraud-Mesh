"""Shared feature windows (PRD §10.3) — ONE module for training and serving.

`FeatureWindows.compute(event)` reads only state built from EARLIER events; `update(event)` then adds the event.
Training (ml/train_*.py) builds rows with `iter_feature_rows`, which runs the same compute-then-update sequence over
events in time order as Pipeline.process does live, so the two paths produce identical vectors
(tests/engine/test_feature_parity.py).

Feature definitions (windows are in event time; "prior" = earlier events only):
  log_amount                  ln(1 + amount_paise / 100) of this transaction
  amount_to_median_30d        amount ÷ median of the customer's prior outgoing amounts in 30 d (1.0 if none)
  txn_count_1h, txn_sum_24h_paise   the customer's prior transactions in 1 h / 24 h
  payee_is_new                1 if this customer added this payee less than 24 h ago
  minutes_since_payee_added   minutes since that payee_added (10,080 if older than 7 d or never)
  payee_fan_in_24h            distinct other senders to this payee in the prior 24 h
  payee_sum_24h_paise         the customer's prior 24 h total to this payee
  near_limit_count_24h        the customer's transfers to this payee in 24 h with amount in [0.95·L, L) for
                              L ∈ {10,000,000; 20,000,000; 50,000,000} paise, including this one
  hour_deviation              circular hours between this event's IST hour and the customer's median login hour (30 d)
  minutes_since_new_device    minutes since the customer's latest event from a device never seen for them before
                              (0 when this event's device is new; 10,080 if none in 7 d)
  device_first_seen, asn_first_seen   1 if this device / ASN has not appeared for the customer in 30 d
  km_from_home                haversine km from the customer's modal (lat, lon) over 30 d of logins; 0 if unknown
  travel_speed_kmh            km from the previous login with coordinates ÷ hours between them (0 if none)
  failed_logins_1h            the customer's prior failed logins in 1 h
  minutes_since_mfa_change    minutes since the customer's last mfa_change (10,080 if none in 7 d)
  ip_failed_customers_1h      distinct customers with failed logins from this IP token in 1 h, including this one
  past_logins_30d             the customer's prior successful logins in 30 d (COLD_START below 5)
  cid_profile_reads_10m       ReadCustomerProfile actions by this cloud identity in 10 min, including this one
  mfa_fails_15m               the customer's prior failed mfa_challenge results in 15 min (MFA_FAIL_THEN_PASS)
  push_rejects_10m            the customer's device_push challenges failed or ignored in 10 min, including this one
                              (PUSH_SPAM)
  ip_stuffing_flagged_1h      1 if this IP already reached 10 failed customers within the prior hour, so
                              CREDENTIAL_STUFFING_IP fires once per IP per hour
  payee_passthrough_24h       the payee account's own outbound ÷ inbound amounts in 24 h (0 without inbound)
The payee features (fan-in, pass-through) are computed for payee_added events too, for the graph detector.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone

from engine.contracts import StoredEvent
from engine.features.txn_windows import TXN_WINDOW_FEATURES, TxnWindows
from engine.features.windows import Windows

IST = timezone(timedelta(hours=5, minutes=30))
NONE_RECENT_MIN = 10_080.0                      # 7 days in minutes
NEAR_LIMITS_PAISE = (10_000_000, 20_000_000, 50_000_000)
H1, H24, D7, D30, M10 = timedelta(hours=1), timedelta(hours=24), timedelta(days=7), timedelta(days=30), timedelta(minutes=10)
MIN_TRAVEL_HOURS = 1 / 60                        # one minute: avoids dividing by ~0 between back-to-back logins

TXN_FEATURES = ["log_amount", "amount_to_median_30d", "txn_count_1h", "txn_sum_24h_paise", "payee_is_new",
                "minutes_since_payee_added", "payee_fan_in_24h", "payee_sum_24h_paise", "near_limit_count_24h",
                "hour_deviation", "minutes_since_new_device"]
FEATURE_NAMES = TXN_FEATURES + ["device_first_seen", "asn_first_seen", "km_from_home", "travel_speed_kmh",
                                "failed_logins_1h", "minutes_since_mfa_change", "ip_failed_customers_1h",
                                "past_logins_30d", "cid_profile_reads_10m", "mfa_fails_15m", "push_rejects_10m",
                                "ip_stuffing_flagged_1h", "payee_passthrough_24h"]
FEATURE_NAMES += TXN_WINDOW_FEATURES   # v3 core: rule-side customer+payee windows (engine/features/txn_windows.py)
STUFFING_MIN_CUSTOMERS = 10
M15 = timedelta(minutes=15)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371.0088 * math.asin(min(1.0, math.sqrt(a)))


def ist_hour(ts: datetime) -> float:
    t = ts.astimezone(IST)
    return t.hour + t.minute / 60 + t.second / 3600


def circular_hours(a: float, b: float) -> float:
    d = abs(a - b) % 24
    return min(d, 24 - d)


def is_near_limit(amount: int) -> bool:
    return any(0.95 * lim <= amount < lim for lim in NEAR_LIMITS_PAISE)


def _minutes(now: datetime, then: datetime | None) -> float:
    if then is None or now - then > D7:
        return NONE_RECENT_MIN
    return max(0.0, (now - then).total_seconds() / 60)


class FeatureWindows:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._devices: dict[str, dict[str, datetime]] = {}       # customer -> device -> last seen
        self._asns: dict[str, dict[str, datetime]] = {}
        self._new_device_at: dict[str, datetime] = {}
        self._login_hours = Windows(D30)                          # customer -> IST hour of successful logins
        self._login_coords = Windows(D30)                         # customer -> (lat, lon) rounded
        self._last_coord_login: dict[str, tuple[datetime, float, float]] = {}
        self._failed = Windows(H1)                                # customer -> None
        self._ip_failed = Windows(H1)                             # ip -> customer
        self._mfa_change_at: dict[str, datetime] = {}
        self._amounts = Windows(D30)                              # customer -> amount
        self._payee_added_at: dict[tuple[str, str], datetime] = {}
        self._fan_in = Windows(H24)                               # payee -> sender
        self._pair = Windows(H24)                                 # (customer, payee) -> amount
        self._cid_reads = Windows(M10)                            # cid -> None
        self._mfa_fails = Windows(M15)                            # customer -> None
        self._push_rejects = Windows(M10)                         # customer -> None
        self._stuffing_flagged_at: dict[str, datetime] = {}       # ip -> when it reached 10 failed customers
        self._inbound = Windows(H24)                              # account -> amount received
        self._outbound = Windows(H24)                             # account -> amount sent
        self._txn = TxnWindows()                                  # v3 core: (who, payee) event-time windows

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def who(ev: StoredEvent) -> str | None:
        return ev.customer or ev.account

    @staticmethod
    def _first_seen(seen: dict[str, dict[str, datetime]], who: str | None, value: str | None, now: datetime) -> bool:
        if not who or not value:
            return False
        last = seen.get(who, {}).get(value)
        return last is None or now - last > D30

    # ------------------------------------------------------------------ compute (state BEFORE the event)
    def compute(self, ev: StoredEvent) -> dict[str, float]:
        now, who, p = ev.occurred_at, self.who(ev), ev.payload
        f = dict.fromkeys(FEATURE_NAMES, 0.0)
        f["amount_to_median_30d"] = 1.0
        f["minutes_since_payee_added"] = f["minutes_since_new_device"] = f["minutes_since_mfa_change"] = NONE_RECENT_MIN

        device_new = self._first_seen(self._devices, who, ev.device, now)
        f["device_first_seen"] = float(device_new)
        f["asn_first_seen"] = float(self._first_seen(self._asns, who, ev.asn, now))
        if who:
            f["minutes_since_new_device"] = 0.0 if device_new else _minutes(now, self._new_device_at.get(who))
            f["minutes_since_mfa_change"] = _minutes(now, self._mfa_change_at.get(who))
            hours = self._login_hours.values(who, now)
            f["past_logins_30d"] = float(len(hours))
            if hours:
                f["hour_deviation"] = circular_hours(ist_hour(now), statistics.median(hours))
            f["failed_logins_1h"] = float(len(self._failed.values(who, now)))
            if ev.lat is not None and ev.lon is not None:
                coords = self._login_coords.values(who, now)
                if coords:
                    home = Counter(coords).most_common(1)[0][0]
                    f["km_from_home"] = haversine_km(ev.lat, ev.lon, home[0], home[1])
                last = self._last_coord_login.get(who)
                if ev.event_type == "login" and last is not None:
                    hours_between = max(MIN_TRAVEL_HOURS, (now - last[0]).total_seconds() / 3600)
                    f["travel_speed_kmh"] = haversine_km(ev.lat, ev.lon, last[1], last[2]) / hours_between

        if ev.event_type == "login" and ev.ip:
            failed = set(self._ip_failed.values(ev.ip, now))
            if p.get("result") == "failure" and who:
                failed.add(who)
            f["ip_failed_customers_1h"] = float(len(failed))
            flagged = self._stuffing_flagged_at.get(ev.ip)
            f["ip_stuffing_flagged_1h"] = float(flagged is not None and now - flagged < H1)

        if ev.event_type == "transaction":
            amount, payee = int(p["amount_paise"]), p.get("payee_account")
            f["log_amount"] = math.log1p(amount / 100)
            if who:
                prior = self._amounts.values(who, now)
                if prior:
                    f["amount_to_median_30d"] = amount / statistics.median(prior)
                f["txn_count_1h"] = float(len(self._amounts.values(who, now, H1)))
                f["txn_sum_24h_paise"] = float(sum(self._amounts.values(who, now, H24)))
            if payee:
                f.update(self._payee_flow(payee, who, now))
                added = self._payee_added_at.get((who, payee)) if who else None
                f["minutes_since_payee_added"] = _minutes(now, added)
                f["payee_is_new"] = float(added is not None and now - added < H24)
                if who:
                    pair = self._pair.values((who, payee), now)
                    f["payee_sum_24h_paise"] = float(sum(pair))
                    f["near_limit_count_24h"] = float(sum(map(is_near_limit, pair)) + is_near_limit(amount))

        if ev.event_type == "payee_added" and p.get("payee_account"):
            f.update(self._payee_flow(p["payee_account"], who, now))
        if ev.event_type == "cloud_audit" and p.get("action") == "ReadCustomerProfile" and p.get("actor_identity"):
            f["cid_profile_reads_10m"] = float(len(self._cid_reads.values(p["actor_identity"], now)) + 1)
        if ev.event_type == "mfa_challenge" and who:
            f["mfa_fails_15m"] = float(len(self._mfa_fails.values(who, now)))
            prior = len(self._push_rejects.values(who, now))
            f["push_rejects_10m"] = float(prior + self._is_push_reject(p))
        f.update(self._txn.compute(ev))
        return f

    def _payee_flow(self, payee: str, who: str | None, now: datetime) -> dict[str, float]:
        inbound = sum(self._inbound.values(payee, now))
        return {"payee_fan_in_24h": float(len({s for s in self._fan_in.values(payee, now) if s != who})),
                "payee_passthrough_24h": sum(self._outbound.values(payee, now)) / inbound if inbound else 0.0}

    @staticmethod
    def _is_push_reject(p: dict) -> bool:
        return p.get("method") == "device_push" and p.get("result") in ("failed", "ignored")

    # ------------------------------------------------------------------ update (add the event)
    def update(self, ev: StoredEvent) -> None:
        self._txn.update(ev)
        now, who, p = ev.occurred_at, self.who(ev), ev.payload
        if who and ev.device:
            if self._first_seen(self._devices, who, ev.device, now):
                self._new_device_at[who] = now
            self._devices.setdefault(who, {})[ev.device] = now
        if who and ev.asn:
            self._asns.setdefault(who, {})[ev.asn] = now
        if ev.event_type == "login":
            if p.get("result") == "success" and who:
                self._login_hours.add(who, now, ist_hour(now))
                if ev.lat is not None and ev.lon is not None:
                    self._login_coords.add(who, now, (round(ev.lat, 2), round(ev.lon, 2)))
            elif p.get("result") == "failure":
                if who:
                    self._failed.add(who, now)
                    if ev.ip:
                        self._ip_failed.add(ev.ip, now, who)
                if ev.ip and len(set(self._ip_failed.values(ev.ip, now))) >= STUFFING_MIN_CUSTOMERS:
                    flagged = self._stuffing_flagged_at.get(ev.ip)
                    if flagged is None or now - flagged >= H1:
                        self._stuffing_flagged_at[ev.ip] = now
            if who and ev.lat is not None and ev.lon is not None:
                self._last_coord_login[who] = (now, ev.lat, ev.lon)
        elif ev.event_type == "mfa_change" and who:
            self._mfa_change_at[who] = now
        elif ev.event_type == "payee_added" and who and p.get("payee_account"):
            self._payee_added_at[(who, p["payee_account"])] = now
        elif ev.event_type == "transaction":
            amount, payee = int(p["amount_paise"]), p.get("payee_account")
            if who:
                self._amounts.add(who, now, amount)
            if payee:
                self._fan_in.add(payee, now, who)
                self._inbound.add(payee, now, amount)
                if who:
                    self._pair.add((who, payee), now, amount)
            if ev.account:
                self._outbound.add(ev.account, now, amount)
        elif ev.event_type == "cloud_audit" and p.get("action") == "ReadCustomerProfile" and p.get("actor_identity"):
            self._cid_reads.add(p["actor_identity"], now)
        elif ev.event_type == "mfa_challenge" and who:
            if p.get("result") == "failed":
                self._mfa_fails.add(who, now)
            if self._is_push_reject(p):
                self._push_rejects.add(who, now)


def iter_feature_rows(events: Iterable[StoredEvent], windows: FeatureWindows | None = None
                      ) -> Iterator[tuple[StoredEvent, dict[str, float]]]:
    """The training path: (event, features) for every event, in the given (time) order, compute then update."""
    fw = FeatureWindows() if windows is None else windows
    for ev in events:
        feats = fw.compute(ev)
        fw.update(ev)
        yield ev, feats
