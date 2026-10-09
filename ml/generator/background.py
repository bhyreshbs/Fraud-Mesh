"""Normal customer days (PRD §12.1) and the event sink every generator stream writes into.

Per day, 0–3 sessions, each a login plus 0–4 transactions. About 3% of days add a new payee; 0.5% add a new
device (a legitimate phone change, sometimes with an MFA change) that creates honest false-positive pressure.
"""
from __future__ import annotations

import math
import random
from datetime import date, datetime, time, timedelta

from engine.contracts import Envelope, Label, validate_payload
from ml.generator.population import Customer, new_device_id, new_external_account

SESSIONS_PER_DAY = ((0, 1, 2, 3), (0.30, 0.40, 0.20, 0.10))
TXNS_PER_SESSION = ((0, 1, 2, 3, 4), (0.45, 0.30, 0.15, 0.07, 0.03))
AUTH_METHODS = (("password+otp", "password+push", "password"), (0.50, 0.35, 0.15))
P_NEW_PAYEE_DAY = 0.03
P_NEW_DEVICE_DAY = 0.005
P_FAILED_BEFORE_LOGIN = 0.02
P_MFA_CHANGE_WITH_NEW_DEVICE = 0.5
UPI_LIMIT_PAISE = 10_000_000          # ₹1,00,000
BACKGROUND = "background"


class Sink:
    """Collects Envelopes and Labels for one generator run; event IDs are drawn from a seeded stream."""

    def __init__(self, rng: random.Random, start: datetime, end: datetime) -> None:
        self.rng = rng
        self.start, self.end = start, end
        self.envelopes: list[Envelope] = []
        self.labels: list[Label] = []
        self._ids: set[str] = set()

    def _event_id(self) -> str:
        while True:
            eid = f"evt_{self.rng.getrandbits(64):016x}"
            if eid not in self._ids:
                self._ids.add(eid)
                return eid

    def in_window(self, *ts: datetime) -> bool:
        return all(self.start <= t < self.end for t in ts)

    def emit(self, event_type: str, at: datetime, payload: dict, *, subject: dict | None = None,
             context: dict | None = None, scenario: str = BACKGROUND, attack_id: str | None = None) -> Envelope | None:
        if not self.in_window(at):
            return None
        validate_payload(event_type, payload)
        env = Envelope(event_id=self._event_id(), event_type=event_type, source="simulator", occurred_at=at,
                       subject=subject or {}, context=context or {}, payload=payload)
        self.envelopes.append(env)
        self.labels.append(Label(event_id=env.event_id, scenario=scenario, is_attack=attack_id is not None,
                                 attack_id=attack_id))
        return env


def subject_of(c: Customer) -> dict:
    return {"customer_ref": c.customer_ref, "account_ref": c.account_ref}


def home_context(c: Customer, device: str, rng: random.Random) -> dict:
    return {"ip": c.home_ip, "device_id": device, "asn": c.asn, "city": c.city,
            "lat": round(c.lat + rng.gauss(0, 0.005), 4), "lon": round(c.lon + rng.gauss(0, 0.005), 4)}


def txn_amount(c: Customer, rng: random.Random) -> int:
    return max(1000, round(c.median_amount_paise * math.exp(rng.gauss(0, 0.6)) / 100) * 100)


def channel_for(amount_paise: int, rng: random.Random) -> str:
    if amount_paise <= UPI_LIMIT_PAISE and rng.random() < 0.85:
        return "UPI"
    return rng.choice(("IMPS", "NEFT"))


def pick_payee(c: Customer, rng: random.Random) -> str:
    weights = [1.0 / (r + 1) for r in range(len(c.payees))]          # a few favourite payees dominate
    return rng.choices(c.payees, weights=weights)[0]


def _session_times(c: Customer, day: date, tz, rng: random.Random) -> list[datetime]:
    n = rng.choices(*SESSIONS_PER_DAY)[0]
    midnight = datetime.combine(day, time(0, 0), tzinfo=tz)
    times = []
    for _ in range(n):
        hour = (c.login_hour + rng.gauss(0, 1.5)) % 24
        times.append(midnight + timedelta(seconds=int(hour * 3600) + rng.randint(0, 59)))
    return sorted(times)


def _login(sink: Sink, c: Customer, at: datetime, device: str, rng: random.Random) -> None:
    ctx = home_context(c, device, rng)
    if rng.random() < P_FAILED_BEFORE_LOGIN:            # a mistyped password a minute earlier
        sink.emit("login", at - timedelta(minutes=1), {"result": "failure", "auth_method": "password"},
                  subject=subject_of(c), context=ctx)
    sink.emit("login", at, {"result": "success", "auth_method": rng.choices(*AUTH_METHODS)[0]},
              subject=subject_of(c), context=ctx)


def _transactions(sink: Sink, c: Customer, at: datetime, device: str, rng: random.Random) -> None:
    t = at
    for _ in range(rng.choices(*TXNS_PER_SESSION)[0]):
        t += timedelta(minutes=rng.randint(1, 4), seconds=rng.randint(0, 59))
        amount = txn_amount(c, rng)
        sink.emit("transaction", t, {"amount_paise": amount, "payee_account": pick_payee(c, rng),
                                     "channel": channel_for(amount, rng)},
                  subject=subject_of(c), context=home_context(c, device, rng))


def _new_payee(sink: Sink, c: Customer, at: datetime, device: str, rng: random.Random) -> None:
    payee = new_external_account(rng)
    nickname = rng.choice(("Plumber", "Carpenter", "School fees", "Doctor", "Shop", "Friend", "Colleague"))
    t = at + timedelta(minutes=1, seconds=rng.randint(0, 59))
    sink.emit("payee_added", t, {"payee_account": payee, "payee_name_match": rng.random() < 0.95 or None,
                                 "nickname": nickname}, subject=subject_of(c), context=home_context(c, device, rng))
    c.payees.append(payee)
    c.nicknames[payee] = nickname
    if rng.random() < 0.7:
        amount = txn_amount(c, rng)
        sink.emit("transaction", t + timedelta(minutes=rng.randint(1, 5)),
                  {"amount_paise": amount, "payee_account": payee, "channel": channel_for(amount, rng)},
                  subject=subject_of(c), context=home_context(c, device, rng))


def _new_device(c: Customer, at: datetime, sink: Sink, rng: random.Random) -> str:
    """A legitimate phone change: the new device replaces the oldest one and logs in from home."""
    device = new_device_id(rng)
    c.devices = (c.devices[1:] if len(c.devices) > 1 else []) + [device]
    if rng.random() < P_MFA_CHANGE_WITH_NEW_DEVICE:
        sink.emit("mfa_change", at + timedelta(minutes=2), {"factor": "device_push", "action": "replace"},
                  subject={"customer_ref": c.customer_ref}, context={"ip": c.home_ip, "device_id": device})
    return device


def customer_day(sink: Sink, c: Customer, day: date, tz, rng: random.Random) -> None:
    sessions = _session_times(c, day, tz, rng)
    new_device = rng.random() < P_NEW_DEVICE_DAY
    new_payee = rng.random() < P_NEW_PAYEE_DAY
    if (new_device or new_payee) and not sessions:      # these days always have one session
        sessions = [datetime.combine(day, time(int(c.login_hour) % 24, rng.randint(0, 59)), tzinfo=tz)]
    for i, at in enumerate(sessions):
        if i == 0 and new_device:
            device = _new_device(c, at, sink, rng)
        else:
            device = c.devices[0] if len(c.devices) == 1 or rng.random() < 0.7 else c.devices[-1]
        _login(sink, c, at, device, rng)
        if i == 0 and new_payee:
            _new_payee(sink, c, at, device, rng)
        _transactions(sink, c, at, device, rng)


def background(sink: Sink, customers: list[Customer], tz, rng: random.Random) -> None:
    first, last = sink.start.astimezone(tz).date(), sink.end.astimezone(tz).date()
    for c in customers:
        day = first
        while day <= last:
            customer_day(sink, c, day, tz, rng)
            day += timedelta(days=1)
