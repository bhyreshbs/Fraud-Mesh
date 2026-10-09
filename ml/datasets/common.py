"""Shared plumbing for the external datasets: rows -> FraudMesh events -> engine features."""
from __future__ import annotations

import itertools
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import numpy as np

from engine.common.tokenize import to_stored_event
from engine.contracts import Envelope, StoredEvent
from engine.features.features import TXN_FEATURES, iter_feature_rows

T0 = datetime(2026, 1, 1, tzinfo=UTC)          # anchors relative dataset clocks (seconds, hours, days)
_ids = itertools.count(1)


@dataclass(frozen=True)
class Txn:
    """One payment: who paid whom, how much, when, from which device, and whether it was fraud."""
    ts: datetime
    customer: str
    account: str
    payee: str
    amount_paise: int
    is_fraud: bool
    device: str | None = None


@dataclass
class Domain:
    """Feature rows of one dataset's transactions, in time order."""
    name: str
    X: np.ndarray
    y: np.ndarray
    ts: np.ndarray

    def split(self, train: float = 0.60, calib: float = 0.15) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Boolean masks by time: the first `train` share trains, the next `calib` share calibrates, the rest tests."""
        n = len(self.y)
        idx = np.arange(n)
        a, b = int(train * n), int((train + calib) * n)
        return idx < a, (idx >= a) & (idx < b), idx >= b


def _envelope(etype: str, ts: datetime, t: Txn, payload: dict) -> Envelope:
    return Envelope(event_id=f"evt_ext{next(_ids):012d}", event_type=etype, source="simulator", occurred_at=ts,
                    subject={"customer_ref": t.customer, "account_ref": t.account},
                    context={"device_id": t.device} if t.device else {}, payload=payload)


def events(txns: Iterable[Txn], with_login: bool = False) -> Iterator[tuple[StoredEvent, bool | None]]:
    """FraudMesh events for time-ordered payments, as (event, is_fraud or None for non-transactions).

    A bank requires a beneficiary before the first payment to it, so each new (customer, payee) pair gets a
    payee_added one second earlier. with_login adds a successful login two seconds before each payment (card-not-
    present purchases are made in a session), which feeds hour_deviation and the new-device features.
    """
    seen: set[tuple[str, str]] = set()
    for t in txns:
        if with_login:
            login = _envelope("login", t.ts - timedelta(seconds=2), t, {"result": "success", "auth_method": "password+otp"})
            yield to_stored_event(login, login.occurred_at), None
        if (t.customer, t.payee) not in seen:
            seen.add((t.customer, t.payee))
            added = _envelope("payee_added", t.ts - timedelta(seconds=1), t, {"payee_account": t.payee})
            yield to_stored_event(added, added.occurred_at), None
        pay = _envelope("transaction", t.ts, t, {"amount_paise": max(int(t.amount_paise), 1), "payee_account": t.payee,
                                                 "channel": "IMPS"})
        yield to_stored_event(pay, pay.occurred_at), t.is_fraud


def featurize(name: str, txns: Iterable[Txn], with_login: bool = False) -> Domain:
    """Stream the events through the engine's feature windows (compute, then update) and keep transaction rows.

    The payments must be in time order; the 1-2 s pre-events can interleave with a neighbouring payment, which is
    harmless for windows measured in hours and days."""
    labels: dict[str, bool] = {}

    def stream() -> Iterator[StoredEvent]:
        for ev, fraud in events(txns, with_login):
            if fraud is not None:
                labels[ev.event_id] = fraud
            yield ev

    X, y, ts = [], [], []
    for ev, f in iter_feature_rows(stream()):
        if ev.event_type == "transaction":
            X.append([f[k] for k in TXN_FEATURES])
            y.append(labels.pop(ev.event_id))
            ts.append(ev.occurred_at.timestamp())
    return Domain(name, np.asarray(X, dtype=np.float64), np.asarray(y, dtype=np.int8), np.asarray(ts))
