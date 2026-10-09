"""External payee / mobile-number risk provider interface (v3 phase 7). OFF by default.

Banks can ask an external registry whether a beneficiary account or mobile number has been reported for fraud (in India
the DoT Financial Fraud Risk Indicator is such a source). FraudMesh has NO connection to any live registry: this module
defines the interface and ships one synthetic fixture provider for demos and tests. Do not present the fixture as a
real feed.

    FM_PAYEE_RISK_PROVIDER = off (default) | fixture

The engine never calls a network service and only ever sees tokens. A provider is wrapped with `engine_lookup()` into the
engine's PayeeRiskLookup (payee token, event time -> PayeeRiskSignal | None) and attached to the live graph detector with
`attach(pipeline, provider)`. A report adds APP_PAYEE_REPORTED (weight in engine/detectors/rules/app_scam.yaml) to the
APP-scam assessment. Wiring it at API start-up is one line in api/pipeline_factory.py (not done on this branch: the
default is off, and that file is owned elsewhere):

    from api.payee_risk import attach, provider_from_env;  attach(pipeline, provider_from_env())
"""
from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from engine.common.tokenize import tok
from engine.features.app_scam import PayeeRiskLookup, PayeeRiskSignal

IdentifierKind = Literal["account", "mobile"]


@dataclass(frozen=True)
class PayeeRisk:
    kind: IdentifierKind
    score: float                     # 0..1, provider-defined; FraudMesh only compares it with provider_min_score
    reports: int
    source: str


class PayeeRiskProvider(Protocol):
    name: str

    def lookup(self, kind: IdentifierKind, raw: str) -> PayeeRisk | None: ...

    def known_identifiers(self) -> Iterable[tuple[IdentifierKind, str]]: ...


class DisabledProvider:
    name = "off"

    def lookup(self, kind: IdentifierKind, raw: str) -> PayeeRisk | None:
        return None

    def known_identifiers(self) -> Iterable[tuple[IdentifierKind, str]]:
        return ()


# Synthetic, clearly fake identifiers (the scam_app "safe account" and two made-up mobile numbers).
SYNTHETIC_FIXTURE: dict[tuple[str, str], PayeeRisk] = {
    ("account", "A-SAFE-4471"): PayeeRisk("account", 0.92, 6, "synthetic-fixture"),
    ("account", "A-RING-01"): PayeeRisk("account", 0.65, 2, "synthetic-fixture"),
    ("mobile", "+919000099901"): PayeeRisk("mobile", 0.88, 4, "synthetic-fixture"),
    ("mobile", "+919000099902"): PayeeRisk("mobile", 0.40, 1, "synthetic-fixture"),
}


class SyntheticFixtureProvider:
    """In-memory synthetic registry for demos and tests. Not a real fraud registry."""
    name = "fixture"

    def __init__(self, entries: dict[tuple[str, str], PayeeRisk] | None = None) -> None:
        self.entries = dict(SYNTHETIC_FIXTURE if entries is None else entries)

    def lookup(self, kind: IdentifierKind, raw: str) -> PayeeRisk | None:
        return self.entries.get((kind, raw.strip()))

    def known_identifiers(self) -> Iterable[tuple[IdentifierKind, str]]:
        return list(self.entries)


def provider_from_env() -> PayeeRiskProvider:
    name = os.getenv("FM_PAYEE_RISK_PROVIDER", "off").strip().lower()
    if name in ("", "off", "none", "0"):
        return DisabledProvider()
    if name == "fixture":
        return SyntheticFixtureProvider()
    raise ValueError(f"FM_PAYEE_RISK_PROVIDER={name!r}: only 'off' or 'fixture' exist (no live registry is connected)")


def engine_lookup(provider: PayeeRiskProvider) -> PayeeRiskLookup | None:
    """The engine sees payee ACCOUNT tokens only, so the provider's account identifiers are tokenized once here (the
    same tok() the ingestion uses). Mobile numbers are kept for an API-side check at payee creation (no engine field)."""
    if isinstance(provider, DisabledProvider):
        return None
    by_token: dict[str, PayeeRisk] = {}
    for kind, raw in provider.known_identifiers():
        if kind == "account":
            risk = provider.lookup(kind, raw)
            if risk is not None:
                by_token[tok("acct", raw)] = risk

    def lookup(payee_token: str, now: datetime) -> PayeeRiskSignal | None:
        r = by_token.get(payee_token)
        return PayeeRiskSignal(score=r.score, reports=r.reports, source=r.source) if r is not None else None
    return lookup


def attach(pipeline, provider: PayeeRiskProvider) -> bool:
    """Give the pipeline's graph detector the provider's lookup. Returns False when off or no graph detector exists."""
    lookup = engine_lookup(provider)
    if lookup is None:
        return False
    for d in getattr(pipeline, "detectors", []):
        if getattr(d, "id", None) == "graph" and hasattr(d, "payee_risk"):
            d.payee_risk = lookup
            return True
    return False
