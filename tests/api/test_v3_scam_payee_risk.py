"""v3 phase 7 (API): the external payee-risk provider interface (api/payee_risk.py). Off by default; the only
implementation is a synthetic fixture (no live registry such as DoT FRI is connected)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from api.payee_risk import DisabledProvider, SyntheticFixtureProvider, attach, engine_lookup, provider_from_env
from engine.common.tokenize import tok
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def test_default_is_off_and_unknown_providers_are_refused(monkeypatch):
    monkeypatch.delenv("FM_PAYEE_RISK_PROVIDER", raising=False)
    assert isinstance(provider_from_env(), DisabledProvider)
    assert engine_lookup(DisabledProvider()) is None
    monkeypatch.setenv("FM_PAYEE_RISK_PROVIDER", "dot_fri")
    with pytest.raises(ValueError, match="no live registry"):
        provider_from_env()
    monkeypatch.setenv("FM_PAYEE_RISK_PROVIDER", "fixture")
    assert isinstance(provider_from_env(), SyntheticFixtureProvider)


def test_fixture_provider_answers_on_tokens_only():
    p = SyntheticFixtureProvider()
    assert p.lookup("account", "A-SAFE-4471").source == "synthetic-fixture"
    assert p.lookup("mobile", "+919000099901").reports == 4
    lookup = engine_lookup(p)
    sig = lookup(tok("acct", "A-SAFE-4471"), NOW)
    assert sig is not None and sig.score > 0.9 and sig.source == "synthetic-fixture"
    assert lookup("acct:unknown", NOW) is None
    assert lookup("A-SAFE-4471", NOW) is None                        # a raw value never matches: the engine sees tokens


def test_attach_sets_the_graph_detectors_lookup_only_when_enabled():
    pipe = Pipeline(MemoryStore())
    graph = next(d for d in pipe.detectors if d.id == "graph")
    assert graph.payee_risk is None
    assert attach(pipe, DisabledProvider()) is False and graph.payee_risk is None
    assert attach(pipe, SyntheticFixtureProvider()) is True and graph.payee_risk is not None
