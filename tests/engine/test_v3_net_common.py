"""Shared builders for the v3 network/session tests (tests/engine/test_v3_net_*.py), plus a smoke test of them."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.common.tokenize import to_stored_event, tok
from engine.contracts import BAND_ORDER, Envelope, StoredEvent
from engine.netintel.intel import NetworkIntel
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore

IST = timezone(timedelta(hours=5, minutes=30))
T0 = datetime(2026, 10, 1, 0, 0, tzinfo=IST)
BLR = (12.9716, 77.5946)
_INTEL = NetworkIntel()
_n = 0


def network(ip: str | None, asn: str | None = None) -> dict | None:
    """What api/enrichment.py passes to to_stored_event for this raw ip."""
    return _INTEL.lookup(ip, asn).as_enrichment() if ip else None


def ev(event_type: str, payload: dict, minutes: float = 0.0, cust: str | None = "C-1", acct: str | None = "A-1",
       ip: str | None = "49.207.10.21", dev: str | None = "fp_a", asn: str | None = "AS24560 Airtel", coords=BLR,
       enrich: bool = True, net: dict | None = None, **client) -> StoredEvent:
    """One StoredEvent; `client` = 1.1.0 context fields (session_id, platform, webgl_renderer, screen,
    browser_timezone, locale, telemetry). enrich=True classifies the raw ip like the API does."""
    global _n
    _n += 1
    ctx: dict = {"ip": ip, "device_id": dev, "asn": asn, **client}
    if coords:
        ctx.update(lat=coords[0], lon=coords[1])
    subject = {k: v for k, v in (("customer_ref", cust), ("account_ref", acct)) if v}
    env = Envelope(event_id=f"evt_v3net{_n:010d}", event_type=event_type, source="demo-bank-web",
                   occurred_at=T0 + timedelta(minutes=minutes), subject=subject,
                   context={k: v for k, v in ctx.items() if v is not None}, payload=payload, schema_version="1.1")
    return to_stored_event(env, env.occurred_at, network=net if net is not None else (network(ip, asn) if enrich else None))


def login(minutes: float = 0.0, result: str = "success", **kw) -> StoredEvent:
    return ev("login", {"result": result, "auth_method": "password"}, minutes, **kw)


def new_pipeline() -> tuple[MemoryStore, Pipeline]:
    store = MemoryStore()
    pipe = Pipeline(store)
    pipe.startup()
    return store, pipe


def feed(store: MemoryStore, pipe: Pipeline, events: list[StoredEvent]) -> list:
    out = []
    for e in sorted(events, key=lambda x: x.occurred_at):
        store.insert_event(e)
        out += pipe.process(e)
    return out


def reasons_in_case(store: MemoryStore, case_id: str) -> set[str]:
    return {r.code for e in store.list_evidence(case_id) for r in e.reasons}


def all_reasons(store: MemoryStore) -> set[str]:
    return {code for c in store.list_cases() for code in reasons_in_case(store, c.case_id)}


def band_rank(band: str) -> int:
    return BAND_ORDER.index(band)


def cust(ref: str) -> str:
    return tok("cust", ref)


def test_builders_tokenize_and_enrich():
    e = login(ip="185.220.101.7", dev="fp_attacker_01", asn="AS64500 HostCo", session_id="s-1", platform="Linux x86_64")
    assert e.ip.startswith("ip:") and e.session.startswith("ses:") and e.network_type == "hosting"
    assert "185.220.101.7" not in e.model_dump_json()
