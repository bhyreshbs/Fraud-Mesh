"""Ingestion-time network enrichment (v3 phase 5): classify the RAW ip before it is tokenized.

accept_envelope (api/routers/ingest.py) calls `enrich(env)`, which returns (envelope, network) for
`to_stored_event(env, received_at, network=network)`:
  - network: {network_type, network_source, network_confidence, ip_timezone?} from engine.netintel.NetworkIntel
    (offline, local files only), or None when the event has no ip. Any failure degrades to network_type "unknown".
  - envelope: unchanged, except that a missing context.platform is filled from the user agent as "ua:<platform>"
    (StoredEvent does not keep the user agent; the prefix marks it as derived, not sent by the client).
Optional databases (never downloaded or committed): FM_IP2PROXY_CSV (IP2Proxy LITE PX2 CSV) and FM_GEOLITE2_ASN_MMDB
(MaxMind GeoLite2-ASN, needs the `maxminddb` package), read when the classifier is first built.
Privacy: the raw ip is never logged; log lines name only the exception type.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any

from engine.contracts import Envelope
from engine.netintel.intel import NetworkIntel

log = logging.getLogger("fraudmesh.enrichment")
_lock = threading.Lock()
_intel: NetworkIntel | None = None
UNKNOWN = {"network_type": "unknown", "network_source": "error", "network_confidence": 0.0}

# substring of the user agent (lower case) -> platform; first match wins
UA_PLATFORMS = (("iphone", "iPhone"), ("ipad", "iPad"), ("android", "Android"), ("windows", "Win32"),
                ("macintosh", "MacIntel"), ("cros", "CrOS"), ("linux", "Linux x86_64"))


def intel() -> NetworkIntel:
    global _intel
    if _intel is None:
        with _lock:
            if _intel is None:
                _intel = NetworkIntel(ip2proxy_csv=os.getenv("FM_IP2PROXY_CSV") or None,
                                      maxmind_asn_mmdb=os.getenv("FM_GEOLITE2_ASN_MMDB") or None)
                log.info("network intelligence sources: %s", _intel.status)
    return _intel


def reset() -> None:
    """Tests: rebuild the classifier on next use (e.g. after changing the env vars)."""
    global _intel
    with _lock:
        _intel = None


def network_for(ip: str | None, asn: str | None = None) -> dict[str, Any] | None:
    if not ip:
        return None
    try:
        return intel().lookup(ip, asn).as_enrichment()
    except Exception as e:                                  # never fail ingestion because of enrichment
        log.warning("network enrichment failed (%s); using unknown", type(e).__name__)
        return dict(UNKNOWN)


def platform_from_user_agent(ua: str | None) -> str | None:
    u = (ua or "").lower()
    for needle, platform in UA_PLATFORMS:
        if needle in u:
            return f"ua:{platform}"
    return None


def enrich(env: Envelope) -> tuple[Envelope, dict[str, Any] | None]:
    ctx = env.context
    if ctx.platform is None and ctx.user_agent:
        derived = platform_from_user_agent(ctx.user_agent)
        if derived:
            env = env.model_copy(update={"context": ctx.model_copy(update={"platform": derived})})
    return env, network_for(ctx.ip, ctx.asn)
