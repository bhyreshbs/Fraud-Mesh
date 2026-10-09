"""Offline network intelligence (v3 phase 5): classify a RAW ip as residential / mobile / hosting / vpn / tor / unknown.

Only the API calls the lookup (api/enrichment.py), at ingestion, before the ip is tokenized; the engine itself only
ever sees the result on the StoredEvent. Pure and local: no network access, no wall clock.
"""
from engine.netintel.intel import NetworkIntel, NetworkResult, geo_confidence_factor, load_intel_config

__all__ = ["NetworkIntel", "NetworkResult", "geo_confidence_factor", "load_intel_config"]
