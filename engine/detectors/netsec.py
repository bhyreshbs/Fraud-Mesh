"""netsec detector (PRD §10.4): network IDS alerts, stage S0.

IDS: p by severity (IDS_SEV1/2/3) capped at CAP; technique from ids_map.yaml. The only entity is the alert's
src_ip token.
CREDENTIAL_STUFFING_IP (PayPal-derived, D2-P4): a failed login that brings this IP to >= 10 distinct customers with
failed logins in 1 h, once per IP per hour (feature ip_stuffing_flagged_1h); entities = [ip] only.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from engine.contracts import Evidence, Reason, StoredEvent
from engine.detectors.base import RULES_DIR, load_calibration, make_evidence, should_emit
from engine.graph.store import EntityGraph

VERSION = "netsec-1"
STUFFING_MIN_CUSTOMERS = 10


@lru_cache(maxsize=2)
def load_ids_map(path: str | Path = RULES_DIR / "ids_map.yaml") -> dict[int, str]:
    return {int(k): str(v) for k, v in (yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}).items()}


class NetsecDetector:
    id = "netsec"
    handles = frozenset({"network_ids_alert", "login"})

    def __init__(self) -> None:
        self.cal = load_calibration()["netsec"]
        self.ids_map = load_ids_map()

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        if event.event_type == "login":
            return self._stuffing(event, feats, rel)
        if event.event_type != "network_ids_alert":
            return []
        p_ = event.payload
        code = f"IDS_SEV{int(p_['severity'])}"
        p = min(self.cal[code], self.cal["CAP"])
        reasons = [Reason(code=code, detail=str(p_.get("signature", ""))[:200] or None)]
        if not should_emit(p, reasons):
            return []
        ip = p_.get("src_ip")
        return [make_evidence(self.id, VERSION, event, "S0_RECON", p, rel, reasons,
                              technique=self.ids_map.get(int(p_["signature_id"])), entities=[ip] if ip else [])]

    def _stuffing(self, event: StoredEvent, feats: dict[str, Any], rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        if (event.payload.get("result") != "failure" or not event.ip or feats.get("ip_stuffing_flagged_1h")
                or feats.get("ip_failed_customers_1h", 0) < STUFFING_MIN_CUSTOMERS):
            return []
        p = self.cal["CREDENTIAL_STUFFING_IP"]
        reasons = [Reason(code="CREDENTIAL_STUFFING_IP",
                          detail=f"{feats['ip_failed_customers_1h']:.0f} customers with failed logins from one IP in 1 h")]
        return [make_evidence(self.id, VERSION, event, "S0_RECON", p, rel, reasons, technique="T1110.004",
                              entities=[event.ip])]
