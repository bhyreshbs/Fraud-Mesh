"""netsec detector (PRD §10.4): network IDS alerts, stage S0.

IDS: p by severity (IDS_SEV1/2/3) capped at CAP; technique from ids_map.yaml. The only entity is the alert's
src_ip token.
CREDENTIAL_STUFFING_IP (PayPal-derived, D2-P4): a failed login that brings this IP to >= 10 distinct customers with
failed logins in 1 h, once per IP per hour (feature ip_stuffing_flagged_1h); entities = [ip] only.

v3 distributed credential stuffing (phase 4.2; features from engine/features/identity_windows.py, thresholds and p in
engine/detectors/rules/cred_stuffing.yaml), on failed logins, each once per key per window:
  ACCOUNT_DISTRIBUTED_FAILURES   one account, many failures from several ips/devices      entities [acct, cust]
  ACCOUNT_LOW_SLOW_FAILURES      one account, failures spread over many ips, <= 2 per ip   entities [acct, cust]
  DEVICE_MULTI_ACCOUNT_FAILURES  one device tries many accounts                           entities [dev]
  GLOBAL_LOGIN_FAILURE_SPIKE     all failures in 10 min >= ratio x baseline and many accounts targeted; fires once per
                                 window (entities [ip] or [dev]) and multiplies the other stuffing rules' p by `boost`
                                 while active
As §10.4 requires, several rules on one event give one evidence item: the highest p, all reasons, and the union of
the rules' entities. None of these p values can reach a block on its own.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from engine.contracts import Evidence, Reason, StoredEvent
from engine.detectors.base import RULES_DIR, load_calibration, make_evidence, should_emit
from engine.features.identity_windows import load_stuffing_config, stuffing_rule_hits
from engine.graph.store import EntityGraph

VERSION = "netsec-2"
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
        self.stuff = load_stuffing_config()

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
        if event.payload.get("result") != "failure":
            return []
        hits: list[tuple[str, float, str, str, list[str]]] = []          # (code, p, technique, detail, entities)
        if (event.ip and not feats.get("ip_stuffing_flagged_1h")
                and feats.get("ip_failed_customers_1h", 0) >= STUFFING_MIN_CUSTOMERS):
            hits.append(("CREDENTIAL_STUFFING_IP", self.cal["CREDENTIAL_STUFFING_IP"], "T1110.004",
                         f"{feats['ip_failed_customers_1h']:.0f} customers with failed logins from one IP in 1 h", [event.ip]))
        hits.extend(self._distributed(event, feats))
        if not hits:
            return []
        hits.sort(key=lambda h: -h[1])
        p, technique = hits[0][1], hits[0][2]
        reasons = [Reason(code=c, detail=d) for c, _, _, d, _ in hits]
        entities = sorted({t for *_, ents in hits for t in ents})
        if not entities:
            return []
        return [make_evidence(self.id, VERSION, event, "S0_RECON", p, rel, reasons, technique=technique,
                              entities=entities)]

    def _distributed(self, event: StoredEvent, feats: dict[str, Any]) -> list[tuple[str, float, str, str, list[str]]]:
        c, on = self.stuff, stuffing_rule_hits(feats, self.stuff)
        spike = bool(feats.get("global_spike_active"))
        boost = float(c["global_spike"]["boost"]) if spike else 1.0
        victim = [t for t in (event.account, event.customer) if t]
        out = []
        if on["ACCOUNT_DISTRIBUTED_FAILURES"] and not feats.get("acct_distributed_flagged") and victim:
            out.append(("ACCOUNT_DISTRIBUTED_FAILURES", float(c["account_distributed"]["p"]) * boost, "T1110.004",
                        f"{feats['acct_fail_1h']:.0f} failed logins on one account from {feats['acct_fail_sources_1h']:.0f} "
                        f"ips/devices in {c['account_distributed']['window_min']} min", victim))
        if on["ACCOUNT_LOW_SLOW_FAILURES"] and not feats.get("acct_lowslow_flagged") and victim:
            out.append(("ACCOUNT_LOW_SLOW_FAILURES", float(c["account_low_and_slow"]["p"]) * boost, "T1110.003",
                        f"{feats['acct_fail_24h']:.0f} failed logins from {feats['acct_fail_ips_24h']:.0f} ips "
                        f"(max {feats['acct_max_fail_per_ip_24h']:.0f} per ip) in {c['account_low_and_slow']['window_h']} h",
                        victim))
        if on["DEVICE_MULTI_ACCOUNT_FAILURES"] and not feats.get("dev_multi_flagged") and event.device:
            out.append(("DEVICE_MULTI_ACCOUNT_FAILURES", float(c["device_multi_account"]["p"]) * boost, "T1110.004",
                        f"one device tried {feats['dev_accounts_1h']:.0f} accounts ({feats['dev_fail_1h']:.0f} failures) "
                        f"in {c['device_multi_account']['window_min']} min", [event.device]))
        if spike and not feats.get("global_spike_flagged"):
            anchor = [event.ip] if event.ip else ([event.device] if event.device else [])
            out.append(("GLOBAL_LOGIN_FAILURE_SPIKE", float(c["global_spike"]["p"]), "T1110.003",
                        f"{feats['global_fail_10m']:.0f} failed logins on {feats['global_accounts_10m']:.0f} accounts in "
                        f"{c['global_spike']['window_min']} min (baseline {feats['global_fail_baseline_10m']:.1f})", anchor))
        return out
