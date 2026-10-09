"""NetworkIntel: offline lookup of a raw ip -> NetworkResult (network_type, source, confidence, ip_timezone).

Sources and their order are documented in engine/detectors/rules/network_intel.yaml. Every source is local:
  - the committed demo list ip_intel_demo.csv (documentation and demo ranges only),
  - an optional IP2Proxy LITE PX2 CSV (ip_from, ip_to as integers, proxy_type, ...), loaded by a small range loader,
  - an optional MaxMind GeoLite2-ASN .mmdb, read with the `maxminddb` package when it is installed (otherwise skipped),
  - cgnat.txt (carrier-grade NAT egress -> mobile),
  - the sender-supplied ASN string mapped through asn_types (low confidence).
Anything unclassified is `unknown`. A missing or unreadable optional file degrades to the next source, never raises.
Nothing here logs or stores the raw ip.
"""
from __future__ import annotations

import bisect
import csv
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

RULES_DIR = Path(__file__).resolve().parents[1] / "detectors" / "rules"
CONFIG_FILE = RULES_DIR / "network_intel.yaml"
NETWORK_TYPES = ("residential", "mobile", "hosting", "vpn", "tor", "unknown")
ANONYMISING = frozenset({"vpn", "tor", "hosting"})
_ASN_RE = re.compile(r"AS(\d+)", re.IGNORECASE)

IpNet = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class NetworkResult:
    network_type: str
    network_source: str
    network_confidence: float
    ip_timezone: str | None = None
    asn: str | None = None              # "AS64500" when a source knows it (not stored on the event; diagnostics only)

    def as_enrichment(self) -> dict[str, Any]:
        """The dict to_stored_event(..., network=...) accepts."""
        out: dict[str, Any] = {"network_type": self.network_type, "network_source": self.network_source,
                               "network_confidence": round(float(self.network_confidence), 3)}
        if self.ip_timezone:
            out["ip_timezone"] = self.ip_timezone
        return out


UNKNOWN = NetworkResult("unknown", "none", 0.0)


@lru_cache(maxsize=4)
def load_intel_config(path: str | Path = CONFIG_FILE) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def geo_confidence_factor(network_type: str | None, confidence: float | None, cfg: dict[str, Any] | None = None) -> float:
    """Multiplier for location evidence (FAR_FROM_HOME, IMPOSSIBLE_TRAVEL). 1.0 when the event was not enriched."""
    if not network_type:
        return 1.0
    g = (cfg or load_intel_config()).get("geo_confidence", {})
    factor = float(g.get("factors", {}).get(network_type, 1.0))
    if network_type == "unknown" and float(confidence or 0.0) < float(g.get("unknown_low_confidence_below", 0.0)):
        factor = min(factor, float(g.get("unknown_low_confidence_factor", 1.0)))
    return max(0.0, min(1.0, factor))


def parse_asn(asn: str | int | None) -> str | None:
    """'AS64500 HostCo' / 'as64500' / 64500 -> 'AS64500'."""
    if asn is None:
        return None
    if isinstance(asn, int):
        return f"AS{asn}"
    m = _ASN_RE.search(str(asn))
    if m:
        return f"AS{int(m.group(1))}"
    s = str(asn).strip()
    return f"AS{int(s)}" if s.isdigit() else None


# ---------------------------------------------------------------------------- loaders
@dataclass(frozen=True)
class _Row:
    net: IpNet
    network_type: str
    asn: str | None
    tz: str | None
    confidence: float


def load_demo_csv(path: str | Path) -> list[_Row]:
    """cidr,network_type,asn,org,ip_timezone,confidence; '#' lines ignored; returned most-specific first."""
    rows: list[_Row] = []
    lines = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    for rec in csv.DictReader(lines):
        nt = (rec.get("network_type") or "").strip().lower()
        if nt not in NETWORK_TYPES:
            raise ValueError(f"{path}: unknown network_type {nt!r}")
        rows.append(_Row(net=ipaddress.ip_network(rec["cidr"].strip(), strict=False), network_type=nt,
                         asn=parse_asn(rec.get("asn")), tz=(rec.get("ip_timezone") or "").strip() or None,
                         confidence=float(rec.get("confidence") or 0.9)))
    rows.sort(key=lambda r: -r.net.prefixlen)
    return rows


class RangeTable:
    """Sorted, non-overlapping [start, end] integer ranges per ip version -> value; bisect lookup."""

    def __init__(self) -> None:
        self._starts: dict[int, list[int]] = {4: [], 6: []}
        self._ends: dict[int, list[int]] = {4: [], 6: []}
        self._vals: dict[int, list[str]] = {4: [], 6: []}

    @classmethod
    def from_rows(cls, rows: list[tuple[int, int, int, str]]) -> RangeTable:
        """rows = (ip version, start, end, value)."""
        t = cls()
        for version in (4, 6):
            sel = sorted((s, e, v) for ver, s, e, v in rows if ver == version)
            t._starts[version] = [r[0] for r in sel]
            t._ends[version] = [r[1] for r in sel]
            t._vals[version] = [r[2] for r in sel]
        return t

    def __len__(self) -> int:
        return len(self._starts[4]) + len(self._starts[6])

    def lookup(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        n, starts = int(ip), self._starts[ip.version]
        i = bisect.bisect_right(starts, n) - 1
        if i >= 0 and n <= self._ends[ip.version][i]:
            return self._vals[ip.version][i]
        return None


def load_ip2proxy_csv(path: str | Path, type_map: dict[str, str]) -> RangeTable:
    """IP2Proxy LITE PX2 (or PX1+) CSV: "ip_from","ip_to","proxy_type",... with integer addresses. Rows whose
    proxy_type is not in type_map (e.g. '-') are skipped. IPv6 files store integers above 2**32."""
    rows: list[tuple[int, int, int, str]] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for rec in csv.reader(fh):
            if len(rec) < 3 or not rec[0].strip().isdigit():
                continue
            nt = type_map.get(rec[2].strip().upper())
            if nt is None:
                continue
            lo, hi = int(rec[0]), int(rec[1])
            rows.append((4 if hi < 2 ** 32 else 6, lo, hi, nt))
    return RangeTable.from_rows(rows)


# ---------------------------------------------------------------------------- classifier
class NetworkIntel:
    """lookup(raw_ip, asn_hint) -> NetworkResult. Construct once and reuse (loads files at construction)."""

    def __init__(self, config: dict[str, Any] | None = None, demo_csv: str | Path | None = None,
                 ip2proxy_csv: str | Path | None = None, maxmind_asn_mmdb: str | Path | None = None,
                 cgnat_networks: Iterable[IpNet] | None = None) -> None:
        self.cfg = load_intel_config() if config is None else config
        src = self.cfg.get("sources", {})
        self.conf: dict[str, float] = {k: float(v) for k, v in self.cfg.get("confidence", {}).items()}
        self.asn_types: dict[str, str] = {parse_asn(k) or str(k): str(v) for k, v in (self.cfg.get("asn_types") or {}).items()}
        self.org_keywords: dict[str, list[str]] = {k: [w.lower() for w in v] for k, v in (self.cfg.get("org_keywords") or {}).items()}
        self.status: dict[str, str] = {}

        demo = demo_csv if demo_csv is not None else src.get("demo_csv")
        self.demo: list[_Row] = []
        if demo:
            p = Path(demo) if Path(demo).is_absolute() else RULES_DIR / demo
            self.demo = load_demo_csv(p)
            self.status["demo_list"] = f"{len(self.demo)} ranges"

        self.ip2proxy: RangeTable | None = None
        px = ip2proxy_csv if ip2proxy_csv is not None else src.get("ip2proxy_csv")
        if px:
            try:
                types = {str(k).upper(): str(v) for k, v in (self.cfg.get("ip2proxy_types") or {}).items()}
                self.ip2proxy = load_ip2proxy_csv(px, types)
                self.status["ip2proxy"] = f"{len(self.ip2proxy)} ranges"
            except OSError as e:
                self.status["ip2proxy"] = f"unavailable ({type(e).__name__})"

        self.mmdb: Any = None
        mm = maxmind_asn_mmdb if maxmind_asn_mmdb is not None else src.get("maxmind_asn_mmdb")
        if mm:
            try:
                import maxminddb  # optional dependency, not in requirements
                self.mmdb = maxminddb.open_database(str(mm))
                self.status["maxmind_asn"] = "loaded"
            except ImportError:
                self.status["maxmind_asn"] = "unavailable (maxminddb not installed)"
            except (OSError, ValueError) as e:
                self.status["maxmind_asn"] = f"unavailable ({type(e).__name__})"

        if cgnat_networks is None:
            from engine.graph.resolve import load_cgnat_networks
            cgnat_networks = load_cgnat_networks()
        self.cgnat: list[IpNet] = list(cgnat_networks)

    # ------------------------------------------------------------------ helpers
    def _c(self, source: str, default: float = 0.5) -> float:
        return self.conf.get(source, default)

    def classify_org(self, org: str | None) -> str | None:
        o = (org or "").lower()
        for nt in ("vpn", "hosting", "mobile"):                 # most specific anonymiser first
            if any(w in o for w in self.org_keywords.get(nt, [])):
                return nt
        return None

    # ------------------------------------------------------------------ lookup
    def lookup(self, raw_ip: str | None, asn_hint: str | None = None) -> NetworkResult:
        if not raw_ip:
            return UNKNOWN
        try:
            ip = ipaddress.ip_address(str(raw_ip).strip())
        except ValueError:
            return UNKNOWN
        for row in self.demo:
            if ip.version == row.net.version and ip in row.net:
                return NetworkResult(row.network_type, "demo_list", min(row.confidence, 1.0), row.tz, row.asn)
        if self.ip2proxy is not None:
            nt = self.ip2proxy.lookup(ip)
            if nt is not None:
                return NetworkResult(nt, "ip2proxy", self._c("ip2proxy", 0.8))
        if self.mmdb is not None:
            try:
                rec = self.mmdb.get(str(ip)) or {}
            except ValueError:
                rec = {}
            num = rec.get("autonomous_system_number")
            if num is not None:
                asn = parse_asn(int(num))
                nt = self.asn_types.get(asn or "") or self.classify_org(rec.get("autonomous_system_organization"))
                if nt is not None:
                    return NetworkResult(nt, "maxmind_asn", self._c("maxmind_asn", 0.6), None, asn)
                return NetworkResult("unknown", "maxmind_asn", self._c("maxmind_asn_unmatched", 0.2), None, asn)
        if any(ip.version == n.version and ip in n for n in self.cgnat):
            return NetworkResult("mobile", "cgnat_list", self._c("cgnat_list", 0.6))
        asn = parse_asn(asn_hint)
        if asn and asn in self.asn_types:
            return NetworkResult(self.asn_types[asn], "asn_map", self._c("asn_map", 0.4), None, asn)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return NetworkResult("unknown", "special", self._c("special", 0.3))
        return UNKNOWN
