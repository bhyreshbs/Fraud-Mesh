"""v3 phase 5: offline network intelligence (engine/netintel) and geo-confidence."""
from __future__ import annotations

import pytest

from engine.netintel.intel import NetworkIntel, geo_confidence_factor, load_ip2proxy_csv, parse_asn

INTEL = NetworkIntel()


@pytest.mark.parametrize("ip,asn,expected,source", [
    ("185.220.101.7", "AS64500 HostCo", "hosting", "demo_list"),       # Midnight ATO attacker (PRD §4)
    ("49.207.10.21", "AS24560 Airtel", "mobile", "demo_list"),         # Priya
    ("103.21.4.9", "AS55836 Jio", "mobile", "demo_list"),              # Ravi / mule
    ("192.0.2.44", None, "vpn", "demo_list"),
    ("198.51.100.9", None, "tor", "demo_list"),
    ("203.0.113.200", None, "hosting", "demo_list"),
    ("2001:db8::1", None, "hosting", "demo_list"),
    ("49.36.128.77", None, "mobile", "cgnat_list"),                    # cgnat.txt
    ("45.12.1.1", "AS14061 DigitalOcean", "hosting", "asn_map"),        # sender-supplied ASN, low confidence
    ("10.1.2.3", None, "unknown", "special"),
    ("8.8.4.4", None, "unknown", "none"),
])
def test_lookup_types_and_sources(ip, asn, expected, source):
    r = INTEL.lookup(ip, asn)
    assert (r.network_type, r.network_source) == (expected, source)
    assert 0.0 <= r.network_confidence <= 1.0


def test_bad_or_missing_ip_is_unknown():
    assert INTEL.lookup(None).network_type == "unknown"
    assert INTEL.lookup("not-an-ip").network_type == "unknown"


def test_enrichment_dict_carries_timezone_only_when_known():
    assert INTEL.lookup("185.220.101.7").as_enrichment() == {
        "network_type": "hosting", "network_source": "demo_list", "network_confidence": 0.9, "ip_timezone": "Europe/Berlin"}
    assert "ip_timezone" not in INTEL.lookup("8.8.4.4").as_enrichment()


def test_ip2proxy_csv_range_loader(tmp_path):
    f = tmp_path / "px2.csv"
    f.write_text('"16777216","16777471","DCH","US","United States"\n'           # 1.0.0.0/24
                 '"16777472","16777727","-","-","-"\n'                            # not a proxy
                 '"3232235776","3232236031","TOR","DE","Germany"\n', encoding="utf-8")   # 192.168.1.0/24
    table = load_ip2proxy_csv(f, {"DCH": "hosting", "TOR": "tor"})
    assert len(table) == 2
    intel = NetworkIntel(demo_csv="", ip2proxy_csv=f)
    assert intel.lookup("1.0.0.99").network_type == "hosting" and intel.lookup("1.0.0.99").network_source == "ip2proxy"
    assert intel.lookup("192.168.1.5").network_type == "tor"
    assert intel.lookup("1.0.1.5").network_source != "ip2proxy"


def test_missing_optional_databases_degrade(tmp_path):
    intel = NetworkIntel(ip2proxy_csv=tmp_path / "absent.csv", maxmind_asn_mmdb=tmp_path / "absent.mmdb")
    assert intel.status["ip2proxy"].startswith("unavailable")
    assert intel.status["maxmind_asn"].startswith("unavailable")
    assert intel.lookup("185.220.101.7").network_type == "hosting"


def test_parse_asn():
    assert parse_asn("AS64500 HostCo") == "AS64500" and parse_asn(24560) == "AS24560" and parse_asn("x") is None


def test_geo_confidence_factor():
    assert geo_confidence_factor(None, None) == 1.0                 # not enriched (direct mode, golden fixtures)
    assert geo_confidence_factor("mobile", 0.8) == 1.0
    assert geo_confidence_factor("residential", 0.9) == 1.0
    assert geo_confidence_factor("hosting", 0.9) == pytest.approx(0.3)
    assert geo_confidence_factor("vpn", 0.9) == pytest.approx(0.3)
    assert geo_confidence_factor("tor", 0.9) == pytest.approx(0.2)
    assert geo_confidence_factor("unknown", 0.0) == pytest.approx(0.7)   # low-confidence unknown
    assert geo_confidence_factor("unknown", 0.5) == 1.0
