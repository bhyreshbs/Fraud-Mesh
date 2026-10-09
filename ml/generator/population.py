"""Customer population for the synthetic generator (PRD §12.1).

Each customer gets a home city with coordinates, a home IP in its own /24, 1–2 devices and an ASN, a median login
hour near 09:00 or 20:00, a log-normal median UPI amount around ₹8,000 and 3–10 regular payees.
"""
from __future__ import annotations

import ipaddress
import math
import random
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from engine.graph.resolve import load_cgnat_networks

CITIES: dict[str, tuple[float, float]] = {
    "Bengaluru": (12.9716, 77.5946), "Mysuru": (12.2958, 76.6394), "Chennai": (13.0827, 80.2707),
    "Hyderabad": (17.3850, 78.4867), "Pune": (18.5204, 73.8567)}
# Residential broadband / mobile ASNs and the first octet their customer /24s are drawn from.
ASNS: list[tuple[str, int]] = [("AS24560 Airtel", 122), ("AS55836 Jio", 49), ("AS9829 BSNL", 117),
                               ("AS18209 ACT", 106), ("AS17488 Hathway", 183)]
LOGIN_HOUR_MODES = (9.0, 20.0)
MEDIAN_UPI_RUPEES = 8000.0
NICKNAMES = ("Rent", "Milk", "Maid", "Electricity", "Mom", "Dad", "Gym", "Tuition", "Grocer", "Landlord", "Sister",
             "Brother", "Driver", "Cook", "Society", "Pharmacy", "Tailor", "Friend")
SCENARIO_DIR = Path(__file__).resolve().parents[2] / "scenarios"

# Priya (PRD §4 demo identities) is one of the generated customers, so the demo victim has 14 days of
# ordinary history. She is never chosen as an attack victim. See docs/CONTRACT_REQUESTS.md.
PRIYA = {"customer_ref": "C-1042", "account_ref": "A-88213", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946,
         "home_ip": "49.207.10.21", "asn": "AS24560 Airtel", "devices": ["fp_priya_phone", "fp_priya_laptop"],
         "login_hour": 20.0}


@dataclass
class Customer:
    customer_ref: str
    account_ref: str
    city: str
    lat: float
    lon: float
    home_ip: str
    asn: str
    devices: list[str]
    login_hour: float
    median_amount_paise: int
    payees: list[str]
    nicknames: dict[str, str] = field(default_factory=dict)
    is_demo: bool = False


def reserved_networks() -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Networks generated customers must never use: CGNAT ranges and every IP named in a scenario file."""
    nets = set(load_cgnat_networks())
    for path in sorted(SCENARIO_DIR.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for ident in (raw.get("identities") or {}).values():
            ip = ((ident or {}).get("context") or {}).get("ip")
            if ip:
                nets.add(ipaddress.ip_network(f"{ip}/24", strict=False))
        for item in (raw.get("steps") or []) + (raw.get("preload") or []):
            ip = (item.get("payload") or {}).get("src_ip")
            if ip:
                nets.add(ipaddress.ip_network(f"{ip}/24", strict=False))
    return nets


class NetworkAllocator:
    """Hands out distinct /24s, so no two generated customers (or mules) ever share an IP node (PRD §10.2)."""

    _SPAN = 150 * 256

    def __init__(self) -> None:
        self._k = 0
        self._reserved = reserved_networks()

    def next_ip(self, first_octet: int, rng: random.Random) -> str:
        while True:
            if self._k >= self._SPAN:
                raise ValueError(f"the generator supports at most {self._SPAN} distinct customer networks")
            b, c = 100 + self._k // 256, self._k % 256
            self._k += 1
            net = ipaddress.ip_network(f"{first_octet}.{b}.{c}.0/24")
            if net not in self._reserved:
                return f"{first_octet}.{b}.{c}.{rng.randint(2, 254)}"


def new_device_id(rng: random.Random) -> str:
    return f"fp_{rng.getrandbits(48):012x}"


def new_external_account(rng: random.Random, prefix: str = "P") -> str:
    return f"A-{prefix}{rng.randrange(10**8, 10**9)}"


def _median_amount(rng: random.Random) -> int:
    rupees = math.exp(rng.gauss(math.log(MEDIAN_UPI_RUPEES), 0.45))
    return max(500, round(rupees)) * 100


def _payees(rng: random.Random) -> tuple[list[str], dict[str, str]]:
    payees: list[str] = []
    target = rng.randint(3, 10)
    while len(payees) < target:
        acct = new_external_account(rng)
        if acct not in payees:
            payees.append(acct)
    return payees, {p: rng.choice(NICKNAMES) for p in payees}


def build_population(n: int, rng: random.Random, alloc: NetworkAllocator) -> list[Customer]:
    """n customers; the first is Priya (demo identity), the rest are C-100001 … with fresh identities."""
    if n < 1:
        raise ValueError("--customers must be at least 1")
    out: list[Customer] = []
    payees, nicks = _payees(rng)
    out.append(Customer(customer_ref=PRIYA["customer_ref"], account_ref=PRIYA["account_ref"], city=PRIYA["city"],
                        lat=PRIYA["lat"], lon=PRIYA["lon"], home_ip=PRIYA["home_ip"], asn=PRIYA["asn"],
                        devices=list(PRIYA["devices"]), login_hour=PRIYA["login_hour"],
                        median_amount_paise=_median_amount(rng), payees=payees, nicknames=nicks, is_demo=True))
    for i in range(1, n):
        city = rng.choice(sorted(CITIES))
        lat, lon = CITIES[city]
        asn, first_octet = rng.choice(ASNS)
        payees, nicks = _payees(rng)
        out.append(Customer(
            customer_ref=f"C-{100000 + i}", account_ref=f"A-{500000 + i}", city=city,
            lat=round(lat + rng.gauss(0, 0.03), 4), lon=round(lon + rng.gauss(0, 0.03), 4),
            home_ip=alloc.next_ip(first_octet, rng), asn=asn,
            devices=[new_device_id(rng) for _ in range(rng.randint(1, 2))],
            login_hour=(rng.choice(LOGIN_HOUR_MODES) + rng.gauss(0, 0.75)) % 24,
            median_amount_paise=_median_amount(rng), payees=payees, nicknames=nicks))
    return out
