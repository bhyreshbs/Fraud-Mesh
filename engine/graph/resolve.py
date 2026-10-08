"""Entity resolution: which graph edges one StoredEvent creates (PRD §7.1) and which nodes are CGNAT.

Pure functions, no graph state. engine.graph.store.EntityGraph applies the edges and adds the derived
SHARES_DEVICE edges (§10.2), which need the graph's history.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from pathlib import Path

from engine.common.tokenize import tok
from engine.contracts import Edge, StoredEvent

CGNAT_FILE = Path(__file__).resolve().parents[1] / "detectors" / "rules" / "cgnat.txt"

# PRD §7.1: edge confidence by edge type.
CONF_OWNS = 1.0
CONF_LOGGED_IN_FROM = 0.9
CONF_CONNECTED_VIA = 0.5
CONF_CONNECTED_VIA_CGNAT = 0.0
CONF_RESET = 0.9
CONF_HAS_PHONE = 1.0
CONF_ADDED_PAYEE = 0.9
CONF_SENT = 1.0
CONF_ACTED_FROM = 0.7
CONF_ACCESSED = 0.8
CONF_SHARES_DEVICE = 0.9          # §10.2 derived edge

_MAX_EXPANDED = 65536             # guard against a typo like 0.0.0.0/0 in cgnat.txt


def kind_of(token: str) -> str:
    """Entity kind of a token, e.g. 'dev' for 'dev:k3x7q2mzt9b4wd1c'."""
    return token.split(":", 1)[0]


def load_cgnat_networks(path: str | Path = CGNAT_FILE) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse cgnat.txt into /24 (IPv4) and /64 (IPv6) networks, the granularity tokens are computed at."""
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        net = ipaddress.ip_network(entry, strict=False)
        unit = 24 if net.version == 4 else 64
        if net.prefixlen >= unit:
            nets.append(ipaddress.ip_network(f"{net.network_address}/{unit}", strict=False))
            continue
        if 2 ** (unit - net.prefixlen) > _MAX_EXPANDED:
            raise ValueError(f"cgnat.txt entry {entry!r} expands to more than {_MAX_EXPANDED} networks")
        nets.extend(net.subnets(new_prefix=unit))
    return nets


def cgnat_tokens(networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None) -> frozenset[str]:
    """ip tokens of the CGNAT networks. tok('ip', …) normalises to /24 or /64, so the network address is enough."""
    nets = load_cgnat_networks() if networks is None else networks
    return frozenset(tok("ip", str(n.network_address)) for n in nets)


def _edge(src: str, dst: str, edge_type: str, confidence: float, ev: StoredEvent) -> Edge:
    return Edge(src=src, dst=dst, edge_type=edge_type, confidence=confidence, first_seen=ev.occurred_at,
                last_seen=ev.occurred_at, count=1, source_event_ids=[ev.event_id])


def edges_for_event(ev: StoredEvent, cgnat: frozenset[str] = frozenset()) -> list[Edge]:
    """The §7.1 edges for one event, each as a single observation (count 1, this event's id).

    A failed login proves only that a device tried an account, so it creates OWNS and CONNECTED_VIA but
    not LOGGED_IN_FROM (see docs/CONTRACT_REQUESTS.md). Self-loops are never created.
    """
    p = ev.payload
    out: list[Edge] = []

    def add(src: str | None, dst: str | None, edge_type: str, conf: float) -> None:
        if src and dst and src != dst:
            out.append(_edge(src, dst, edge_type, conf, ev))

    if ev.event_type == "login":
        if p.get("result") == "success":
            add(ev.account, ev.device, "LOGGED_IN_FROM", CONF_LOGGED_IN_FROM)
        conf = CONF_CONNECTED_VIA_CGNAT if ev.ip in cgnat else CONF_CONNECTED_VIA
        add(ev.device, ev.ip, "CONNECTED_VIA", conf)
        add(ev.customer, ev.account, "OWNS", CONF_OWNS)
    elif ev.event_type == "mfa_change":
        add(ev.device, p.get("new_phone"), "RESET", CONF_RESET)
        add(ev.customer, p.get("new_phone"), "HAS_PHONE", CONF_HAS_PHONE)
    elif ev.event_type == "payee_added":
        add(ev.account, p.get("payee_account"), "ADDED_PAYEE", CONF_ADDED_PAYEE)
    elif ev.event_type == "transaction":
        add(ev.account, p.get("payee_account"), "SENT", CONF_SENT)
    elif ev.event_type == "cloud_audit":
        add(p.get("actor_identity"), p.get("src_ip"), "ACTED_FROM", CONF_ACTED_FROM)
        add(p.get("actor_identity"), p.get("target_customer"), "ACCESSED", CONF_ACCESSED)
    # mfa_challenge, sim_signal, kyc_result, profile_change, network_ids_alert, step_up_result: no edges.
    return out
