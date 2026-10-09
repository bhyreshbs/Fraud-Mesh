"""EntityGraph.is_hub() caching (added by DEV1 at CP1 for decision latency; DEV2 to review).

The cache must never change an answer: after every edge added, every node's cached is_hub() equals a fresh
len(linked_customers(node)) >= HUB_MIN_CUSTOMERS on the same graph."""
from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from engine.contracts import Edge
from engine.graph.store import HUB_MIN_CUSTOMERS, EntityGraph

T0 = datetime(2026, 10, 1, tzinfo=UTC)


def _edge(src: str, dst: str, et: str, i: int) -> Edge:
    t = T0 + timedelta(minutes=i)
    return Edge(src=src, dst=dst, edge_type=et, confidence=0.9, first_seen=t, last_seen=t, count=1, source_event_ids=[f"evt_{i:08d}x"])


def _random_edges(rng: random.Random, n: int):
    """Customers own accounts, log in from devices (some shared), connect via IPs, pay a few popular payees —
    enough sharing that several devices, IPs and payees become hubs part-way through."""
    for i in range(n):
        c = rng.randrange(120)
        cust, acct = f"cust:c{c:03d}", f"acct:a{c:03d}"
        dev = f"dev:d{rng.randrange(40) if rng.random() < 0.3 else 100 + c:03d}"
        ip = f"ip:i{rng.randrange(15):03d}"
        kind = rng.random()
        if kind < 0.25:
            yield _edge(cust, acct, "OWNS", i)
        elif kind < 0.55:
            yield _edge(acct, dev, "LOGGED_IN_FROM", i)
        elif kind < 0.75:
            yield _edge(dev, ip, "CONNECTED_VIA", i)
        elif kind < 0.9:
            yield _edge(acct, f"acct:shop{rng.randrange(4)}", "SENT", i)
        else:
            yield _edge(dev, f"phone:p{rng.randrange(10)}", "RESET", i)


def test_cached_is_hub_matches_a_fresh_computation_after_every_edge():
    rng = random.Random(7)
    g = EntityGraph(cgnat=frozenset())
    became_hub = 0
    for i, e in enumerate(_random_edges(rng, 3000)):
        g._merge(e)
        nodes = list(g.g.nodes) if i % 25 == 0 else [e.src, e.dst] + list(g.g.adj[e.src]) + list(g.g.adj[e.dst])
        for node in nodes:
            cached = g.is_hub(node)
            fresh = len(g.linked_customers(node)) >= HUB_MIN_CUSTOMERS
            assert cached == fresh, (i, node)
        became_hub = len(g._hubs)
    assert became_hub >= 5                                    # the scenario really exercised hub transitions


def test_load_clears_the_cache():
    g = EntityGraph(cgnat=frozenset())
    edges = [_edge(f"cust:c{i:03d}", f"acct:a{i:03d}", "OWNS", i) for i in range(30)]
    edges += [_edge(f"acct:a{i:03d}", "dev:shared", "LOGGED_IN_FROM", 100 + i) for i in range(30)]
    g.load(edges, [])
    assert g.is_hub("dev:shared")
    g.load(edges[:5] + edges[30:35], [])
    assert not g.is_hub("dev:shared")
