"""In-memory entity graph (PRD §10.2): networkx.MultiGraph keyed by token, rebuilt from the Store's edges.

Nodes carry `kind` and `seed`; edges are keyed by edge_type and carry the Edge fields. The graph applies
edges with the same upsert rule as the Store (§8), so the in-memory graph and the edges table never drift.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from datetime import timedelta

import networkx as nx

from engine.contracts import Edge, StoredEvent
from engine.graph.resolve import CONF_SHARES_DEVICE, cgnat_tokens, edges_for_event, kind_of

HUB_MIN_CUSTOMERS = 21                 # "linked to more than 20 distinct customers"
SHARES_DEVICE_WINDOW = timedelta(days=30)
EXCLUDED_KINDS = frozenset({"mer", "cid"})
MAX_SOURCE_EVENT_IDS = 50               # same cap as the edges table upsert


class EntityGraph:
    def __init__(self, cgnat: frozenset[str] | None = None) -> None:
        self.g = nx.MultiGraph()
        self.cgnat: frozenset[str] = cgnat_tokens() if cgnat is None else cgnat

    # ------------------------------------------------------------------ building
    def load(self, edges: Iterable[Edge], seeds: Iterable[str]) -> None:
        """Rebuild from store.load_edges() and store.list_fraud_seeds(). Idempotent."""
        self.g.clear()
        for e in edges:
            self._merge(e)
        self.set_seeds(list(seeds), True)

    def apply(self, event: StoredEvent) -> list[Edge]:
        """Add the event's §7.1 edges and any derived SHARES_DEVICE edges; return them for store.upsert_edges.

        Each returned Edge is this event's observation (count 1, [event_id]); the Store's upsert and
        the graph's merge both turn it into the accumulated edge.
        """
        new = edges_for_event(event, self.cgnat)
        for e in new:
            self._merge(e)
        derived = self._shares_device(event, new)
        for e in derived:
            self._merge(e)
        return new + derived

    def set_seeds(self, entity_ids: list[str], value: bool = True) -> None:
        for t in entity_ids:
            self._ensure_node(t)
            self.g.nodes[t]["seed"] = value

    @property
    def seeds(self) -> set[str]:
        return {n for n, s in self.g.nodes(data="seed") if s}

    def is_seed(self, token: str) -> bool:
        return bool(self.g.nodes[token].get("seed")) if token in self.g else False

    def edges(self) -> list[Edge]:
        return [self._to_edge(d) for _, _, d in self.g.edges(data=True)]

    def get_edge(self, src: str, dst: str, edge_type: str) -> Edge | None:
        for key in (edge_type, edge_type + ":rev"):
            d = self.g.get_edge_data(src, dst, key)
            if d is not None and d["src"] == src and d["dst"] == dst:
                return self._to_edge(d)
        return None

    def _ensure_node(self, token: str) -> None:
        if token not in self.g:
            self.g.add_node(token, kind=kind_of(token), seed=False)

    def _key(self, e: Edge) -> str:
        # The graph is undirected, but the edges table keys on (src, dst, edge_type): the reverse direction of
        # an existing edge (B SENT A after A SENT B) gets its own key so neither row is lost.
        d = self.g.get_edge_data(e.src, e.dst, e.edge_type)
        if d is None or (d["src"] == e.src and d["dst"] == e.dst):
            return e.edge_type
        return e.edge_type + ":rev"

    def _merge(self, e: Edge) -> None:
        self._ensure_node(e.src)
        self._ensure_node(e.dst)
        key = self._key(e)
        d = self.g.get_edge_data(e.src, e.dst, key)
        if d is None:
            self.g.add_edge(e.src, e.dst, key=key, src=e.src, dst=e.dst, edge_type=e.edge_type, confidence=e.confidence,
                            first_seen=e.first_seen, last_seen=e.last_seen, count=e.count,
                            source_event_ids=list(e.source_event_ids)[:MAX_SOURCE_EVENT_IDS])
            return
        d["last_seen"] = max(d["last_seen"], e.last_seen)
        d["count"] += 1
        d["confidence"] = max(d["confidence"], e.confidence)
        d["source_event_ids"] = (d["source_event_ids"] + list(e.source_event_ids))[:MAX_SOURCE_EVENT_IDS]

    @staticmethod
    def _to_edge(d: dict) -> Edge:
        return Edge(src=d["src"], dst=d["dst"], edge_type=d["edge_type"], confidence=d["confidence"],
                    first_seen=d["first_seen"], last_seen=d["last_seen"], count=d["count"],
                    source_event_ids=list(d["source_event_ids"]))

    # ------------------------------------------------------------------ SHARES_DEVICE
    def _typed_neighbours(self, token: str, edge_type: str, kind: str | None = None) -> list[tuple[str, dict]]:
        out = []
        for nbr, keyed in self.g.adj[token].items():
            if kind is not None and kind_of(nbr) != kind:
                continue
            for d in keyed.values():
                if d["edge_type"] == edge_type:
                    out.append((nbr, d))
        return out

    def _owners(self, acct: str) -> set[str]:
        return {c for c, _ in self._typed_neighbours(acct, "OWNS", "cust")}

    def customers_of_device(self, dev: str, since=None) -> set[str]:
        """Customers owning an account that logged in from this device (LOGGED_IN_FROM last_seen >= since)."""
        if dev not in self.g:
            return set()
        out: set[str] = set()
        for acct, d in self._typed_neighbours(dev, "LOGGED_IN_FROM", "acct"):
            if since is None or d["last_seen"] >= since:
                out |= self._owners(acct)
        return out

    def _shares_device(self, event: StoredEvent, new: list[Edge]) -> list[Edge]:
        if not event.customer or not event.device:
            return []
        if not any(e.edge_type == "LOGGED_IN_FROM" and e.dst == event.device for e in new):
            return []
        customers = self.customers_of_device(event.device, event.occurred_at - SHARES_DEVICE_WINDOW)
        if len(customers) < 2 or len(customers) >= HUB_MIN_CUSTOMERS or event.customer not in customers:
            return []                     # a hub device links nobody (§10.2)
        out = []
        for other in sorted(customers - {event.customer}):
            a, b = sorted((event.customer, other))
            out.append(Edge(src=a, dst=b, edge_type="SHARES_DEVICE", confidence=CONF_SHARES_DEVICE,
                            first_seen=event.occurred_at, last_seen=event.occurred_at, count=1,
                            source_event_ids=[event.event_id]))
        return out

    # ------------------------------------------------------------------ hubs and exclusions
    def linked_customers(self, token: str, limit: int = HUB_MIN_CUSTOMERS) -> set[str]:
        """Distinct customers this node links to (stops counting at `limit`).

        cust: itself. acct: its owners and the owners of accounts it paid or was paid by. dev: owners of the
        accounts that logged in from it. ip: the customers of every device connected via it. phone: customers
        holding it and customers of the devices that reset to it. Other kinds: adjacent customers.
        """
        if token not in self.g:
            return set()
        kind = kind_of(token)
        if kind == "cust":
            return {token}
        out: set[str] = set()

        def add(cs: set[str]) -> bool:
            out.update(cs)
            return len(out) >= limit

        if kind == "acct":
            if add(self._owners(token)):
                return out
            for nbr, keyed in self.g.adj[token].items():
                if kind_of(nbr) == "acct" and any(d["edge_type"] in ("SENT", "ADDED_PAYEE") for d in keyed.values()):
                    if add(self._owners(nbr)):
                        return out
        elif kind == "dev":
            add(self.customers_of_device(token))
        elif kind == "ip":
            for dev, _ in self._typed_neighbours(token, "CONNECTED_VIA", "dev"):
                if add(self.customers_of_device(dev)):
                    return out
        elif kind == "phone":
            if add({c for c, _ in self._typed_neighbours(token, "HAS_PHONE", "cust")}):
                return out
            for dev, _ in self._typed_neighbours(token, "RESET", "dev"):
                if add(self.customers_of_device(dev)):
                    return out
        else:
            add({n for n in self.g.adj[token] if kind_of(n) == "cust"})
        return out

    def is_hub(self, token: str) -> bool:
        return len(self.linked_customers(token)) >= HUB_MIN_CUSTOMERS

    def is_excluded(self, token: str) -> bool:
        """Hubs, mer and cid nodes and CGNAT IPs never join cases and are never walked in seed searches."""
        return kind_of(token) in EXCLUDED_KINDS or token in self.cgnat or self.is_hub(token)

    # ------------------------------------------------------------------ searches
    def _devices_of_customer(self, cust: str) -> set[str]:
        devs: set[str] = set()
        for acct, _ in self._typed_neighbours(cust, "OWNS", "acct"):
            devs |= {d for d, _ in self._typed_neighbours(acct, "LOGGED_IN_FROM", "dev")}
        return devs

    def _shares_device_live(self, a: str, b: str) -> bool:
        """A SHARES_DEVICE edge counts only while the two customers still share a device that is not a hub;
        otherwise edges derived before a device became a hub would link its customers around the exclusion."""
        common = self._devices_of_customer(a) & self._devices_of_customer(b)
        return any(not self.is_excluded(d) for d in common)

    def _max_conf(self, a: str, b: str) -> float:
        """The strongest edge between two adjacent nodes, as used by the searches (-1 when none counts)."""
        best = -1.0
        for d in self.g.adj[a][b].values():
            if d["confidence"] > best and (d["edge_type"] != "SHARES_DEVICE" or self._shares_device_live(a, b)):
                best = d["confidence"]
        return best

    def neighbours_within(self, token: str, hops: int = 2, min_conf: float = 0.5) -> dict[str, int]:
        """Hop distance to every node reachable within `hops` over edges with confidence >= min_conf.

        Excluded nodes are neither returned nor walked through. The start token itself is not in the result.
        """
        if token not in self.g or hops < 1:
            return {}
        dist = {token: 0}
        frontier = deque([token])
        excluded: dict[str, bool] = {}
        while frontier:
            node = frontier.popleft()
            if dist[node] >= hops:
                continue
            for nbr in sorted(self.g.adj[node]):
                if nbr in dist or self._max_conf(node, nbr) < min_conf:
                    continue
                if nbr not in excluded:
                    excluded[nbr] = self.is_excluded(nbr)
                if excluded[nbr]:
                    continue
                dist[nbr] = dist[node] + 1
                frontier.append(nbr)
        del dist[token]
        return dist

    def seed_distance(self, token: str, max_hops: int = 3) -> tuple[int, list[str]] | None:
        """Shortest (distance, path from token to the seed) to any fraud seed, or None.

        Walks edges with confidence > 0, never through an excluded node. A seed token is at distance 0.
        Ties are broken by token order, so the result is deterministic.
        """
        if token not in self.g:
            return None
        if self.is_seed(token):
            return 0, [token]
        parent: dict[str, str | None] = {token: None}
        frontier = [token]
        excluded: dict[str, bool] = {}
        for depth in range(1, max_hops + 1):
            nxt: list[str] = []
            for node in frontier:
                for nbr in sorted(self.g.adj[node]):
                    if nbr in parent or self._max_conf(node, nbr) <= 0.0:
                        continue
                    if nbr not in excluded:
                        excluded[nbr] = self.is_excluded(nbr)
                    if excluded[nbr]:
                        continue
                    parent[nbr] = node
                    if self.is_seed(nbr):
                        path = [nbr]
                        while parent[path[-1]] is not None:
                            path.append(parent[path[-1]])
                        return depth, path[::-1]
                    nxt.append(nbr)
            frontier = nxt
            if not frontier:
                break
        return None
