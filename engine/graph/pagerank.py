"""Personalized PageRank over the time-decayed local graph (v3 phase 9.1, optional; mule.yaml `pagerank.enabled`).

The restart set is the "known bad" in the neighbourhood: fraud seeds plus accounts with a seed-independent mule signal
(engine/graph/mule.py). The score of a token is its PPR mass: how much of a random walk that keeps restarting at known
bad nodes ends up there. Edge weights are confidence decayed by event time (mule.decayed_weight). Only the ego graph
within `radius` hops (excluded nodes are not walked, at most `max_nodes` nodes) is ranked, so the cost per call is
bounded; a full-graph PPR on every event would not fit the latency budget.

It is OFF by default: on the v3 tests and the seed-7 benchmark it changed no detection outcome (every PPR-positive
payee already had a seed path or a mule signal), so it is kept as an analyst/experiment tool, not a live rule.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime

import networkx as nx

from engine.graph.mule import MuleAnalytics, MuleConfig, decayed_weight
from engine.graph.resolve import kind_of
from engine.graph.store import EntityGraph


def local_graph(graph: EntityGraph, token: str, now: datetime, radius: int, max_nodes: int, half_life_h: float) -> nx.Graph:
    g = graph.g
    out = nx.Graph()
    if token not in g:
        return out
    dist = {token: 0}
    frontier = deque([token])
    while frontier and len(dist) < max_nodes:
        node = frontier.popleft()
        if dist[node] >= radius:
            continue
        for nbr in sorted(g.adj[node]):
            if nbr in dist or graph.is_excluded(nbr):
                continue
            dist[nbr] = dist[node] + 1
            frontier.append(nbr)
            if len(dist) >= max_nodes:
                break
    for a in dist:
        for b, keyed in g.adj[a].items():
            if b not in dist or a >= b:
                continue
            w = max((decayed_weight(d, now, half_life_h) for d in keyed.values() if d["first_seen"] <= now), default=0.0)
            if w > 0:
                out.add_edge(a, b, weight=w)
    out.add_node(token)
    return out


def ppr_proximity(graph: EntityGraph, token: str, now: datetime, cfg: MuleConfig) -> float:
    """PPR mass of `token` with restarts at the seeds / mule-signalled accounts of its neighbourhood (0 if none)."""
    pr = cfg.pagerank or {}
    sub = local_graph(graph, token, now, int(pr.get("radius", 3)), int(pr.get("max_nodes", 400)), cfg.decay_half_life_h)
    mule = MuleAnalytics(graph, cfg)
    bad = {n for n in sub.nodes if n != token and (graph.is_seed(n) or (kind_of(n) == "acct" and mule.signals(n, now)))}
    if not bad or sub.number_of_edges() == 0:
        return 0.0
    scores = nx.pagerank(sub, alpha=float(pr.get("alpha", 0.85)), personalization=dict.fromkeys(bad, 1.0),
                         weight="weight", max_iter=200, tol=1e-8)
    return float(scores.get(token, 0.0))
