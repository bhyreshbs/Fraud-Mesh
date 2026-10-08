"""Pipeline (PRD §6.2, §10.1): the engine entry point Dev 1's worker calls once per event.

process() runs, inside one store.transaction():
    graph.apply → upsert_edges → features (compute, then update) → reliability snapshot → detectors in order →
    for each evidence: joiner.attach → fusion.recompute → stages.update → policy.decide → save_case → CaseUpdate
Transactions get a payment_outcome from the case's payment state.

The seven real detectors and the feature windows arrive in D2-P3; until then a Pipeline built with the frozen
signature Pipeline(store) runs the graph and case machinery with no detectors, and tests pass a FixtureDetector.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

from engine.cases.joiner import Joiner
from engine.cases.stages import Stages
from engine.contracts import CaseUpdate, Evidence, GraphEdge, GraphElements, GraphNode, Store, StoredEvent, summarize
from engine.detectors.base import Detector
from engine.fusion.fusion import Fusion
from engine.graph.resolve import kind_of
from engine.graph.store import EntityGraph
from engine.policy.policy import Policy

PAYMENT_OUTCOME = {"blocked": "blocked", "held": "held"}


class Features(Protocol):
    """§10.3 feature windows (D2-P3): compute from state before the event, then update with it."""

    def compute(self, event: StoredEvent) -> dict[str, Any]: ...
    def update(self, event: StoredEvent) -> None: ...
    def reset(self) -> None: ...


class Pipeline:
    def __init__(self, store: Store, detectors: Sequence[Detector] | None = None, features: Features | None = None) -> None:
        self.store = store
        self.graph = EntityGraph()
        self.detectors: list[Detector] = list(detectors) if detectors is not None else []
        self.features = features
        self.joiner = Joiner(store, self.graph)
        self.fusion = Fusion(store)
        self.stages = Stages()
        self.policy = Policy(store)
        self._ready = False

    # ------------------------------------------------------------------ lifecycle
    def startup(self) -> None:
        """Rebuild the graph from the edges table and seeds, and the feature windows from past events. Idempotent."""
        self._ready = False
        self.graph.load(self.store.load_edges(), self.store.list_fraud_seeds())
        if self.features is not None:
            self.features.reset()
            for ev in self.store.iter_events():
                self.features.update(ev)
        self._ready = True

    @property
    def ready(self) -> bool:
        return self._ready

    def set_seeds(self, entity_ids: list[str], value: bool = True) -> None:
        self.store.set_fraud_seeds(entity_ids, value)
        self.graph.set_seeds(entity_ids, value)

    # ------------------------------------------------------------------ §10.1
    def process(self, event: StoredEvent) -> list[CaseUpdate]:
        with self.store.transaction():
            new_edges = self.graph.apply(event)
            self.store.upsert_edges(new_edges)
            feats: dict[str, Any] = {}
            if self.features is not None:
                feats = self.features.compute(event)           # from state BEFORE this event
                self.features.update(event)
            rel = self.store.get_reliability()
            evidence: list[Evidence] = [e for d in self.detectors if event.event_type in d.handles
                                        for e in d.score(event, feats, self.graph, rel)]
            touched: dict[str, CaseUpdate] = {}
            for ev in evidence:
                case = self.joiner.attach(ev)
                if case is None:
                    continue
                fused = self.fusion.recompute(case)
                ev.contribution = fused.contributions[ev.evidence_id]
                self.stages.update(case, ev)
                decision, step_up = self.policy.decide(case, event, ev)
                self.store.save_case(case)
                prev = touched.get(case.case_id)
                touched[case.case_id] = CaseUpdate(
                    case=summarize(case), event_id=event.event_id,
                    new_evidence_ids=(prev.new_evidence_ids if prev else []) + [ev.evidence_id],
                    decision_id=decision.decision_id, step_up=step_up)
            if event.event_type == "transaction":
                for u in touched.values():
                    u.payment_outcome = PAYMENT_OUTCOME.get(u.case.payment_state, "completed")
            return list(touched.values())

    # ------------------------------------------------------------------ console graph
    def graph_elements(self, case_id: str, hops: int = 2, max_nodes: int = 300) -> GraphElements:
        """The case's entities plus everything within `hops` (breadth-first, case entities first), capped at
        max_nodes. Excluded nodes (hubs, CGNAT IPs, cid, mer) are shown but never expanded. Unknown case → KeyError."""
        case = self.store.get_case(case_id)
        if case is None:
            raise KeyError(case_id)
        g = self.graph.g
        in_case = set(case.entities)
        dist: dict[str, int] = {t: 0 for t in sorted(in_case) if t in g}
        frontier = list(dist)
        for depth in range(1, hops + 1):
            nxt = []
            for node in frontier:
                if self.graph.is_excluded(node) and node not in in_case:
                    continue
                for nbr in sorted(g.adj[node]):
                    if nbr not in dist:
                        dist[nbr] = depth
                        nxt.append(nbr)
            frontier = nxt
        keep = sorted(dist, key=lambda t: (dist[t], t))[:max_nodes]
        kept = set(keep)
        for t in sorted(in_case - set(dist)):                  # case entities never seen in an edge
            if len(keep) < max_nodes:
                keep.append(t)
                kept.add(t)
        nodes = [GraphNode(id=t, label=f"{kind_of(t)} …{t.split(':', 1)[-1][-6:]}", kind=kind_of(t),
                           seed=self.graph.is_seed(t), in_case=t in in_case) for t in keep]
        found: dict[str, GraphEdge] = {}
        for a in keep:
            if a not in g:
                continue
            for b, keyed in g.adj[a].items():
                if b not in kept:
                    continue
                for d in keyed.values():
                    eid = f"{d['src']}|{d['edge_type']}|{d['dst']}"
                    found[eid] = GraphEdge(id=eid, source=d["src"], target=d["dst"], edge_type=d["edge_type"],
                                           confidence=d["confidence"])
        edges = [found[k] for k in sorted(found)]
        return GraphElements(nodes=nodes, edges=edges)
