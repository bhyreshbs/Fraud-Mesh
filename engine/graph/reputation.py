"""Payee reputation: tells an established, popular payee account apart from a mule (DEV1 FW, pending Dev 2 review).

Why: a payee account with 2–20 payers is not a §10.2 hub, so the §10.6 joiner chains every payer's case through it.
That is what mule_fanin needs (12 victims → one mule → one case), but a popular legitimate P2P payee (13–20 long-standing
payers) then chains unrelated customers into one ever-growing case (docs/CONTRACT_REQUESTS.md, CP1 "Shared-payee
chaining"). Reputation separates the two from graph history alone:

    established account     oldest incident edge >= min_account_age_days old
    long-standing payers    >= min_tenured_payers payers whose first ADDED_PAYEE/SENT to it is >= min_payer_tenure_days
                            old, and they are >= min_tenured_share of all payers
    no burst of new payers  payers first seen in the last recent_window_h <= max_new_payer_share of all payers
    no pass-through         it did not start paying a new counterparty in the window while also gaining a new payer
    clean neighbourhood     not a fraud seed, and no seed within seed_clear_hops hops

Every input is an edge (first_seen, src/dst, type) or a seed flag, so Pipeline.startup() rebuilds it from the edges
table, and "now" is always the processed event's time (never the wall clock). Thresholds live in
engine/detectors/rules/payee_reputation.yaml. Nothing here is a contract field: reputation only changes which nodes
the joiner walks and whether MULE_FLOW fires.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path

import yaml

from engine.graph.resolve import kind_of
from engine.graph.store import EntityGraph

CONFIG_FILE = Path(__file__).resolve().parents[1] / "detectors" / "rules" / "payee_reputation.yaml"
PAYER_EDGES = frozenset({"SENT", "ADDED_PAYEE"})


@dataclass(frozen=True)
class ReputationConfig:
    min_account_age_days: float
    min_payer_tenure_days: float
    min_tenured_payers: int
    min_tenured_share: float
    recent_window_h: float
    max_new_payer_share: float
    seed_clear_hops: int


@lru_cache(maxsize=4)
def load_config(path: str | Path = CONFIG_FILE) -> ReputationConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return ReputationConfig(**{k: raw[k] for k in ReputationConfig.__dataclass_fields__})


@dataclass(frozen=True)
class PayeeProfile:
    """The reputation inputs of one acct node at one moment (also useful for tests and explanations)."""
    account_age_days: float
    payers: int
    tenured_payers: int
    new_payers_recent: int
    new_outbound_recent: int
    seed_nearby: bool

    @property
    def tenured_share(self) -> float:
        return self.tenured_payers / self.payers if self.payers else 0.0

    @property
    def new_payer_share(self) -> float:
        return self.new_payers_recent / self.payers if self.payers else 0.0


class PayeeReputation:
    def __init__(self, graph: EntityGraph, config: ReputationConfig | None = None) -> None:
        self.graph = graph
        self.cfg = load_config() if config is None else config

    def profile(self, token: str, now: datetime) -> PayeeProfile | None:
        """None for a token that is not an acct node in the graph."""
        g = self.graph.g
        if kind_of(token) != "acct" or token not in g:
            return None
        recent = now - timedelta(hours=self.cfg.recent_window_h)
        oldest: datetime | None = None
        payer_first: dict[str, datetime] = {}
        new_outbound = 0
        for _, keyed in g.adj[token].items():
            for d in keyed.values():
                first = d["first_seen"]
                if first > now:                                      # never look ahead of the processed event
                    continue
                oldest = first if oldest is None else min(oldest, first)
                if d["dst"] == token and d["edge_type"] in PAYER_EDGES and kind_of(d["src"]) == "acct":
                    prev = payer_first.get(d["src"])
                    payer_first[d["src"]] = first if prev is None else min(prev, first)
                elif d["src"] == token and d["edge_type"] == "SENT" and first >= recent:
                    new_outbound += 1
        tenure_cut = now - timedelta(days=self.cfg.min_payer_tenure_days)
        return PayeeProfile(
            account_age_days=((now - oldest).total_seconds() / 86400) if oldest is not None else 0.0,
            payers=len(payer_first),
            tenured_payers=sum(1 for t in payer_first.values() if t <= tenure_cut),
            new_payers_recent=sum(1 for t in payer_first.values() if t >= recent),
            new_outbound_recent=new_outbound,
            seed_nearby=self._seed_nearby(token),
        )

    def _seed_nearby(self, token: str) -> bool:
        if self.graph.is_seed(token):
            return True
        found = self.graph.seed_distance(token, max_hops=self.cfg.seed_clear_hops)
        return found is not None

    def is_reputable(self, token: str, now: datetime) -> bool:
        g = self.graph.g
        if kind_of(token) != "acct" or token not in g:
            return False
        # cheap pre-check before the full profile: enough distinct payer accounts at all
        payers = {d["src"] for keyed in g.adj[token].values() for d in keyed.values()
                  if d["dst"] == token and d["edge_type"] in PAYER_EDGES}
        if len(payers) < self.cfg.min_tenured_payers:
            return False
        p = self.profile(token, now)
        c = self.cfg
        return (p is not None
                and p.account_age_days >= c.min_account_age_days
                and p.tenured_payers >= c.min_tenured_payers
                and p.tenured_share >= c.min_tenured_share
                and p.new_payer_share <= c.max_new_payer_share
                and not (p.new_outbound_recent > 0 and p.new_payers_recent > 0)
                and not p.seed_nearby)
