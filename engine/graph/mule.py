"""Seed-independent mule analytics (v3 phase 9.1): money-flow shape of one account, from graph edges alone.

A fraud seed is only known after an analyst confirms a case; a fresh mule ring has none. These signals look at how
money moves through an account instead, at the processed event's time (never the wall clock):

    unique payers / beneficiaries in window_h     distinct accounts that paid (SENT / ADDED_PAYEE) it, or that it paid
    new payers / beneficiaries in window_h        ... whose FIRST edge to / from it is inside the window
    account age                                   oldest edge of the account
    pass-through time                             minutes from the latest money in to the next money out (receive → send)
    dormant activation                            no edge activity for dormant_days, then a burst of new payers
    rapid multi-hop                               a payer of this account is itself passing fresh money through
    shared control                                accounts logged into from one non-hub device, receiving together
    time-decayed weight                           confidence × 0.5 ** (age_h / half-life), age measured from last_seen

Edges keep only (first_seen, last_seen, count), so times are those two instants per edge; amounts stay in the feature
windows (payee_passthrough_24h, used by MULE_FLOW). Every input survives Pipeline.startup() (graph.load from the edges
table), so a restarted engine answers the same. Thresholds and p values: engine/detectors/rules/mule.yaml.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path

import yaml

from engine.graph.resolve import kind_of
from engine.graph.store import EntityGraph

CONFIG_FILE = Path(__file__).resolve().parents[1] / "detectors" / "rules" / "mule.yaml"
PAYER_EDGES = frozenset({"SENT", "ADDED_PAYEE"})
MULE_CODES = ("MULE_RING", "MULE_PASS_THROUGH", "MULE_RAPID_HOPS", "MULE_FAN_OUT", "MULE_DORMANT_ACTIVATED",
              "MULE_FAN_IN_NEW_ACCOUNT")


@dataclass(frozen=True)
class MuleConfig:
    window_h: float
    young_account_days: float
    min_new_payers: int
    pass_through_max_min: float
    pass_through_min_payers: int
    fan_out_min: int
    dormant_days: float
    dormant_min_new_payers: int
    hop_window_min: float
    ring_min_accounts: int
    ring_min_new_payers: int
    decay_half_life_h: float
    p: dict = field(default_factory=dict)
    join: dict = field(default_factory=dict)
    pagerank: dict = field(default_factory=dict)


@lru_cache(maxsize=4)
def load_config(path: str | Path = CONFIG_FILE) -> MuleConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return MuleConfig(**{k: raw[k] for k in MuleConfig.__dataclass_fields__ if k in raw})


def decayed_weight(d: dict, now: datetime, half_life_h: float) -> float:
    """Edge confidence decayed by the time since the edge was last seen (event time; future edges count as now)."""
    age_h = max(0.0, (now - d["last_seen"]).total_seconds() / 3600)
    return float(d["confidence"]) * 0.5 ** (age_h / half_life_h) if half_life_h > 0 else float(d["confidence"])


@dataclass(frozen=True)
class FlowProfile:
    """The flow shape of one acct node at one moment (useful for explanations and tests)."""
    account_age_days: float
    payers: int
    unique_payers_window: int
    new_payers_window: int
    beneficiaries: int
    new_beneficiaries_window: int
    pass_through_min: float | None          # receive → send, minutes; None when it never sent after receiving
    dormant_activated: bool
    decayed_fan_in: float                   # Σ over payers of their strongest decayed edge weight

    @property
    def inflow_outflow_ratio(self) -> float:
        """Distinct beneficiaries ÷ distinct payers in the window (edge counts; amounts live in MULE_FLOW)."""
        return self.new_beneficiaries_window / self.unique_payers_window if self.unique_payers_window else 0.0


class MuleAnalytics:
    def __init__(self, graph: EntityGraph, config: MuleConfig | None = None) -> None:
        self.graph = graph
        self.cfg = load_config() if config is None else config

    # ------------------------------------------------------------------ one account
    def _edges(self, acct: str, now: datetime):
        """(direction, other, edge data, activity times <= now) for every edge of `acct` first seen by `now`."""
        for other, keyed in self.graph.g.adj[acct].items():
            for d in keyed.values():
                if d["first_seen"] > now:
                    continue
                times = [d["first_seen"]] + ([d["last_seen"]] if d["last_seen"] <= now else [])
                direction = "in" if d["dst"] == acct else "out"
                yield direction, other, d, times

    def profile(self, acct: str, now: datetime) -> FlowProfile | None:
        g = self.graph.g
        if kind_of(acct) != "acct" or acct not in g:
            return None
        c = self.cfg
        window = now - timedelta(hours=c.window_h)
        dormant_cut = now - timedelta(days=c.dormant_days)
        oldest: datetime | None = None
        payer_first: dict[str, datetime] = {}
        payer_recent: set[str] = set()
        payer_weight: dict[str, float] = {}
        ben_first: dict[str, datetime] = {}
        money_in: list[datetime] = []
        money_out: list[datetime] = []
        activity: list[datetime] = []
        for direction, other, d, times in self._edges(acct, now):
            oldest = d["first_seen"] if oldest is None else min(oldest, d["first_seen"])
            activity.extend(times)
            if kind_of(other) != "acct":
                continue
            if direction == "in" and d["edge_type"] in PAYER_EDGES:
                prev = payer_first.get(other)
                payer_first[other] = d["first_seen"] if prev is None else min(prev, d["first_seen"])
                if max(times) >= window:
                    payer_recent.add(other)
                payer_weight[other] = max(payer_weight.get(other, 0.0), decayed_weight(d, now, c.decay_half_life_h))
                if d["edge_type"] == "SENT":
                    money_in.extend(times)
            elif direction == "out" and d["edge_type"] == "SENT":
                prev = ben_first.get(other)
                ben_first[other] = d["first_seen"] if prev is None else min(prev, d["first_seen"])
                money_out.extend(times)
        new_payers = sum(1 for t in payer_first.values() if t >= window)
        pass_through = self._pass_through(money_in, money_out, window)
        idle_before = [t for t in activity if t < window]
        dormant = (oldest is not None and oldest <= dormant_cut and new_payers >= c.dormant_min_new_payers
                   and all(t <= dormant_cut for t in idle_before))
        return FlowProfile(
            account_age_days=((now - oldest).total_seconds() / 86400) if oldest is not None else 0.0,
            payers=len(payer_first), unique_payers_window=len(payer_recent), new_payers_window=new_payers,
            beneficiaries=len(ben_first), new_beneficiaries_window=sum(1 for t in ben_first.values() if t >= window),
            pass_through_min=pass_through, dormant_activated=dormant, decayed_fan_in=sum(payer_weight.values()))

    @staticmethod
    def _pass_through(money_in: list[datetime], money_out: list[datetime], window: datetime) -> float | None:
        """Shortest receive → send gap (minutes) for money sent out inside the window."""
        ins = sorted(t for t in money_in if t >= window)
        best: float | None = None
        for t_out in money_out:
            if t_out < window:
                continue
            before = [t for t in ins if t <= t_out]
            if before:
                gap = (t_out - before[-1]).total_seconds() / 60
                best = gap if best is None else min(best, gap)
        return best

    # ------------------------------------------------------------------ signals
    def is_pass_through(self, prof: FlowProfile) -> bool:
        c = self.cfg
        return (prof.new_payers_window >= c.pass_through_min_payers and prof.pass_through_min is not None
                and prof.pass_through_min <= c.pass_through_max_min)

    def signals(self, acct: str, now: datetime, as_sender: bool = False) -> list[tuple[str, str]]:
        """[(reason code, detail)] for `acct`, strongest first. as_sender: the account is moving money out right now
        (its own transaction), so only its pass-through / fan-out shape is asked."""
        prof = self.profile(acct, now)
        if prof is None or self.graph.is_excluded(acct):
            return []
        c, out = self.cfg, []
        if self.is_pass_through(prof):
            out.append(("MULE_PASS_THROUGH", f"{prof.new_payers_window} new payers, money out "
                                             f"{prof.pass_through_min:.0f} min after money in"))
        if prof.new_beneficiaries_window >= c.fan_out_min and prof.new_payers_window >= 1:
            out.append(("MULE_FAN_OUT", f"paid {prof.new_beneficiaries_window} new beneficiaries in {c.window_h:.0f} h "
                                        f"after {prof.new_payers_window} new payers"))
        if not as_sender:
            if prof.account_age_days < c.young_account_days and prof.new_payers_window >= c.min_new_payers:
                out.append(("MULE_FAN_IN_NEW_ACCOUNT", f"{prof.new_payers_window} first-time payers in {c.window_h:.0f} h "
                                                       f"to a {prof.account_age_days:.1f}-day-old account"))
            if prof.dormant_activated:
                out.append(("MULE_DORMANT_ACTIVATED", f"idle {c.dormant_days:.0f}+ days, then "
                                                      f"{prof.new_payers_window} new payers"))
            hop = self.upstream_pass_through(acct, now)
            if hop is not None:
                out.append(("MULE_RAPID_HOPS", f"fed by {hop}, which is passing fresh money through"))
            ring = self.ring(acct, now)
            if ring is not None:
                out.append(("MULE_RING", f"{ring[0]} accounts on one shared device took {ring[1]} new payers"))
        order = {code: i for i, code in enumerate(MULE_CODES)}
        return sorted(out, key=lambda x: order[x[0]])

    def upstream_pass_through(self, acct: str, now: datetime) -> str | None:
        """A payer of `acct` (paying it within hop_window_min) that is itself a pass-through account, or None."""
        window = now - timedelta(minutes=self.cfg.hop_window_min)
        for other, keyed in sorted(self.graph.g.adj[acct].items()):
            if kind_of(other) != "acct" or self.graph.is_excluded(other):
                continue
            if not any(d["edge_type"] == "SENT" and d["dst"] == acct and window <= d["first_seen"] <= now
                       for d in keyed.values()):
                continue
            prof = self.profile(other, now)
            if prof is not None and self.is_pass_through(prof):
                return other
        return None

    def ring(self, acct: str, now: datetime) -> tuple[int, int] | None:
        """(ring accounts, their new payers) when accounts sharing a non-hub device with `acct` take new payers
        together; None below ring_min_accounts / ring_min_new_payers. `acct` itself must have a new payer."""
        g, c = self.graph.g, self.cfg
        mine = self.profile(acct, now)
        if mine is None or mine.new_payers_window < 1:
            return None
        devices = {d for d, keyed in g.adj[acct].items() if kind_of(d) == "dev" and not self.graph.is_excluded(d)
                   and any(x["edge_type"] == "LOGGED_IN_FROM" and x["first_seen"] <= now for x in keyed.values())}
        siblings: set[str] = set()
        for dev in devices:
            for other, keyed in g.adj[dev].items():
                if other != acct and kind_of(other) == "acct" and any(
                        x["edge_type"] == "LOGGED_IN_FROM" and x["first_seen"] <= now for x in keyed.values()):
                    siblings.add(other)
        members, payers = 1, mine.new_payers_window
        for s in sorted(siblings):
            prof = self.profile(s, now)
            if prof is not None and prof.new_payers_window >= 1:
                members += 1
                payers += prof.new_payers_window
        if members >= c.ring_min_accounts and payers >= c.ring_min_new_payers:
            return members, payers
        return None

    def is_suspicious_bridge(self, acct: str, now: datetime) -> bool:
        """Any payee-side mule signal (used by the joiner's safe-joining rule)."""
        return bool(self.signals(acct, now))
