"""Replay (PRD §10.9): re-judge a case's stored evidence, in order, without re-running any model.

fused   after each item, re-run fusion, patterns, floors, bands and policy over the items so far, using each evidence
        row's stored p and reliability (engine.fusion.fuse — the same function live scoring uses)
siloed  judge each item alone: band SILOED_ALERT if p >= 0.5 else SILOED_NONE; actions [BLOCK_PENDING_PAYMENTS] only
        for a txn item with p >= 0.5, else [ALLOW]
severity = max ACTION_SEVERITY of the actions; eip = first point with severity >= SEVERITY_HOLD.
lead_time_s = first S6 evidence ts − eip ts; lead_time_lost_s = eip ts − baseline eip ts (fused, nothing ablated);
money_protected_paise = S6 amounts with ts >= eip ts. Ablation never removes the money: S6 evidence is always counted.
"""
from __future__ import annotations

from dataclasses import dataclass

from engine.common.ids import new_id
from engine.common.settings import settings
from engine.contracts import SEVERITY_HOLD, BandThresholds, Evidence, ReplayPoint, ReplayResult, Store
from engine.fusion.fusion import default_thresholds, fuse, ordered
from engine.fusion.patterns import load_patterns
from engine.policy.policy import Policy, payment_state_after, severity

SILOED_ALERT_P = 0.5
DETECTOR_IDS = ("txn", "behaviour", "auth", "kyc", "cyber", "netsec", "graph")


@dataclass
class Timeline:
    points: list[ReplayPoint]
    payment_states: list[str]          # payment state after each point (fused mode)

    @property
    def eip(self) -> ReplayPoint | None:
        return next((p for p in self.points if p.severity >= SEVERITY_HOLD), None)


def fused_timeline(evidence: list[Evidence], *, thresholds: BandThresholds | None = None, base_rate: float | None = None,
                   ablate: list[str] | tuple[str, ...] = ()) -> Timeline:
    th = default_thresholds() if thresholds is None else thresholds
    br = settings.base_rate if base_rate is None else base_rate
    pats, policy = load_patterns(), Policy(store=None)          # read-only: rules only, no decisions written
    kept = [e for e in ordered(evidence) if e.detector not in ablate]
    points, states, state = [], [], "normal"
    for k, ev in enumerate(kept, 1):
        res = fuse(kept[:k], base_rate=br, thresholds=th, patterns=pats)
        actions = list(policy.rule_for(res.band, {r.code for r in ev.reasons}, set(res.pattern_hits)).actions)
        state = payment_state_after(state, actions)
        points.append(ReplayPoint(ts=ev.ts, evidence_id=ev.evidence_id, p=res.p_attack, band=res.band, actions=actions,
                                  severity=severity(actions)))
        states.append(state)
    return Timeline(points, states)


def siloed_timeline(evidence: list[Evidence], ablate: list[str] | tuple[str, ...] = ()) -> Timeline:
    points = []
    for ev in ordered(evidence):
        if ev.detector in ablate:
            continue
        alert = ev.p >= SILOED_ALERT_P
        actions = ["BLOCK_PENDING_PAYMENTS"] if alert and ev.detector == "txn" else ["ALLOW"]
        points.append(ReplayPoint(ts=ev.ts, evidence_id=ev.evidence_id, p=ev.p,
                                  band="SILOED_ALERT" if alert else "SILOED_NONE", actions=actions, severity=severity(actions)))
    return Timeline(points, ["blocked" if "BLOCK_PENDING_PAYMENTS" in p.actions else "normal" for p in points])


def build_replay(case_id: str, evidence: list[Evidence], *, mode: str = "fused", ablate: list[str] | None = None,
                 thresholds: BandThresholds | None = None, base_rate: float | None = None) -> ReplayResult:
    if mode not in ("fused", "siloed"):
        raise ValueError(f"mode must be fused or siloed, not {mode!r}")
    ablated = sorted(set(ablate or []))
    unknown = [d for d in ablated if d not in DETECTOR_IDS]
    if unknown:
        raise ValueError(f"unknown detectors to ablate: {unknown}")
    tl = (fused_timeline(evidence, thresholds=thresholds, base_rate=base_rate, ablate=ablated) if mode == "fused"
          else siloed_timeline(evidence, ablated))
    baseline = fused_timeline(evidence, thresholds=thresholds, base_rate=base_rate).eip
    eip = tl.eip
    s6 = [e for e in ordered(evidence) if e.stage == "S6_MONETIZATION"]
    lead = int((s6[0].ts - eip.ts).total_seconds()) if eip and s6 else None
    lost = int((eip.ts - baseline.ts).total_seconds()) if eip and baseline else None
    money = sum(e.amount_paise or 0 for e in s6 if eip and e.ts >= eip.ts)
    return ReplayResult(replay_id=new_id("rep"), case_id=case_id, mode=mode, ablated=ablated, timeline=tl.points, eip=eip,
                        baseline_eip=baseline, lead_time_s=lead, lead_time_lost_s=lost, money_protected_paise=money)


def replay_case(store: Store, case_id: str, ablate: list[str] | None = None, mode: str = "fused") -> ReplayResult:
    if store.get_case(case_id) is None:
        raise KeyError(case_id)
    result = build_replay(case_id, store.list_evidence(case_id), mode=mode, ablate=ablate)
    store.save_replay(result)
    return result
