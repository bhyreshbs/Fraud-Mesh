"""Policy simulator (PRD §10.9): replay every case in fused mode with the given thresholds, then measure.

attacks_total / caught      attacks grouped by labels.attack_id; caught = a case containing any of the attack's events
                            reached severity >= HOLD before the attack's last event
benign customers / flagged  customers with no attack label; flagged = has a case that reached HIGH or above
legit payments / stopped    benign transactions; stopped = one of the customer's cases had payment state held or
                            blocked at that moment
money_protected_paise       for each caught attack, its cases' S6 amounts at or after the earliest intervention
median_lead_time_s          over caught attacks: first S6 evidence (else the attack's last event) − earliest intervention
"""
from __future__ import annotations

import statistics
from bisect import bisect_right
from collections import defaultdict
from datetime import datetime

from engine.contracts import BAND_ORDER, BandThresholds, SimulationResult, Store
from engine.fusion.fusion import ordered
from engine.replay.replay import Timeline, fused_timeline

FLAG_BAND = "HIGH"


def simulate_policy(store: Store, thresholds: BandThresholds) -> SimulationResult:
    labels = store.get_labels()
    cases = store.list_cases()
    evidence = {c.case_id: ordered(store.list_evidence(c.case_id)) for c in cases}
    timelines: dict[str, Timeline] = {c.case_id: fused_timeline(evidence[c.case_id], thresholds=thresholds) for c in cases}

    # attacks
    attack_events: dict[str, list[str]] = defaultdict(list)
    for lb in labels.values():
        if lb.is_attack and lb.attack_id:
            attack_events[lb.attack_id].append(lb.event_id)
    event_ts: dict[str, datetime] = {}
    attack_customers: set[str] = set()
    benign_txns: list[tuple[datetime, str]] = []
    all_customers: set[str] = set()
    for ev in store.iter_events():
        lb = labels.get(ev.event_id)
        if lb is not None and lb.is_attack:
            event_ts[ev.event_id] = ev.occurred_at
            if ev.customer:
                attack_customers.add(ev.customer)
        if ev.customer:
            all_customers.add(ev.customer)
        if ev.event_type == "transaction" and not (lb is not None and lb.is_attack) and ev.customer:
            benign_txns.append((ev.occurred_at, ev.customer))

    cases_of_event: dict[str, set[str]] = defaultdict(set)
    for cid, evs in evidence.items():
        for e in evs:
            cases_of_event[e.event_id].add(cid)

    caught, leads, money = 0, [], 0
    for ids in attack_events.values():
        known = [event_ts[i] for i in ids if i in event_ts]
        if not known:
            continue
        last = max(known)
        cids = set().union(*(cases_of_event.get(i, set()) for i in ids))
        eips = [(timelines[c].eip, c) for c in cids if timelines[c].eip is not None and timelines[c].eip.ts < last]
        if not eips:
            continue
        caught += 1
        eip, cid = min(eips, key=lambda t: t[0].ts)
        s6 = [e for c in cids for e in evidence[c] if e.stage == "S6_MONETIZATION"]
        first_s6 = min((e.ts for e in s6), default=last)
        leads.append(int((first_s6 - eip.ts).total_seconds()))
        money += sum(e.amount_paise or 0 for e in s6 if e.ts >= eip.ts)

    # benign customers and their payments
    benign_customers = all_customers - attack_customers
    flagged = {c.customer for c in cases if c.customer in benign_customers
               and any(BAND_ORDER.index(p.band) >= BAND_ORDER.index(FLAG_BAND) for p in timelines[c.case_id].points)}
    states_by_customer: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for c in cases:
        if c.customer:
            states_by_customer[c.customer] += [(p.ts, s) for p, s in zip(timelines[c.case_id].points,
                                                                          timelines[c.case_id].payment_states, strict=True)]
    stopped = 0
    for ts, cust in benign_txns:
        if cust not in benign_customers:
            continue
        hist = sorted(states_by_customer.get(cust, []))
        i = bisect_right([t for t, _ in hist], ts)
        if i and hist[i - 1][1] in ("held", "blocked"):
            stopped += 1

    return SimulationResult(thresholds=thresholds, attacks_total=len(attack_events), attacks_caught=caught,
                            benign_customers_total=len(benign_customers), benign_customers_flagged=len(flagged),
                            legit_payments_total=sum(1 for _, c in benign_txns if c in benign_customers),
                            legit_payments_stopped=stopped, money_protected_paise=money,
                            median_lead_time_s=int(statistics.median(leads)) if leads else None)
