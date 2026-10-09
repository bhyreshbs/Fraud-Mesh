"""Digital Twin entry points: twin_case (one case: virtual state, strategies compared, forecast) and twin_overview
(the whole virtual bank). Both only read the Store; nothing is written."""
from __future__ import annotations

from collections import Counter
from datetime import timedelta

from engine.contracts import ACTION_SEVERITY, SEVERITY_HOLD, STAGE_ORDER, Evidence, Label, Store, StoredEvent
from engine.fusion.fusion import ordered
from engine.graph.resolve import kind_of
from engine.graph.store import EntityGraph
from engine.replay.replay import fused_timeline
from engine.twin.models import CaseTwin, EntityState, TwinOverview, TwinStep
from engine.twin.predict import predict, stage_of
from engine.twin.simulate import PUSH_RESPONSE, STRATEGIES, SimStep, simulate
from engine.twin.state import VirtualBank

ASSUMPTIONS = [
    "The risk after each event is the engine's real fused score for this case; strategies change what the attacker can "
    "still do, not what the detectors saw.",
    "An SMS one-time password stops the attacker unless the SMS number or SIM is already under their control.",
    "During an attack the genuine customer denies a push on their registered device: at the time of their real answer "
    f"when the case has one, otherwise {int(PUSH_RESPONSE.total_seconds() // 60)} minutes after the push.",
    "Held and blocked transfers keep the money in the bank; a revoked attacker's remaining in-session steps never happen.",
    "Network-sensor and support-console events are outside the customer's session and always happen.",
    "The forecast reflects how similar labelled attacks progressed; it is a probability, not a certainty.",
]


def _actor(ev: StoredEvent, label: Label | None, unknown_devices: set[str]) -> tuple[str, bool]:
    """(actor, is_attack). The attacker acts from a device the customer had not used before (NEW_DEVICE); a labelled
    attack step from the customer's own device is the customer being used (e.g. a scammed sender)."""
    attack_label = label.is_attack if label is not None else None
    if ev.source == "network-ids":
        return "network", bool(attack_label)
    if ev.source == "cloud-audit":
        return "insider", bool(attack_label)
    if ev.device is None:
        return "system", bool(attack_label)
    if ev.device in unknown_devices and attack_label is not False:     # a genuine customer on a new phone stays genuine
        return "attacker", True
    return "customer", bool(attack_label)


NEW_DEVICE_REASONS = {"NEW_DEVICE", "MFA_CHANGED_AFTER_NEW_DEVICE", "PROFILE_CHANGE_AFTER_NEW_DEVICE"}
NEW_DEVICE_WINDOW = timedelta(hours=24)


def _unknown_devices(events: list[StoredEvent], evidence: list[Evidence], case_opened, graph: EntityGraph | None) -> set[str]:
    """Devices new to the customer: a case event from the device carries a *_NEW_DEVICE reason, or (with the live
    graph) the account's LOGGED_IN_FROM edge to the device was first seen within 24 h before the case opened, or later."""
    flagged = {e.event_id for e in evidence if any(r.code in NEW_DEVICE_REASONS for r in e.reasons)}
    out = {ev.device for ev in events if ev.device and ev.event_id in flagged}
    if graph is not None:
        for ev in events:
            if ev.device and ev.account:
                edge = graph.get_edge(ev.account, ev.device, "LOGGED_IN_FROM")
                if edge is not None and edge.first_seen >= case_opened - NEW_DEVICE_WINDOW:
                    out.add(ev.device)
    return out


CUSTOMER_DEVICE_REASONS = {"STEP_UP_PASSED_TRUSTED", "CUSTOMER_DENIED"}      # answered on the registered device
APP_PATTERNS = {"pat_APP_SCAM1"}
APP_REASON_PREFIX = "APP_SCAM_"


def _is_app_case(case_patterns: list[str], evidence: list[Evidence]) -> bool:
    return bool(APP_PATTERNS & set(case_patterns)) or any(r.code.startswith(APP_REASON_PREFIX)
                                                            for e in evidence for r in e.reasons)


def _customer_devices(events: list[StoredEvent], evidence: list[Evidence], case_patterns: list[str]) -> set[str]:
    """Devices the case itself shows belong to the genuine customer, even when their graph edge is young (v3 fix: the
    APP-scam victim was labelled "attacker" because her device edge was < 24 h old):
      - the device that answered a trusted-factor step-up (passed with an old factor, or the customer's "Not me");
      - in an APP-scam case (pat_APP_SCAM1 or APP_SCAM_* reasons), every device no *_NEW_DEVICE reason flagged:
        the scam victim pays from her own registered phone, which is what makes it an APP scam and not a takeover."""
    by_event = {ev.event_id: ev for ev in events}
    out = {by_event[e.event_id].device for e in evidence
           if e.event_id in by_event and by_event[e.event_id].device
           and any(r.code in CUSTOMER_DEVICE_REASONS for r in e.reasons)}
    if _is_app_case(case_patterns, evidence):
        flagged = {e.event_id for e in evidence if any(r.code in NEW_DEVICE_REASONS for r in e.reasons)}
        out |= {ev.device for ev in events if ev.device and ev.event_id not in flagged}
    return out


def _case_kind(steps: list[TwinStep], case_patterns: list[str], evidence: list[Evidence], any_attack_label: bool) -> str:
    if any(s.actor == "attacker" for s in steps):
        return "account_takeover"
    if _is_app_case(case_patterns, evidence):
        return "app_scam"
    if not any_attack_label:
        return "legitimate"
    return "unclassified"


def _describe(ev: StoredEvent, actor: str) -> str:
    p, who = ev.payload, {"attacker": "Attacker", "customer": "Customer", "network": "Network sensor",
                          "insider": "Support console", "system": "Telco / bank system"}[actor]
    t = ev.event_type
    if t == "login":
        return f"{who} login {'succeeded' if p.get('result') == 'success' else 'failed'}" + (f" via {ev.asn}" if ev.asn else "")
    if t == "network_ids_alert":
        return f"IDS: {p.get('signature', 'alert')} (severity {p.get('severity')})"
    if t == "mfa_change":
        return f"{who} {p.get('action')}s the {p.get('factor')} factor"
    if t == "sim_signal":
        return f"SIM changed {p.get('sim_change_age_h')} h ago"
    if t == "profile_change":
        return f"{who} changes the {p.get('field')}"
    if t == "kyc_result":
        return (f"Re-KYC: liveness {p.get('liveness_score')}, face match {p.get('face_match_score')}, "
                f"document tamper {p.get('doc_tamper_score')}")
    if t == "cloud_audit":
        return f"{p.get('actor_identity')} runs {p.get('action')}"
    if t == "payee_added":
        return f"{who} adds a payee" + (" (name does not match)" if p.get("payee_name_match") is False else "")
    if t == "transaction":
        return f"{who} transfers {int(p.get('amount_paise', 0)) // 100:,} INR via {p.get('channel', 'IMPS')}"
    if t == "step_up_result":
        return f"Step-up {p.get('method')}: {p.get('result')}"
    return t


def twin_case(store: Store, case_id: str, *, graph: EntityGraph | None = None,
              labels: dict[str, Label] | None = None) -> CaseTwin:
    case = store.get_case(case_id)
    if case is None:
        raise KeyError(case_id)
    evidence = ordered(store.list_evidence(case_id))
    points = dict(zip([e.evidence_id for e in evidence], fused_timeline(evidence).points, strict=True))
    labels = store.get_labels() if labels is None else labels
    by_event: dict[str, list[Evidence]] = {}
    for e in evidence:
        by_event.setdefault(e.event_id, []).append(e)

    events = {eid: ev for eid in by_event if (ev := store.get_event(eid)) is not None}
    unknown = _unknown_devices(list(events.values()), evidence, case.opened_at, graph)
    unknown -= _customer_devices(list(events.values()), evidence, case.pattern_hits)
    live, steps, sims = VirtualBank(), [], []
    customer_answer, furthest = None, None
    for i, (event_id, evs) in enumerate((k, v) for k, v in by_event.items() if k in events):
        ev = events[event_id]
        actor, is_attack = _actor(ev, labels.get(event_id), unknown)
        pt = points[evs[-1].evidence_id]
        stage = evs[0].stage or stage_of(ev.event_type, ev.payload) or "S0_RECON"
        if ev.event_type == "step_up_result" and ev.payload.get("result") == "denied_by_customer" and customer_answer is None:
            customer_answer = ev.occurred_at
        txn = [e.p for e in evs if e.detector == "txn"]
        if actor == "attacker" or (is_attack and actor != "network"):
            furthest = stage if furthest is None else max(furthest, stage, key=STAGE_ORDER.index)
        f = predict(furthest)
        top = f.next_stages[0] if f.next_stages else None
        steps.append(TwinStep(index=i, ts=ev.occurred_at, event_id=event_id, event_type=ev.event_type, actor=actor, stage=stage,
                              summary=_describe(ev, actor), changes=live.apply(ev, actor), p=pt.p, band=pt.band,
                              actions=list(pt.actions), amount_paise=ev.payload.get("amount_paise"),
                              forecast_stage=furthest, forecast_next=top.stage if top else None,
                              forecast_probability=top.probability if top else None,
                              forecast_p_money=f.p_reach_monetization,
                              forecast_minutes_to_money=f.expected_minutes_to_monetization))
        sims.append(SimStep(event=ev, actor=actor, is_attack=is_attack, stage=stage, band=pt.band, p=pt.p,
                            live_actions=list(pt.actions), txn_p=max(txn) if txn else None))

    outcomes = [simulate(s, sims, VirtualBank(), customer_answer) for s in STRATEGIES]
    best = max(outcomes, key=lambda o: (o.money_protected_paise - o.money_lost_paise, -o.customer_friction,
                                        -(o.stopped_at.timestamp() if o.stopped_at else 1e12)))
    eip = next((s.ts for s in steps if max((ACTION_SEVERITY[a] for a in s.actions), default=0) >= SEVERITY_HOLD), None)
    entities = _entities(case.entities, live, graph)
    return CaseTwin(case_id=case_id, customer=case.customer, steps=steps, entities=entities, policies=outcomes,
                    best_policy=best.policy_id, live_policy="fraudmesh", earliest_intervention=eip,
                    prediction=predict(furthest), assumptions=ASSUMPTIONS,
                    case_kind=_case_kind(steps, case.pattern_hits, evidence, any(s.is_attack for s in sims)))


def _entities(tokens: list[str], live: VirtualBank, graph: EntityGraph | None) -> list[EntityState]:
    out = []
    for t in sorted(set(tokens)):
        tags = set(live.tags.get(t, set()))
        if graph is not None and t in graph.g:
            if graph.is_seed(t):
                tags.add("confirmed fraud seed")
            elif kind_of(t) in ("acct", "dev"):
                d = graph.seed_distance(t, max_hops=2)
                if d is not None and d[0] > 0:
                    tags.add(f"{d[0]} hop{'s' if d[0] > 1 else ''} from a known mule")
            if graph.is_hub(t):
                tags.add("hub (shared by many customers)")
        out.append(EntityState(entity=t, kind=kind_of(t), tags=sorted(tags)))
    return out


INTERVENTIONS = {"HOLD_OUTBOUND_PAYMENTS", "BLOCK_PENDING_PAYMENTS", "FREEZE_NEW_PAYEES", "REVOKE_SESSIONS",
                 "STEP_UP_ANY_FACTOR", "STEP_UP_TRUSTED_FACTOR"}


def twin_overview(store: Store, graph: EntityGraph | None = None) -> TwinOverview:
    cases = store.list_cases()
    kinds = Counter(kind_of(n) for n in graph.g.nodes) if graph is not None else Counter()
    held = [c for c in cases if c.payment_state == "held"]
    blocked = [c for c in cases if c.payment_state == "blocked"]
    hottest = sorted(cases, key=lambda c: -c.p_attack)[:8]
    return TwinOverview(
        entities={k: kinds[k] for k in ("cust", "acct", "dev", "ip", "phone", "cid") if kinds[k]},
        fraud_seeds=len(store.list_fraud_seeds()),
        cases_by_band={b: sum(1 for c in cases if c.band == b) for b in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        payments_held=len(held), payments_blocked=len(blocked),
        active_interventions=sum(1 for c in cases if INTERVENTIONS & set(c.latest_actions)),
        money_at_risk_paise=sum(c.amount_at_risk_paise for c in cases if c.payment_state == "normal" and c.band != "LOW"),
        money_protected_paise=sum(c.amount_at_risk_paise for c in held + blocked),
        hottest_cases=[{"case_id": c.case_id, "band": c.band, "p_attack": round(c.p_attack, 4), "customer": c.customer,
                        "stages": len(c.stages), "payment_state": c.payment_state,
                        "amount_at_risk_paise": c.amount_at_risk_paise, "last_event_ts": c.last_event_ts.isoformat()}
                       for c in hottest])
