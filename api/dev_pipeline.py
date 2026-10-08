"""DEV-ONLY stand-in for Dev 2's engine, enabled with FM_DEV_PIPELINE=1. Not the engine, not used in CI or the demo.

Purpose: let Dev 1 click the Midnight ATO story through the bank app, phones and console before Dev 2's real
Pipeline lands (Checkpoint 1). It uses fixed rule probabilities from PRD §10.4 calibration.json and the §10.5–10.8
fusion / pattern / floor / policy rules on a single per-customer case. It has no ML, no feature windows, no 2-hop joiner.
Delete the flag (or this file) once engine/pipeline.py is real.
"""
from __future__ import annotations

import math
from datetime import timedelta

from api.demo_identities import REGISTERED_DEVICE
from engine.common.ids import new_id
from engine.common.settings import settings
from engine.common.tokenize import tok
from engine.contracts import (
    BAND_ORDER,
    DETECTOR_FAMILY,
    Case,
    CaseUpdate,
    Decision,
    Evidence,
    Explanation,
    ExplanationPart,
    GraphEdge,
    GraphElements,
    GraphNode,
    NarrativeSentence,
    Reason,
    StageHit,
    StepUpRequest,
    StoredEvent,
    summarize,
)

BASE = settings.base_rate
REL = {"txn": 0.85, "behaviour": 0.6, "auth": 0.7, "kyc": 0.6, "cyber": 0.5, "netsec": 0.5, "graph": 0.8}
POLICY = [("critical", "CRITICAL", ["BLOCK_PENDING_PAYMENTS", "FREEZE_NEW_PAYEES", "REVOKE_SESSIONS", "OPEN_CASE_P1"]),
          ("high", "HIGH", ["HOLD_OUTBOUND_PAYMENTS", "STEP_UP_TRUSTED_FACTOR", "OPEN_CASE_P2"]),
          ("medium", "MEDIUM", ["STEP_UP_ANY_FACTOR"]), ("low", "LOW", ["ALLOW"])]
PATTERNS = {"pat_ATO1": ("New-device login followed by an MFA or profile change", 0.5),
            "pat_CASE_IP_CLOUD": ("Cloud action from an IP already seen in this case", 0.3)}
SEEDS = {tok("dev", "fp_mule_shared"), tok("acct", "A-MULE-01")}
SEED_LINKED_PAYEES = {tok("acct", "A-RAVI-778")}        # Ravi's account logs in from the mule's device (1 hop)


def logit(x: float) -> float:
    return math.log(x / (1 - x))


def band_of(p: float) -> str:
    return "CRITICAL" if p >= settings.band_critical else "HIGH" if p >= settings.band_high else "MEDIUM" if p >= settings.band_medium else "LOW"


class ScriptedPipeline:
    def __init__(self, store) -> None:
        self.store = store
        self._ready = False
        self.case_by_customer: dict[str, str] = {}
        self.case_by_ip: dict[str, str] = {}
        self.known_devices: dict[str, set[str]] = {tok("cust", c): {tok("dev", d)} for c, d in REGISTERED_DEVICE.items()}

    # ------------------------------------------------------------ Pipeline interface
    @property
    def ready(self) -> bool:
        return self._ready

    def startup(self) -> None:
        for c in self.store.list_cases():
            if c.status in ("OPEN", "INVESTIGATING"):
                if c.customer:
                    self.case_by_customer[c.customer] = c.case_id
                for t in c.entities:
                    if t.startswith("ip:"):
                        self.case_by_ip.setdefault(t, c.case_id)
        self._ready = True

    def set_seeds(self, entity_ids, value=True):
        self.store.set_fraud_seeds(entity_ids, value)

    def process(self, ev: StoredEvent) -> list[CaseUpdate]:
        scored = self._score(ev)
        if scored is None:
            return []
        detector, stage, p, reasons, technique, entities = scored
        with self.store.transaction():
            case = self._case_for(ev, p)
            if case is None:
                return []
            evd = Evidence(evidence_id=new_id("ev"), event_id=ev.event_id, detector=detector, detector_version="dev-stand-in",
                           family=DETECTOR_FAMILY[detector], stage=stage, attack_technique=technique, p=p, reliability=REL[detector],
                           entities=sorted(set(entities)), reasons=[Reason(code=c, detail=d) for c, d in reasons], ts=ev.occurred_at,
                           amount_paise=ev.payload.get("amount_paise") if ev.event_type == "transaction" else None)
            evidence = [*self.store.list_evidence(case.case_id), evd]
            prev_actions = list(case.latest_actions)
            case = self._fuse(case, evidence, evd)
            rule, actions = next((r, a) for r, b, a in POLICY if BAND_ORDER.index(case.band) >= BAND_ORDER.index(b))
            if "BLOCK_PENDING_PAYMENTS" in actions:
                case.payment_state = "blocked"
            elif "HOLD_OUTBOUND_PAYMENTS" in actions and case.payment_state == "normal":
                case.payment_state = "held"
            if evd.amount_paise:
                case.amount_at_risk_paise += evd.amount_paise
            case.latest_actions = actions
            dec = Decision(decision_id=new_id("dec"), case_id=case.case_id, trigger_event_id=ev.event_id, trigger_evidence_id=evd.evidence_id,
                           band=case.band, p_attack=case.p_attack, policy_rule=rule, actions=actions, created_at=ev.occurred_at)
            self.store.save_case(case)                         # case first: evidence and decisions reference it
            for e in evidence:
                self.store.save_evidence(e, case.case_id)
            self.store.save_decision(dec)
            self.store.append_audit("engine", "DECISION", dec.decision_id, {"case_id": case.case_id, "band": case.band, "rule": rule})
        step = None
        for a, cls in (("STEP_UP_TRUSTED_FACTOR", "trusted"), ("STEP_UP_ANY_FACTOR", "any")):
            if a in actions and a not in prev_actions and case.customer:
                step = StepUpRequest(case_id=case.case_id, customer=case.customer, method_class=cls, reason_event_id=ev.event_id)
                break
        upd = CaseUpdate(case=summarize(case), event_id=ev.event_id, new_evidence_ids=[evd.evidence_id], decision_id=dec.decision_id,
                         step_up=step)
        if ev.event_type == "transaction":
            upd.payment_outcome = {"blocked": "blocked", "held": "held"}.get(case.payment_state, "completed")
        return [upd]

    # ------------------------------------------------------------ rules (fixed probabilities from §10.4)
    def _score(self, ev: StoredEvent):
        p, t = ev.payload, ev.event_type
        ents = [x for x in ev.entity_tokens]
        if t == "network_ids_alert":
            sev = int(p.get("severity", 3))
            return "netsec", "S0_RECON", {1: 0.05, 2: 0.03, 3: 0.015}[sev], [(f"IDS_SEV{sev}", p.get("signature"))], "T1110.004", [p["src_ip"]]
        if not ev.customer and t != "cloud_audit":
            return None
        if t == "login" and p.get("result") == "success":
            known = self.known_devices.setdefault(ev.customer, set())
            if ev.device and ev.device not in known:
                known.add(ev.device)
                return "behaviour", "S1_INITIAL_ACCESS", 0.05, [("NEW_DEVICE", None), ("NEW_ASN", ev.asn)], "T1078", ents
            return None
        if t == "mfa_change":
            return "auth", "S2_CONTROL_TAKEOVER", 0.06, [("MFA_CHANGED_AFTER_NEW_DEVICE", f"{p.get('factor')} factor {p.get('action')}")], "T1556.006", ents
        if t == "profile_change":
            return "auth", "S2_CONTROL_TAKEOVER", 0.05, [("PROFILE_CHANGE_AFTER_NEW_DEVICE", p.get("field"))], "T1098", ents
        if t == "step_up_result":
            r, age = p.get("result"), float(p.get("factor_age_h", 0))
            if r == "denied_by_customer":
                return "auth", "S2_CONTROL_TAKEOVER", BASE, [("CUSTOMER_DENIED", "customer tapped Not me")], None, ents
            if r == "passed":
                return ("auth", "S2_CONTROL_TAKEOVER", 0.08, [("STEP_UP_PASSED_WITH_FRESH_FACTOR", f"factor age {age:.2f} h")], "T1556.006", ents) \
                    if age < 72 else ("auth", "S2_CONTROL_TAKEOVER", 0.003, [("STEP_UP_PASSED_TRUSTED", f"factor age {age:.0f} h")], None, ents)
            return "auth", "S2_CONTROL_TAKEOVER", 0.05, [("STEP_UP_FAILED_OR_TIMEOUT", r)], None, ents
        if t == "kyc_result":
            reasons = []
            if p.get("liveness_score", 1) < 0.5:
                reasons.append(("LOW_LIVENESS", f"liveness {p['liveness_score']}"))
            if p.get("face_match_score", 1) < 0.7:
                reasons.append(("LOW_FACE_MATCH", f"face match {p['face_match_score']}"))
            if p.get("injection_suspected"):
                reasons.append(("INJECTION_SUSPECTED", None))
            return ("kyc", "S3_IDENTITY_MANIPULATION", 0.12 if p.get("injection_suspected") else 0.06, reasons, None, ents) if reasons else None
        if t == "cloud_audit" and p.get("action") == "UpdateTransferLimit" and p.get("target_customer"):
            return "cyber", "S4_ESCALATION", 0.04, [("cloud_limit_raise_untrusted_ip", f"{p['action']} by {p.get('actor_type')}")], "T1098", ents
        if t == "payee_added":
            if p.get("payee_account") in SEED_LINKED_PAYEES:
                return "graph", "S5_POSITIONING", 0.10, [("SEED_DISTANCE_1", "payee shares a device with a confirmed mule")], "T1657", ents
            if p.get("payee_name_match") is False:
                return "graph", "S5_POSITIONING", 0.03, [("PAYEE_NAME_MISMATCH", None)], "T1657", ents
            return None
        if t == "transaction":
            big = int(p.get("amount_paise", 0)) >= 10_000_000
            return ("txn", "S6_MONETIZATION", 0.20 if big else 0.03,
                    [("AMOUNT_HIGH_VS_MEDIAN", None), ("NEW_PAYEE", None)] if big else [("NEW_PAYEE", None)], None, ents)
        return None

    # ------------------------------------------------------------ joining (one case per customer; IDS cases by IP)
    def _case_for(self, ev: StoredEvent, p: float) -> Case | None:
        cust = ev.customer or ev.payload.get("target_customer")
        case = None
        if cust and cust in self.case_by_customer:
            case = self.store.get_case(self.case_by_customer[cust])
        if case is None:
            ip = ev.ip or ev.payload.get("src_ip")
            if ip and ip in self.case_by_ip:
                case = self.store.get_case(self.case_by_ip[ip])
                if case and cust and not case.customer:                     # re-anchor the IDS case to the customer
                    case.anchor_entity, case.customer = cust, cust
                    self.store.append_audit("engine", "CASE_REANCHORED", case.case_id, {"anchor": cust})
        if case is None or case.status not in ("OPEN", "INVESTIGATING"):
            if p <= BASE:
                return None
            anchor = cust or sorted(ev.entity_tokens)[0]
            case = Case(case_id=new_id("case"), anchor_entity=anchor, customer=cust, opened_at=ev.occurred_at,
                        updated_at=ev.occurred_at, last_event_ts=ev.occurred_at)
        if case.customer:
            self.case_by_customer[case.customer] = case.case_id
        for t in ev.entity_tokens:
            if t.startswith("ip:"):
                self.case_by_ip[t] = case.case_id
        case.entities = sorted(set(case.entities) | set(ev.entity_tokens))
        case.updated_at = case.last_event_ts = ev.occurred_at
        return case

    # ------------------------------------------------------------ fusion, patterns, floors, stages (§10.5, §10.7)
    @staticmethod
    def _ell(e: Evidence) -> float:
        return e.reliability * max(-2.0, min(3.0, logit(e.p) - logit(BASE)))

    def _fuse(self, case: Case, evidence: list[Evidence], new: Evidence) -> Case:
        by_fam: dict[str, list[Evidence]] = {}
        for e in evidence:
            by_fam.setdefault(e.family, []).append(e)
        for items in by_fam.values():
            for k, e in enumerate(sorted(items, key=self._ell, reverse=True)):
                e.contribution = self._ell(e) * (1.0 if k == 0 else 0.5)
        hits = list(case.pattern_hits)
        s1 = [e for e in evidence if e.stage == "S1_INITIAL_ACCESS" and e.contribution > 0]
        if "pat_ATO1" not in hits and new.stage == "S2_CONTROL_TAKEOVER" and new.contribution > 0 and \
                any(timedelta(0) <= new.ts - e.ts <= timedelta(minutes=30) for e in s1):
            hits.append("pat_ATO1")
        if "pat_CASE_IP_CLOUD" not in hits and new.detector == "cyber":
            earlier_ips = {t for e in evidence if e is not new for t in e.entities if t.startswith("ip:")}
            if any(t in earlier_ips for t in new.entities if t.startswith("ip:")):
                hits.append("pat_CASE_IP_CLOUD")
        L = logit(BASE) + sum(e.contribution for e in evidence) + sum(PATTERNS[h][1] for h in hits)
        p = 1 / (1 + math.exp(-L))
        band = band_of(p)
        floors = list(case.floors)
        if any(r.code == "CUSTOMER_DENIED" for e in evidence for r in e.reasons) and "floor_CUSTOMER_DENIED" not in floors:
            floors.append("floor_CUSTOMER_DENIED")
            case.status = "INVESTIGATING"
        stages = dict(case.stages)
        if new.contribution > 0 and new.stage not in stages:
            stages[new.stage] = StageHit(ts=new.ts, evidence_id=new.evidence_id)
        recent = {s for s, h in stages.items() if new.ts - h.ts <= timedelta(minutes=30)}
        if len(recent) >= 3 and "floor_THREE_STAGES" not in floors:
            floors.append("floor_THREE_STAGES")
        floor_min = {"floor_CUSTOMER_DENIED": "CRITICAL", "floor_THREE_STAGES": "MEDIUM", "floor_SEED_PAYEE": "HIGH"}
        for f in floors:
            if BAND_ORDER.index(floor_min[f]) > BAND_ORDER.index(band):
                band = floor_min[f]
        return case.model_copy(update={"log_odds": L, "p_attack": p, "band": band, "pattern_hits": hits, "floors": floors, "stages": stages})

    # ------------------------------------------------------------ console read models
    def graph_elements(self, case_id: str, hops: int = 2, max_nodes: int = 300) -> GraphElements:
        case = self.store.get_case(case_id)
        if case is None:
            raise KeyError(case_id)
        ents = set(case.entities)
        if ents & SEED_LINKED_PAYEES:
            ents |= SEEDS | {tok("cust", "C-RAVI-01"), tok("cust", "C-MULE-01")}
        nodes = [GraphNode(id=t, label=f"{t.split(':')[0]} …{t[-6:]}", kind=t.split(":")[0], seed=t in SEEDS, in_case=t in case.entities)
                 for t in sorted(ents)][:max_nodes]
        ids = {n.id for n in nodes}
        cust = case.customer
        pairs = []
        for t in ids:
            k = t.split(":")[0]
            if cust and t != cust and k in ("acct", "phone", "cid"):
                pairs.append((t, cust, {"acct": "OWNS", "phone": "HAS_PHONE", "cid": "ACCESSED"}[k], 0.8))
            if k == "dev":
                pairs += [(a, t, "LOGGED_IN_FROM", 0.9) for a in ids if a.startswith("acct:") and a not in SEED_LINKED_PAYEES | SEEDS and t not in SEEDS]
                pairs += [(t, i, "CONNECTED_VIA", 0.5) for i in ids if i.startswith("ip:")][:1]
        for payee in ids & SEED_LINKED_PAYEES:
            pairs += [(payee, d, "LOGGED_IN_FROM", 0.9) for d in ids & SEEDS if d.startswith("dev:")]
            pairs += [(a, payee, "ADDED_PAYEE", 0.9) for a in ids if a.startswith("acct:") and a not in SEED_LINKED_PAYEES | SEEDS][:1]
        pairs += [(a, d, "LOGGED_IN_FROM", 0.9) for a in ids & SEEDS if a.startswith("acct:") for d in ids & SEEDS if d.startswith("dev:")]
        edges = [GraphEdge(id=f"{s}|{d}|{et}", source=s, target=d, edge_type=et, confidence=c) for s, d, et, c in pairs if s in ids and d in ids]
        return GraphElements(nodes=nodes, edges=list({e.id: e for e in edges}.values()))

    def dev_explain(self, store, case_id: str) -> Explanation:
        case = store.get_case(case_id)
        if case is None:
            raise KeyError(case_id)
        evidence = store.list_evidence(case_id)
        parts = [ExplanationPart(part_id="prior", kind="prior", label=f"Base rate {BASE:.0%}", contribution=logit(BASE),
                                 running_log_odds=logit(BASE), running_p=BASE)]
        run = logit(BASE)
        for e in evidence:
            run += e.contribution
            parts.append(ExplanationPart(part_id=e.evidence_id, kind="evidence", label=", ".join(r.code for r in e.reasons)[:80],
                                         detector=e.detector, stage=e.stage, contribution=e.contribution, running_log_odds=run,
                                         running_p=1 / (1 + math.exp(-run)), ts=e.ts))
        for h in case.pattern_hits:
            run += PATTERNS[h][1]
            parts.append(ExplanationPart(part_id=h, kind="pattern", label=PATTERNS[h][0], contribution=PATTERNS[h][1],
                                         running_log_odds=run, running_p=1 / (1 + math.exp(-run)), ts=case.updated_at))
        narrative = [NarrativeSentence(text=f"{e.stage}: {', '.join(r.code for r in e.reasons)} [{e.evidence_id}].", cites=[e.evidence_id])
                     for e in evidence]
        return Explanation(case_id=case_id, prior_log_odds=logit(BASE), parts=parts, final_log_odds=run, p_attack=1 / (1 + math.exp(-run)),
                           band=case.band, floors=case.floors, narrative=narrative, shap_by_evidence={}, seed_paths=[])

