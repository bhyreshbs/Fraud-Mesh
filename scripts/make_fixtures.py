"""Build fixtures/api/*.json and the Phase 0 fixtures/engine/*_example.json from the PRD §12.4 golden values.

Every file is validated against its contract model before it is written. Run: python scripts/make_fixtures.py
The fusion arithmetic here exists only to make example data; the real engine lives in engine/ (Dev 2).
"""
from __future__ import annotations

import json
import math
import sys  # noqa: E402
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.common.tokenize import tok
from engine.contracts import (
    ACTION_SEVERITY,
    DETECTOR_FAMILY,
    STAGE_ORDER,
    BandThresholds,
    BenchmarkReport,
    Case,
    Decision,
    Evidence,
    Explanation,
    ExplanationPart,
    FamilyMetrics,
    FeedbackResult,
    GraphEdge,
    GraphElements,
    GraphNode,
    NarrativeSentence,
    Reason,
    ReplayPoint,
    ReplayResult,
    ShapItem,
    SimulationResult,
    StageHit,
    summarize,
)

ROOT = Path(__file__).resolve().parent.parent
IST = timezone(timedelta(hours=5, minutes=30))
BASE = 0.01
POLICY = {"LOW": ("low", ["ALLOW"]), "MEDIUM": ("medium", ["STEP_UP_ANY_FACTOR"]),
          "HIGH": ("high", ["HOLD_OUTBOUND_PAYMENTS", "STEP_UP_TRUSTED_FACTOR", "OPEN_CASE_P2"]),
          "CRITICAL": ("critical", ["BLOCK_PENDING_PAYMENTS", "FREEZE_NEW_PAYEES", "REVOKE_SESSIONS", "OPEN_CASE_P1"])}


def logit(x: float) -> float:
    return math.log(x / (1 - x))


def sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def band_of(p: float, t: BandThresholds = BandThresholds()) -> str:
    return "CRITICAL" if p >= t.critical else "HIGH" if p >= t.high else "MEDIUM" if p >= t.medium else "LOW"


def at(hh: int, mm: int, ss: int = 0) -> datetime:
    return datetime(2026, 10, 9, hh, mm, ss, tzinfo=IST)


# ---------------------------------------------------------------- demo identities -> tokens
PRIYA = tok("cust", "C-1042")
PRIYA_ACCT = tok("acct", "A-88213")
PRIYA_PHONE_DEV = tok("dev", "fp_priya_phone")
PRIYA_IP = tok("ip", "49.207.10.21")
ATT_DEV = tok("dev", "fp_attacker_01")
ATT_IP = tok("ip", "185.220.101.7")
NEW_PHONE = tok("phone", "+91 90000 11111")
CID = tok("cid", "svc-support-07")
RAVI = tok("cust", "C-RAVI-01")
RAVI_ACCT = tok("acct", "A-RAVI-778")
MULE = tok("cust", "C-MULE-01")
MULE_ACCT = tok("acct", "A-MULE-01")
MULE_DEV = tok("dev", "fp_mule_shared")
MULE_IP = tok("ip", "103.21.4.9")

CASE_ID = "case_51b0c3d2e4f5a6b7"

# (ts, detector, stage, p, r, technique, reasons, entities, amount, shap)
ITEMS = [
    (at(0, 39), "netsec", "S0_RECON", 0.03, 0.5, "T1110.004", [("IDS_SEV2", "SID 9000001 credential stuffing against /api/login")], [ATT_IP], None, None),
    (at(0, 41), "behaviour", "S1_INITIAL_ACCESS", 0.05, 0.6, "T1078", [("NEW_DEVICE", None), ("NEW_ASN", "AS64500 HostCo")], [PRIYA, PRIYA_ACCT, ATT_DEV, ATT_IP], None, None),
    (at(0, 44), "auth", "S2_CONTROL_TAKEOVER", 0.06, 0.7, "T1556.006", [("MFA_CHANGED_AFTER_NEW_DEVICE", "sms factor replaced 3 min after new-device login")], [PRIYA, ATT_DEV, ATT_IP, NEW_PHONE], None, None),
    (at(0, 52), "auth", "S2_CONTROL_TAKEOVER", 0.08, 0.7, "T1556.006", [("STEP_UP_PASSED_WITH_FRESH_FACTOR", "factor age 0.13 h")], [PRIYA, ATT_DEV, ATT_IP], None, None),
    (at(0, 52), "kyc", "S3_IDENTITY_MANIPULATION", 0.06, 0.6, None, [("LOW_LIVENESS", "liveness 0.38")], [PRIYA, ATT_DEV, ATT_IP], None, None),
    (at(0, 58), "cyber", "S4_ESCALATION", 0.04, 0.5, "T1098", [("cloud_limit_raise_untrusted_ip", "UpdateTransferLimit by support console")], [CID, ATT_IP, PRIYA], None, None),
    (at(1, 3), "graph", "S5_POSITIONING", 0.10, 0.8, "T1657", [("SEED_DISTANCE_1", "payee shares a device with a confirmed mule")], [PRIYA, PRIYA_ACCT, RAVI_ACCT, ATT_DEV, ATT_IP], None, None),
    (at(1, 5), "txn", "S6_MONETIZATION", 0.20, 0.85, None, [("AMOUNT_HIGH_VS_MEDIAN", None), ("NEW_PAYEE", None), ("PAYEE_FAN_IN", None)],
     [PRIYA, PRIYA_ACCT, RAVI_ACCT, ATT_DEV, ATT_IP], 48000000,
     [("amount_to_median_30d", 61.2, 1.84), ("payee_is_new", 1.0, 0.97), ("minutes_since_new_device", 24.0, 0.61),
      ("hour_deviation", 4.1, 0.32), ("payee_fan_in_24h", 1.0, 0.08)]),
]
EVENT_TYPES = ["network_ids_alert", "login", "mfa_change", "step_up_result", "kyc_result", "cloud_audit", "payee_added", "transaction"]
PATTERN_AFTER = {2: ("pat_ATO1", "New-device login followed by an MFA or profile change", 0.5),
                 5: ("pat_CASE_IP_CLOUD", "Cloud action from an IP already seen in this case", 0.3)}


def evidence_list() -> list[Evidence]:
    out = []
    for i, (ts, det, stage, p, r, tech, reasons, ents, amount, shap) in enumerate(ITEMS):
        out.append(Evidence(
            evidence_id=f"ev_{i + 1:02d}9c2e{'a1b2c3d4e5'}", event_id=f"evt_{i + 1:02d}3f9a1c0d2b7e4a",
            detector=det, detector_version="1.0.0", family=DETECTOR_FAMILY[det], stage=stage, attack_technique=tech,
            p=p, reliability=r, entities=sorted(set(ents)), reasons=[Reason(code=c, detail=d) for c, d in reasons],
            shap=[ShapItem(feature=f, value=v, shap=s) for f, v, s in shap] if shap else None,
            amount_paise=amount, ts=ts))
    return out


def raw_l(ev: Evidence) -> float:
    return ev.reliability * max(-2.0, min(3.0, logit(ev.p) - logit(BASE)))


def fuse(evs: list[Evidence], bonuses: float) -> tuple[float, dict[str, float]]:
    by_fam: dict[str, list[Evidence]] = {}
    for e in evs:
        by_fam.setdefault(e.family, []).append(e)
    contrib = {}
    for items in by_fam.values():
        for k, e in enumerate(sorted(items, key=raw_l, reverse=True)):
            contrib[e.evidence_id] = raw_l(e) * (1.0 if k == 0 else 0.5)
    return logit(BASE) + sum(contrib.values()) + bonuses, contrib


def main() -> None:
    evs = evidence_list()
    # incremental fusion -> replay timeline + decisions
    points, decisions, bonus = [], [], 0.0
    for i, ev in enumerate(evs):
        if i in PATTERN_AFTER:
            bonus += PATTERN_AFTER[i][2]
        L, _ = fuse(evs[: i + 1], bonus)
        p = sigmoid(L)
        band = band_of(p)
        rule, actions = POLICY[band]
        points.append(ReplayPoint(ts=ev.ts, evidence_id=ev.evidence_id, p=p, band=band, actions=actions,
                                  severity=max(ACTION_SEVERITY[a] for a in actions)))
        decisions.append(Decision(decision_id=f"dec_{i + 1:02d}77aa0b1c2d3e4f", case_id=CASE_ID, trigger_event_id=ev.event_id,
                                  trigger_evidence_id=ev.evidence_id, band=band, p_attack=p, policy_rule=rule,
                                  actions=actions, created_at=ev.ts))
    final_L, contrib = fuse(evs, bonus)
    for ev in evs:
        ev.contribution = contrib[ev.evidence_id]

    stages = {}
    for ev in evs:
        if ev.stage not in stages and ev.contribution > 0:
            stages[ev.stage] = StageHit(ts=ev.ts, evidence_id=ev.evidence_id)
    entities = sorted({t for e in evs for t in e.entities})
    case = Case(case_id=CASE_ID, anchor_entity=PRIYA, customer=PRIYA, status="OPEN", band=band_of(sigmoid(final_L)),
                p_attack=sigmoid(final_L), log_odds=final_L, stages=stages, entities=entities,
                pattern_hits=["pat_ATO1", "pat_CASE_IP_CLOUD"], floors=[], amount_at_risk_paise=48000000,
                payment_state="blocked", latest_actions=POLICY["CRITICAL"][1], opened_at=evs[0].ts,
                updated_at=evs[-1].ts, last_event_ts=evs[-1].ts)
    summary = summarize(case)

    eip = next(pt for pt in points if pt.severity >= 2)
    s6 = next(e for e in evs if e.stage == "S6_MONETIZATION")
    replay = ReplayResult(replay_id="rep_a1f3b2c4d5e6f708", case_id=CASE_ID, mode="fused", ablated=[], timeline=points,
                          eip=eip, baseline_eip=eip, lead_time_s=int((s6.ts - eip.ts).total_seconds()), lead_time_lost_s=0,
                          money_protected_paise=sum(e.amount_paise or 0 for e in evs if e.stage == "S6_MONETIZATION" and e.ts >= eip.ts))

    # explanation parts with final contributions
    parts = [ExplanationPart(part_id="prior", kind="prior", label="Base rate 1%", contribution=logit(BASE),
                             running_log_odds=logit(BASE), running_p=BASE)]
    run = logit(BASE)
    labels = {"netsec": "IDS credential stuffing", "behaviour": "New device + new ASN login", "kyc": "Low liveness on re-KYC",
              "cyber": "Support console raised transfer limit", "graph": "Payee 1 hop from fraud seed", "txn": "₹4,80,000 IMPS transfer"}
    for i, ev in enumerate(evs):
        run += ev.contribution
        lab = labels.get(ev.detector) or ("SMS number changed after new device" if i == 2 else "OTP passed on 8-minute-old number")
        parts.append(ExplanationPart(part_id=ev.evidence_id, kind="evidence", label=lab, detector=ev.detector, stage=ev.stage,
                                     contribution=ev.contribution, running_log_odds=run, running_p=sigmoid(run), ts=ev.ts))
        if i in PATTERN_AFTER:
            pid, plab, b = PATTERN_AFTER[i]
            run += b
            parts.append(ExplanationPart(part_id=pid, kind="pattern", label=plab, contribution=b, running_log_odds=run,
                                         running_p=sigmoid(run), ts=ev.ts))
    assert abs(run - final_L) < 1e-9
    e = {i + 1: ev.evidence_id for i, ev in enumerate(evs)}
    narrative = [
        NarrativeSentence(text=f"At 00:39 credential stuffing (IDS severity 2) was seen from 185.220.x [{e[1]}].", cites=[e[1]]),
        NarrativeSentence(text=f"At 00:41 a login succeeded from a new device on a new network (AS64500 HostCo) [{e[2]}].", cites=[e[2]]),
        NarrativeSentence(text=f"At 00:44 the SMS number was replaced 3 minutes after a new-device login [{e[3]}] [pat_ATO1].", cites=[e[3], "pat_ATO1"]),
        NarrativeSentence(text=f"At 00:52 a step-up passed on a factor only 0.13 hours old [{e[4]}].", cites=[e[4]]),
        NarrativeSentence(text=f"At 00:52 a KYC check returned low liveness (0.38) [{e[5]}].", cites=[e[5]]),
        NarrativeSentence(text=f"At 00:58 a support-console identity raised the transfer limit from an untrusted IP (T1098) [{e[6]}] [pat_CASE_IP_CLOUD].", cites=[e[6], "pat_CASE_IP_CLOUD"]),
        NarrativeSentence(text=f"At 01:03 a payee was added that is 1 hop from a confirmed mule device [{e[7]}].", cites=[e[7]]),
        NarrativeSentence(text=f"At 01:05 a transfer of Rs 4,80,000 was attempted (amount far above median, new payee) [{e[8]}].", cites=[e[8]]),
        NarrativeSentence(text=f"FraudMesh first intervened at 00:52 with HOLD_OUTBOUND_PAYMENTS, STEP_UP_TRUSTED_FACTOR [{decisions[4].decision_id}]; "
                               f"the case is now CRITICAL [{decisions[7].decision_id}].", cites=[decisions[4].decision_id, decisions[7].decision_id]),
    ]
    explanation = Explanation(case_id=CASE_ID, prior_log_odds=logit(BASE), parts=parts, final_log_odds=final_L,
                              p_attack=sigmoid(final_L), band=case.band, floors=[], narrative=narrative,
                              shap_by_evidence={evs[7].evidence_id: evs[7].shap},
                              seed_paths=[[RAVI_ACCT, RAVI, MULE_DEV], [ATT_DEV, PRIYA_ACCT, RAVI_ACCT, RAVI, MULE_DEV]][:1])

    simulation = SimulationResult(thresholds=BandThresholds(), attacks_total=90, attacks_caught=81, benign_customers_total=1960,
                                  benign_customers_flagged=23, legit_payments_total=48211, legit_payments_stopped=37,
                                  money_protected_paise=2_184_500_000, median_lead_time_s=742)
    feedback = FeedbackResult(case_id=CASE_ID, verdict="CONFIRMED_FRAUD",
                              reliability_before={"txn": 0.85, "behaviour": 0.6, "auth": 0.7, "kyc": 0.6, "cyber": 0.5, "netsec": 0.5, "graph": 0.8},
                              reliability_after={"txn": 18 / 21, "behaviour": 7 / 11, "auth": 8 / 11, "kyc": 7 / 11, "cyber": 6 / 11, "netsec": 0.5, "graph": 9 / 11},
                              seeds_added=[ATT_DEV, ATT_IP, CID, RAVI_ACCT], status_after="CONFIRMED_FRAUD")

    # graph
    def node(t: str, seed: bool = False) -> GraphNode:
        return GraphNode(id=t, label=f"{t.split(':')[0]} …{t[-6:]}", kind=t.split(":")[0], seed=seed, in_case=t in entities)
    nodes = [node(t) for t in [PRIYA, PRIYA_ACCT, PRIYA_PHONE_DEV, PRIYA_IP, ATT_DEV, ATT_IP, NEW_PHONE, CID, RAVI_ACCT, RAVI, MULE, MULE_IP]]
    nodes += [node(MULE_DEV, seed=True), node(MULE_ACCT, seed=True)]
    eds = [(PRIYA, PRIYA_ACCT, "OWNS", 1.0), (PRIYA_ACCT, PRIYA_PHONE_DEV, "LOGGED_IN_FROM", 0.9), (PRIYA_PHONE_DEV, PRIYA_IP, "CONNECTED_VIA", 0.5),
           (PRIYA_ACCT, ATT_DEV, "LOGGED_IN_FROM", 0.9), (ATT_DEV, ATT_IP, "CONNECTED_VIA", 0.5), (ATT_DEV, NEW_PHONE, "RESET", 0.9),
           (PRIYA, NEW_PHONE, "HAS_PHONE", 1.0), (CID, ATT_IP, "ACTED_FROM", 0.7), (CID, PRIYA, "ACCESSED", 0.8),
           (PRIYA_ACCT, RAVI_ACCT, "ADDED_PAYEE", 0.9), (PRIYA_ACCT, RAVI_ACCT, "SENT", 1.0), (RAVI, RAVI_ACCT, "OWNS", 1.0),
           (RAVI_ACCT, MULE_DEV, "LOGGED_IN_FROM", 0.9), (MULE_ACCT, MULE_DEV, "LOGGED_IN_FROM", 0.9), (MULE, MULE_ACCT, "OWNS", 1.0),
           (MULE_DEV, MULE_IP, "CONNECTED_VIA", 0.5), (RAVI, MULE, "SHARES_DEVICE", 0.9)]
    graph = GraphElements(nodes=nodes, edges=[GraphEdge(id=f"{s}|{d}|{t}", source=s, target=d, edge_type=t, confidence=c) for s, d, t, c in eds])

    challenges = [
        {"challenge_id": "chl_0d4e1a2b3c4d5e6f", "method": "sms_otp", "status": "passed", "created_at": at(0, 44, 5).isoformat()},
        {"challenge_id": "chl_1e5f2a3b4c5d6e7f", "method": "device_push", "status": "pending", "created_at": at(0, 52, 5).isoformat()},
    ]

    # extra queue rows so the console shows more than one case
    def other(cid: str, cust_raw: str, band: str, p: float, stages: list[str], actions: list[str], pay: str, amt: int, t: datetime) -> dict:
        c = tok("cust", cust_raw)
        return {"case_id": cid, "anchor_entity": c, "customer": c, "status": "OPEN", "band": band, "p_attack": p,
                "stages_reached": stages, "current_stage": stages[-1] if stages else None, "latest_actions": actions,
                "payment_state": pay, "amount_at_risk_paise": amt, "updated_at": t.isoformat()}
    others = [
        other("case_7c2e9a1b3d4f5e60", "C-MULE-01", "HIGH", 0.684, ["S5_POSITIONING", "S6_MONETIZATION"], POLICY["HIGH"][1], "held", 112_000_000, at(0, 31)),
        other("case_2a9d4c1e7b3f8a05", "C-2219", "MEDIUM", 0.312, ["S1_INITIAL_ACCESS", "S2_CONTROL_TAKEOVER"], ["STEP_UP_ANY_FACTOR"], "normal", 0, at(0, 22)),
        other("case_9e1f0a2b3c4d5e6f", "C-0457", "MEDIUM", 0.214, ["S1_INITIAL_ACCESS"], ["STEP_UP_ANY_FACTOR"], "normal", 0, at(0, 17)),
        other("case_4b8c2d6e0f1a3b5c", "C-1877", "LOW", 0.043, ["S0_RECON"], ["CAPTCHA_CHALLENGE"], "normal", 0, at(0, 12)),
        other("case_6d0e4f8a2b1c3d5e", "C-0093", "LOW", 0.018, ["S1_INITIAL_ACCESS"], ["ALLOW"], "normal", 0, at(0, 5)),
    ]
    from engine.contracts import CaseSummary
    items = [summary] + [CaseSummary.model_validate(o) for o in others]

    detectors = [{"detector": d, "family": DETECTOR_FAMILY[d], "alpha": a, "beta": b, "reliability": a / (a + b)}
                 for d, (a, b) in {"txn": (17, 3), "behaviour": (6, 4), "auth": (7, 3), "kyc": (6, 4), "cyber": (5, 5), "netsec": (5, 5), "graph": (8, 2)}.items()]
    bench = BenchmarkReport(seed=7, days=14, families={
        "ato": FamilyMetrics(instances=30, caught_fused=28, caught_siloed=9, median_lead_time_s=780),
        "mule_fanin": FamilyMetrics(instances=30, caught_fused=27, caught_siloed=14, median_lead_time_s=1260),
        "structuring": FamilyMetrics(instances=30, caught_fused=26, caught_siloed=11, median_lead_time_s=540)},
        benign_customers=1910, benign_flagged_high=21, false_positive_rate=0.011, false_declines_rate=0.0008,
        alert_compression=6.0, txn_pr_auc=0.81, txn_roc_auc=0.97, txn_ece=0.031)
    open_cases = [i for i in items if i.status in ("OPEN", "INVESTIGATING")]
    metrics = {"benchmark": bench.model_dump(mode="json"),
               "live": {"cases_open": len(open_cases), "critical_open": sum(1 for i in open_cases if i.band == "CRITICAL"),
                        "money_protected_paise": 48000000 + 112_000_000, "alert_compression": 6.0}}

    def dump(path: str, obj) -> None:
        p = ROOT / path
        p.parent.mkdir(parents=True, exist_ok=True)
        data = obj.model_dump(mode="json") if hasattr(obj, "model_dump") else obj
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("wrote", path)

    dump("fixtures/engine/explanation_example.json", explanation)
    dump("fixtures/engine/replay_example.json", replay)
    dump("fixtures/engine/simulation_example.json", simulation)
    dump("fixtures/engine/feedback_example.json", feedback)
    dump("fixtures/api/cases_list.json", {"items": [i.model_dump(mode="json") for i in items], "next_cursor": None})
    dump("fixtures/api/case.json", {"case": case.model_dump(mode="json"), "summary": summary.model_dump(mode="json")})
    dump("fixtures/api/timeline.json", {"evidence": [x.model_dump(mode="json") for x in evs],
                                        "decisions": [d.model_dump(mode="json") for d in decisions], "challenges": challenges})
    dump("fixtures/api/graph.json", graph)
    dump("fixtures/api/simulation.json", simulation)
    dump("fixtures/api/detectors.json", detectors)
    dump("fixtures/api/metrics.json", metrics)
    dump("fixtures/api/explanation.json", explanation)
    dump("fixtures/api/replay.json", replay)
    print("bands:", [pt.band for pt in points], f"final L={final_L:.3f} P={sigmoid(final_L):.3f}")
    assert [pt.band for pt in points] == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "CRITICAL", "CRITICAL", "CRITICAL"]
    assert STAGE_ORDER[0] in case.stages


if __name__ == "__main__":
    main()
