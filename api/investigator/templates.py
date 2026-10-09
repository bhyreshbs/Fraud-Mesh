"""Investigator AI answers (PRD §15.6 task 2): three demo questions routed by keywords, answered by fixed templates over
the case tools. No language model, no free text from the question or from the data reaches the answer — only enum labels,
tool numbers (via fmt_*) and IDs. Every sentence carries its citations.

  "why" / "block"              -> top contributions + policy rule + amount
  "ignore" / "without <det>"   -> run_replay(ablate=[det]) vs the baseline
  "earliest"                   -> baseline earliest intervention point
  anything else                -> what it can answer
"""
from __future__ import annotations

import re

from api.investigator.tools import CaseTools
from engine.contracts import ACTION_SEVERITY, SEVERITY_HOLD, NarrativeSentence

DETECTOR_WORDS = {"kyc": "kyc", "liveness": "kyc", "cyber": "cyber", "cloud": "cyber", "support": "cyber", "netsec": "netsec",
                  "network": "netsec", "ids": "netsec", "behaviour": "behaviour", "behavior": "behaviour", "login": "behaviour",
                  "auth": "auth", "mfa": "auth", "otp": "auth", "graph": "graph", "payee": "graph", "txn": "txn",
                  "transaction": "txn", "transfer": "txn"}
DETECTOR_LABEL = {"kyc": "KYC", "cyber": "the cloud-audit detector", "netsec": "the network IDS", "behaviour": "login behaviour",
                  "auth": "the auth and MFA detector", "graph": "the entity graph", "txn": "the transaction model"}
ACTION_TEXT = {"ALLOW": "allow", "CAPTCHA_CHALLENGE": "CAPTCHA", "STEP_UP_ANY_FACTOR": "step-up on any factor",
               "STEP_UP_TRUSTED_FACTOR": "step-up on the trusted device", "HOLD_OUTBOUND_PAYMENTS": "hold outbound payments",
               "FREEZE_NEW_PAYEES": "freeze new payees", "BLOCK_PENDING_PAYMENTS": "block pending payments",
               "REVOKE_SESSIONS": "revoke sessions", "OPEN_CASE_P2": "open a priority-two case", "OPEN_CASE_P1": "open a priority-one case"}
REASON_SHORT = {"IDS_SEV1": "IDS alert", "IDS_SEV2": "credential-stuffing alert", "IDS_SEV3": "IDS alert", "NEW_DEVICE": "new-device login",
                "MFA_CHANGED_AFTER_NEW_DEVICE": "SMS factor swapped after a new-device login",
                "STEP_UP_PASSED_WITH_FRESH_FACTOR": "step-up passed on a fresh factor", "LOW_LIVENESS": "low KYC liveness",
                "cloud_limit_raise_untrusted_ip": "limit raised from an untrusted IP", "SEED_DISTANCE_1": "payee next to a confirmed mule",
                "AMOUNT_HIGH_VS_MEDIAN": "unusually large transfer", "CUSTOMER_DENIED": "customer tapped Not me"}


def _label(e) -> str:
    return REASON_SHORT.get(e.reasons[0].code, e.reasons[0].code.replace("_", " ").lower()) if e.reasons else e.detector


def _actions(actions: list[str]) -> str:
    return ", ".join(ACTION_TEXT.get(a, a) for a in actions)


def _sentence(text: str, cites: list[str]) -> NarrativeSentence:
    return NarrativeSentence(text=text, cites=[c for c in dict.fromkeys(cites) if c])


def route(question: str) -> tuple[str, str | None]:
    q = question.lower()
    words = re.findall(r"[a-z]+", q)
    if "without" in words or "ignore" in words or "ignored" in words or "ignoring" in words:
        return "without", next((DETECTOR_WORDS[w] for w in words if w in DETECTOR_WORDS), None)
    if "earliest" in words or "earlier" in words:
        return "earliest", None
    if "why" in words or any(w.startswith("block") for w in words):
        return "why", None
    return "help", None


def answer(question: str, t: CaseTools) -> list[NarrativeSentence]:
    kind, detector = route(question)
    if kind == "why":
        return _why(t)
    if kind == "without":
        return _without(t, detector) if detector else [_sentence(
            "Name the detector to leave out, for example: what if we ignored KYC, the network IDS or the cloud-audit detector.",
            [t.case.case_id])]
    if kind == "earliest":
        return _earliest(t)
    return [_sentence("I can answer three questions about this case: why it was blocked or held, what would change without "
                      "one detector (for example without KYC), and when the earliest intervention point was.", [t.case.case_id])]


def _why(t: CaseTools) -> list[NarrativeSentence]:
    s = t.get_case_summary()
    evidence, decisions = t.get_timeline()
    out = []
    if decisions:
        last = t.get_policy_rule(decisions[-1].decision_id)
        out.append(_sentence(f"FraudMesh rates this case {s.band} with P(attack) {t.fmt_pct(s.p_attack)}.", [last.decision_id]))
    top = sorted((e for e in evidence if e.contribution > 0), key=lambda e: e.contribution, reverse=True)[:3]
    if top:
        parts = [f"{_label(e)} ({t.fmt_signed(e.contribution)})" for e in top]
        out.append(_sentence("The largest contributions were " + ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1] + ".",
                             [e.evidence_id for e in top]))
    if decisions:
        last = decisions[-1]
        verb = "blocks pending payments" if "BLOCK_PENDING_PAYMENTS" in last.actions else \
            "holds outbound payments" if "HOLD_OUTBOUND_PAYMENTS" in last.actions else "does not stop payments"
        out.append(_sentence(f"Policy rule {last.policy_rule} applied: {_actions(last.actions)}, so the bank {verb}.", [last.decision_id]))
    s6 = [e for e in evidence if e.stage == "S6_MONETIZATION" and e.amount_paise]
    if s6:
        out.append(_sentence(f"The amount at risk is {t.fmt_inr(sum(e.amount_paise for e in s6))}.", [e.evidence_id for e in s6]))
    return out


def _without(t: CaseTools, detector: str) -> list[NarrativeSentence]:
    r = t.run_replay([detector])
    base = t.run_replay([])
    label = DETECTOR_LABEL[detector]
    out = []
    if r.eip and r.baseline_eip:
        if r.lead_time_lost_s and r.lead_time_lost_s > 0:
            out.append(_sentence(f"Without {label}, the earliest intervention moves from {t.fmt_time(r.baseline_eip.ts)} to "
                                 f"{t.fmt_time(r.eip.ts)}, {t.fmt_int(r.lead_time_lost_s)} seconds later.",
                                 [r.baseline_eip.evidence_id, r.eip.evidence_id, r.replay_id]))
        else:
            out.append(_sentence(f"Without {label}, the earliest intervention stays at {t.fmt_time(r.eip.ts)}.",
                                 [r.eip.evidence_id, r.replay_id]))
        out.append(_sentence(f"At that point P(attack) would be {t.fmt_pct(r.eip.p)} and the policy would {_actions(r.eip.actions)}.",
                             [r.eip.evidence_id, r.replay_id]))
    elif r.baseline_eip:
        out.append(_sentence(f"Without {label}, FraudMesh would never reach a hold in this case.", [r.replay_id, r.baseline_eip.evidence_id]))
    else:
        out.append(_sentence(f"FraudMesh did not reach a hold in this case, with or without {label}.", [r.replay_id]))
    out.append(_sentence(f"Money protected would be {t.fmt_inr(r.money_protected_paise)} instead of {t.fmt_inr(base.money_protected_paise)}.",
                         [r.replay_id, base.replay_id]))
    return out


def _earliest(t: CaseTools) -> list[NarrativeSentence]:
    r = t.run_replay([])
    if not r.eip:
        return [_sentence("FraudMesh has not intervened in this case yet: no decision reached a hold.", [r.replay_id])]
    _, decisions = t.get_timeline()
    dec = next((d for d in decisions if d.trigger_evidence_id == r.eip.evidence_id
                and max(ACTION_SEVERITY[a] for a in d.actions) >= SEVERITY_HOLD), None)
    out = [_sentence(f"The earliest intervention point was {t.fmt_time(r.eip.ts)}, when P(attack) reached {t.fmt_pct(r.eip.p)} "
                     f"and the policy chose to {_actions(r.eip.actions)}.", [r.eip.evidence_id, dec.decision_id if dec else r.replay_id])]
    evidence, _ = t.get_timeline()
    s6 = sorted((e for e in evidence if e.stage == "S6_MONETIZATION"), key=lambda e: e.ts)
    if r.lead_time_s is not None and s6:
        out.append(_sentence(f"That was {t.fmt_int(r.lead_time_s)} seconds before the first transfer.", [s6[0].evidence_id, r.replay_id]))
    out.append(_sentence(f"Acting there protects {t.fmt_inr(r.money_protected_paise)}.", [r.replay_id]))
    return out
