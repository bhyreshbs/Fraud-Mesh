"""Narrative templates (PRD §10.10): one sentence per evidence item, keyed by stage, plus a closing sentence.
Every sentence ends with its citations; reason codes become human text through REASON_TEXT."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from engine.contracts import SEVERITY_HOLD, Decision, Evidence, NarrativeSentence

IST = timezone(timedelta(hours=5, minutes=30))

TEMPLATES = {
    "S0_RECON": "At {time} {reason_text} was seen from {ip_short} [{evidence_id}].",
    "S1_INITIAL_ACCESS": "At {time} a login succeeded from {reason_text} [{evidence_id}].",
    "S2_CONTROL_TAKEOVER": "At {time} {reason_text} [{evidence_id}]{pattern_cite}.",
    "S3_IDENTITY_MANIPULATION": "At {time} a KYC check returned {reason_text} [{evidence_id}].",
    "S4_ESCALATION": "At {time} {reason_text} ({technique}) [{evidence_id}]{pattern_cite}.",
    "S5_POSITIONING": "At {time} a payee was added that {reason_text} [{evidence_id}].",
    "S6_MONETIZATION": "At {time} a transfer of Rs {amount} was attempted ({reason_text}) [{evidence_id}].",
}
CLOSING = ("FraudMesh first intervened at {eip_time} with {eip_actions} [{eip_decision_id}]; "
           "the case is now {band} [{last_decision_id}].")
CLOSING_NO_INTERVENTION = "FraudMesh has not needed to intervene; the case is now {band} [{last_decision_id}]."

REASON_TEXT = {
    # netsec
    "IDS_SEV1": "a severity-1 IDS alert", "IDS_SEV2": "a severity-2 IDS alert", "IDS_SEV3": "a severity-3 IDS alert",
    "CREDENTIAL_STUFFING_IP": "credential stuffing against many customers",
    # behaviour
    "NEW_DEVICE": "a new device", "NEW_ASN": "a new network", "FAR_FROM_HOME": "far from home",
    "ODD_HOUR": "an unusual hour", "FAILED_LOGINS": "recent failed logins", "COLD_START": "a customer with little history",
    "IMPOSSIBLE_TRAVEL": "an impossible-travel location",
    # auth
    "MFA_CHANGED_AFTER_NEW_DEVICE": "the MFA factor was changed soon after a new-device login",
    "PROFILE_CHANGE_AFTER_NEW_DEVICE": "the profile was changed soon after a new-device login",
    "MFA_FAIL_THEN_PASS": "an MFA challenge passed after repeated failures",
    "PUSH_SPAM": "repeated push challenges were rejected or ignored", "RECENT_SIM_SWAP": "the SIM was swapped recently",
    "STEP_UP_PASSED_WITH_FRESH_FACTOR": "a step-up passed on a freshly changed factor",
    "STEP_UP_FAILED_OR_TIMEOUT": "a step-up failed or timed out",
    "STEP_UP_PASSED_TRUSTED": "a step-up passed on a long-registered factor",
    "CUSTOMER_DENIED": "the customer answered \"Not me\" on the registered phone",
    # kyc
    "LOW_LIVENESS": "low liveness", "LOW_FACE_MATCH": "a weak face match", "DOC_TAMPER": "signs of document tampering",
    "INJECTION_SUSPECTED": "a suspected camera injection",
    # cyber
    "cloud_limit_raise_untrusted_ip": "a support identity raised the transfer limit from an untrusted IP",
    "bulk_profile_read_support_console": "a support identity bulk-read customer profiles",
    "mfa_reset_by_support_untrusted_ip": "a support identity reset the customer's MFA from an untrusted IP",
    # graph
    "SEED_DISTANCE_0": "is itself a confirmed fraud entity", "SEED_DISTANCE_1": "is one hop from a confirmed fraud entity",
    "SEED_DISTANCE_2": "is two hops from a confirmed fraud entity", "SEED_DISTANCE_3": "is three hops from a confirmed fraud entity",
    "WEAK_PATH_CAP": "over a weak link", "PAYEE_NAME_MISMATCH": "does not match the payee's name",
    "MULE_FLOW": "shows mule-like money flow",
    # txn
    "AMOUNT_HIGH": "a high amount", "AMOUNT_HIGH_VS_MEDIAN": "far above the usual amount", "TXN_VELOCITY_1H": "many transfers in an hour",
    "TXN_SUM_24H": "a high 24-hour total", "NEW_PAYEE": "a new payee", "PAYEE_RECENTLY_ADDED": "a just-added payee",
    "PAYEE_FAN_IN": "a payee receiving from many senders", "PAYEE_SUM_24H": "a high total to this payee",
    "NEAR_LIMIT_AMOUNTS": "amounts just under a limit", "RECENT_NEW_DEVICE": "a recently seen new device",
    "STRUCTURING": "amounts structured just under a limit", "DEGRADED_HIGH": "a large amount to a new payee, model offline",
    "DEGRADED_LOW": "model offline",
}
ACTION_TEXT = {
    "ALLOW": "allow", "CAPTCHA_CHALLENGE": "a CAPTCHA", "STEP_UP_ANY_FACTOR": "a step-up on any factor",
    "STEP_UP_TRUSTED_FACTOR": "a step-up on a trusted factor", "HOLD_OUTBOUND_PAYMENTS": "a hold on outbound payments",
    "FREEZE_NEW_PAYEES": "a freeze on new payees", "BLOCK_PENDING_PAYMENTS": "a block on pending payments",
    "REVOKE_SESSIONS": "revoked sessions", "OPEN_CASE_P1": "a P1 case", "OPEN_CASE_P2": "a P2 case",
}


def hhmm(ts: datetime) -> str:
    return ts.astimezone(IST).strftime("%H:%M")


def indian_amount(paise: int) -> str:
    """₹4,80,000 style grouping of whole rupees: 48000000 paise → '4,80,000'."""
    s = str(paise // 100)
    if len(s) <= 3:
        return s
    head, tail = s[:-3], s[-3:]
    groups = []
    while len(head) > 2:
        groups.insert(0, head[-2:])
        head = head[:-2]
    return ",".join([head, *groups, tail]) if head else ",".join([*groups, tail])


def join_words(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def reason_text(ev: Evidence) -> str:
    return join_words([REASON_TEXT.get(r.code, r.code.lower().replace("_", " ")) for r in ev.reasons])


def ip_short(ev: Evidence) -> str:
    """Raw IPs are never stored (PRD §1 privacy), so the sentence names the IP token, shortened."""
    ip = next((t for t in ev.entities if t.startswith("ip:")), None)
    return f"IP {ip[3:9]}…" if ip else "an unknown IP"


def evidence_sentence(ev: Evidence, patterns_completed: list[str]) -> NarrativeSentence:
    pattern_cite = "".join(f" [{p}]" for p in patterns_completed)
    text = TEMPLATES[ev.stage].format(
        time=hhmm(ev.ts), reason_text=reason_text(ev), ip_short=ip_short(ev), evidence_id=ev.evidence_id,
        pattern_cite=pattern_cite, technique=ev.attack_technique or "no ATT&CK mapping",
        amount=indian_amount(ev.amount_paise or 0))
    if pattern_cite and "{pattern_cite}" not in TEMPLATES[ev.stage]:
        text = text[:-1] + pattern_cite + "."
    return NarrativeSentence(text=text, cites=[ev.evidence_id, *patterns_completed])


def closing_sentence(decisions: list[Decision], band: str, severity_of) -> NarrativeSentence | None:
    if not decisions:
        return None
    last = decisions[-1]
    first_hold = next((d for d in decisions if severity_of(d.actions) >= SEVERITY_HOLD), None)
    if first_hold is None:
        return NarrativeSentence(text=CLOSING_NO_INTERVENTION.format(band=band, last_decision_id=last.decision_id),
                                 cites=[last.decision_id])
    actions = join_words([ACTION_TEXT[a] for a in first_hold.actions if not a.startswith("OPEN_CASE")])
    text = CLOSING.format(eip_time=hhmm(first_hold.created_at), eip_actions=actions, eip_decision_id=first_hold.decision_id,
                          band=band, last_decision_id=last.decision_id)
    return NarrativeSentence(text=text, cites=list(dict.fromkeys([first_hold.decision_id, last.decision_id])))
