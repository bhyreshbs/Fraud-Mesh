"""Attack and policy simulator (Digital Twin phase 2): replay a case's events into an isolated copy of the virtual bank
under one prevention strategy at a time, and measure what that strategy would have saved.

The risk the engine computes after each event does not depend on the strategy (the same evidence arrives), but what the
attacker can still do does. Effects, in order of the policy actions (documented assumptions, shown in the UI):
  SMS OTP step-up           passes for the attacker when the SMS number / SIM is attacker-controlled, otherwise the
                            attacker fails and is locked out; the real customer always passes (friction only when the
                            activity was genuine: checking a scammed payment is the point, not friction)
  registered-device push    the genuine customer sees it; during an attack they deny it (at the time of their actual
                            answer when the case has one, else PUSH_RESPONSE later), which revokes the attacker's sessions
  hold / block payments     outbound transfers are held for review / blocked (the money stays in the bank),
                            including the transfer whose own risk triggered the control
  freeze new payees         payees added afterwards are rejected, so transfers to them are rejected too
  revoke sessions           the attacker is logged out and their remaining in-session steps never happen
Network sensor and support-console events are outside the customer's session, so they always happen.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta

from engine.contracts import BAND_ORDER, StoredEvent
from engine.twin.models import Intervention, PolicyOutcome
from engine.twin.state import VirtualBank

PUSH_RESPONSE = timedelta(minutes=10)
SESSION_EVENTS = {"login", "mfa_change", "mfa_challenge", "profile_change", "kyc_result", "payee_added", "transaction"}


@dataclass
class SimStep:
    event: StoredEvent
    actor: str                     # attacker | customer | network | insider | system
    is_attack: bool                # ground-truth label (or the actor heuristic when there is none)
    stage: str
    band: str                      # fused band after this event
    p: float
    live_actions: list[str]        # what the live FraudMesh policy did after this event
    txn_p: float | None            # the txn detector's own p on a transfer (for the siloed baseline)


@dataclass(frozen=True)
class Strategy:
    policy_id: str
    label: str
    description: str

    def actions(self, s: SimStep) -> list[str]:
        at_least = lambda band: BAND_ORDER.index(s.band) >= BAND_ORDER.index(band)  # noqa: E731
        if self.policy_id in ("fraudmesh", "fraudmesh_strong_txn"):
            return list(s.live_actions)
        if self.policy_id == "otp_only":
            return ["STEP_UP_ANY_FACTOR"] if at_least("MEDIUM") else []
        if self.policy_id == "hold_at_high":
            return ["HOLD_OUTBOUND_PAYMENTS"] if at_least("HIGH") else []
        if self.policy_id == "block_at_critical":
            return ["BLOCK_PENDING_PAYMENTS"] if at_least("CRITICAL") else []
        if self.policy_id == "freeze_payees_at_medium":
            return ["FREEZE_NEW_PAYEES"] if at_least("MEDIUM") else []
        return []                                                   # allow_all, siloed (handled on the transfer)


STRATEGIES = [
    Strategy("allow_all", "No controls", "Every step is allowed; the money moves."),
    Strategy("siloed", "Siloed detectors (today)", "Each team's tool alone: only a transfer the txn model scores >= 0.5 "
             "is blocked; identity, KYC and cyber alerts are not joined."),
    Strategy("otp_only", "SMS OTP at MEDIUM", "Ask for an SMS one-time password once the case reaches MEDIUM."),
    Strategy("freeze_payees_at_medium", "Freeze new payees at MEDIUM", "Reject new payees once the case reaches MEDIUM."),
    Strategy("hold_at_high", "Hold payments at HIGH", "Hold outbound payments once the case reaches HIGH."),
    Strategy("block_at_critical", "Block at CRITICAL only", "Block pending payments only once the case is CRITICAL."),
    Strategy("fraudmesh", "FraudMesh policy (live)", "policy.yaml: step-up at MEDIUM; hold + push to the registered "
             "device at HIGH; block, freeze payees and revoke sessions at CRITICAL."),
    Strategy("fraudmesh_strong_txn", "FraudMesh + strong txn block", "The live policy, plus: block any transfer the txn "
             "model alone scores >= 0.9 (a candidate rule tested in the twin, not in production)."),
]
STRONG_TXN_P = 0.9


def _amount(ev: StoredEvent) -> int:
    return int(ev.payload.get("amount_paise", 0) or 0)


def simulate(strategy: Strategy, steps: list[SimStep], start: VirtualBank, customer_answer: datetime | None) -> PolicyOutcome:
    bank = copy.deepcopy(start)                                    # isolated copy of the initial state
    payments, frozen, rejected_payees = "normal", False, set()
    attacker_out, stopped_at, stop_reason, stopped_stage = False, None, None, None
    push_deadline: datetime | None = None
    lost = protected = friction = 0
    interventions: list[Intervention] = []
    outcomes, stages = [], []
    done_stepups: set[str] = set()
    first_transfer = next((s.event.occurred_at for s in steps if s.event.event_type == "transaction" and s.is_attack), None)

    def stop(ts: datetime, why: str, stage: str) -> None:
        nonlocal attacker_out, stopped_at, stop_reason, stopped_stage
        if not attacker_out:
            attacker_out, stopped_at, stop_reason, stopped_stage = True, ts, why, stage

    for s in steps:
        ev = s.event
        if push_deadline is not None and ev.occurred_at >= push_deadline and not attacker_out:
            stop(push_deadline, "customer denied the push on their registered device; sessions revoked", s.stage)
            interventions.append(Intervention(ts=push_deadline, action="REVOKE_SESSIONS", effect="customer said 'Not me'"))
        in_session = s.actor == "attacker" and ev.event_type in SESSION_EVENTS
        if attacker_out and in_session:                            # locked out: this step never happens
            outcomes.append("prevented")
            if ev.event_type == "transaction":
                protected += _amount(ev)
            continue
        # the step happens (possibly with its money stopped)
        if ev.event_type == "payee_added" and frozen and s.actor in ("attacker", "customer"):
            rejected_payees.add(ev.payload.get("payee_account"))
            outcomes.append("rejected")
            continue
        bank.apply(ev, s.actor)
        if s.actor == "attacker" or s.is_attack:
            stages.append(s.stage)
        actions = strategy.actions(s)
        # Payment controls decided on this event apply to it too: the live worker sets a transfer's outcome from the
        # case's payment state AFTER the decision on that same transfer (PRD §6.4). Step-ups are asynchronous: they
        # can lock the attacker out of later steps, but never hold the transfer that triggered them.
        for action in actions:
            if action == "HOLD_OUTBOUND_PAYMENTS" and payments == "normal":
                payments = "held"
                interventions.append(Intervention(ts=ev.occurred_at, action=action, effect="outbound payments held"))
            elif action == "BLOCK_PENDING_PAYMENTS" and payments != "blocked":
                payments = "blocked"
                interventions.append(Intervention(ts=ev.occurred_at, action=action, effect="pending payments blocked"))
            elif action == "FREEZE_NEW_PAYEES" and not frozen:
                frozen = True
                interventions.append(Intervention(ts=ev.occurred_at, action=action, effect="new payees frozen"))
        if ev.event_type == "transaction":
            amt = _amount(ev)
            siloed_block = ((strategy.policy_id == "siloed" and (s.txn_p or 0) >= 0.5)
                            or (strategy.policy_id == "fraudmesh_strong_txn" and (s.txn_p or 0) >= STRONG_TXN_P))
            if ev.payload.get("payee_account") in rejected_payees:
                outcome = "rejected"
            elif payments == "blocked" or siloed_block:
                outcome = "blocked"
            elif payments == "held":
                outcome = "held"
            else:
                outcome = "lost" if s.is_attack else "completed"
            if s.is_attack:
                if outcome == "lost":
                    lost += amt
                else:
                    protected += amt
            elif outcome in ("held", "blocked", "rejected"):
                friction += 1                                       # a genuine payment was delayed
            if siloed_block:
                interventions.append(Intervention(ts=ev.occurred_at, action="BLOCK_PENDING_PAYMENTS",
                                                  effect=f"txn model alone scored {s.txn_p:.2f}: transfer blocked"))
            outcomes.append(outcome)
        else:
            outcomes.append("happened")
        for action in actions:                                      # identity controls: affect later steps
            if action == "STEP_UP_ANY_FACTOR" and action not in done_stepups:
                done_stepups.add(action)
                c = bank.customer(ev.customer) if ev.customer else None
                if _attacker_active(steps, s) and not attacker_out:        # the attacker is the one in session
                    if c is not None and c.sms_attacker_controlled:
                        effect = "OTP went to the attacker's swapped number: attacker passed"
                    else:
                        effect = "OTP went to the real customer's phone: attacker failed"
                        stop(ev.occurred_at, "attacker failed the SMS one-time password", s.stage)
                else:                                                      # the real customer answers the OTP
                    effect = "the customer passed the OTP" + ("" if s.is_attack else " (genuine activity: friction)")
                    friction += 0 if s.is_attack else 1
                interventions.append(Intervention(ts=ev.occurred_at, action=action, effect=effect))
            elif action == "STEP_UP_TRUSTED_FACTOR" and action not in done_stepups:
                done_stepups.add(action)
                if s.is_attack and _attacker_active(steps, s):
                    push_deadline = customer_answer if customer_answer and customer_answer > ev.occurred_at                         else ev.occurred_at + PUSH_RESPONSE
                    effect = "push sent to the customer's registered device"
                else:
                    effect = "the customer approved the push" + ("" if s.is_attack else " (genuine activity: friction)")
                    friction += 0 if s.is_attack else 1
                interventions.append(Intervention(ts=ev.occurred_at, action=action, effect=effect))
            elif action == "REVOKE_SESSIONS" and _attacker_active(steps, s) and not attacker_out:
                stop(ev.occurred_at, "sessions revoked", s.stage)
                interventions.append(Intervention(ts=ev.occurred_at, action=action, effect="attacker logged out"))

    lead = int((first_transfer - stopped_at).total_seconds()) if first_transfer and stopped_at else None
    return PolicyOutcome(policy_id=strategy.policy_id, label=strategy.label, description=strategy.description,
                         money_lost_paise=lost, money_protected_paise=protected,
                         attack_stopped=attacker_out or (lost == 0 and protected > 0),
                         stopped_at=stopped_at, stopped_stage=stopped_stage, stop_reason=stop_reason, lead_time_s=lead,
                         first_intervention=interventions[0].ts if interventions else None, interventions=interventions,
                         customer_friction=friction, steps=outcomes, stages_reached=sorted(set(stages)))


def _attacker_active(steps: list[SimStep], s: SimStep) -> bool:
    """An attacker (not the customer) is acting in this case up to this step."""
    return any(x.actor == "attacker" for x in steps if x.event.occurred_at <= s.event.occurred_at)
