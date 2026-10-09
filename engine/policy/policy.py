"""Policy (PRD §10.8): one Decision per processed evidence item, payment state and step-up requests.

    payment state   BLOCK_PENDING_PAYMENTS → blocked; else HOLD_OUTBOUND_PAYMENTS → held (only from normal).
                    It never goes down here (only a FALSE_POSITIVE verdict resets it, in feedback).
    step-up         set when STEP_UP_ANY_FACTOR / STEP_UP_TRUSTED_FACTOR is in this decision but not in the case's
                    previous decision (case.latest_actions); reason_event_id = the current event.

v3 core additions (engine/detectors/rules/v3_core.yaml):
    floor_any         optional rule condition: the case has one of these floors (policy.yaml ato_new_payee_hold and
                      txn_high_confidence_hold), so decision.policy_rule records WHICH floor escalated the case; the
                      explanation's floor part cites the evidence item that satisfied it.
    late evidence     `late_evidence`: while the case holds payments (payment_state held), a new item from one of the
                      configured detectors (cloud audit, account control, KYC — not a response to our own step-up)
                      that raises the case (contribution > min_contribution) with the band at min_band or above adds
                      BLOCK_PENDING_PAYMENTS: held → blocked. policy_rule = "late_evidence_block". In payment-rail terms
                      (api/payments) a held payment is authorised but not captured, so blocking it voids the
                      authorisation before settlement; a captured (completed) payment is not reversed by the engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from engine.common.ids import new_id
from engine.contracts import ACTION_SEVERITY, BAND_ORDER, Case, Decision, Evidence, StepUpRequest, Store, StoredEvent
from engine.fusion.v3_core import load_v3_core

POLICY_FILE = Path(__file__).resolve().parent / "policy.yaml"
STEP_UP_CLASS = {"STEP_UP_TRUSTED_FACTOR": "trusted", "STEP_UP_ANY_FACTOR": "any"}   # trusted wins if both appear
LATE_EVIDENCE_RULE = "late_evidence_block"
BLOCK = "BLOCK_PENDING_PAYMENTS"


@dataclass(frozen=True)
class Rule:
    id: str
    band: str | None
    reason_any: frozenset[str]
    actions: tuple[str, ...]
    pattern_any: frozenset[str] = frozenset()     # DEV1 FW (pending Dev 2 review): the case has one of these patterns
    floor_any: frozenset[str] = frozenset()       # v3 core: the case has one of these floors

    def matches(self, band: str, reasons: set[str], patterns: frozenset[str] | set[str] = frozenset(),
                floors: frozenset[str] | set[str] = frozenset()) -> bool:
        return ((self.band is None or self.band == band) and (not self.reason_any or bool(self.reason_any & reasons))
                and (not self.pattern_any or bool(self.pattern_any & set(patterns)))
                and (not self.floor_any or bool(self.floor_any & set(floors))))


@lru_cache(maxsize=8)
def load_rules(path: str | Path = POLICY_FILE) -> tuple[Rule, ...]:
    rules = []
    for item in yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []:
        when = item.get("when") or {}
        band = when.get("band")
        if band is not None and band not in BAND_ORDER:
            raise ValueError(f"policy rule {item['id']}: unknown band {band}")
        actions = tuple(item["actions"])
        unknown = [a for a in actions if a not in ACTION_SEVERITY]
        if unknown:
            raise ValueError(f"policy rule {item['id']}: unknown actions {unknown}")
        rules.append(Rule(id=item["id"], band=band, reason_any=frozenset(when.get("reason_any") or ()), actions=actions,
                          pattern_any=frozenset(when.get("pattern_any") or ()),
                          floor_any=frozenset(when.get("floor_any") or ())))
    return tuple(rules)


def payment_state_after(current: str, actions: list[str] | tuple[str, ...]) -> str:
    if BLOCK in actions:
        return "blocked"
    if "HOLD_OUTBOUND_PAYMENTS" in actions and current == "normal":
        return "held"
    return current


def severity(actions: list[str] | tuple[str, ...]) -> int:
    return max((ACTION_SEVERITY[a] for a in actions), default=0)


def late_evidence_escalates(cfg: dict[str, Any], band: str, ev: Evidence, contribution: float, payment_state: str) -> bool:
    """v3 11.6: does this item escalate a case that already holds payments to blocked?"""
    return (bool(cfg.get("enabled")) and payment_state == "held" and ev.detector in set(cfg.get("detectors") or ())
            and contribution > float(cfg.get("min_contribution", 0.0))
            and not any(r.code in set(cfg.get("exclude_reasons") or ()) for r in ev.reasons)
            and BAND_ORDER.index(band) >= BAND_ORDER.index(cfg.get("min_band", "HIGH")))


class Policy:
    def __init__(self, store: Store | None, rules: tuple[Rule, ...] | None = None, v3: dict[str, Any] | None = None) -> None:
        self.store = store
        self.rules = load_rules() if rules is None else rules
        self.v3 = load_v3_core() if v3 is None else v3

    def rule_for(self, band: str, reasons: set[str], patterns: frozenset[str] | set[str] = frozenset(),
                 floors: frozenset[str] | set[str] = frozenset()) -> Rule:
        for rule in self.rules:
            if rule.matches(band, reasons, patterns, floors):
                return rule
        raise ValueError(f"policy.yaml has no rule for band {band}")

    def evaluate(self, band: str, ev: Evidence, patterns: frozenset[str] | set[str] | list[str] = frozenset(),
                 floors: frozenset[str] | set[str] | list[str] = frozenset(), payment_state: str = "normal",
                 contribution: float | None = None) -> tuple[str, list[str]]:
        """(policy_rule, actions) for one evidence item; shared by live decisions and replay."""
        rule = self.rule_for(band, {r.code for r in ev.reasons}, set(patterns), set(floors))
        actions = list(rule.actions)
        c = ev.contribution if contribution is None else contribution
        if BLOCK not in actions and late_evidence_escalates(self.v3["late_evidence"], band, ev, c, payment_state):
            return LATE_EVIDENCE_RULE, actions + [BLOCK]
        return rule.id, actions

    def decide(self, case: Case, event: StoredEvent, ev: Evidence) -> tuple[Decision, StepUpRequest | None]:
        """Write the Decision for `ev`, and update the case's actions and payment state (the caller saves the case)."""
        rule_id, actions = self.evaluate(case.band, ev, case.pattern_hits, case.floors, case.payment_state)
        decision = Decision(decision_id=new_id("dec"), case_id=case.case_id, trigger_event_id=event.event_id,
                            trigger_evidence_id=ev.evidence_id, band=case.band, p_attack=case.p_attack,
                            policy_rule=rule_id, actions=actions, created_at=ev.ts)
        self.store.save_decision(decision)
        step_up = None
        new = [a for a in actions if a in STEP_UP_CLASS and a not in case.latest_actions]
        if new and case.customer:
            cls = "trusted" if "STEP_UP_TRUSTED_FACTOR" in new else "any"
            step_up = StepUpRequest(case_id=case.case_id, customer=case.customer, method_class=cls,
                                    reason_event_id=event.event_id)
        case.payment_state = payment_state_after(case.payment_state, actions)
        case.latest_actions = actions
        return decision, step_up
