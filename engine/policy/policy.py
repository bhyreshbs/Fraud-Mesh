"""Policy (PRD §10.8): one Decision per processed evidence item, payment state and step-up requests.

    payment state   BLOCK_PENDING_PAYMENTS → blocked; else HOLD_OUTBOUND_PAYMENTS → held (only from normal).
                    It never goes down here (only a FALSE_POSITIVE verdict resets it, in feedback).
    step-up         set when STEP_UP_ANY_FACTOR / STEP_UP_TRUSTED_FACTOR is in this decision but not in the case's
                    previous decision (case.latest_actions); reason_event_id = the current event.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from engine.common.ids import new_id
from engine.contracts import ACTION_SEVERITY, BAND_ORDER, Case, Decision, Evidence, StepUpRequest, Store, StoredEvent

POLICY_FILE = Path(__file__).resolve().parent / "policy.yaml"
STEP_UP_CLASS = {"STEP_UP_TRUSTED_FACTOR": "trusted", "STEP_UP_ANY_FACTOR": "any"}   # trusted wins if both appear


@dataclass(frozen=True)
class Rule:
    id: str
    band: str | None
    reason_any: frozenset[str]
    actions: tuple[str, ...]

    def matches(self, band: str, reasons: set[str]) -> bool:
        return (self.band is None or self.band == band) and (not self.reason_any or bool(self.reason_any & reasons))


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
        rules.append(Rule(id=item["id"], band=band, reason_any=frozenset(when.get("reason_any") or ()), actions=actions))
    return tuple(rules)


def payment_state_after(current: str, actions: list[str] | tuple[str, ...]) -> str:
    if "BLOCK_PENDING_PAYMENTS" in actions:
        return "blocked"
    if "HOLD_OUTBOUND_PAYMENTS" in actions and current == "normal":
        return "held"
    return current


def severity(actions: list[str] | tuple[str, ...]) -> int:
    return max((ACTION_SEVERITY[a] for a in actions), default=0)


class Policy:
    def __init__(self, store: Store, rules: tuple[Rule, ...] | None = None) -> None:
        self.store = store
        self.rules = load_rules() if rules is None else rules

    def rule_for(self, band: str, reasons: set[str]) -> Rule:
        for rule in self.rules:
            if rule.matches(band, reasons):
                return rule
        raise ValueError(f"policy.yaml has no rule for band {band}")

    def decide(self, case: Case, event: StoredEvent, ev: Evidence) -> tuple[Decision, StepUpRequest | None]:
        """Write the Decision for `ev`, and update the case's actions and payment state (the caller saves the case)."""
        rule = self.rule_for(case.band, {r.code for r in ev.reasons})
        actions = list(rule.actions)
        decision = Decision(decision_id=new_id("dec"), case_id=case.case_id, trigger_event_id=event.event_id,
                            trigger_evidence_id=ev.evidence_id, band=case.band, p_attack=case.p_attack,
                            policy_rule=rule.id, actions=actions, created_at=ev.ts)
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
