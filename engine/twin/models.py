"""Digital Twin outputs. Plain pydantic models owned by engine/twin (not part of the frozen engine/contracts.py)."""
from __future__ import annotations

from pydantic import AwareDatetime, BaseModel, ConfigDict

ActorKind = str          # "attacker" | "customer" | "network" | "insider" | "system"
StepOutcome = str        # "happened" | "prevented" | "held" | "blocked" | "rejected" | "lost" | "completed"


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TwinStep(_M):
    """One case event replayed into the virtual bank, with the risk the engine had after it."""
    index: int
    ts: AwareDatetime
    event_id: str
    event_type: str
    actor: ActorKind
    stage: str
    summary: str                      # what happened, in plain words
    changes: list[str]                # how the virtual bank's state changed
    p: float                          # fused attack probability after this event
    band: str
    actions: list[str]                # what the live FraudMesh policy did at this point
    amount_paise: int | None = None
    # the twin's forecast as of this step, from the furthest stage the attack has reached so far
    forecast_stage: str | None = None
    forecast_next: str | None = None
    forecast_probability: float | None = None
    forecast_p_money: float | None = None
    forecast_minutes_to_money: float | None = None


class EntityState(_M):
    """The virtual state of one entity at the end of the case (keyed by token, as everywhere in FraudMesh)."""
    entity: str
    kind: str
    tags: list[str]                   # e.g. "new device", "SIM controlled by attacker", "mule-linked payee", "frozen"


class Intervention(_M):
    ts: AwareDatetime
    action: str
    effect: str


class PolicyOutcome(_M):
    """What would have happened under one prevention strategy, on an isolated copy of the case's initial state."""
    policy_id: str
    label: str
    description: str
    money_lost_paise: int
    money_protected_paise: int
    attack_stopped: bool
    stopped_at: AwareDatetime | None
    stopped_stage: str | None
    stop_reason: str | None
    lead_time_s: int | None           # first attempted transfer ts - stop ts (positive = stopped before money moved)
    first_intervention: AwareDatetime | None
    interventions: list[Intervention]
    customer_friction: int            # checks shown to the genuine customer + genuine payments held or blocked
    steps: list[StepOutcome]          # per TwinStep: what became of it under this policy
    stages_reached: list[str]


class NextStage(_M):
    stage: str
    probability: float
    median_minutes: float | None


class Prediction(_M):
    """Where the attack is likely to go next (first-order stage transitions learned from labelled attacks)."""
    from_stage: str | None
    next_stages: list[NextStage]
    p_reach_monetization: float | None
    expected_minutes_to_monetization: float | None
    sample_size: int
    note: str


class CaseTwin(_M):
    case_id: str
    customer: str | None
    steps: list[TwinStep]
    entities: list[EntityState]
    policies: list[PolicyOutcome]
    best_policy: str
    live_policy: str
    earliest_intervention: AwareDatetime | None
    prediction: Prediction
    assumptions: list[str]
    # v3: what kind of case this is, from who acted (engine/twin/build.py _case_kind):
    # "account_takeover" (an attacker acted in the customer's account) | "app_scam" (the genuine customer was
    # manipulated into paying: APP pattern / APP_SCAM_* reasons, no attacker) | "legitimate" (no attack label and no
    # scam or takeover signal) | "unclassified"
    case_kind: str | None = None


class TwinOverview(_M):
    entities: dict[str, int]          # virtual bank size by entity kind
    fraud_seeds: int
    cases_by_band: dict[str, int]
    payments_held: int
    payments_blocked: int
    active_interventions: int
    money_at_risk_paise: int
    money_protected_paise: int
    hottest_cases: list[dict]
