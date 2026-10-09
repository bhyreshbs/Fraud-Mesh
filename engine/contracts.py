"""engine/contracts.py — BOTH-FROZEN. Shared by api/ (Dev 1) and engine/ (Dev 2)."""
from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import datetime
from typing import Iterator, Literal, Protocol

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

CONTRACT_VERSION = "1.1.0"          # 1.1.0: additive, optional fields only (CONTRACT_REQUESTS.md, 2026-10-10 v3)

# ----------------------------------------------------------------- enums
EventType = Literal["login", "mfa_change", "mfa_challenge", "sim_signal", "kyc_result", "profile_change",
                    "payee_added", "transaction", "cloud_audit", "network_ids_alert", "step_up_result"]
Source = Literal["demo-bank-web", "cloud-audit", "network-ids", "simulator"]
EntityKind = Literal["cust", "acct", "dev", "ip", "phone", "email", "cid", "res", "mer", "ses"]   # ses: 1.1.0
EdgeType = Literal["OWNS", "LOGGED_IN_FROM", "CONNECTED_VIA", "HAS_PHONE", "ENROLLED", "RESET",
                   "ADDED_PAYEE", "SENT", "ACTED_FROM", "ACCESSED", "TARGETED", "SHARES_DEVICE"]
Stage = Literal["S0_RECON", "S1_INITIAL_ACCESS", "S2_CONTROL_TAKEOVER", "S3_IDENTITY_MANIPULATION",
                "S4_ESCALATION", "S5_POSITIONING", "S6_MONETIZATION"]
STAGE_ORDER: tuple[str, ...] = ("S0_RECON", "S1_INITIAL_ACCESS", "S2_CONTROL_TAKEOVER",
                                "S3_IDENTITY_MANIPULATION", "S4_ESCALATION", "S5_POSITIONING", "S6_MONETIZATION")
DetectorId = Literal["txn", "behaviour", "auth", "kyc", "cyber", "netsec", "graph"]
Family = Literal["transaction", "identity", "device", "kyc", "cyber", "graph"]
DETECTOR_FAMILY: dict[str, str] = {"txn": "transaction", "behaviour": "identity", "auth": "device",
                                   "kyc": "kyc", "cyber": "cyber", "netsec": "cyber", "graph": "graph"}
Band = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
BAND_ORDER: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
Action = Literal["ALLOW", "CAPTCHA_CHALLENGE", "STEP_UP_ANY_FACTOR", "STEP_UP_TRUSTED_FACTOR",
                 "HOLD_OUTBOUND_PAYMENTS", "FREEZE_NEW_PAYEES", "BLOCK_PENDING_PAYMENTS", "REVOKE_SESSIONS",
                 "OPEN_CASE_P2", "OPEN_CASE_P1",
                 "SCAM_WARNING", "COOLING_OFF_HOLD"]                       # 1.1.0: APP-scam interventions
ACTION_SEVERITY: dict[str, int] = {"ALLOW": 0, "OPEN_CASE_P2": 0, "OPEN_CASE_P1": 0, "CAPTCHA_CHALLENGE": 1,
                                   "STEP_UP_ANY_FACTOR": 1, "STEP_UP_TRUSTED_FACTOR": 2, "HOLD_OUTBOUND_PAYMENTS": 2,
                                   "FREEZE_NEW_PAYEES": 3, "BLOCK_PENDING_PAYMENTS": 3, "REVOKE_SESSIONS": 3,
                                   "SCAM_WARNING": 1, "COOLING_OFF_HOLD": 2}
SEVERITY_HOLD = 2                       # an action at or above this counts as an intervention
CaseStatus = Literal["OPEN", "INVESTIGATING", "CONFIRMED_FRAUD", "FALSE_POSITIVE", "CLOSED"]
Verdict = Literal["CONFIRMED_FRAUD", "FALSE_POSITIVE", "INCONCLUSIVE"]
Role = Literal["analyst", "lead", "admin"]
PaymentState = Literal["normal", "held", "blocked"]
PaymentOutcome = Literal["completed", "held", "blocked"]
StepUpMethod = Literal["sms_otp", "totp", "device_push"]
ChallengeStatus = Literal["pending", "passed", "failed", "timeout", "denied_by_customer"]
ReplayMode = Literal["fused", "siloed"]


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------ raw ingestion models
class Subject(_M):
    customer_ref: str | None = None
    account_ref: str | None = None


NetworkType = Literal["residential", "mobile", "hosting", "vpn", "tor", "unknown"]     # 1.1.0


class Telemetry(_M):
    """1.1.0: coarse, privacy-conscious behavioural telemetry from the bank app (never characters, OTPs or clipboard)."""
    pointer_type: Literal["mouse", "touch", "pen"] | None = None
    keystroke_interval_ms_mean: float | None = Field(default=None, ge=0, le=60_000)
    keystroke_interval_ms_std: float | None = Field(default=None, ge=0, le=60_000)
    paste_in_sensitive_field: bool | None = None
    payment_screen_dwell_s: float | None = Field(default=None, ge=0, le=86_400)
    beneficiary_screen_dwell_s: float | None = Field(default=None, ge=0, le=86_400)
    screen_resolution_changes: int | None = Field(default=None, ge=0, le=1_000)
    remote_access_demo: bool | None = None          # demo-only simulated indicator
    active_call_demo: bool | None = None            # demo-only simulated indicator


class Context(_M):
    ip: str | None = None
    device_id: str | None = None
    user_agent: str | None = Field(default=None, max_length=256)
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: str | None = None
    # 1.1.0, all optional (client-supplied, therefore probabilistic evidence only)
    session_id: str | None = Field(default=None, max_length=128)
    browser_timezone: str | None = Field(default=None, max_length=64)
    locale: str | None = Field(default=None, max_length=35)
    platform: str | None = Field(default=None, max_length=64)
    webgl_renderer: str | None = Field(default=None, max_length=256)
    screen: str | None = Field(default=None, max_length=32)
    telemetry: Telemetry | None = None


class Envelope(_M):
    event_id: str = Field(pattern=r"^evt_[0-9a-zA-Z]{8,40}$")
    event_type: EventType
    source: Source
    occurred_at: AwareDatetime
    schema_version: Literal["1.0", "1.1"] = "1.0"
    subject: Subject = Field(default_factory=Subject)
    context: Context = Field(default_factory=Context)
    payload: dict


# ------------------------------------------------------------- payloads
class LoginPayload(_M):
    result: Literal["success", "failure"]
    auth_method: Literal["password", "password+otp", "password+push"]


class MfaChangePayload(_M):
    factor: Literal["sms", "totp", "device_push"]
    action: Literal["add", "replace", "remove"]
    new_phone: str | None = None


class MfaChallengePayload(_M):
    method: StepUpMethod
    result: Literal["passed", "failed", "ignored"]


class SimSignalPayload(_M):
    sim_change_age_h: float = Field(ge=0)


class KycResultPayload(_M):
    liveness_score: float = Field(ge=0, le=1)
    face_match_score: float = Field(ge=0, le=1)
    doc_tamper_score: float = Field(ge=0, le=1)
    injection_suspected: bool
    reason: Literal["onboarding", "re_verification"]


class ProfileChangePayload(_M):
    field: Literal["password", "email", "phone", "address"]


class PayeeAddedPayload(_M):
    payee_account: str
    payee_name_match: bool | None = None
    nickname: str = Field(default="", max_length=64)


class TransactionPayload(_M):
    amount_paise: int = Field(gt=0)
    payee_account: str
    channel: Literal["UPI", "IMPS", "NEFT", "CARD"]


class CloudAuditPayload(_M):
    actor_type: Literal["support_console", "service", "admin"]
    actor_identity: str
    action: str
    target_customer: str | None = None
    src_ip: str
    result: Literal["success", "failure"]


class NetworkIdsAlertPayload(_M):
    src_ip: str
    dest_ip: str
    dest_port: int
    signature_id: int
    signature: str
    category: str
    severity: int = Field(ge=1, le=3)


class StepUpResultPayload(_M):
    challenge_id: str
    method: StepUpMethod
    result: Literal["passed", "failed", "timeout", "denied_by_customer"]
    factor_age_h: float = Field(ge=0)


PAYLOAD_MODELS: dict[str, type[BaseModel]] = {
    "login": LoginPayload, "mfa_change": MfaChangePayload, "mfa_challenge": MfaChallengePayload,
    "sim_signal": SimSignalPayload, "kyc_result": KycResultPayload, "profile_change": ProfileChangePayload,
    "payee_added": PayeeAddedPayload, "transaction": TransactionPayload, "cloud_audit": CloudAuditPayload,
    "network_ids_alert": NetworkIdsAlertPayload, "step_up_result": StepUpResultPayload,
}

# (event_type, payload field) -> entity kind. These fields hold raw values in an Envelope
# and tokens in a StoredEvent. Field names never change.
TOKENIZED_PAYLOAD_FIELDS: dict[tuple[str, str], str] = {
    ("mfa_change", "new_phone"): "phone", ("payee_added", "payee_account"): "acct",
    ("transaction", "payee_account"): "acct", ("cloud_audit", "actor_identity"): "cid",
    ("cloud_audit", "target_customer"): "cust", ("cloud_audit", "src_ip"): "ip",
    ("network_ids_alert", "src_ip"): "ip",   # dest_ip is NOT tokenized (bank's own server)
}


def validate_payload(event_type: str, payload: dict) -> BaseModel:
    return PAYLOAD_MODELS[event_type].model_validate(payload)


# ------------------------------------------------------ what the engine receives
class StoredEvent(_M):
    event_id: str
    event_type: EventType
    source: Source
    occurred_at: AwareDatetime          # UTC
    received_at: AwareDatetime          # UTC
    customer: str | None = None         # cust:…
    account: str | None = None          # acct:…
    ip: str | None = None               # ip:…
    device: str | None = None           # dev:…
    asn: str | None = None              # plain text, not PII
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    payload: dict                       # PAYLOAD_MODELS shape, TOKENIZED_PAYLOAD_FIELDS hold tokens
    entity_tokens: list[str]            # every token in this event, de-duplicated, sorted
    # 1.1.0, all optional
    session: str | None = None          # ses:… (tokenized session id)
    network_type: NetworkType | None = None          # from offline enrichment of the raw IP at ingestion
    network_source: str | None = None                # which local intelligence source decided it
    network_confidence: float | None = Field(default=None, ge=0, le=1)
    ip_timezone: str | None = None                   # IANA tz of the IP's location, when the source knows it
    browser_timezone: str | None = None
    locale: str | None = None
    platform: str | None = None
    webgl_renderer: str | None = None
    screen: str | None = None
    telemetry: Telemetry | None = None


# ------------------------------------------------------------- domain models
class Reason(_M):
    code: str
    detail: str | None = None


class ShapItem(_M):
    feature: str
    value: float
    shap: float


class Evidence(_M):
    evidence_id: str
    event_id: str
    detector: DetectorId
    detector_version: str
    family: Family
    stage: Stage
    attack_technique: str | None = None
    p: float = Field(gt=0, lt=1)
    reliability: float = Field(ge=0, le=1)      # snapshot at creation time
    contribution: float = 0.0                   # set by fusion (log-odds units)
    entities: list[str]
    reasons: list[Reason]
    shap: list[ShapItem] | None = None
    amount_paise: int | None = None             # set on S6 transaction evidence
    degraded: bool = False
    ts: AwareDatetime                           # = event.occurred_at


class StageHit(_M):
    ts: AwareDatetime
    evidence_id: str


class Case(_M):
    case_id: str
    anchor_entity: str
    customer: str | None = None
    status: CaseStatus = "OPEN"
    band: Band = "LOW"
    p_attack: float = 0.0
    log_odds: float = 0.0
    stages: dict[str, StageHit] = Field(default_factory=dict)   # key: Stage value
    entities: list[str] = Field(default_factory=list)
    pattern_hits: list[str] = Field(default_factory=list)
    floors: list[str] = Field(default_factory=list)
    amount_at_risk_paise: int = 0
    payment_state: PaymentState = "normal"
    latest_actions: list[Action] = Field(default_factory=list)
    opened_at: AwareDatetime
    updated_at: AwareDatetime                  # = occurred_at of the last processed event
    last_event_ts: AwareDatetime


class Decision(_M):
    decision_id: str
    case_id: str
    trigger_event_id: str
    trigger_evidence_id: str | None = None
    band: Band
    p_attack: float
    policy_rule: str
    actions: list[Action]
    actor: str = "engine"
    override_reason: str | None = None
    created_at: AwareDatetime


class Edge(_M):
    src: str
    dst: str
    edge_type: EdgeType
    confidence: float = Field(ge=0, le=1)
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    count: int = 1
    source_event_ids: list[str]


class Label(_M):
    event_id: str
    scenario: str
    is_attack: bool
    attack_id: str | None = None


# ------------------------------------------------------------- engine outputs
class CaseSummary(_M):
    case_id: str
    anchor_entity: str
    customer: str | None
    status: CaseStatus
    band: Band
    p_attack: float
    stages_reached: list[Stage]
    current_stage: Stage | None
    latest_actions: list[Action]
    payment_state: PaymentState
    amount_at_risk_paise: int
    updated_at: AwareDatetime


class StepUpRequest(_M):
    case_id: str
    customer: str
    method_class: Literal["any", "trusted"]
    reason_event_id: str


class CaseUpdate(_M):
    type: Literal["case_update"] = "case_update"
    case: CaseSummary
    event_id: str
    new_evidence_ids: list[str]
    decision_id: str | None = None
    step_up: StepUpRequest | None = None
    payment_outcome: PaymentOutcome | None = None   # only when the event is a transaction


class ExplanationPart(_M):
    part_id: str                                 # "prior", ev_…, pat_…, floor_…
    kind: Literal["prior", "evidence", "pattern", "floor"]
    label: str
    detector: DetectorId | None = None
    stage: Stage | None = None
    contribution: float
    running_log_odds: float
    running_p: float
    ts: AwareDatetime | None = None


class NarrativeSentence(_M):
    text: str
    cites: list[str]


class Explanation(_M):
    case_id: str
    prior_log_odds: float
    parts: list[ExplanationPart]
    final_log_odds: float
    p_attack: float
    band: Band
    floors: list[str]
    narrative: list[NarrativeSentence]
    shap_by_evidence: dict[str, list[ShapItem]]
    seed_paths: list[list[str]]                  # entity-token paths from case entities to fraud seeds


class ReplayPoint(_M):
    ts: AwareDatetime
    evidence_id: str
    p: float
    band: str                                    # a Band, or "SILOED_ALERT" / "SILOED_NONE" in siloed mode
    actions: list[Action]
    severity: int


class ReplayResult(_M):
    replay_id: str
    case_id: str
    mode: ReplayMode
    ablated: list[DetectorId]
    timeline: list[ReplayPoint]
    eip: ReplayPoint | None                      # first point with severity >= SEVERITY_HOLD
    baseline_eip: ReplayPoint | None             # same, fused mode, nothing ablated
    lead_time_s: int | None                      # first S6 evidence ts - eip ts
    lead_time_lost_s: int | None                 # eip ts - baseline_eip ts
    money_protected_paise: int                   # S6 amounts with ts >= eip ts


class BandThresholds(_M):
    medium: float = 0.20
    high: float = 0.50
    critical: float = 0.80


class SimulationResult(_M):
    thresholds: BandThresholds
    attacks_total: int
    attacks_caught: int
    benign_customers_total: int
    benign_customers_flagged: int
    legit_payments_total: int
    legit_payments_stopped: int
    money_protected_paise: int
    median_lead_time_s: int | None


class GraphNode(_M):
    id: str
    label: str
    kind: EntityKind
    seed: bool
    in_case: bool


class GraphEdge(_M):
    id: str
    source: str
    target: str
    edge_type: EdgeType
    confidence: float


class GraphElements(_M):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class FeedbackResult(_M):
    case_id: str
    verdict: Verdict
    reliability_before: dict[str, float]
    reliability_after: dict[str, float]
    seeds_added: list[str]
    status_after: CaseStatus


class FamilyMetrics(_M):
    instances: int
    caught_fused: int
    caught_siloed: int
    median_lead_time_s: int | None


class BenchmarkReport(_M):
    seed: int
    days: int
    families: dict[str, FamilyMetrics]
    benign_customers: int
    benign_flagged_high: int
    false_positive_rate: float
    false_declines_rate: float
    alert_compression: float
    txn_pr_auc: float
    txn_roc_auc: float
    txn_ece: float


def summarize(case: Case) -> CaseSummary:
    reached = [s for s in STAGE_ORDER if s in case.stages]
    return CaseSummary(case_id=case.case_id, anchor_entity=case.anchor_entity, customer=case.customer,
                       status=case.status, band=case.band, p_attack=case.p_attack, stages_reached=reached,
                       current_stage=reached[-1] if reached else None, latest_actions=case.latest_actions,
                       payment_state=case.payment_state, amount_at_risk_paise=case.amount_at_risk_paise,
                       updated_at=case.updated_at)


# ------------------------------------------------------------- Store protocol
class Store(Protocol):
    """Implemented by api/store_pg.py:PgStore (Dev 1) and engine/store_memory.py:MemoryStore (Dev 2)."""
    def transaction(self) -> AbstractContextManager[None]: ...
    # events (written by the API at ingestion; the engine only reads)
    def iter_events(self, since: datetime | None = None) -> Iterator[StoredEvent]: ...   # ordered by occurred_at, event_id
    def get_event(self, event_id: str) -> StoredEvent | None: ...
    # graph
    def upsert_edges(self, edges: list[Edge]) -> None: ...
    def load_edges(self) -> list[Edge]: ...
    def list_fraud_seeds(self) -> set[str]: ...
    def set_fraud_seeds(self, entity_ids: list[str], value: bool = True) -> None: ...
    # cases, evidence, decisions
    def find_open_cases(self, entity_ids: list[str], since: datetime) -> list[Case]: ...
    def get_case(self, case_id: str) -> Case | None: ...
    def list_cases(self) -> list[Case]: ...
    def save_case(self, case: Case) -> None: ...                   # upsert, including case entities
    def merge_cases(self, keep_id: str, drop_id: str) -> None: ... # re-point evidence + decisions, delete drop
    def save_evidence(self, ev: Evidence, case_id: str) -> None: ...
    def list_evidence(self, case_id: str) -> list[Evidence]: ...   # ordered by ts, then evidence_id
    def save_decision(self, d: Decision) -> None: ...
    def list_decisions(self, case_id: str) -> list[Decision]: ...  # ordered by created_at
    # learning, labels, replays, audit
    def get_reliability(self) -> dict[str, tuple[float, float]]: ...   # detector -> (alpha, beta)
    def add_reliability(self, detector: str, d_alpha: float, d_beta: float) -> None: ...
    def get_labels(self) -> dict[str, Label]: ...
    def save_replay(self, r: ReplayResult) -> None: ...
    def append_audit(self, actor: str, action: str, object_id: str, details: dict) -> None: ...
