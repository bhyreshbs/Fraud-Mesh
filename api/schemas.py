"""Request bodies and API-only response wrappers (PRD §9). Contract models come from engine.contracts."""
from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from engine.contracts import (
    Action,
    BenchmarkReport,
    Case,
    CaseSummary,
    ChallengeStatus,
    Context,
    Decision,
    DetectorId,
    Envelope,
    EventType,
    Evidence,
    Family,
    NarrativeSentence,
    PaymentOutcome,
    ReplayMode,
    Role,
    StepUpMethod,
    Subject,
    Verdict,
)


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------------------ errors
class ErrorDetail(_M):
    code: str
    message: str
    request_id: str


class ErrorBody(_M):
    error: ErrorDetail


# ------------------------------------------------------------------ auth (§9.1)
class LoginRequest(_M):
    email: str = Field(max_length=254)
    password: str = Field(max_length=256)


class TokenResponse(_M):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = 900
    role: Role


# ------------------------------------------------------------------ ingestion (§9.2)
class EventAccepted(_M):
    event_id: str
    status: Literal["accepted"] = "accepted"


class BatchRequest(_M):
    events: list[Envelope]


class BatchRejected(_M):
    event_id: str
    code: str


class BatchResponse(_M):
    accepted: int
    rejected: list[BatchRejected]


# ------------------------------------------------------------------ cases (§9.3)
class CasesPage(_M):
    items: list[CaseSummary]
    next_cursor: str | None = None


class CaseDetail(_M):
    case: Case
    summary: CaseSummary


class ChallengeInfo(_M):
    challenge_id: str
    method: StepUpMethod
    status: ChallengeStatus
    created_at: AwareDatetime


class Timeline(_M):
    evidence: list[Evidence]
    decisions: list[Decision]
    challenges: list[ChallengeInfo]


class ReplayRequest(_M):
    ablate: list[DetectorId] = Field(default_factory=list)
    mode: ReplayMode = "fused"


class FeedbackRequest(_M):
    verdict: Verdict
    note: str | None = Field(default=None, max_length=2000)


class ActionsRequest(_M):
    actions: list[Action] = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=1000)


class AskRequest(_M):
    question: str = Field(min_length=1, max_length=500)


class AskResponse(_M):
    answer: str
    sentences: list[NarrativeSentence]
    removed: int


# ------------------------------------------------------------------ metrics, audit, health (§9.4)
class LiveMetrics(_M):
    cases_open: int
    critical_open: int
    money_protected_paise: int
    alert_compression: float


class MetricsSummary(_M):
    benchmark: BenchmarkReport | None
    live: LiveMetrics


class DetectorInfo(_M):
    detector: DetectorId
    family: Family
    alpha: float
    beta: float
    reliability: float


class AuditVerify(_M):
    ok: bool
    rows: int
    broken_at: int | None


class Health(_M):
    status: Literal["ok"] = "ok"
    db: bool
    pipeline_ready: bool
    contract_version: str
    model_sha256: str | None


# ------------------------------------------------------------------ demo (§9.5)
class DemoEmitRequest(_M):
    event_type: EventType
    subject: Subject = Field(default_factory=Subject)
    context: Context = Field(default_factory=Context)
    payload: dict


class DemoEmitResponse(_M):
    event_id: str


class PaymentStatus(_M):
    outcome: PaymentOutcome | Literal["pending"]


class PendingChallenge(_M):
    challenge_id: str
    method: StepUpMethod
    expires_at: AwareDatetime
    masked_destination: str


class PendingResponse(_M):
    challenge: PendingChallenge | None


class SmsMessage(_M):
    text: str
    at: AwareDatetime


class SmsInbox(_M):
    messages: list[SmsMessage]


class RespondRequest(_M):
    code: str | None = Field(default=None, pattern=r"^\d{6}$")
    decision: Literal["approve", "deny"] | None = None


class RespondResponse(_M):
    status: ChallengeStatus


class RunRequest(_M):
    speed: float = Field(default=8, gt=0, le=1000)


class RunResponse(_M):
    run_id: str


class StatusOk(_M):
    status: Literal["ok"] = "ok"


# ------------------------------------------------------------------ websocket (§9.6)
class ChallengeUpdate(_M):
    type: Literal["challenge_update"] = "challenge_update"
    challenge_id: str
    status: ChallengeStatus
    case_id: str
