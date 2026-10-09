"""Step-up challenges (PRD §6.4, §15.2 task 2).

- any     -> sms_otp on the customer's active sms factor (if none is pending)
- trusted -> device_push on the oldest factor enrolled >= 72 h before the event and unchanged since the case opened
OTP: 6 digits, stored as SHA-256, 5-minute expiry, 3 attempts. The SMS itself goes to the demo-only in-memory inbox.
Synchronous DB functions are called through asyncio.to_thread; emit_result() is async.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta, timezone

from sqlalchemy import text

from api.db import session
from api.demo_identities import CUSTOMERS, REGISTERED_DEVICE, demo_state, fill_context, mask_phone
from api.errors import ApiError
from engine.common.ids import new_id
from engine.contracts import Envelope, StepUpRequest

log = logging.getLogger("fraudmesh.stepup")

OTP_TTL = timedelta(minutes=5)
PUSH_TTL = timedelta(minutes=30)    # the push waits for the customer; §12.2 answers it 14 scenario-minutes later
MAX_ATTEMPTS = 3
TRUSTED_MIN_AGE = timedelta(hours=72)
IST = timezone(timedelta(hours=5, minutes=30))

_COLS = "challenge_id, case_id, customer, method, factor_id, otp_hash, attempts, status, created_at, expires_at"


def _otp_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def _info(row) -> dict:
    return {"challenge_id": row["challenge_id"], "case_id": row["case_id"], "customer": row["customer"],
            "method": row["method"], "status": row["status"], "factor_id": row["factor_id"],
            "created_at": row["created_at"], "expires_at": row["expires_at"]}


def _audit(c, actor: str, action: str, object_id: str, details: dict) -> None:
    from api.audit import append_audit
    append_audit(c, actor, action, object_id, details)


# ------------------------------------------------------------------ creation
def create_challenge(req: StepUpRequest, event_ts: datetime, case_opened_at: datetime | None) -> dict | None:
    now = datetime.now(UTC)
    with session.transaction() as c:
        if req.method_class == "any":
            pending = c.execute(text("SELECT 1 FROM step_up_challenges WHERE customer = :cu AND status = 'pending' "
                                     "AND method IN ('sms_otp','totp') AND expires_at > :now"), {"cu": req.customer, "now": now}).first()
            if pending:
                return None
            factor = c.execute(text("SELECT factor_id FROM mfa_factors WHERE customer = :cu AND kind = 'sms' AND active "
                                    "ORDER BY enrolled_at DESC LIMIT 1"), {"cu": req.customer}).scalar()
            code = f"{secrets.randbelow(1_000_000):06d}"
            row = c.execute(text(f"INSERT INTO step_up_challenges ({_COLS}) VALUES (:id, :case, :cu, 'sms_otp', :f, :h, 0, 'pending', :now, :exp) "
                                 f"RETURNING {_COLS}"),
                            {"id": new_id("chl"), "case": req.case_id, "cu": req.customer, "f": factor, "h": _otp_hash(code),
                             "now": now, "exp": now + OTP_TTL}).mappings().one()
            phone = demo_state.phone.get(req.customer)
            if phone:
                demo_state.deliver_sms(phone, f"NammaBank: {code} is your one-time code to verify it's you. Never share it.", now)
            else:
                log.warning("no demo phone known for %s; OTP not delivered to any inbox", req.customer)
        else:
            pending = c.execute(text("SELECT 1 FROM step_up_challenges WHERE customer = :cu AND status = 'pending' "
                                     "AND method = 'device_push' AND expires_at > :now"), {"cu": req.customer, "now": now}).first()
            if pending:
                return None
            opened = case_opened_at or event_ts
            factor = c.execute(text(
                "SELECT factor_id FROM mfa_factors WHERE customer = :cu AND active AND enrolled_at <= :cutoff "
                "AND (changed_at IS NULL OR changed_at < :opened) "
                "ORDER BY (kind = 'device_push') DESC, enrolled_at ASC, factor_id LIMIT 1"),
                {"cu": req.customer, "cutoff": event_ts - TRUSTED_MIN_AGE, "opened": opened}).scalar()
            if factor is None:
                _audit(c, "api", "CHALLENGE_SKIPPED", req.case_id, {"customer": req.customer, "reason": "no trusted factor"})
                return None
            row = c.execute(text(f"INSERT INTO step_up_challenges ({_COLS}) VALUES (:id, :case, :cu, 'device_push', :f, NULL, 0, 'pending', :now, :exp) "
                                 f"RETURNING {_COLS}"),
                            {"id": new_id("chl"), "case": req.case_id, "cu": req.customer, "f": factor, "now": now,
                             "exp": now + PUSH_TTL}).mappings().one()
        _audit(c, "api", "CHALLENGE_CREATED", row["challenge_id"],
               {"case_id": req.case_id, "method": row["method"], "reason_event_id": req.reason_event_id})
        return _info(row)


# ------------------------------------------------------------------ reads for the demo routes
def pending_for(customer: str, channel: str) -> dict | None:
    methods = ("device_push",) if channel == "phone" else ("sms_otp", "totp")
    with session.transaction() as c:
        row = c.execute(text(f"SELECT {_COLS} FROM step_up_challenges WHERE customer = :cu AND status = 'pending' "
                             "AND method = ANY(:m) AND expires_at > :now ORDER BY created_at DESC LIMIT 1"),
                        {"cu": customer, "m": list(methods), "now": datetime.now(UTC)}).mappings().first()
    if row is None:
        return None
    info = _info(row)
    if row["method"] == "device_push":
        info["masked_destination"] = "Registered device (enrolled before this session)"
    else:
        info["masked_destination"] = mask_phone(demo_state.phone.get(customer))
    return info


def challenges_for_case(case_id: str) -> list[dict]:
    with session.transaction() as c:
        rows = c.execute(text(f"SELECT {_COLS} FROM step_up_challenges WHERE case_id = :id ORDER BY created_at, challenge_id"),
                         {"id": case_id}).mappings().all()
    return [_info(r) for r in rows]


# ------------------------------------------------------------------ resolution
def _factor_age_h(c, factor_id: str | None, now: datetime) -> float:
    if not factor_id:
        return 0.0
    f = c.execute(text("SELECT enrolled_at, changed_at FROM mfa_factors WHERE factor_id = :f"), {"f": factor_id}).mappings().first()
    if not f:
        return 0.0
    return max(0.0, (now - (f["changed_at"] or f["enrolled_at"])).total_seconds() / 3600)


def resolve(challenge_id: str, code: str | None, decision: str | None) -> tuple[dict, bool, float]:
    """Returns (challenge info, status_changed, factor_age_h)."""
    now = datetime.now(UTC)
    with session.transaction() as c:
        row = c.execute(text(f"SELECT {_COLS} FROM step_up_challenges WHERE challenge_id = :id FOR UPDATE"),
                        {"id": challenge_id}).mappings().first()
        if row is None:
            raise ApiError("NOT_FOUND", "challenge not found")
        info = _info(row)
        if row["status"] != "pending":
            return info, False, 0.0
        attempts = row["attempts"]
        if row["expires_at"] <= now:
            status = "timeout"
        elif row["method"] in ("sms_otp", "totp"):
            if code is None:
                raise ApiError("VALIDATION_FAILED", "this challenge needs a 6-digit code")
            if secrets.compare_digest(_otp_hash(code), row["otp_hash"] or ""):
                status = "passed"
            else:
                attempts += 1
                status = "failed" if attempts >= MAX_ATTEMPTS else "pending"
        else:
            if decision not in ("approve", "deny"):
                raise ApiError("VALIDATION_FAILED", "this challenge needs decision approve or deny")
            status = "passed" if decision == "approve" else "denied_by_customer"
        c.execute(text("UPDATE step_up_challenges SET status = :s, attempts = :a WHERE challenge_id = :id"),
                  {"s": status, "a": attempts, "id": challenge_id})
        info["status"] = status
        if status == "pending":
            return info, False, 0.0
        _audit(c, "api", "CHALLENGE_RESOLVED", challenge_id, {"case_id": row["case_id"], "status": status, "attempts": attempts})
        return info, True, _factor_age_h(c, row["factor_id"], now)


def expire_due() -> list[tuple[dict, float]]:
    now = datetime.now(UTC)
    with session.transaction() as c:
        rows = c.execute(text(f"UPDATE step_up_challenges SET status = 'timeout' WHERE status = 'pending' AND expires_at <= :now "
                              f"RETURNING {_COLS}"), {"now": now}).mappings().all()
        out = []
        for r in rows:
            _audit(c, "api", "CHALLENGE_RESOLVED", r["challenge_id"], {"case_id": r["case_id"], "status": "timeout"})
            out.append((_info(r), _factor_age_h(c, r["factor_id"], now)))
    return out


# ------------------------------------------------------------------ the signed step_up_result event
def _result_time(case_id: str) -> datetime:
    """Now, but never before the case's last event: scenario players stamp events with scenario time (PRD §12.2), so a
    step_up_result answered in wall-clock time must not land before the events that caused it."""
    now = datetime.now(IST)
    with session.transaction() as c:
        last = c.execute(text("SELECT last_event_ts FROM cases WHERE case_id = :c"), {"c": case_id}).scalar()
    return max(now, last + timedelta(seconds=1)) if last else now
def build_result_envelope(info: dict, factor_age_h: float) -> Envelope:
    customer_ref = demo_state.customer_ref.get(info["customer"])
    subject = {"customer_ref": customer_ref, "account_ref": CUSTOMERS.get(customer_ref or "")} if customer_ref else {}
    if info["method"] == "device_push":
        device = REGISTERED_DEVICE.get(customer_ref or "")
        if info.get("factor_id"):
            with session.transaction() as c:
                tokn = c.execute(text("SELECT device_token FROM mfa_factors WHERE factor_id = :f"), {"f": info["factor_id"]}).scalar()
            device = demo_state.device_for_token(tokn) or device
        context = fill_context({"device_id": device}) if device else {}
    else:
        context = {k: v for k, v in demo_state.last_context.get(info["customer"], {}).items() if k != "user_agent"}
    return Envelope(event_id=new_id("evt"), event_type="step_up_result", source="demo-bank-web",
                    occurred_at=_result_time(info["case_id"]), subject=subject, context=context,
                    payload={"challenge_id": info["challenge_id"], "method": info["method"], "result": info["status"],
                             "factor_age_h": round(factor_age_h, 4)})


async def emit_result(app, info: dict, factor_age_h: float) -> str:
    from api.routers.ingest import ingest_server_side
    env = build_result_envelope(info, factor_age_h)
    await ingest_server_side(app, env)
    await app.state.broadcaster.broadcast({"type": "challenge_update", "challenge_id": info["challenge_id"],
                                           "status": info["status"], "case_id": info["case_id"]})
    return env.event_id
