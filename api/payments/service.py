"""Mirrors FraudMesh payment outcomes (PRD §6.4) onto a payment rail, off the event worker's path.

Mapping (one payment_rail row per transaction event; `target` is the state the row should reach):
  outcome completed -> authorize, then capture     target CAPTURED
  outcome blocked   -> authorize, then void        target VOIDED
  outcome held      -> authorize and keep the hold target AUTHORIZED
  later, feedback on the held payment's case:
    FALSE_POSITIVE  -> capture   (target CAPTURED)
    CONFIRMED_FRAUD -> void      (target VOIDED)
    INCONCLUSIVE    -> nothing

The worker only calls submit_transaction() (non-blocking, never raises) after it has released engine_lock. One
asyncio task drains a queue of event ids and moves each row towards its target in a thread; every job is state
driven, so a retry repeats only the steps that did not happen. A failure is logged, written to the row's
last_error and to an audit row PAYMENT_RAIL_ERROR, and retried with backoff up to FM_PAYMENT_MAX_ATTEMPTS.
Voids and the capture of a released hold are audited (PAYMENT_VOIDED / PAYMENT_CAPTURED, with the reason: outcome
or verdict); a verdict that schedules them is audited as PAYMENT_RELEASE_SCHEDULED / PAYMENT_VOID_SCHEDULED. The
routine capture of a completed payment is not audited (one row per allowed payment would flood the chain).

Env (Dev 1, all optional):
  FM_PAYMENT_RAIL         mock (default) | paypal_sandbox | off
  FM_PAYMENT_CURRENCY     rail currency; default INR for mock, USD for paypal_sandbox
  PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET   required for paypal_sandbox (else the rail falls back to mock)
  PAYPAL_BASE_URL         default https://api-m.sandbox.paypal.com
  PAYPAL_VAULT_ID         optional sandbox vaulted payment-method id (lets PayPal authorize without a payer)
  FM_PAYMENT_MAX_ATTEMPTS default 5
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass

from sqlalchemy import text

from api.db import session
from api.payments.rails import MockPayPalRail, PaymentRail, PayPalSandboxRail, RailError
from engine.contracts import StoredEvent

log = logging.getLogger("fraudmesh.payments")
ACTOR = "payments"
TARGET_FOR_OUTCOME = {"completed": "CAPTURED", "blocked": "VOIDED", "held": "AUTHORIZED"}
TARGET_FOR_VERDICT = {"FALSE_POSITIVE": "CAPTURED", "CONFIRMED_FRAUD": "VOIDED"}
MAX_QUEUE = 10_000


@dataclass(frozen=True)
class RailConfig:
    mode: str                     # mock | paypal_sandbox | off
    currency: str
    max_attempts: int = 5
    retry_base_s: float = 2.0


def rail_from_env(env: dict[str, str] | None = None) -> tuple[RailConfig, PaymentRail | None]:
    env = dict(os.environ) if env is None else env
    mode = (env.get("FM_PAYMENT_RAIL") or "mock").strip().lower()
    attempts = int(env.get("FM_PAYMENT_MAX_ATTEMPTS") or 5)
    if mode == "off":
        return RailConfig("off", "", attempts), None
    cid, secret = env.get("PAYPAL_CLIENT_ID", ""), env.get("PAYPAL_CLIENT_SECRET", "")
    if mode == "paypal_sandbox":
        if cid and secret:
            cur = (env.get("FM_PAYMENT_CURRENCY") or "USD").upper()
            rail = PayPalSandboxRail(cid, secret, currency=cur,
                                     base_url=env.get("PAYPAL_BASE_URL") or "https://api-m.sandbox.paypal.com",
                                     vault_id=env.get("PAYPAL_VAULT_ID") or None)
            return RailConfig("paypal_sandbox", cur, attempts), rail
        log.warning("FM_PAYMENT_RAIL=paypal_sandbox but PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET are not set: using the offline mock")
    elif mode != "mock":
        log.warning("unknown FM_PAYMENT_RAIL=%r: using the offline mock", mode)
    cur = (env.get("FM_PAYMENT_CURRENCY") or "INR").upper()
    return RailConfig("mock", cur, attempts), MockPayPalRail(currency=cur)


class PaymentDispatcher:
    def __init__(self, store, config: RailConfig, rail: PaymentRail | None) -> None:
        self.store, self.config, self.rail = store, config, rail
        self.queue: asyncio.Queue[tuple] = asyncio.Queue(maxsize=MAX_QUEUE)   # ("txn", ...) or ("advance", event_id)
        self._task: asyncio.Task | None = None
        self._retries: set[asyncio.Task] = set()
        self._paused = False                     # while a demo reset rewrites the tables (api/routers/demo._engine_paused)
        self._attempts: dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        return self.rail is not None

    # ------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        if self.enabled and self._task is None:
            await asyncio.to_thread(self._restore_mock)
            self._task = asyncio.create_task(self._consume(), name="fm-payments")

    async def stop(self) -> None:
        tasks = [t for t in [self._task, *self._retries] if t is not None]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._task = None
        self._retries.clear()
        close = getattr(self.rail, "close", None)
        if close:
            close()

    async def drain(self) -> None:
        """Wait until queued jobs (and pending retries) are done. For tests and orderly shutdown."""
        while True:
            await self.queue.join()
            if not self._retries:
                return
            await asyncio.gather(*list(self._retries), return_exceptions=True)

    # ------------------------------------------------------------ entry points (never raise)
    def submit_transaction(self, ev: StoredEvent, outcome: str, case_id: str | None) -> None:
        """Called by the worker after _side_effects committed the payment_outcomes row (engine_lock released)."""
        if not self.enabled or ev.event_type != "transaction":
            return
        try:                                     # no I/O here: the row is written by the consumer, in a thread
            job = ("txn", ev.event_id, outcome, case_id, int(ev.payload.get("amount_paise") or 0),
                   ev.payload.get("payee_account"))  # payee_account is already a token (acct:...) in a StoredEvent
            self._enqueue(job)
        except Exception:
            log.exception("payment rail: could not schedule %s", ev.event_id)

    def submit_verdict(self, case_id: str, verdict: str, actor: str) -> None:
        """Feedback on a case: capture (FALSE_POSITIVE) or void (CONFIRMED_FRAUD) its held payments. Queued behind
        the case's transaction jobs (FIFO), so a verdict never overtakes the authorization it releases."""
        target = TARGET_FOR_VERDICT.get(verdict)
        if not self.enabled or target is None:
            return
        try:
            self._enqueue(("verdict", case_id, target, verdict, actor))
        except Exception:
            log.exception("payment rail: could not schedule the %s verdict for %s", verdict, case_id)

    async def pause(self) -> int:
        """Stop accepting jobs, drop queued jobs and pending retries (they name rows about to be truncated or restored),
        and wait for the job already running. Returns how many jobs were dropped."""
        self._paused = True
        for t in list(self._retries):
            t.cancel()
        self._retries.clear()
        dropped = self._clear_queue()
        await self.queue.join()
        return dropped

    def resume(self) -> None:
        self._clear_queue()
        self._attempts.clear()
        self._paused = False

    def _clear_queue(self) -> int:
        n = 0
        while not self.queue.empty():
            self.queue.get_nowait()
            self.queue.task_done()
            n += 1
        return n

    def _enqueue(self, job: tuple) -> None:
        if self._paused:
            log.info("payment rail paused (demo reset): %s %s not scheduled", job[0], job[1])
            return
        try:
            self.queue.put_nowait(job)
        except asyncio.QueueFull:                # the row (if any) keeps its target; it is visible in the case route
            log.error("payment rail queue full: %s not scheduled", job[1])

    # ------------------------------------------------------------ consumer
    async def _consume(self) -> None:
        while True:
            job = await self.queue.get()
            try:
                if job[0] == "verdict":
                    for eid in await asyncio.to_thread(self._retarget_held, *job[1:]):
                        self._enqueue(("advance", eid))
                    continue
                event_id, retry_job = job[1], job              # until the row exists, a retry must write it
                try:
                    if job[0] == "txn":
                        await asyncio.to_thread(self._upsert_row, *job[1:])
                        retry_job = ("advance", event_id)
                    await asyncio.to_thread(self._advance, event_id)
                    self._attempts.pop(event_id, None)
                except Exception as e:                                   # never let one payment stop the consumer
                    self._on_failure(event_id, e, retry_job)
            except Exception:
                log.exception("payment rail job %s failed", job[0])
            finally:
                self.queue.task_done()

    def _on_failure(self, event_id: str, e: Exception, retry_job: tuple) -> None:
        n = self._attempts.get(event_id, 0) + 1
        self._attempts[event_id] = n
        code = e.code if isinstance(e, RailError) else type(e).__name__
        retryable = not isinstance(e, RailError) or e.retryable
        final = (not retryable) or n >= self.config.max_attempts
        log.warning("payment rail %s failed for %s (attempt %d%s): %s", self.config.mode, event_id, n,
                    ", giving up" if final else "", e)
        try:
            self._record_error(event_id, str(e)[:500], code, final=final, attempt=n)
        except Exception:
            log.exception("could not record the payment rail error for %s", event_id)
        if final:
            self._attempts.pop(event_id, None)
            return
        delay = min(self.config.retry_base_s * (2 ** (n - 1)), 300.0)
        t = asyncio.get_running_loop().create_task(self._retry_later(retry_job, delay))
        self._retries.add(t)
        t.add_done_callback(self._retries.discard)

    async def _retry_later(self, job: tuple, delay: float) -> None:
        await asyncio.sleep(delay)
        self._enqueue(job)

    # ------------------------------------------------------------ the state machine step (runs in a thread)
    def _advance(self, event_id: str) -> None:
        row = self._row(event_id)
        if row is None or self.rail is None:
            return
        state, target, auth_id = row["state"], row["target"], row["auth_id"]
        if state == "CREATED" or not auth_id:
            auth_id = self.rail.authorize(event_id, row["amount_paise"], self.config.currency, row["payee_token"])
            state = "AUTHORIZED"
            self._set_state(event_id, state, auth_id)
        if state == target or state in ("CAPTURED", "VOIDED"):
            if state != target:                                     # e.g. captured, later a CONFIRMED_FRAUD verdict
                raise RailError("STATE_FINAL", f"already {state}, cannot reach {target}")
            return
        if target == "CAPTURED":
            new = self.rail.capture(auth_id, request_id=f"{event_id}-capture")
            action = "PAYMENT_CAPTURED"
        elif target == "VOIDED":
            new = self.rail.void(auth_id, request_id=f"{event_id}-void")
            action = "PAYMENT_VOIDED"
        else:
            return
        self._set_state(event_id, new, auth_id)
        if row["reason"] == "outcome:completed":            # routine capture of an allowed payment: not an audit event
            return
        self.store.append_audit(ACTOR, action, event_id, {"rail": self.config.mode, "auth_id": auth_id,
                                                          "case_id": row["case_id"], "reason": row["reason"]})

    # ------------------------------------------------------------ SQL
    def _upsert_row(self, event_id: str, outcome: str, case_id: str | None, amount_paise: int, payee: str | None) -> None:
        target = TARGET_FOR_OUTCOME[outcome]
        with session.transaction() as c:
            c.execute(text(
                "INSERT INTO payment_rail (event_id, case_id, rail, state, target, reason, amount_paise, currency, payee_token) "
                "VALUES (:e, :c, :r, 'CREATED', :t, :reason, :a, :cur, :p) "
                "ON CONFLICT (event_id) DO UPDATE SET case_id = EXCLUDED.case_id, target = EXCLUDED.target, "
                "reason = EXCLUDED.reason, updated_at = now() WHERE payment_rail.state NOT IN ('CAPTURED','VOIDED')"),
                {"e": event_id, "c": case_id, "r": self.config.mode, "t": target, "reason": f"outcome:{outcome}",
                 "a": amount_paise, "cur": self.config.currency, "p": payee})

    def _retarget_held(self, case_id: str, target: str, verdict: str, actor: str) -> list[str]:
        with session.transaction() as c:
            ids = list(c.execute(text(
                "UPDATE payment_rail SET target = :t, reason = :reason, updated_at = now() "
                "WHERE case_id = :c AND target = 'AUTHORIZED' AND state IN ('CREATED','AUTHORIZED') RETURNING event_id"),
                {"t": target, "reason": f"verdict:{verdict}", "c": case_id}).scalars())
            if ids:
                self.store.append_audit(actor, "PAYMENT_RELEASE_SCHEDULED" if target == "CAPTURED" else "PAYMENT_VOID_SCHEDULED",
                                        case_id, {"verdict": verdict, "event_ids": sorted(ids), "rail": self.config.mode})
        return ids

    def _row(self, event_id: str) -> dict | None:
        with session.transaction() as c:
            r = c.execute(text("SELECT * FROM payment_rail WHERE event_id = :e"), {"e": event_id}).mappings().first()
        return dict(r) if r else None

    def _set_state(self, event_id: str, state: str, auth_id: str) -> None:
        with session.transaction() as c:
            c.execute(text("UPDATE payment_rail SET state = :s, auth_id = :a, last_error = NULL, updated_at = now() "
                           "WHERE event_id = :e"), {"s": state, "a": auth_id, "e": event_id})

    def _record_error(self, event_id: str, message: str, code: str, *, final: bool, attempt: int = 0) -> None:
        with session.transaction() as c:
            c.execute(text("UPDATE payment_rail SET last_error = :m, attempts = attempts + 1, updated_at = now() "
                           "WHERE event_id = :e"), {"m": f"{code}: {message}"[:600], "e": event_id})
            self.store.append_audit(ACTOR, "PAYMENT_RAIL_ERROR", event_id,
                                    {"rail": self.config.mode, "code": code, "error": message, "attempt": attempt, "final": final})

    def _restore_mock(self) -> None:
        restore = getattr(self.rail, "restore", None)
        if restore is None:
            return
        try:
            with session.transaction() as c:
                rows = c.execute(text("SELECT event_id, auth_id, state FROM payment_rail "
                                      "WHERE rail = 'mock' AND auth_id IS NOT NULL")).mappings().all()
        except Exception:
            log.warning("payment rail: payment_rail table not readable (migration 0003 not applied?)")
            return
        for r in rows:
            restore(r["auth_id"], r["event_id"], r["state"])


def list_for_case(case_id: str) -> list[dict]:
    """Every transaction of the case with its payment outcome and, when mirrored, its rail state."""
    with session.transaction() as c:
        return [dict(r) for r in c.execute(text(
            "SELECT po.event_id, po.outcome, (ev.data->'payload'->>'amount_paise')::bigint AS amount_paise, "
            "pr.rail, pr.auth_id, pr.state, pr.target, pr.currency, pr.attempts, pr.last_error, pr.updated_at "
            "FROM payment_outcomes po JOIN events ev ON ev.event_id = po.event_id "
            "LEFT JOIN payment_rail pr ON pr.event_id = po.event_id "
            "WHERE po.case_id = :c ORDER BY ev.occurred_at, po.event_id"), {"c": case_id}).mappings()]
