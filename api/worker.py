"""Event worker (PRD §2, §6.2, §6.4, §15.2 task 1).

One asyncio task drains the in-process queue in received_at order and calls Pipeline.process for one event at a time
(never concurrently). After each event it applies the §6.4 side effects:
  - broadcast every CaseUpdate on the WebSocket
  - step_up any -> sms_otp challenge; trusted -> device_push challenge
  - payment_outcome -> payment_outcomes row; a transaction with no update -> 'completed'
  - mfa_change (sms) -> update the customer's sms factor (phone_token, changed_at)
An exception is logged, written as an ENGINE_ERROR audit row, and the worker moves on.
A second task expires pending challenges every 5 s and emits their step_up_result.

engine_lock serialises everything that touches the Pipeline's in-memory state or rewrites a case: the worker holds it
for each event, and the API routes that do the same (feedback, manual actions, the graph view, the demo reset) take it
too, so none of them runs in a thread while process() mutates the graph or saves the same case (no lost updates).
Ingestion is refused with 503 once MAX_BACKLOG events are waiting (see api/routers/ingest.accept_envelope).
"""
from __future__ import annotations

import asyncio
import logging
import traceback

from sqlalchemy import text

from api import stepup
from api.db import session
from engine.common.ids import new_id
from engine.contracts import CaseUpdate, StoredEvent

log = logging.getLogger("fraudmesh.worker")
EXPIRY_INTERVAL_S = 5
MAX_BACKLOG = 10_000                 # ~3 minutes of work at the 50 events/s target; beyond that ingestion answers 503


class Worker:
    def __init__(self, app) -> None:
        self.app = app
        self.queue: asyncio.Queue[StoredEvent] = asyncio.Queue()
        self.engine_lock = asyncio.Lock()
        self._tasks: list[asyncio.Task] = []
        self.processed = 0

    # ------------------------------------------------------------ lifecycle
    def enqueue(self, ev: StoredEvent) -> None:
        self.queue.put_nowait(ev)

    def backlog_full(self) -> bool:
        return self.queue.qsize() >= MAX_BACKLOG

    def discard_backlog(self) -> int:
        """Drop queued events without processing them (the demo reset truncates the rows they refer to)."""
        n = 0
        while not self.queue.empty():
            self.queue.get_nowait()
            self.queue.task_done()
            n += 1
        return n

    async def start(self) -> None:
        pipeline = self.app.state.pipeline
        await asyncio.to_thread(pipeline.startup)
        self._tasks = [asyncio.create_task(self._consume(), name="fm-worker"),
                       asyncio.create_task(self._expire_loop(), name="fm-expiry")]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def drain(self) -> None:
        await self.queue.join()

    # ------------------------------------------------------------ consumer
    async def _consume(self) -> None:
        while True:
            ev = await self.queue.get()
            try:
                await self.handle(ev)
            except Exception as e:                                    # never let one event stop the worker
                log.exception("engine error on %s", ev.event_id)
                try:
                    await asyncio.to_thread(self.app.state.store.append_audit, "engine", "ENGINE_ERROR", ev.event_id,
                                            {"error": f"{type(e).__name__}: {e}", "trace": traceback.format_exc()[-2000:]})
                except Exception:
                    log.exception("could not write ENGINE_ERROR audit row")
            finally:
                self.processed += 1
                self.queue.task_done()

    async def handle(self, ev: StoredEvent) -> list[CaseUpdate]:
        async with self.engine_lock:
            updates: list[CaseUpdate] = await asyncio.to_thread(self.app.state.pipeline.process, ev)
            created = await asyncio.to_thread(self._side_effects, ev, updates)
        hub = self.app.state.broadcaster
        for u in updates:
            await hub.broadcast(u.model_dump(mode="json"))
        for ch in created:
            await hub.broadcast({"type": "challenge_update", "challenge_id": ch["challenge_id"], "status": ch["status"],
                                 "case_id": ch["case_id"]})
        return updates

    def _side_effects(self, ev: StoredEvent, updates: list[CaseUpdate]) -> list[dict]:
        store = self.app.state.store
        with session.transaction() as c:
            if ev.event_type == "mfa_change" and ev.payload.get("factor") == "sms" and ev.customer:
                self._update_sms_factor(c, ev)
            if ev.event_type == "transaction":
                outcome, case_id = "completed", None
                for u in updates:
                    if u.payment_outcome:
                        outcome, case_id = u.payment_outcome, u.case.case_id
                        if outcome != "completed":
                            break
                c.execute(text("INSERT INTO payment_outcomes (event_id, outcome, case_id) VALUES (:e, :o, :c) "
                               "ON CONFLICT (event_id) DO UPDATE SET outcome = EXCLUDED.outcome, case_id = EXCLUDED.case_id"),
                          {"e": ev.event_id, "o": outcome, "c": case_id})
        created = []
        for u in updates:
            if u.step_up is None:
                continue
            case = store.get_case(u.step_up.case_id)
            ch = stepup.create_challenge(u.step_up, ev.occurred_at, case.opened_at if case else None)
            if ch:
                created.append(ch)
        return created

    @staticmethod
    def _update_sms_factor(c, ev: StoredEvent) -> None:
        action, phone = ev.payload.get("action"), ev.payload.get("new_phone")
        if action == "remove":
            c.execute(text("UPDATE mfa_factors SET active = false, changed_at = :t WHERE customer = :cu AND kind = 'sms' AND active"),
                      {"t": ev.occurred_at, "cu": ev.customer})
            return
        updated = c.execute(text("UPDATE mfa_factors SET phone_token = :p, changed_at = :t "
                                 "WHERE customer = :cu AND kind = 'sms' AND active RETURNING factor_id"),
                            {"p": phone, "t": ev.occurred_at, "cu": ev.customer}).first()
        if updated is None:                       # no sms factor yet: this change enrols one
            c.execute(text("INSERT INTO mfa_factors (factor_id, customer, kind, enrolled_at, changed_at, phone_token) "
                           "VALUES (:id, :cu, 'sms', :t, :t, :p)"),
                      {"id": new_id("fac"), "cu": ev.customer, "t": ev.occurred_at, "p": phone})

    # ------------------------------------------------------------ challenge expiry
    async def _expire_loop(self) -> None:
        while True:
            await asyncio.sleep(EXPIRY_INTERVAL_S)
            try:
                await self.expire_once()
            except Exception:
                log.exception("challenge expiry failed")

    async def expire_once(self) -> int:
        expired = await asyncio.to_thread(stepup.expire_due)
        for info, age in expired:
            await stepup.emit_result(self.app, info, age)
        return len(expired)
