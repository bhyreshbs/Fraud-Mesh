"""Scenario player, API mode (PRD §12.2, §15.5 tasks 1 and 5).

Shared by scripts/play.py (real HTTP to a running API, signed with scripts/sign.py) and POST /v1/demo/run/{id}
(the API plays into itself through httpx.ASGITransport, signed with the server-side signer). Either way every
event goes through POST /v1/events with HMAC headers, and every StepUpAction goes through the /v1/demo/step-up/*
routes exactly as the bank app and the phones do: channel "app" reads the OTP from the demo SMS inbox and submits
it; channel "phone" submits the scenario's decision.

Timing: steps keep their scenario timestamps (occurred_at = start + at_min, PRD §12.2); `speed` only compresses the
wall-clock pacing between posts (speed 8 plays the 27-minute Midnight ATO in about 3.4 minutes).
"""
from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

import httpx

from api import scenario_source

Signer = Callable[[str, bytes], dict[str, str]]
CHALLENGE_WAIT_S = 15


@dataclass
class RunState:
    run_id: str
    scenario: str
    speed: float
    status: str = "running"          # running | done | failed | cancelled
    started_at: float = field(default_factory=time.time)
    steps_total: int = 0
    steps_done: int = 0
    accepted: int = 0
    posted: dict[str, list[str]] = field(default_factory=dict)      # event_type -> event_ids accepted (202)
    step_ups: list[tuple[str, str]] = field(default_factory=list)   # (channel, final status | "skipped")
    log: list[str] = field(default_factory=list)

    def say(self, msg: str) -> None:
        self.log.append(f"{time.strftime('%H:%M:%S')} {msg}")
        del self.log[:-200]


async def _wait_until(target_monotonic: float, cancelled: Callable[[], bool]) -> None:
    while True:
        left = target_monotonic - time.monotonic()
        if left <= 0 or cancelled():
            return
        await asyncio.sleep(min(left, 0.25))


async def _step_up(client: httpx.AsyncClient, sc, action, phones: dict[str, str], st: RunState) -> None:
    ident = sc.raw["identities"][action.as_identity]
    customer_ref = str(ident["subject"]["customer_ref"])
    challenge = None
    deadline = time.monotonic() + CHALLENGE_WAIT_S                  # the worker creates the challenge asynchronously
    while time.monotonic() < deadline:
        r = await client.get("/v1/demo/step-up/pending", params={"customer_ref": customer_ref, "channel": action.channel})
        challenge = r.json().get("challenge") if r.status_code == 200 else None
        if challenge:
            break
        await asyncio.sleep(0.5)
    if not challenge:
        st.say(f"[skip] step-up ({action.channel}) for {customer_ref}: no pending challenge")
        st.step_ups.append((action.channel, "skipped"))
        return
    if action.channel == "phone":
        r = await client.post(f"/v1/demo/step-up/{challenge['challenge_id']}/respond", json={"decision": action.decision or "approve"})
        st.say(f"[step-up] phone {action.decision}: {r.json().get('status')}")
        st.step_ups.append(("phone", r.json().get("status", f"http {r.status_code}")))
        return
    phone = phones.get(customer_ref)
    code = None
    if phone:
        for _ in range(int(CHALLENGE_WAIT_S / 0.5)):
            msgs = (await client.get("/v1/demo/sms-inbox", params={"phone": phone})).json().get("messages", [])
            codes = [m.group(0) for m in (re.search(r"\b\d{6}\b", x["text"]) for x in msgs) if m]
            if codes:
                code = codes[-1]
                break
            await asyncio.sleep(0.5)
    if not code:
        st.say(f"[skip] step-up (app) for {customer_ref}: no OTP in the SMS inbox of {phone}")
        st.step_ups.append(("app", "skipped"))
        return
    r = await client.post(f"/v1/demo/step-up/{challenge['challenge_id']}/respond", json={"code": code})
    st.say(f"[step-up] app OTP from {phone}: {r.json().get('status')}")
    st.step_ups.append(("app", r.json().get("status", f"http {r.status_code}")))


async def play(client: httpx.AsyncClient, scenario: str, start: datetime, speed: float, signer: Signer,
               st: RunState, only: str | None = None, preload_only: bool = False,
               label_sink: Callable | None = None) -> RunState:
    """label_sink(sc, envelopes), when given, records ground-truth labels for the events about to be played
    (in-process autopilot only: labels have no HTTP route; the policy simulator scores against them)."""
    sc = scenario_source.load_scenario(str(scenario_source.resolve(scenario)))
    items = scenario_source.preload_envelopes(sc, start) if preload_only else scenario_source.expand(sc, start, "api")
    if label_sink and not preload_only:
        await asyncio.to_thread(label_sink, sc, [it for it in items if hasattr(it, "event_type")])
    st.steps_total = len(items)
    phones: dict[str, str] = {}                                     # customer_ref -> latest SMS number the scenario set
    t0, first = time.monotonic(), None
    try:
        for it in items:
            at = getattr(it, "occurred_at", None) or it.at
            first = first or at
            if not preload_only:
                await _wait_until(t0 + (at - first).total_seconds() / speed, lambda: st.status == "cancelled")
            if st.status == "cancelled":
                st.say("[cancelled]")
                return st
            if hasattr(it, "event_type"):                           # an Envelope
                if only and it.event_type != only:
                    st.steps_done += 1
                    continue
                if it.event_type == "mfa_change" and it.payload.get("new_phone"):
                    phones[str(it.subject.customer_ref)] = str(it.payload["new_phone"])
                body = it.model_dump_json().encode()
                r = await client.post("/v1/events", content=body, headers=signer(it.source, body))
                st.accepted += r.status_code == 202
                if r.status_code == 202:
                    st.posted.setdefault(it.event_type, []).append(it.event_id)
                st.say(f"[{r.status_code}] {it.event_type} ({it.source})")
            elif not only:
                await _step_up(client, sc, it, phones, st)
            st.steps_done += 1
        st.status = "done"
        st.say(f"[done] {st.accepted} events accepted")
    except Exception as e:                                          # report, never crash the API
        st.status = "failed"
        st.say(f"[failed] {type(e).__name__}: {e}")
    return st
