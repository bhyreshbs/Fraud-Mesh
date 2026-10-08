"""WebSocket /v1/stream (PRD §9.6): first message {"token": "<jwt>"} within 5 s, else close 4401.
The Broadcaster fans CaseUpdate / challenge_update JSON out to every authenticated client (used by the worker in D1-P2)."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.errors import ApiError
from api.security import decode_access_token

router = APIRouter(tags=["stream"])
AUTH_TIMEOUT_S = 5


class Broadcaster:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    async def add(self, ws: WebSocket) -> None:
        self._clients.add(ws)

    def remove(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    @property
    def count(self) -> int:
        return len(self._clients)

    async def broadcast(self, message: dict) -> None:
        text = json.dumps(message, default=str)
        dead = []
        for ws in list(self._clients):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.remove(ws)


@router.websocket("/v1/stream")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    try:
        first = await asyncio.wait_for(ws.receive_text(), timeout=AUTH_TIMEOUT_S)
        decode_access_token(json.loads(first)["token"])
    except (TimeoutError, ApiError, KeyError, TypeError, ValueError, WebSocketDisconnect):
        await ws.close(code=4401)
        return
    hub: Broadcaster = ws.app.state.broadcaster
    await hub.add(ws)
    try:
        while True:
            await ws.receive_text()            # clients only send keep-alives; ignore them
    except WebSocketDisconnect:
        pass
    finally:
        hub.remove(ws)
