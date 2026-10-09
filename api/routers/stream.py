"""WebSocket /v1/stream (PRD §9.6): first message {"token": "<jwt>"} within 5 s, else close 4401.
The Broadcaster fans CaseUpdate / challenge_update JSON out to every authenticated client (used by the worker).

Hardening: sends go to all clients concurrently with a per-client timeout, and a client that cannot keep up is dropped,
so one stalled reader can never hold up the worker that broadcasts. A connection is closed (4401) when its access
token expires; the client reconnects with a fresh token. At most MAX_CLIENTS sockets are open at once.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.errors import ApiError
from api.security import decode_access_token

router = APIRouter(tags=["stream"])
AUTH_TIMEOUT_S = 5
SEND_TIMEOUT_S = 2.0
MAX_CLIENTS = 200
CLOSE_UNAUTHENTICATED = 4401
CLOSE_TRY_AGAIN_LATER = 1013


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

    async def _send(self, ws: WebSocket, text: str) -> bool:
        try:
            await asyncio.wait_for(ws.send_text(text), timeout=SEND_TIMEOUT_S)
            return True
        except Exception:                                    # closed, broken or too slow: drop it
            return False

    async def broadcast(self, message: dict) -> None:
        text = json.dumps(message, default=str)
        clients = list(self._clients)
        results = await asyncio.gather(*(self._send(ws, text) for ws in clients))
        for ws, ok in zip(clients, results, strict=True):
            if not ok:
                self.remove(ws)
                try:
                    await ws.close()
                except Exception:
                    pass


@router.websocket("/v1/stream")
async def stream(ws: WebSocket) -> None:
    hub: Broadcaster = ws.app.state.broadcaster
    await ws.accept()
    if hub.count >= MAX_CLIENTS:
        await ws.close(code=CLOSE_TRY_AGAIN_LATER)
        return
    try:
        first = await asyncio.wait_for(ws.receive_text(), timeout=AUTH_TIMEOUT_S)
        principal = decode_access_token(json.loads(first)["token"])
    except (TimeoutError, ApiError, KeyError, TypeError, ValueError, WebSocketDisconnect):
        await ws.close(code=CLOSE_UNAUTHENTICATED)
        return
    await hub.add(ws)
    try:
        while True:                                            # clients only send keep-alives; ignore them
            left = (principal.expires_at - datetime.now(UTC)).total_seconds() if principal.expires_at else None
            if left is not None and left <= 0:
                raise TimeoutError
            await asyncio.wait_for(ws.receive_text(), timeout=left)
    except TimeoutError:                                       # the access token expired
        hub.remove(ws)
        await ws.close(code=CLOSE_UNAUTHENTICATED)
    except WebSocketDisconnect:
        pass
    finally:
        hub.remove(ws)
