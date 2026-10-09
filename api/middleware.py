"""Pure-ASGI middleware (PRD §9.7). Same behaviour as decorator middleware, without Starlette's BaseHTTPMiddleware
overhead on every request (it shares the event loop with the event worker, so it shows up in decision latency).

RequestContextMiddleware (outermost): request_id on every request; CSP / HSTS / nosniff / Referrer-Policy / X-Frame-Options
    and X-Request-ID on every response; unhandled exceptions become a §4-format 500 INTERNAL_ERROR.
DefaultRateLimitMiddleware (innermost): the default 20/s per user (or IP) on /v1 routes without their own limit.
"""
from __future__ import annotations

import logging

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from api.errors import error_response
from api.ratelimit import DEFAULT_LIMIT, default_limit_exceeded
from engine.common.ids import new_id

log = logging.getLogger("fraudmesh.api")

DOCS_PATHS = {"/docs", "/redoc", "/docs/oauth2-redirect"}
# Swagger UI (/docs) loads its JS/CSS from jsDelivr, so those paths get a CSP that allows it; everything else is 'self'.
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com")
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        rid = new_id("req")
        scope.setdefault("state", {})["request_id"] = rid
        csp = DOCS_CSP if scope.get("path") in DOCS_PATHS else "default-src 'self'"
        started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = rid
                headers["Content-Security-Policy"] = csp
                for k, v in SECURITY_HEADERS.items():
                    headers[k] = v
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:                                      # unexpected bug: still answer in the §4 error format
            log.exception("unhandled error on %s %s", scope.get("method"), scope.get("path"))
            if started:
                raise
            await error_response(Request(scope), "INTERNAL_ERROR", "internal error", 500)(scope, receive, send_with_headers)


class DefaultRateLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            request = Request(scope)
            if default_limit_exceeded(request):
                resp = error_response(request, "RATE_LIMITED", f"rate limit exceeded: {DEFAULT_LIMIT}", 429)
                resp.headers["Retry-After"] = "1"
                await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)
