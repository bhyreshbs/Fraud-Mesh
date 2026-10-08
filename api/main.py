"""FraudMesh API (PRD §2, §9). One process: routers + one Pipeline + one in-process event queue."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from api.errors import error_response, install_error_handlers
from api.pipeline_factory import make_pipeline
from api.ratelimit import DEFAULT_LIMIT, default_limit_exceeded, limiter, rate_limited_handler
from api.routers import auth, cases, demo, health, ingest, metrics, stream
from api.store_pg import PgStore
from api.worker import Worker
from engine.common.ids import new_id
from engine.common.settings import settings

log = logging.getLogger("fraudmesh.api")

# Swagger UI (/docs) loads its JS/CSS from jsDelivr, so those two paths get a CSP that allows it; everything else is 'self'.
DOCS_PATHS = {"/docs", "/redoc", "/docs/oauth2-redirect"}
DOCS_CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.store = PgStore()
    app.state.pipeline = make_pipeline(app.state.store)   # one Pipeline per API process (PRD §6.2)
    app.state.runs = {}                                   # autopilot runs: run_id -> (RunState, Task)
    app.state.reset_lock = asyncio.Lock()
    app.state.broadcaster = stream.Broadcaster()
    app.state.worker = Worker(app)
    app.state.enqueue = app.state.worker.enqueue
    await app.state.worker.start()                        # runs pipeline.startup() in a thread first
    try:
        yield
    finally:
        await app.state.worker.stop()


def create_app() -> FastAPI:
    logging.basicConfig(level=settings.log_level)
    app = FastAPI(title="FraudMesh API", version="1.0.0", lifespan=lifespan)

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limited_handler)

    @app.middleware("http")                                # innermost: default 20/s per user (or IP) on /v1 routes
    async def default_rate_limit(request: Request, call_next):
        if default_limit_exceeded(request):
            resp = error_response(request, "RATE_LIMITED", f"rate limit exceeded: {DEFAULT_LIMIT}", 429)
            resp.headers["Retry-After"] = "1"
            return resp
        return await call_next(request)

    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                       allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type", "X-FM-Source",
                                                                     "X-FM-Timestamp", "X-FM-Signature"],
                       expose_headers=["X-Request-ID"])

    @app.middleware("http")                                # outermost: request id + security headers on every response
    async def request_id_and_headers(request: Request, call_next):
        request.state.request_id = new_id("req")
        try:
            response = await call_next(request)
        except Exception:                                  # unexpected bug: still answer in the §4 error format
            log.exception("unhandled error on %s %s", request.method, request.url.path)
            response = error_response(request, "INTERNAL_ERROR", "internal error", 500)
        response.headers["X-Request-ID"] = request.state.request_id
        docs = request.url.path in DOCS_PATHS
        response.headers["Content-Security-Policy"] = DOCS_CSP if docs else "default-src 'self'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    install_error_handlers(app)
    for r in (health.router, auth.router, ingest.router, cases.router, metrics.router, stream.router):
        app.include_router(r)
    if settings.demo_mode:
        app.include_router(demo.router)
    return app


app = create_app()
