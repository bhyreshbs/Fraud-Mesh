"""FraudMesh API (PRD §2, §9). One process: routers + one Pipeline + one in-process event queue."""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from api import firebase_boundary
from api.errors import install_error_handlers
from api.middleware import BodySizeLimitMiddleware, DefaultRateLimitMiddleware, RequestContextMiddleware
from api.payments import build_dispatcher
from api.pipeline_factory import make_pipeline
from api.ratelimit import limiter, rate_limited_handler
from api.routers import auth, cases, config, demo, health, ingest, metrics, payments, stream, twin
from api.store_pg import PgStore
from api.worker import Worker
from engine.common.settings import settings

log = logging.getLogger("fraudmesh.api")



@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.store = PgStore()
    app.state.pipeline = make_pipeline(app.state.store)   # one Pipeline per API process (PRD §6.2)
    app.state.runs = {}                                   # autopilot runs: run_id -> (RunState, Task)
    app.state.reset_lock = asyncio.Lock()
    app.state.broadcaster = stream.Broadcaster()
    app.state.payments = build_dispatcher(app.state.store)   # payment rail (FM_PAYMENT_RAIL): off the worker path
    app.state.worker = Worker(app)
    app.state.enqueue = app.state.worker.enqueue
    await app.state.worker.start()                        # runs pipeline.startup() in a thread first
    await app.state.payments.start()
    try:
        yield
    finally:
        await app.state.worker.stop()
        await app.state.payments.stop()


def create_app() -> FastAPI:
    logging.basicConfig(level=settings.log_level)
    # interactive docs and the schema only in demo mode: elsewhere they map the attack surface for free
    docs = {} if settings.demo_mode else {"docs_url": None, "redoc_url": None, "openapi_url": None}
    app = FastAPI(title="FraudMesh API", version="1.0.0", lifespan=lifespan, **docs)

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limited_handler)
    # add_middleware wraps outward: rate limit (innermost) < CORS < body limit < request context + headers (outermost)
    app.add_middleware(DefaultRateLimitMiddleware)       # default 20/s per user (or IP) on /v1 routes
    # CORS_ORIGIN_REGEX (Dev 1 env, off by default): lets the console and bank app be opened from other devices on the
    # same LAN, e.g. ^http://(10|192\.168)\.[0-9.]+:(5173|5174)$ . Only set it for a local demo network.
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_origin_regex=os.getenv("CORS_ORIGIN_REGEX") or None,
                       allow_credentials=True,
                       allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type", "X-FM-CSRF", "X-FM-Source",
                                                                     "X-FM-Timestamp", "X-FM-Signature", "X-FM-Signature-Alg"],
                       expose_headers=["X-Request-ID"])
    app.add_middleware(BodySizeLimitMiddleware)          # caps every request body before any route reads it
    app.add_middleware(RequestContextMiddleware)          # request_id + security headers on every response

    install_error_handlers(app)
    for r in (health.router, auth.router, ingest.router, cases.router, payments.router, metrics.router, stream.router,
              twin.router, config.router):
        app.include_router(r)
    if firebase_boundary.auth_provider() == "firebase":   # optional Firebase sign-in (off by default)
        app.include_router(auth.firebase_router)
    if settings.demo_mode:
        app.include_router(demo.router)
    return app


app = create_app()
