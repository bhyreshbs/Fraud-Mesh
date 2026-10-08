"""FraudMesh API (PRD §2, §9). One process: routers + one Pipeline + one in-process event queue."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from api.errors import install_error_handlers
from api.routers import auth, cases, demo, health, ingest, metrics, stream
from api.store_pg import PgStore
from api.worker import Worker
from engine.common.ids import new_id
from engine.common.settings import settings
from engine.pipeline import Pipeline

log = logging.getLogger("fraudmesh.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.store = PgStore()
    app.state.pipeline = Pipeline(app.state.store)        # one Pipeline per API process (PRD §6.2)
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

    @app.middleware("http")
    async def request_id(request: Request, call_next):
        request.state.request_id = new_id("req")
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                       allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type", "X-FM-Source",
                                                                     "X-FM-Timestamp", "X-FM-Signature"],
                       expose_headers=["X-Request-ID"])
    install_error_handlers(app)
    for r in (health.router, auth.router, ingest.router, cases.router, metrics.router, stream.router):
        app.include_router(r)
    if settings.demo_mode:
        app.include_router(demo.router)
    return app


app = create_app()
