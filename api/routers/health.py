"""GET /v1/health (PRD §9.4)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import APIRouter, Request

from api.db.session import db_ok
from api.schemas import Health
from engine.common.settings import settings
from engine.contracts import CONTRACT_VERSION

router = APIRouter(prefix="/v1", tags=["health"])


def _model_sha256() -> str | None:
    """sha256 of the txn model from ml/artifacts/manifest.json (written by Dev 2 in D2-P3), if present."""
    manifest = Path(settings.model_dir) / "manifest.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    items = data if isinstance(data, list) else data.get("artifacts", data.get("files", [data]))
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and "txn" in str(item.get("file", "")) and item.get("sha256"):
            return item["sha256"]
    return data.get("sha256") if isinstance(data, dict) else None


@router.get("/health", response_model=Health)
async def health(request: Request) -> Health:
    pipeline = request.app.state.pipeline
    return Health(db=await asyncio.to_thread(db_ok), pipeline_ready=bool(pipeline and pipeline.ready),
                  contract_version=CONTRACT_VERSION, model_sha256=_model_sha256())
