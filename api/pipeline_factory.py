"""One place that decides which Pipeline the API and the loaders use (so load.py and the API process agree)."""
from __future__ import annotations

import logging
import os

from engine.pipeline import Pipeline

log = logging.getLogger("fraudmesh.api")


def dev_pipeline_enabled() -> bool:
    return os.getenv("FM_DEV_PIPELINE") == "1"


def make_pipeline(store):
    """Dev 2's engine.pipeline.Pipeline, or the dev-only scripted stand-in when FM_DEV_PIPELINE=1."""
    if dev_pipeline_enabled():
        from api.dev_pipeline import ScriptedPipeline
        log.warning("FM_DEV_PIPELINE=1: using the scripted dev stand-in, NOT the real engine")
        return ScriptedPipeline(store)
    return Pipeline(store)
