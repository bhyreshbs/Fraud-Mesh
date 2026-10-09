"""One place that builds the Pipeline the API and the loaders use (so load.py, the demo reset and the API process agree)."""
from __future__ import annotations

from engine.pipeline import Pipeline


def make_pipeline(store) -> Pipeline:
    """Dev 2's engine.pipeline.Pipeline with the real detectors (PRD §6.2)."""
    return Pipeline(store)
