"""One place that builds the Pipeline the API and the loaders use (so load.py, the demo reset and the API process agree)."""
from __future__ import annotations

from engine.api import FeedbackGuard
from engine.pipeline import Pipeline


def make_pipeline(store) -> Pipeline:
    """Dev 2's engine.pipeline.Pipeline with the real detectors (PRD §6.2), plus two v3 attachments:
    - feedback_guard: reliability decay and per-batch caps persist between analyst verdicts (engine/feedback.py)
    - the external payee-risk provider (api/payee_risk.py, FM_PAYEE_RISK_PROVIDER, off by default; no live registry)"""
    from api import payee_risk
    pipeline = Pipeline(store)
    pipeline.feedback_guard = FeedbackGuard()
    payee_risk.attach(pipeline, payee_risk.provider_from_env())
    return pipeline
