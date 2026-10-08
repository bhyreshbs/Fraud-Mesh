"""Shared training plumbing (PRD §16.3): load generator output, build features through the SAME engine module the
live Pipeline uses (engine.features.iter_feature_rows), split by time, compute metrics, update manifest.json.

Split by event day counted from the first event: days 1–9 train, 10–11 calibrate, 12–14 test.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from engine.common.tokenize import to_stored_event
from engine.contracts import Envelope, Label, StoredEvent
from engine.detectors.models import MANIFEST, sha256_file
from engine.features.features import iter_feature_rows

TRAIN_DAYS, CALIB_DAYS = range(1, 10), range(10, 12)          # test = everything from day 12 on
ECE_BINS = 10


@dataclass
class Rows:
    events: list[StoredEvent]
    feats: list[dict[str, float]]
    labels: list[Label]
    day: list[int]


def load_events(data: str, labels: str) -> tuple[list[StoredEvent], dict[str, Label]]:
    envs = [Envelope.model_validate_json(line) for line in Path(data).read_text(encoding="utf-8").splitlines() if line]
    lab = {lb.event_id: lb for lb in (Label.model_validate_json(x) for x in Path(labels).read_text(encoding="utf-8").splitlines() if x)}
    events = sorted((to_stored_event(e, e.occurred_at) for e in envs), key=lambda e: (e.occurred_at, e.event_id))
    return events, lab


def feature_rows(events: list[StoredEvent], labels: dict[str, Label], keep) -> Rows:
    """Rows for the events `keep(event, feats)` selects, with features from ALL earlier events."""
    t0 = events[0].occurred_at
    out = Rows([], [], [], [])
    for ev, feats in iter_feature_rows(events):
        if keep(ev, feats):
            out.events.append(ev)
            out.feats.append(feats)
            out.labels.append(labels[ev.event_id])
            out.day.append((ev.occurred_at - t0).days + 1)
    return out


def split(day: list[int]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    d = np.array(day)
    train, calib = np.isin(d, list(TRAIN_DAYS)), np.isin(d, list(CALIB_DAYS))
    return train, calib, ~(train | calib)


def ece(y: np.ndarray, p: np.ndarray, bins: int = ECE_BINS) -> float:
    """Expected calibration error with equal-width probability bins."""
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    total = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            total += m.sum() / len(p) * abs(y[m].mean() - p[m].mean())
    return float(total)


def metrics(y: np.ndarray, p: np.ndarray) -> dict[str, float]:
    both = len(set(y.tolist())) == 2
    return {"pr_auc": round(float(average_precision_score(y, p)), 4) if both else None,
            "roc_auc": round(float(roc_auc_score(y, p)), 4) if both else None,
            "ece": round(ece(y, p), 4), "n": int(len(y)), "positives": int(y.sum())}


def save_artifact(obj, out_dir: str, file: str, entry: dict) -> dict:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    joblib.dump(obj, d / file, compress=3)
    entry = {"file": file, "sha256": sha256_file(d / file), **entry}
    manifest_path = d / MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"artifacts": []}
    manifest["artifacts"] = sorted([a for a in manifest.get("artifacts", []) if a.get("file") != file] + [entry],
                                   key=lambda a: a["file"])
    manifest_path.write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return entry
