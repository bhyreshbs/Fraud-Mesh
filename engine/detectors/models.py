"""Model artifacts (PRD §16.3): ml/artifacts/*.joblib, verified against manifest.json before use.

MODEL_DIR (settings.model_dir) is used as given when it exists, else resolved against the repository root, so
the engine finds the committed artifacts from any working directory. A missing artifact or a SHA-256 mismatch
returns None, and the detector runs in its documented degraded mode.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import joblib

from engine.common.settings import settings

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "manifest.json"


def model_dir() -> Path:
    d = Path(settings.model_dir)
    return d if d.is_absolute() or d.exists() else REPO_ROOT / d


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(directory: Path | None = None) -> dict[str, Any]:
    path = (directory or model_dir()) / MANIFEST
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"artifacts": []}


def manifest_entry(file: str, directory: Path | None = None) -> dict[str, Any] | None:
    return next((a for a in load_manifest(directory).get("artifacts", []) if a.get("file") == file), None)


def load_artifact(file: str, directory: Path | None = None) -> tuple[Any | None, str | None]:
    """(object, sha256) when the file exists and matches its manifest sha256, else (None, reason)."""
    d = directory or model_dir()
    path, entry = d / file, manifest_entry(file, d)
    if not path.exists():
        return None, "missing"
    if entry is None:
        return None, "not in manifest"
    digest = sha256_file(path)
    if digest != entry.get("sha256"):
        return None, "sha256 mismatch"
    return joblib.load(path), digest
