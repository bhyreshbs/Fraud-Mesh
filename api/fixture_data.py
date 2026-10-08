"""Loads fixtures/api/*.json for the Phase 0 route stubs (replaced route by route in D1-P2)."""
from __future__ import annotations

import json
from functools import cache
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "api"


@cache
def _raw(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def fixture(name: str):
    return json.loads(_raw(name))
