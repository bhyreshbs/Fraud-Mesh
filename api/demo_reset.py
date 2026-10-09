"""Demo reset (PRD §12.3), shared by scripts/reset_demo.sh and POST /v1/demo/reset.

1. Truncate every runtime table; reseed detector_reliability and the three users.
2. START = now rounded up to the next minute, plus 2 minutes.
3. Generate the background with Dev 2's generator (--end START - 10 min), when ml/generator exists.
4. Load the background in-process (--direct): insert events + labels and run Pipeline.process.
5. Play the midnight_ato preload and mark its fraud seeds.
6. Seed MFA factors for every customer in events (Priya's push on fp_priya_phone). The caller then rebuilds the API's
   in-memory Pipeline (startup) and demo state.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from api import loader, seeding
from api.pipeline_factory import make_pipeline

log = logging.getLogger("fraudmesh.reset")
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
BACKGROUND, BACKGROUND_LABELS = DATA / "background.jsonl", DATA / "background_labels.jsonl"
IST = timezone(timedelta(hours=5, minutes=30))
# PRD §12.1 / §12.3 demo background: 14 days x 2000 customers by default. FM_BG_DAYS / FM_BG_CUSTOMERS shrink it
# (tests, quick local runs). Tests that need no background switch BACKGROUND_ENABLED off.
BACKGROUND_ENABLED = True


def generator_args() -> list[str]:
    return ["--days", os.getenv("FM_BG_DAYS", "14"), "--customers", os.getenv("FM_BG_CUSTOMERS", "2000"),
            "--seed", "7", "--attacks", "0"]


def scenario_start(now: datetime | None = None) -> datetime:
    now = (now or datetime.now(UTC)).replace(second=0, microsecond=0) + timedelta(minutes=1)
    return now + timedelta(minutes=2)


def generator_available() -> bool:
    return (ROOT / "ml" / "generator" / "run.py").exists()


def generate_background(start: datetime, say=print) -> bool:
    """PRD §12.1 generator CLI (Dev 2). Returns False (and keeps going) when the generator is not merged yet."""
    if not BACKGROUND_ENABLED:
        say("[skip] background: disabled")
        return False
    if not generator_available():
        say("[skip] background: ml/generator not merged yet (Dev 2, D2-P1) - demo runs on the scenario alone")
        return False
    DATA.mkdir(exist_ok=True)
    end = (start - timedelta(minutes=10)).astimezone(IST)          # e.g. 2026-10-09T00:30:00+05:30, as in §12.1
    cmd = [sys.executable, "-m", "ml.generator.run", *generator_args(),
           "--end", end.isoformat(), "--out", str(BACKGROUND), "--labels", str(BACKGROUND_LABELS)]
    say("[run] " + " ".join(cmd[1:]))
    subprocess.run(cmd, cwd=ROOT, check=True)
    return True


def reset_demo(store, password: str | None = None, say=print, generate: bool = True) -> dict:
    t0 = time.monotonic()
    password = password or os.environ.get("DEMO_PASSWORD")
    if not password:
        raise RuntimeError("DEMO_PASSWORD is not set")
    summary: dict = {}

    seeding.truncate_runtime()
    if hasattr(store, "clear_caches"):
        store.clear_caches()                                     # reliability was reseeded behind the store's back
    seeding.seed_users(password)
    say("[ok] 1. runtime tables truncated; reliability and users reseeded")

    start = scenario_start()
    summary["start"] = start.isoformat()
    say(f"[ok] 2. START = {start.astimezone(IST).isoformat()}")

    pipeline = make_pipeline(store)
    pipeline.startup()
    if generate and generate_background(start, say) and BACKGROUND.exists():
        rep = loader.load_file(BACKGROUND, BACKGROUND_LABELS, store, pipeline)
        summary["background"] = rep.line()
        say(f"[ok] 3-4. background loaded: {rep.line()}")
    else:
        summary["background"] = None

    rep = loader.load_preload("midnight_ato", start, store, pipeline)
    summary["preload"] = rep.line()
    summary["seeds"] = rep.seeds
    say(f"[ok] 5. midnight_ato preload: {rep.line()}; seeds marked: {len(rep.seeds)}")

    n = seeding.seed_factors_for_all_customers(start)
    summary["factors"] = n
    say(f"[ok] 6. MFA factors seeded: {n}")

    summary["seconds"] = round(time.monotonic() - t0, 2)
    say(f"[done] reset in {summary['seconds']}s - restart the API worker (or use POST /v1/demo/reset) so Pipeline.startup() rebuilds memory")
    return summary
