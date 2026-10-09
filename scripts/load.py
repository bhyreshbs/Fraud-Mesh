"""In-process loader (PRD §15.5 task 2, §12.3 steps 4–5). Talks to Postgres directly and runs Pipeline.process itself
(no HTTP, no signing). The pipeline is engine.pipeline.Pipeline.

Usage:
  python scripts/load.py --file data/background.jsonl --labels data/background_labels.jsonl --direct
  python scripts/load.py --scenario scenarios/midnight_ato.yaml --preload-only --start 2026-10-09T00:39:00+05:30
Restart the API afterwards so its Pipeline.startup() rebuilds memory from the database.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scripts._env  # noqa: E402, F401
from api import loader  # noqa: E402
from api.pipeline_factory import make_pipeline  # noqa: E402
from api.store_pg import PgStore  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file")
    ap.add_argument("--labels")
    ap.add_argument("--direct", action="store_true", help="insert + process in-process (the only mode; kept for PRD parity)")
    ap.add_argument("--scenario")
    ap.add_argument("--preload-only", action="store_true")
    ap.add_argument("--start", help="scenario start, ISO datetime with offset (default: the scenario's default_start)")
    a = ap.parse_args()
    if bool(a.file) == bool(a.scenario):
        ap.error("use exactly one of --file or --scenario")

    store = PgStore()
    pipeline = make_pipeline(store)
    pipeline.startup()
    if a.file:
        rep = loader.load_file(a.file, a.labels, store, pipeline)
    else:
        if not a.preload_only:
            ap.error("--scenario supports --preload-only (use scripts/play.py to play the steps)")
        from api.scenario_source import load_scenario, resolve
        start = datetime.fromisoformat(a.start) if a.start else load_scenario(str(resolve(a.scenario))).default_start
        rep = loader.load_preload(a.scenario, start, store, pipeline)
        print(f"seeds marked: {len(rep.seeds)}")
    print(rep.line())
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
