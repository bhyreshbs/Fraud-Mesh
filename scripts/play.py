"""Play a scenario into a running API (PRD §15.5 task 1): signed Envelopes to POST /v1/events and StepUpActions through
/v1/demo/step-up/* (the OTP is read from the demo SMS inbox for channel "app").

Usage:
  python scripts/play.py midnight_ato [--speed 8] [--start now|2026-10-09T00:39:00+05:30] [--only login] [--preload-only]
                         [--api http://localhost:8000]
The scenario is an id (midnight_ato | mule_fanin | benign_odd) or a path to a scenario YAML.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402

import scripts._env  # noqa: E402, F401
from api.autopilot import RunState, play  # noqa: E402
from api.scenario_source import SOURCE  # noqa: E402
from engine.common.ids import new_id  # noqa: E402
from scripts.sign import sign  # noqa: E402

IST = timezone(timedelta(hours=5, minutes=30))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario")
    ap.add_argument("--speed", type=float, default=8.0)
    ap.add_argument("--start", default="now", help="'now' (default) or an ISO datetime with offset")
    ap.add_argument("--only", default=None, help="play only this event_type (skips step-up actions)")
    ap.add_argument("--preload-only", action="store_true", help="post only the scenario's preload events")
    ap.add_argument("--api", default="http://localhost:8000")
    a = ap.parse_args()
    start = datetime.now(IST) if a.start == "now" else datetime.fromisoformat(a.start)
    st = RunState(run_id=new_id("run"), scenario=a.scenario, speed=a.speed)
    print(f"playing {a.scenario} (scenario source: {SOURCE}) at speed {a.speed}, start {start.isoformat()} -> {a.api}")

    async def run() -> None:
        async with httpx.AsyncClient(base_url=a.api, timeout=30) as client:
            task = asyncio.create_task(play(client, a.scenario, start, a.speed, sign, st, only=a.only, preload_only=a.preload_only))
            shown = 0
            while not task.done():
                await asyncio.sleep(0.3)
                for line in st.log[shown:]:
                    print(line)
                shown = len(st.log)
            await task
            for line in st.log[shown:]:
                print(line)

    asyncio.run(run())
    return 0 if st.status == "done" else 1


if __name__ == "__main__":
    sys.exit(main())
