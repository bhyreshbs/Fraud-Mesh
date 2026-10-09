"""v3 phase 15: engine latency. Times every Pipeline.process call over the seed-7 generator stream (the benchmark's
traffic: 14 days, 2,000 customers, 30 attacks per family) and reports p50 / p95 / p99 / max per event and per event
type, plus throughput. Optionally profiles the run (--profile) to find where the time goes.

This measures the ENGINE only (MemoryStore, no database, no HTTP, no queue). End-to-end decision latency through the
API (ingest -> queue -> worker -> payment outcome) is measured by scripts/perf.py against a running stack.
Timing code lives here, never in engine/.

Usage:
    python -m benchmark.perf_pipeline                       # writes benchmark/perf_pipeline.json
    python -m benchmark.perf_pipeline --customers 400 --profile --no-write
"""
from __future__ import annotations

import argparse
import cProfile
import io
import json
import platform
import pstats
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from engine.common.tokenize import to_stored_event
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from ml.generator.run import DEFAULT_END, generate

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "benchmark" / "perf_pipeline.json"


def pct(xs: list[float], q: float) -> float:
    s = sorted(xs)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))] if s else 0.0


def summary(ms: list[float]) -> dict:
    return {"n": len(ms), "p50_ms": round(pct(ms, 0.50), 3), "p95_ms": round(pct(ms, 0.95), 3),
            "p99_ms": round(pct(ms, 0.99), 3), "max_ms": round(max(ms), 3) if ms else 0.0,
            "mean_ms": round(sum(ms) / len(ms), 3) if ms else 0.0}


def run(seed: int, days: int, customers: int, attacks: int, end: str, profile: bool) -> tuple[dict, str | None]:
    envelopes, labels = generate(days=days, customers=customers, seed=seed, end=datetime.fromisoformat(end), attacks=attacks)
    events = [to_stored_event(e, e.occurred_at) for e in envelopes]
    store = MemoryStore()
    store.save_labels(labels)
    pipe = Pipeline(store)
    pipe.startup()
    per_type: dict[str, list[float]] = defaultdict(list)
    all_ms: list[float] = []
    prof = cProfile.Profile() if profile else None
    t0 = time.perf_counter()
    if prof:
        prof.enable()
    for ev in events:
        store.insert_event(ev)
        s = time.perf_counter()
        pipe.process(ev)
        ms = (time.perf_counter() - s) * 1000
        all_ms.append(ms)
        per_type[ev.event_type].append(ms)
    if prof:
        prof.disable()
    wall = time.perf_counter() - t0
    # the second half of the stream: the graph, windows and cases are warm (closest to a long-running process)
    half = all_ms[len(all_ms) // 2:]
    report = {
        "run": {"seed": seed, "days": days, "customers": customers, "attacks_per_family": attacks, "end": end,
                "events": len(events), "python": platform.python_version(), "machine": platform.machine(),
                "processor": platform.processor() or None},
        "all": summary(all_ms),
        "second_half": summary(half),
        "by_event_type": {t: summary(v) for t, v in sorted(per_type.items())},
        "throughput_events_per_s": round(len(events) / wall, 1),
        "wall_seconds": round(wall, 1),
        "cases": len(store.list_cases()),
    }
    text = None
    if prof:
        buf = io.StringIO()
        pstats.Stats(prof, stream=buf).sort_stats("cumulative").print_stats(30)
        text = buf.getvalue()
    return report, text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmark.perf_pipeline")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--customers", type=int, default=2000)
    ap.add_argument("--attacks", type=int, default=30)
    ap.add_argument("--end", default=DEFAULT_END)
    ap.add_argument("--profile", action="store_true", help="print the 30 most expensive calls (cumulative)")
    ap.add_argument("--no-write", action="store_true")
    a = ap.parse_args(argv)
    report, prof = run(a.seed, a.days, a.customers, a.attacks, a.end, a.profile)
    print(json.dumps({k: report[k] for k in ("all", "second_half", "throughput_events_per_s", "wall_seconds")}, indent=1))
    for t, s in report["by_event_type"].items():
        print(f"  {t:15s} n={s['n']:6d} p50={s['p50_ms']:7.3f} p95={s['p95_ms']:7.3f} p99={s['p99_ms']:7.3f} ms")
    if prof:
        print(prof)
    if not a.no_write:
        OUT.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {OUT.relative_to(ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
