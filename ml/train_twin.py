"""Learn the Digital Twin's stage-transition table from labelled attacks (PRD §12.1 generator, training seed).

    python -m ml.train_twin [--seed 1] [--attacks 40] [--out ml/artifacts]

For every attack and every actor in it (victim session, mule, scammed sender), the attack's events are put in time order,
mapped to kill-chain stages with the detectors' stage mapping, and consecutive repeats are merged. Each change of stage
is one transition; the table keeps its count and the median minutes it took.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from engine.twin.predict import FILE, stage_of
from ml.generator.run import generate


def transitions(seed: int, attacks: int, days: int = 14, customers: int = 2000) -> dict:
    envs, labels = generate(days=days, customers=customers, seed=seed,
                            end=datetime.fromisoformat("2026-10-09T00:30:00+05:30"), attacks=attacks)
    attack_of = {lb.event_id: lb.attack_id for lb in labels if lb.is_attack}
    runs: dict[tuple[str, str], list] = defaultdict(list)
    for e in envs:
        if e.event_id in attack_of:
            who = e.subject.customer_ref or e.payload.get("target_customer") or "-"
            runs[(attack_of[e.event_id], who)].append(e)
    gaps: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for evs in runs.values():
        prev = None                                               # (stage, time)
        for e in sorted(evs, key=lambda x: x.occurred_at):
            stage = stage_of(e.event_type, e.payload)
            if stage is None:
                continue
            if prev is None or stage != prev[0]:
                if prev is not None:
                    gaps[prev[0]][stage].append((e.occurred_at - prev[1]).total_seconds() / 60)
                prev = (stage, e.occurred_at)
    table = {s: {t: {"count": len(v), "median_minutes": round(statistics.median(v), 1)} for t, v in row.items()}
             for s, row in gaps.items()}
    return {"source": f"generator seed {seed}, {attacks} attacks per family", "attacks": attacks * 3,
            "actor_runs": len(runs), "transitions": table}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ml.train_twin")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--attacks", type=int, default=40)
    ap.add_argument("--out", default="ml/artifacts")
    a = ap.parse_args(argv)
    data = transitions(a.seed, a.attacks)
    out = Path(a.out) / FILE
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"{out}: {sum(len(r) for r in data['transitions'].values())} transitions from {data['actor_runs']} attack runs",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
