"""Synthetic data generator CLI (PRD §12.1).

    python -m ml.generator.run --days 14 --customers 2000 --seed 7 \\
      --end 2026-10-09T00:30:00+05:30 --attacks 0 \\
      --out data/background.jsonl --labels data/background_labels.jsonl

Writes one raw Envelope per line (source "simulator"), ordered by occurred_at then event_id and ending before
--end, plus one Label per line in the same order. The same arguments always produce byte-identical files.
Training data uses --seed 1 --attacks 40; the demo background uses seed 7 with --attacks 0.
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from engine.contracts import Envelope, Label
from ml.generator.attacks import inject_attacks
from ml.generator.background import Sink, background
from ml.generator.population import NetworkAllocator, build_population

DEFAULT_END = "2026-10-09T00:30:00+05:30"


def generate(days: int, customers: int, seed: int, end: datetime, attacks: int = 0) -> tuple[list[Envelope], list[Label]]:
    """Envelopes and their Labels, both ordered by (occurred_at, event_id). Deterministic for fixed arguments.

    Separate random streams drive the population, the normal days, the attacks and the event IDs, so adding
    attacks leaves every background event unchanged.
    """
    if days < 1:
        raise ValueError("--days must be at least 1")
    if attacks < 0:
        raise ValueError("--attacks must be >= 0")
    if end.tzinfo is None:
        raise ValueError("--end must carry a UTC offset, e.g. 2026-10-09T00:30:00+05:30")
    tz = end.tzinfo
    start = end - timedelta(days=days)
    alloc = NetworkAllocator()
    population = build_population(customers, random.Random(f"{seed}:population"), alloc)
    sink = Sink(random.Random(f"{seed}:event-ids"), start, end)
    background(sink, population, tz, random.Random(f"{seed}:background"))
    inject_attacks(sink, attacks, population, alloc, tz, random.Random(f"{seed}:attacks"))
    label_of = {lb.event_id: lb for lb in sink.labels}
    envelopes = sorted(sink.envelopes, key=lambda e: (e.occurred_at, e.event_id))
    return envelopes, [label_of[e.event_id] for e in envelopes]


def write_jsonl(path: str, rows: list) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(row.model_dump_json())
            f.write("\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ml.generator.run", description=__doc__.split("\n\n")[0])
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--customers", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--end", default=DEFAULT_END, help="exclusive end of the window, ISO 8601 with offset")
    ap.add_argument("--attacks", type=int, default=0, help="instances of EACH family: ato, mule_fanin, structuring")
    ap.add_argument("--out", required=True, help="JSONL of Envelopes")
    ap.add_argument("--labels", required=True, help="JSONL of Labels")
    args = ap.parse_args(argv)
    try:
        end = datetime.fromisoformat(args.end)
        t0 = time.perf_counter()
        envelopes, labels = generate(args.days, args.customers, args.seed, end, args.attacks)
        write_jsonl(args.out, envelopes)
        write_jsonl(args.labels, labels)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    n_attack = sum(lb.is_attack for lb in labels)
    print(f"wrote {len(envelopes)} events ({n_attack} attack events, {args.attacks} instance(s) per family) "
          f"to {args.out} and {args.labels} in {time.perf_counter() - t0:.1f}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
