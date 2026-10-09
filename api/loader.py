"""In-process loading (PRD §12.3 steps 4–5, §15.5 task 2), shared by scripts/load.py and POST /v1/demo/reset.

load_envelopes() inserts events + labels in bulk, then runs Pipeline.process on each event in occurred_at order (no HTTP,
no worker, no signing: --direct mode). load_preload() plays a scenario's preload and marks its fraud seeds.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from api import scenario_source
from engine.common.tokenize import to_stored_event
from engine.contracts import Envelope, Label

log = logging.getLogger("fraudmesh.loader")
CHUNK = 2000


@dataclass
class LoadReport:
    events_read: int = 0
    events_inserted: int = 0
    labels: int = 0
    processed: int = 0
    case_updates: int = 0
    errors: int = 0
    seconds: float = 0.0
    seeds: list[str] = field(default_factory=list)

    def line(self) -> str:
        return (f"read {self.events_read} | inserted {self.events_inserted} | labels {self.labels} | processed {self.processed} "
                f"| case updates {self.case_updates} | errors {self.errors} | {self.seconds:.1f}s")


def read_jsonl(path: str | Path) -> Iterable[dict]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def load_envelopes(envelopes: list[Envelope], labels: list[Label], store, pipeline, report: LoadReport | None = None) -> LoadReport:
    rep = report or LoadReport()
    t0 = time.monotonic()
    now = datetime.now(UTC)
    stored = sorted((to_stored_event(e, now) for e in envelopes), key=lambda s: (s.occurred_at, s.event_id))
    rep.events_read += len(stored)
    for i in range(0, len(stored), CHUNK):
        rep.events_inserted += store.insert_events_bulk(stored[i:i + CHUNK])
    if labels:
        store.save_labels(labels)
        rep.labels += len(labels)
    for ev in stored:
        try:
            rep.case_updates += len(pipeline.process(ev))
        except Exception:                                              # same rule as the worker: log, audit, continue
            rep.errors += 1
            log.exception("engine error on %s", ev.event_id)
            store.append_audit("engine", "ENGINE_ERROR", ev.event_id, {"phase": "load"})
        rep.processed += 1
    rep.seconds += time.monotonic() - t0
    return rep


def load_file(events_path: str | Path, labels_path: str | Path | None, store, pipeline) -> LoadReport:
    envs = [Envelope.model_validate(d) for d in read_jsonl(events_path)]
    labels = [Label.model_validate(d) for d in read_jsonl(labels_path)] if labels_path and Path(labels_path).exists() else []
    return load_envelopes(envs, labels, store, pipeline)


def load_preload(scenario: str, start: datetime, store, pipeline) -> LoadReport:
    """Play the scenario's preload (labelled benign) through the pipeline, then mark its fraud seeds (PRD §12.3 step 5)."""
    sc = scenario_source.load_scenario(str(scenario_source.resolve(scenario)))
    envs = scenario_source.preload_envelopes(sc, start)
    labels = [Label(event_id=e.event_id, scenario=sc.id, is_attack=False, attack_id=None) for e in envs]
    rep = load_envelopes(envs, labels, store, pipeline)
    rep.seeds = scenario_source.seed_tokens(sc)
    if rep.seeds:
        pipeline.set_seeds(rep.seeds)
    return rep
