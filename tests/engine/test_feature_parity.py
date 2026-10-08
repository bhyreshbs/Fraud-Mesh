"""PRD §16.3: the training path and the live path produce identical feature vectors for 200 events."""
from __future__ import annotations

from datetime import datetime

import pytest

from engine.common.tokenize import to_stored_event
from engine.features.features import FEATURE_NAMES, iter_feature_rows
from engine.pipeline import Pipeline
from engine.store_memory import MemoryStore
from ml.generator.run import generate

N = 200


class Recorder:
    """A detector that records the features the Pipeline hands it and emits nothing."""
    id = "recorder"
    handles = frozenset({"login", "mfa_change", "mfa_challenge", "sim_signal", "kyc_result", "profile_change",
                         "payee_added", "transaction", "cloud_audit", "network_ids_alert", "step_up_result"})

    def __init__(self) -> None:
        self.seen: dict[str, dict[str, float]] = {}

    def score(self, event, feats, graph, rel):
        self.seen[event.event_id] = dict(feats)
        return []


@pytest.fixture(scope="module")
def events():
    envs, labels = generate(days=4, customers=80, seed=11, end=datetime.fromisoformat("2026-10-09T00:30:00+05:30"),
                            attacks=1)
    evs = [to_stored_event(e, e.occurred_at) for e in envs]
    first_attack = next(i for i, lb in enumerate(labels) if lb.is_attack)
    start = max(0, min(first_attack - N // 2, len(evs) - 2 * N))
    window = evs[start:start + 2 * N]
    assert len(window) == 2 * N
    assert any(lb.is_attack for lb in labels[start:start + N])             # attack events are in the first 200
    return window


def training_vectors(evs):
    return {ev.event_id: f for ev, f in iter_feature_rows(evs)}


def test_live_pipeline_matches_training_for_200_events(events):
    evs = events[:N]
    rec = Recorder()
    store = MemoryStore()
    pipe = Pipeline(store, detectors=[rec])
    pipe.startup()
    for ev in evs:
        store.insert_event(ev)
        pipe.process(ev)
    train = training_vectors(evs)
    assert len(rec.seen) == N
    for ev in evs:
        assert list(rec.seen[ev.event_id]) == FEATURE_NAMES
        assert rec.seen[ev.event_id] == train[ev.event_id], ev.event_id


def test_startup_replay_gives_the_same_vectors(events):
    """Pipeline.startup rebuilds the windows from stored events; the next 200 vectors still match training."""
    history, live = events[:N], events[N:2 * N]
    store = MemoryStore()
    for ev in history:
        store.insert_event(ev)
    rec = Recorder()
    pipe = Pipeline(store, detectors=[rec])
    pipe.startup()
    for ev in live:
        store.insert_event(ev)
        pipe.process(ev)
    train = training_vectors(history + live)
    assert all(rec.seen[ev.event_id] == train[ev.event_id] for ev in live)


def test_vectors_vary(events):
    rows = list(training_vectors(events[:N]).values())
    for name in ("log_amount", "amount_to_median_30d", "hour_deviation", "past_logins_30d"):
        assert len({r[name] for r in rows}) > 1, name
