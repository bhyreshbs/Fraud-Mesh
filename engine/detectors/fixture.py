"""FixtureDetector (PRD §16.2): replays fixed evidence instead of running models.

Each fixture item fires on the event that falls in the same minute as the item's ts and whose type the item's
detector handles (§10.4). demo_evidence.json carries the §12.4 table times (HH:MM), while the scenario spaces
same-minute steps 10 s apart (§12.2), so matching is per minute, not per second. The emitted Evidence keeps the item's detector, family, stage, p,
reliability, reasons, technique and amount, and takes a fresh evidence_id, the event's event_id and ts, and the
event's entity tokens (so the joiner sees the same entities the real detectors would).
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from engine.common.ids import new_id
from engine.contracts import Evidence, StoredEvent
from engine.detectors.base import DETECTOR_HANDLES
from engine.graph.store import EntityGraph

ALL_EVENT_TYPES = frozenset({"login", "mfa_change", "mfa_challenge", "sim_signal", "kyc_result", "profile_change",
                             "payee_added", "transaction", "cloud_audit", "network_ids_alert", "step_up_result"})
DEMO_EVIDENCE = Path(__file__).resolve().parents[2] / "fixtures" / "engine" / "demo_evidence.json"


def _minute(ts: datetime) -> datetime:
    return ts.astimezone(UTC).replace(second=0, microsecond=0)


class FixtureDetector:
    id = "fixture"
    handles = ALL_EVENT_TYPES

    def __init__(self, items: list[Evidence], use_event_entities: bool = True) -> None:
        self.items = list(items)
        self.use_event_entities = use_event_entities

    @classmethod
    def from_file(cls, path: str | Path = DEMO_EVIDENCE, **kw) -> FixtureDetector:
        return cls([Evidence.model_validate(x) for x in json.loads(Path(path).read_text(encoding="utf-8"))], **kw)

    def score(self, event: StoredEvent, feats: dict[str, Any], graph: EntityGraph,
              rel: dict[str, tuple[float, float]]) -> list[Evidence]:
        out = []
        for item in self.items:
            if _minute(item.ts) != _minute(event.occurred_at) or event.event_type not in DETECTOR_HANDLES[item.detector]:
                continue
            entities = list(event.entity_tokens) if self.use_event_entities else list(item.entities)
            out.append(item.model_copy(deep=True, update={
                "evidence_id": new_id("ev"), "event_id": event.event_id, "ts": event.occurred_at,
                "entities": entities, "contribution": 0.0}))
        return out
