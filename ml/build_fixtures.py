"""The golden Midnight ATO case (PRD §12.4) built from fixtures/engine/demo_evidence.json, and the four engine
example fixtures regenerated from the REAL engine.api outputs on it (PRD §16.5: "the stub fixtures have been
replaced by real outputs").

    python -m ml.build_fixtures            # rewrites fixtures/engine/{explanation,replay,simulation,feedback}_example.json

The case is built with the engine's own joiner-free path: every fixture item (with its fixed evidence_id and the
§12.4 table time) goes through fusion, stages and policy in order, exactly as Pipeline.process would after attach.
The preload's graph edges and seeds are stored too, so explanations can show the seed path.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

from engine.cases.stages import Stages
from engine.common.tokenize import _norm, to_stored_event, tok
from engine.contracts import Case, Evidence, Label, StoredEvent
from engine.fusion.fusion import Fusion
from engine.graph.store import EntityGraph
from engine.policy.policy import Policy
from engine.store_memory import MemoryStore
from ml.scenario import load_scenario, preload_envelopes, seed_tokens

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "engine"
# demo_evidence.json stores entity tokens computed with the default TOKEN_KEY (64 zeros). Tokens depend on the key, so
# the golden case re-tokenizes them with the active key (tests/api sets its own TOKEN_KEY before settings load).
FIXTURE_TOKEN_KEY = "00" * 32
FIXTURE_RAW_ENTITIES = [("cust", "C-1042"), ("acct", "A-88213"), ("ip", "185.220.101.7"), ("dev", "fp_attacker_01"),
                        ("phone", "+91 90000 11111"), ("cid", "svc-support-07"), ("acct", "A-RAVI-778")]
EVENT_TYPE = {"netsec": "network_ids_alert", "behaviour": "login", "kyc": "kyc_result", "cyber": "cloud_audit",
              "graph": "payee_added", "txn": "transaction"}


def _token_with_key(key_hex: str, kind: str, raw: str) -> str:
    """engine.common.tokenize.tok with an explicit key (same normalisation and HMAC-SHA256)."""
    digest = hmac.new(bytes.fromhex(key_hex), f"{kind}:{_norm(kind, raw)}".encode(), hashlib.sha256).digest()
    return f"{kind}:{base64.b32encode(digest).decode().lower()[:16]}"


def rekey() -> dict[str, str]:
    return {_token_with_key(FIXTURE_TOKEN_KEY, k, r): tok(k, r) for k, r in FIXTURE_RAW_ENTITIES}


def golden_evidence() -> list[Evidence]:
    """The 8 §12.4 items, with entity tokens for the active TOKEN_KEY."""
    table = rekey()
    items = [Evidence.model_validate(x) for x in json.loads((FIX / "demo_evidence.json").read_text(encoding="utf-8"))]
    unknown = {t for e in items for t in e.entities if t not in table}
    if unknown:
        raise ValueError(f"demo_evidence.json has tokens not in FIXTURE_RAW_ENTITIES: {sorted(unknown)}")
    return [e.model_copy(update={"entities": sorted(table[t] for t in e.entities)}) for e in items]


def _event_for(ev: Evidence) -> StoredEvent:
    etype = EVENT_TYPE.get(ev.detector, "mfa_change" if ev.reasons[0].code.startswith("MFA") else "step_up_result")
    payload: dict = {"golden": True}
    if etype in ("payee_added", "transaction"):
        payload = {"payee_account": tok("acct", "A-RAVI-778")}
        if etype == "transaction":
            payload.update(amount_paise=ev.amount_paise, channel="IMPS")
    return StoredEvent(event_id=ev.event_id, event_type=etype, source="demo-bank-web", occurred_at=ev.ts, received_at=ev.ts,
                       customer=tok("cust", "C-1042"), payload=payload, entity_tokens=sorted(ev.entities))


def golden_store(extra: list[Evidence] | None = None) -> tuple[MemoryStore, Case]:
    """A MemoryStore holding the golden case (8 items + optional extra ones), its decisions, labels and the graph."""
    store = MemoryStore()
    sc = load_scenario(str(ROOT / "scenarios" / "midnight_ato.yaml"))
    graph = EntityGraph()
    for env in preload_envelopes(sc, sc.default_start):
        sev = to_stored_event(env, env.occurred_at)
        store.insert_event(sev)
        store.upsert_edges(graph.apply(sev))
    store.set_fraud_seeds(seed_tokens(sc))
    items = golden_evidence() + list(extra or [])
    first = items[0]
    case = Case(case_id="case_golden0000000001", anchor_entity=tok("cust", "C-1042"), customer=tok("cust", "C-1042"),
                opened_at=first.ts, updated_at=first.ts, last_event_ts=first.ts)
    store.save_case(case)
    fusion, stages, policy = Fusion(store), Stages(), Policy(store)
    for ev in items:
        event = _event_for(ev)
        store.insert_event(event)
        store.save_labels([Label(event_id=event.event_id, scenario="midnight_ato", is_attack=True, attack_id="atk_midnight_1")])
        case.entities = sorted(set(case.entities) | set(ev.entities))
        case.last_event_ts = case.updated_at = ev.ts
        store.save_case(case)
        store.save_evidence(ev, case.case_id)
        res = fusion.recompute(case)
        ev.contribution = res.contributions[ev.evidence_id]
        stages.update(case, ev)
        policy.decide(case, event, ev)
        store.save_case(case)
    return store, store.get_case(case.case_id)


def write_examples() -> list[Path]:
    from engine import api
    from engine.contracts import BandThresholds
    from engine.pipeline import Pipeline

    store, case = golden_store()
    out = {"explanation_example.json": api.explain_case(store, case.case_id),
           "replay_example.json": api.replay_case(store, case.case_id),
           "simulation_example.json": api.simulate_policy(store, BandThresholds())}
    pipe = Pipeline(store, detectors=[])
    pipe.startup()
    out["feedback_example.json"] = api.apply_feedback(store, pipe, case.case_id, "CONFIRMED_FRAUD", "usr_analyst")
    paths = []
    for name, model in out.items():
        path = FIX / name
        path.write_text(json.dumps(model.model_dump(mode="json"), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        paths.append(path)
    return paths


if __name__ == "__main__":
    for p in write_examples():
        print(f"wrote {p.relative_to(ROOT)}", file=sys.stderr)
    sys.exit(0)
