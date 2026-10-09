"""Load the fixture cases (fixtures/api/*.json, built from the PRD §12.4 golden values) into Postgres through PgStore,
so the API routes and the console have a known case without running the engine (tests/api `seeded` fixture, UI work).

Writes: one StoredEvent per golden evidence item, the Midnight ATO case with its evidence and decisions, the
transaction's 'blocked' payment outcome, and the extra queue rows from cases_list.json (summary-level cases).
Idempotent. Usage: python scripts/seed_fixture_case.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sqlalchemy import text  # noqa: E402

import scripts._env  # noqa: E402, F401
from api.db import session  # noqa: E402
from api.store_pg import PgStore  # noqa: E402
from engine.contracts import Case, Decision, Evidence, StageHit, StoredEvent  # noqa: E402

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "api"
EVENT_TYPE = {"netsec": "network_ids_alert", "behaviour": "login", "kyc": "kyc_result", "cyber": "cloud_audit",
              "graph": "payee_added", "txn": "transaction"}
SOURCE = {"network_ids_alert": "network-ids", "cloud_audit": "cloud-audit"}


def _load(name: str):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def _event_for(ev: Evidence) -> StoredEvent:
    et = EVENT_TYPE.get(ev.detector) or ("mfa_change" if ev.reasons[0].code.startswith("MFA") else "step_up_result")
    cust = next((t for t in ev.entities if t.startswith("cust:")), None)
    ip = next((t for t in ev.entities if t.startswith("ip:")), None)
    dev = next((t for t in ev.entities if t.startswith("dev:")), None)
    payee = next((t for t in ev.entities if t.startswith("acct:")), None)
    payload = {"amount_paise": ev.amount_paise, "payee_account": payee, "channel": "IMPS"} if et == "transaction" else {}
    return StoredEvent(event_id=ev.event_id, event_type=et, source=SOURCE.get(et, "demo-bank-web"), occurred_at=ev.ts,
                       received_at=ev.ts, customer=cust if SOURCE.get(et) is None else None, ip=ip, device=dev,
                       payload=payload, entity_tokens=sorted(ev.entities))


def seed_fixture_case(store: PgStore | None = None) -> list[str]:
    store = store or PgStore()
    detail = _load("case.json")
    timeline = _load("timeline.json")
    case = Case.model_validate(detail["case"])
    evidence = [Evidence.model_validate(e) for e in timeline["evidence"]]
    decisions = [Decision.model_validate(d) for d in timeline["decisions"]]
    with store.transaction():
        for ev in evidence:
            store.insert_event(_event_for(ev))
        store.save_case(case)
        for ev in evidence:
            store.save_evidence(ev, case.case_id)
        for d in decisions:
            store.save_decision(d)
        txn = next(e for e in evidence if e.detector == "txn")
        with session.transaction() as c:
            c.execute(text("INSERT INTO payment_outcomes (event_id, outcome, case_id) VALUES (:e, 'blocked', :c) "
                           "ON CONFLICT (event_id) DO NOTHING"), {"e": txn.event_id, "c": case.case_id})
        ids = [case.case_id]
        for s in _load("cases_list.json")["items"]:
            if s["case_id"] == case.case_id:
                continue
            stages = {st: StageHit(ts=s["updated_at"], evidence_id="ev_fixture") for st in s["stages_reached"]}
            other = Case(case_id=s["case_id"], anchor_entity=s["anchor_entity"], customer=s["customer"], status=s["status"],
                         band=s["band"], p_attack=s["p_attack"], stages=stages, entities=[s["anchor_entity"]],
                         amount_at_risk_paise=s["amount_at_risk_paise"], payment_state=s["payment_state"],
                         latest_actions=s["latest_actions"], opened_at=s["updated_at"], updated_at=s["updated_at"],
                         last_event_ts=s["updated_at"])
            store.save_case(other)
            ids.append(other.case_id)
    return ids


if __name__ == "__main__":
    print("seeded cases:", ", ".join(seed_fixture_case()))
