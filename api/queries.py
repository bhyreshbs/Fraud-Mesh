"""Read queries for the API routes that are not part of the Store protocol (PRD §9.3–§9.5)."""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import text

from api import crypto_box
from api.db import session
from engine.contracts import BenchmarkReport, Case, Label

_BAND_RANK = "CASE band WHEN 'CRITICAL' THEN 3 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 1 ELSE 0 END"
ROOT = Path(__file__).resolve().parent.parent


def list_cases(queues: list[str], status: str | None, band: str | None, limit: int, offset: int) -> tuple[list[Case], str | None]:
    """Cases in the caller's queues, CRITICAL first then p_attack desc. Cursor = opaque offset."""
    where, params = ["queue = ANY(:queues)"], {"queues": queues, "limit": limit + 1, "offset": offset}
    if status:
        where.append("status = :status")
        params["status"] = status
    if band:
        where.append("band = :band")
        params["band"] = band
    sql = (f"SELECT data FROM cases WHERE {' AND '.join(where)} "
           f"ORDER BY {_BAND_RANK} DESC, p_attack DESC, updated_at DESC, case_id LIMIT :limit OFFSET :offset")
    with session.transaction() as c:
        rows = c.execute(text(sql), params).scalars().all()
    more = len(rows) > limit
    return [Case.model_validate(d) for d in rows[:limit]], (f"o{offset + limit}" if more else None)


def case_in_queues(case_id: str, queues: list[str]) -> Case | None:
    with session.transaction() as c:
        data = c.execute(text("SELECT data FROM cases WHERE case_id = :id AND queue = ANY(:q)"),
                         {"id": case_id, "q": queues}).scalar()
    return Case.model_validate(data) if data is not None else None


def labels_for_case(case_id: str) -> dict[str, Label]:
    """Ground-truth labels of the events behind a case's evidence (the Digital Twin's attacker/customer split)."""
    with session.transaction() as c:
        rows = c.execute(text("SELECT DISTINCT l.event_id, l.scenario, l.is_attack, l.attack_id FROM evidence e "
                              "JOIN labels l ON l.event_id = e.event_id WHERE e.case_id = :id"), {"id": case_id}).mappings().all()
    return {r["event_id"]: Label(**r) for r in rows}


def case_ids_in_queues(case_ids: list[str], queues: list[str]) -> set[str]:
    with session.transaction() as c:
        return set(c.execute(text("SELECT case_id FROM cases WHERE case_id = ANY(:ids) AND queue = ANY(:q)"),
                             {"ids": case_ids, "q": queues}).scalars())


def recent_ids_alert(ip_token: str, since) -> bool:
    """A network_ids_alert from this IP token was ingested at or after `since` (any source: sensor or replay)."""
    with session.transaction() as c:
        return c.execute(text("SELECT 1 FROM events WHERE event_type = 'network_ids_alert' AND occurred_at >= :since "
                              "AND entity_tokens @> ARRAY[CAST(:ip AS text)] LIMIT 1"), {"since": since, "ip": ip_token}).first() is not None


def payment_outcome(event_id: str) -> str | None:
    with session.transaction() as c:
        return c.execute(text("SELECT outcome FROM payment_outcomes WHERE event_id = :e"), {"e": event_id}).scalar()


def save_feedback(case_id: str, verdict: str, analyst: str, note: str | None, result_json: str) -> None:
    """With FM_DATA_KEYS set, note is stored AES-256-GCM encrypted, bound to (feedback, note, feedback_id): the row is
    inserted first so its id is known, then the ciphertext is written, in one transaction."""
    encrypt = note is not None and crypto_box.enabled()
    with session.transaction() as c:
        fid = c.execute(text("INSERT INTO feedback (case_id, verdict, analyst, note, data) "
                             "VALUES (:c, :v, :a, :n, CAST(:d AS jsonb)) RETURNING feedback_id"),
                        {"c": case_id, "v": verdict, "a": analyst, "n": None if encrypt else note, "d": result_json}).scalar()
        if encrypt:
            c.execute(text("UPDATE feedback SET note = :n WHERE feedback_id = :id"),
                      {"n": crypto_box.encrypt_text(note, table="feedback", column="note", row_id=str(fid)), "id": fid})


def feedback_notes(case_id: str) -> list[str | None]:
    """Decrypted feedback notes of a case, oldest first (key rotation: any configured kid decrypts)."""
    with session.transaction() as c:
        rows = c.execute(text("SELECT feedback_id, note FROM feedback WHERE case_id = :c ORDER BY feedback_id"),
                         {"c": case_id}).all()
    return [crypto_box.decrypt_text(n, table="feedback", column="note", row_id=str(fid)) if n is not None else None
            for fid, n in rows]


def live_metrics() -> dict:
    """PRD §9.4: alert_compression = evidence (p >= 0.05) in open cases / open cases;
    money_protected = amounts of held/blocked transactions in cases not marked FALSE_POSITIVE."""
    with session.transaction() as c:
        open_cases, critical = c.execute(text(
            "SELECT count(*), count(*) FILTER (WHERE band = 'CRITICAL') FROM cases WHERE status IN ('OPEN','INVESTIGATING')")).one()
        alerts = c.execute(text(
            "SELECT count(*) FROM evidence e JOIN cases c ON c.case_id = e.case_id "
            "WHERE c.status IN ('OPEN','INVESTIGATING') AND (e.data->>'p')::float >= 0.05")).scalar()
        money = c.execute(text(
            "SELECT coalesce(sum((ev.data->'payload'->>'amount_paise')::bigint), 0) FROM payment_outcomes po "
            "JOIN events ev ON ev.event_id = po.event_id LEFT JOIN cases c ON c.case_id = po.case_id "
            "WHERE po.outcome IN ('held','blocked') AND coalesce(c.status, '') <> 'FALSE_POSITIVE'")).scalar()
    return {"cases_open": open_cases, "critical_open": critical, "money_protected_paise": int(money),
            "alert_compression": round(alerts / open_cases, 4) if open_cases else 0.0}


def benchmark_report() -> BenchmarkReport | None:
    """benchmark/report.json is generated and committed by Dev 2 (D2-P6)."""
    path = ROOT / "benchmark" / "report.json"
    try:
        return BenchmarkReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None
