"""Read queries for the API routes that are not part of the Store protocol (PRD §9.3–§9.5)."""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import text

from api.db import session
from engine.contracts import BenchmarkReport, Case

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


def payment_outcome(event_id: str) -> str | None:
    with session.transaction() as c:
        return c.execute(text("SELECT outcome FROM payment_outcomes WHERE event_id = :e"), {"e": event_id}).scalar()


def save_feedback(case_id: str, verdict: str, analyst: str, note: str | None, result_json: str) -> None:
    with session.transaction() as c:
        c.execute(text("INSERT INTO feedback (case_id, verdict, analyst, note, data) VALUES (:c, :v, :a, :n, CAST(:d AS jsonb))"),
                  {"c": case_id, "v": verdict, "a": analyst, "n": note, "d": result_json})


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
