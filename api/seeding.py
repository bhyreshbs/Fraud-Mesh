"""Seed data (PRD §8 "Seed data", §12.3): the three users, detector reliability, MFA factors.

Used by /v1/demo/reset and by scripts/ (seed_users.py, seed_demo_factors.py, reset_demo.py).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from api.db import session
from api.demo_identities import REGISTERED_DEVICE, REGISTERED_PHONE
from api.security import hash_password
from api.store_pg import RELIABILITY_SEED as RELIABILITY
from engine.common.tokenize import tok

USERS = [("usr_analyst", "analyst@fraudmesh.local", "analyst"),
         ("usr_lead", "lead@fraudmesh.local", "lead"),
         ("usr_admin", "admin@fraudmesh.local", "admin")]
RUNTIME_TABLES = ["audit_log", "step_up_challenges", "mfa_factors", "users", "labels", "replays", "feedback", "decisions",
                  "evidence", "case_entities", "cases", "edges", "entities", "payment_outcomes", "events"]


def seed_users(password: str) -> None:
    pw_hash = hash_password(password)
    with session.transaction() as c:
        for user_id, email, role in USERS:
            c.execute(text("INSERT INTO users (user_id, email, pw_hash, role, queues) VALUES (:u, :e, :h, :r, ARRAY['default']) "
                           "ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email, pw_hash = EXCLUDED.pw_hash, "
                           "role = EXCLUDED.role"),
                      {"u": user_id, "e": email, "h": pw_hash, "r": role})


def truncate_runtime() -> None:
    """Every runtime table + reliability reseed. Owner role: the app role cannot truncate audit_log (0002_roles)."""
    from api.db.session import admin_engine
    with admin_engine().begin() as c:
        c.execute(text("TRUNCATE " + ", ".join(RUNTIME_TABLES) + " RESTART IDENTITY CASCADE"))
        c.execute(text("DELETE FROM detector_reliability"))
        for d, (a, b) in RELIABILITY.items():
            c.execute(text("INSERT INTO detector_reliability (detector, alpha, beta) VALUES (:d, :a, :b)"), {"d": d, "a": a, "b": b})


def seed_demo_factors(now: datetime | None = None) -> int:
    """sms + device_push factors enrolled 90 days ago for the named demo customers (Priya's push on fp_priya_phone)."""
    enrolled = (now or datetime.now(UTC)) - timedelta(days=90)
    n = 0
    with session.transaction() as c:
        for ref, device in REGISTERED_DEVICE.items():
            cust = tok("cust", ref)
            slug = ref.lower().replace("-", "_")
            phone = REGISTERED_PHONE.get(ref, "+91 90000 00000")
            for fid, kind, phone_tok, dev_tok in ((f"fac_sms_{slug}", "sms", tok("phone", phone), None),
                                                  (f"fac_push_{slug}", "device_push", None, tok("dev", device))):
                n += c.execute(text(
                    "INSERT INTO mfa_factors (factor_id, customer, kind, enrolled_at, phone_token, device_token) "
                    "VALUES (:id, :cu, :k, :t, :p, :d) ON CONFLICT (factor_id) DO UPDATE SET enrolled_at = EXCLUDED.enrolled_at, "
                    "changed_at = NULL, phone_token = EXCLUDED.phone_token, device_token = EXCLUDED.device_token, active = true"),
                    {"id": fid, "cu": cust, "k": kind, "t": enrolled, "p": phone_tok, "d": dev_tok}).rowcount
    return n


def seed_factors_for_all_customers(scenario_start: datetime) -> int:
    """PRD §8: for every customer in events, one sms and one device_push factor enrolled 90 days before the scenario
    start. The push factor sits on the customer's most-used device. Named demo customers keep their registered ones."""
    enrolled = scenario_start - timedelta(days=90)
    named = sorted(tok("cust", ref) for ref in REGISTERED_DEVICE)        # seeded with their registered factors below
    with session.transaction() as c:
        n = c.execute(text("""
            WITH dev AS (
              SELECT customer, data->>'device' AS device,
                     row_number() OVER (PARTITION BY customer ORDER BY count(*) DESC, data->>'device') AS rk
              FROM events WHERE customer IS NOT NULL AND data->>'device' IS NOT NULL GROUP BY customer, data->>'device')
            INSERT INTO mfa_factors (factor_id, customer, kind, enrolled_at, device_token)
            SELECT 'fac_' || k.kind || '_' || substr(md5(c.customer), 1, 16), c.customer, k.kind, :t,
                   CASE WHEN k.kind = 'device_push' THEN d.device END
            FROM (SELECT DISTINCT customer FROM events WHERE customer IS NOT NULL AND NOT (customer = ANY(:named))) c
            CROSS JOIN (VALUES ('sms'), ('device_push')) AS k(kind)
            LEFT JOIN dev d ON d.customer = c.customer AND d.rk = 1
            ON CONFLICT (factor_id) DO NOTHING"""), {"t": enrolled, "named": named}).rowcount
    return n + seed_demo_factors(scenario_start)
