"""Seed MFA factors for the named demo customers (PRD §8 "Seed data"): one sms and one device_push factor enrolled
90 days before now; Priya's device_push is on fp_priya_phone. Idempotent. reset_demo.sh (D1-P5) also seeds every
generated customer; this script covers the named demo identities only.

Usage: python scripts/seed_demo_factors.py
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sqlalchemy import text  # noqa: E402

import scripts._env  # noqa: E402, F401
from api.db import session  # noqa: E402
from api.demo_identities import REGISTERED_DEVICE, REGISTERED_PHONE  # noqa: E402
from engine.common.tokenize import tok  # noqa: E402


def seed_demo_factors(now: datetime | None = None) -> int:
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


if __name__ == "__main__":
    print("seeded factors:", seed_demo_factors())
