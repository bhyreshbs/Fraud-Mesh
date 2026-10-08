"""Seed the three demo users (PRD §4) with DEMO_PASSWORD from the environment. Idempotent (upsert).

Usage: python scripts/seed_users.py      (called by scripts/reset_demo.sh)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sqlalchemy import text  # noqa: E402

import scripts._env  # noqa: E402, F401  (loads .env before settings are read)
from api.db import session  # noqa: E402
from api.security import hash_password  # noqa: E402

USERS = [("usr_analyst", "analyst@fraudmesh.local", "analyst"),
         ("usr_lead", "lead@fraudmesh.local", "lead"),
         ("usr_admin", "admin@fraudmesh.local", "admin")]


def seed_users(password: str) -> None:
    with session.transaction() as c:
        for user_id, email, role in USERS:
            c.execute(text("INSERT INTO users (user_id, email, pw_hash, role, queues) VALUES (:u, :e, :h, :r, ARRAY['default']) "
                           "ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email, pw_hash = EXCLUDED.pw_hash, "
                           "role = EXCLUDED.role"),
                      {"u": user_id, "e": email, "h": hash_password(password), "r": role})


def main() -> int:
    password = os.getenv("DEMO_PASSWORD")
    if not password:
        print("DEMO_PASSWORD is not set (run scripts/make_env.py or export it)")
        return 1
    seed_users(password)
    print("seeded:", ", ".join(e for _, e, _ in USERS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
