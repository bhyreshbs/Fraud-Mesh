"""Seed the three demo users (PRD §4) with DEMO_PASSWORD from the environment. Idempotent (upsert).

Usage: python scripts/seed_users.py      (reset_demo.sh / POST /v1/demo/reset do this too)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scripts._env  # noqa: E402, F401  (loads .env before settings are read)
from api.seeding import USERS, seed_users  # noqa: E402, F401  (re-exported for callers)


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
