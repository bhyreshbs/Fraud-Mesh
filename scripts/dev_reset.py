"""Clean slate for manual UI testing (dev only; D1-P5's scripts/reset_demo.sh replaces it for the real demo).

Truncates every runtime table, reseeds detector reliability, the three users, the demo customers' MFA factors and,
with --fixture-case, the golden fixture cases. Restart the API afterwards (its in-memory SMS inbox / pipeline state).
Usage: python scripts/dev_reset.py [--fixture-case]
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sqlalchemy import text  # noqa: E402

import scripts._env  # noqa: E402, F401
from api.db.session import admin_engine  # noqa: E402
from scripts.seed_demo_factors import seed_demo_factors  # noqa: E402
from scripts.seed_fixture_case import seed_fixture_case  # noqa: E402
from scripts.seed_users import seed_users  # noqa: E402

RUNTIME = ["audit_log", "step_up_challenges", "mfa_factors", "users", "labels", "replays", "feedback", "decisions",
           "evidence", "case_entities", "cases", "edges", "entities", "payment_outcomes", "events"]
RELIABILITY = "('txn',17,3), ('behaviour',6,4), ('auth',7,3), ('kyc',6,4), ('cyber',5,5), ('netsec',5,5), ('graph',8,2)"


def main() -> int:
    with admin_engine().begin() as c:                       # owner role: the app role cannot truncate audit_log
        c.execute(text("TRUNCATE " + ", ".join(RUNTIME) + " RESTART IDENTITY CASCADE"))
        c.execute(text("DELETE FROM detector_reliability"))
        c.execute(text(f"INSERT INTO detector_reliability (detector, alpha, beta) VALUES {RELIABILITY}"))
    seed_users(os.environ["DEMO_PASSWORD"])
    print("users, reliability reset; factors:", seed_demo_factors())
    if "--fixture-case" in sys.argv:
        print("fixture cases:", len(seed_fixture_case()))
    print("now restart the API")
    return 0


if __name__ == "__main__":
    sys.exit(main())
