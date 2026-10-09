"""Clean slate for manual UI testing (dev only). For the real demo use scripts/reset_demo.sh or POST /v1/demo/reset.

Truncates every runtime table, reseeds reliability, the three users and the demo customers' MFA factors and, with
--fixture-case, the golden fixture cases. Restart the API afterwards (in-memory SMS inbox / pipeline state).
Usage: python scripts/dev_reset.py [--fixture-case]
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scripts._env  # noqa: E402, F401
from api.seeding import seed_demo_factors, seed_users, truncate_runtime  # noqa: E402
from scripts.seed_fixture_case import seed_fixture_case  # noqa: E402


def main() -> int:
    truncate_runtime()
    seed_users(os.environ["DEMO_PASSWORD"])
    print("users, reliability reset; factors:", seed_demo_factors())
    if "--fixture-case" in sys.argv:
        print("fixture cases:", len(seed_fixture_case()))
    print("now restart the API")
    return 0


if __name__ == "__main__":
    sys.exit(main())
