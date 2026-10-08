"""PRD §12.3 demo reset as a CLI (called by scripts/reset_demo.sh). Same steps as POST /v1/demo/reset.

Usage: python scripts/reset_demo.py [--no-background]
Afterwards restart the API (docker compose -f deploy/docker-compose.yml restart api) so Pipeline.startup() rebuilds
memory - or call POST /v1/demo/reset as admin, which does all of this in-process.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scripts._env  # noqa: E402, F401
from api.demo_reset import reset_demo  # noqa: E402
from api.store_pg import PgStore  # noqa: E402

if __name__ == "__main__":
    summary = reset_demo(PgStore(), generate="--no-background" not in sys.argv)
    sys.exit(0 if summary["seconds"] < 240 else 1)                 # PRD §15.5: under 4 minutes on a laptop
