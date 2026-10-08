"""Write .env with fresh secrets (PRD §4). Refuses to overwrite an existing .env unless --force.

Usage: python scripts/make_env.py [--force]
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    target = ROOT / ".env"
    if target.exists() and "--force" not in sys.argv:
        print(".env already exists (use --force to replace it)")
        return 1
    hx = lambda: secrets.token_hex(32)  # noqa: E731
    hmac_secrets = {s: hx() for s in ("demo-bank-web", "cloud-audit", "network-ids", "simulator")}
    demo_password = "fm-" + secrets.token_urlsafe(9)
    lines = [
        "DATABASE_URL=postgresql+psycopg://fm:fm@localhost:5432/fraudmesh",
        f"HMAC_SECRETS={json.dumps(hmac_secrets, separators=(',', ':'))}",
        f"TOKEN_KEY={hx()}",
        f"JWT_SECRET={hx()}",
        "BASE_RATE=0.01", "BAND_MEDIUM=0.20", "BAND_HIGH=0.50", "BAND_CRITICAL=0.80",
        "MODEL_DIR=ml/artifacts",
        "DEMO_MODE=1",
        "CORS_ORIGINS=http://localhost:5173,http://localhost:5174",
        "LOG_LEVEL=INFO",
        "VITE_API_BASE=http://localhost:8000",
        "# Dev 1 scripts only: password for the three seed users (see docs/CONTRACT_REQUESTS.md)",
        f"DEMO_PASSWORD={demo_password}",
    ]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {target}\nseed-user password (DEMO_PASSWORD): {demo_password}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
