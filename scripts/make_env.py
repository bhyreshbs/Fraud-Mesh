"""Write .env with fresh secrets (PRD §4). Refuses to overwrite an existing .env unless --force.

Usage: python scripts/make_env.py [--force]
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Opt-in TLS / mTLS / Ed25519 / EdDSA settings (README "Transport security and keys"), written commented out with their
# defaults. deploy/docker-compose.yml sets its own values for the api container.
TRANSPORT_SECURITY_LINES = [
    "# --- transport security and keys (defaults shown; uncomment to change; keys: python scripts/make_certs.py)",
    "# FM_INGEST_AUTH=any                        # hmac | ed25519 | any: signature algorithms POST /v1/events accepts",
    "# FM_SIGN_ALG=hmac                          # senders (scripts/sign.py): ed25519 signs with FM_SIGNING_KEY_DIR/<source>.key",
    "# FM_SIGNING_KEY_DIR=data/keys              # Ed25519 private keys (senders, and the API's own server-side signing)",
    "# FM_SIGNING_PUBLIC_KEY_DIR=data/keys       # Ed25519 public keys the API verifies with (<source>.pub)",
    "# FM_JWT_ALG=HS256                          # HS256 (JWT_SECRET) | EdDSA (keys below)",
    "# FM_JWT_PRIVATE_KEY=data/keys/jwt.key",
    "# FM_JWT_PUBLIC_KEY=data/keys/jwt.pub",
    "# FM_REQUIRE_CLIENT_CERT=0                  # 1 only behind deploy/nginx-proxy.conf (trusts its X-Client-Cert-* headers)",
    "# FM_TLS=0                                  # 1: Secure refresh cookie (served over https)",
    "# FM_TLS_CA=data/certs/ca.crt               # senders: trust the local CA for https://localhost:8000",
    "# FM_TLS_CERT_DIR=data/certs                # senders: mTLS client certs <source>.crt / <source>.key",
]


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
        *TRANSPORT_SECURITY_LINES,
    ]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {target}\nseed-user password (DEMO_PASSWORD): {demo_password}")
    print("transport security / key settings were added as comments with their defaults; keys: python scripts/make_certs.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
