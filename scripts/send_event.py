"""Manual ingestion check (PRD §14.4 "Sender -> /v1/events"): signed login -> 202, tampered body -> 401, same id -> 409.

Usage: python scripts/send_event.py [--api http://localhost:8000]
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402

import scripts._env  # noqa: E402, F401
from engine.common.ids import new_id  # noqa: E402
from scripts.sign import sign  # noqa: E402

IST = timezone(timedelta(hours=5, minutes=30))


def main() -> int:
    api = sys.argv[sys.argv.index("--api") + 1] if "--api" in sys.argv else "http://localhost:8000"
    env = {"event_id": new_id("evt"), "event_type": "login", "source": "demo-bank-web",
           "occurred_at": datetime.now(IST).isoformat(), "schema_version": "1.0",
           "subject": {"customer_ref": "C-1042", "account_ref": "A-88213"},
           "context": {"ip": "185.220.101.7", "device_id": "fp_attacker_01", "asn": "AS64500 HostCo"},
           "payload": {"result": "success", "auth_method": "password+otp"}}
    body = json.dumps(env).encode()
    ok = True
    with httpx.Client(base_url=api, timeout=10) as c:
        checks = [
            ("signed event", c.post("/v1/events", content=body, headers=sign("demo-bank-web", body)), 202),
            ("tampered body", c.post("/v1/events", content=body.replace(b"success", b"failure"), headers=sign("demo-bank-web", body)), 401),
            ("repeated event_id", c.post("/v1/events", content=body, headers=sign("demo-bank-web", body)), 409),
        ]
        for name, r, want in checks:
            good = r.status_code == want
            ok &= good
            print(f"[{'ok' if good else 'FAIL'}] {name}: {r.status_code} {r.text}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
