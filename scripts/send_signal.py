"""Send the two Midnight ATO signals that do not come from the bank app, signed like their real sources (PRD §12.2):

  ids    network-ids  network_ids_alert: credential stuffing from 185.220.101.7 (scenario step at_min 0)
  cloud  cloud-audit  cloud_audit: support console raises C-1042's transfer limit from 185.220.101.7 (at_min 19)

Usage: python scripts/send_signal.py ids|cloud [--api http://localhost:8000]
(D1-P5's play.py and Suricata adapter replace this for the autopilot.)
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
from scripts.tls import httpx_kwargs  # noqa: E402

SIGNALS = {
    "ids": ("network-ids", "network_ids_alert", {"src_ip": "185.220.101.7", "dest_ip": "10.0.1.20", "dest_port": 443,
            "signature_id": 9000001, "signature": "FM LOCAL credential stuffing against /api/login",
            "category": "Attempted User Privilege Gain", "severity": 2}),
    "cloud": ("cloud-audit", "cloud_audit", {"actor_type": "support_console", "actor_identity": "svc-support-07",
              "action": "UpdateTransferLimit", "target_customer": "C-1042", "src_ip": "185.220.101.7", "result": "success"}),
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in SIGNALS:
        print(__doc__)
        return 2
    api = sys.argv[sys.argv.index("--api") + 1] if "--api" in sys.argv else "http://localhost:8000"
    source, event_type, payload = SIGNALS[sys.argv[1]]
    env = {"event_id": new_id("evt"), "event_type": event_type, "source": source,
           "occurred_at": datetime.now(timezone(timedelta(hours=5, minutes=30))).isoformat(), "payload": payload}
    body = json.dumps(env).encode()
    r = httpx.post(api + "/v1/events", content=body, headers=sign(source, body), timeout=10, **httpx_kwargs(source))
    print(f"{event_type} from {source}: {r.status_code} {r.text}")
    return 0 if r.status_code == 202 else 1


if __name__ == "__main__":
    sys.exit(main())
