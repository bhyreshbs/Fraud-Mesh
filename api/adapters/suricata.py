"""Suricata EVE adapter (PRD §7.4): one eve.json line with event_type == "alert" -> one network_ids_alert Envelope.

Lines with any other event_type are skipped. No live sensor runs: the demo replays saved lines.

CLI:  python -m api.adapters.suricata <eve.jsonl> --post [--api http://localhost:8000]
      without --post it prints the Envelopes it would send.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime

from engine.common.ids import new_id
from engine.contracts import Envelope


def _parse_ts(ts: str) -> datetime:
    """Suricata writes 2026-10-09T00:39:00.123456+0530 (no colon in the offset); also accept Z / +05:30."""
    ts = ts.strip().replace("Z", "+00:00")
    if len(ts) > 5 and ts[-5] in "+-" and ts[-3] != ":":
        ts = ts[:-2] + ":" + ts[-2:]
    return datetime.fromisoformat(ts)


def eve_to_envelope(line: str) -> Envelope | None:
    d = json.loads(line)
    if d.get("event_type") != "alert":
        return None
    a = d["alert"]
    return Envelope(event_id=new_id("evt"), event_type="network_ids_alert", source="network-ids",
                    occurred_at=_parse_ts(d["timestamp"]),
                    payload={"src_ip": d["src_ip"], "dest_ip": d["dest_ip"], "dest_port": int(d["dest_port"]),
                             "signature_id": int(a["signature_id"]), "signature": a["signature"], "category": a["category"],
                             "severity": min(3, max(1, int(a["severity"])))})


def read_alerts(path: str) -> tuple[list[Envelope], int]:
    """Returns (envelopes, skipped lines): non-alert lines, and alert lines that are malformed or lack a field the
    envelope needs (e.g. ICMP alerts have no dest_port), so one bad line never stops the rest."""
    out, skipped = [], 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                env = eve_to_envelope(line)
            except (ValueError, KeyError, TypeError) as e:     # ValueError covers JSON and pydantic validation errors
                print(f"[skip] malformed EVE line: {type(e).__name__}", file=sys.stderr)
                env = None
            if env is None:
                skipped += 1
            else:
                out.append(env)
    return out, skipped


def main(argv: list[str]) -> int:
    if not argv or argv[0].startswith("-"):
        print(__doc__)
        return 2
    envs, skipped = read_alerts(argv[0])
    print(f"{len(envs)} alert line(s), {skipped} other or malformed line(s) skipped")
    if "--post" not in argv:
        for e in envs:
            print(e.model_dump_json())
        return 0
    import httpx  # CLI only: a sender, signed like every other sender

    import scripts._env  # noqa: F401  (loads .env so HMAC_SECRETS is available)
    from scripts.sign import sign
    from scripts.tls import httpx_kwargs
    api = argv[argv.index("--api") + 1] if "--api" in argv else "http://localhost:8000"
    ok = True
    for e in envs:
        body = e.model_dump_json().encode()
        r = httpx.post(api + "/v1/events", content=body, headers=sign("network-ids", body), timeout=10, **httpx_kwargs("network-ids"))
        print(f"[{r.status_code}] {e.event_id} sid {e.payload['signature_id']} from {e.payload['src_ip']}")
        ok &= r.status_code == 202
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
