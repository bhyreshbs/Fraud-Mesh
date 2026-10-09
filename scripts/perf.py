"""Load test (PRD §15.7 task 4): 50 events/s for 2 minutes through HTTP, then p50/p95 of
  - ingest latency   : POST /v1/events round trip (signed, 202)
  - decision latency : events.received_at -> the worker's payment_outcomes row (written right after Pipeline.process
                       for every transaction), i.e. queue wait + engine + side effects. Target p95 < 150 ms (PRD §1).

Traffic (--traffic):
  generator (default when Dev 2's ml/generator exists): realistic customer activity — a fresh slice of the PRD §12.1
      generator (2,000 customers, seed 101 so ids never collide with the demo background), posted in time order.
  synthetic: 400 customers paying only 25 shared payees. A stress case, NOT realistic: under the §10.6 joiner the first
      ~20 payers of each payee (hub threshold) chain into one ever-growing case, so per-event work grows over the run.

Usage: python scripts/perf.py [--rate 50] [--seconds 120] [--traffic generator|synthetic] [--api http://localhost:8000]
Run it against a reset demo (it adds rate x seconds events).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402
from sqlalchemy import text  # noqa: E402

import scripts._env  # noqa: E402, F401
from api.db.session import admin_engine  # noqa: E402
from engine.common.ids import new_id  # noqa: E402
from scripts.sign import sign  # noqa: E402
from scripts.tls import SourceRoutedAsyncClient  # noqa: E402

IST = timezone(timedelta(hours=5, minutes=30))


def pct(xs: list[float], q: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))]


def make_event(rng: random.Random) -> dict:
    n = rng.randrange(400)
    subject = {"customer_ref": f"C-PERF-{n:03d}", "account_ref": f"A-PERF-{n:03d}"}
    context = {"ip": f"10.{n // 200}.{n % 200}.7", "device_id": f"fp_perf_{n:03d}", "asn": "AS9829 BSNL", "city": "Mysuru",
               "lat": 12.30, "lon": 76.64}
    if rng.random() < 0.8:
        etype, payload = "transaction", {"amount_paise": rng.randrange(50_000, 2_000_000), "payee_account": f"A-SHOP-{rng.randrange(25):02d}",
                                         "channel": rng.choice(["UPI", "IMPS"])}
    else:
        etype, payload = "login", {"result": "success", "auth_method": "password+otp"}
    return {"event_id": new_id("evt"), "event_type": etype, "source": "simulator", "occurred_at": datetime.now(IST).isoformat(),
            "subject": subject, "context": context, "payload": payload}


ROOT = Path(__file__).resolve().parent.parent


def generator_events(n: int) -> list[dict]:
    """n consecutive envelopes from a fresh generator run (PRD §12.1 CLI), in occurred_at order."""
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out, labels = Path(tmp) / "ev.jsonl", Path(tmp) / "lb.jsonl"
        end = datetime.now(IST).replace(microsecond=0).isoformat()
        subprocess.run([sys.executable, "-m", "ml.generator.run", "--days", "3", "--customers", "2000", "--seed", "101",
                        "--attacks", "0", "--end", end, "--out", str(out), "--labels", str(labels)],
                       cwd=ROOT, check=True, capture_output=True)
        events = [json.loads(line) for line in open(out, encoding="utf-8") if line.strip()]
    events.sort(key=lambda e: (e["occurred_at"], e["event_id"]))
    if len(events) < n:
        raise SystemExit(f"generator produced {len(events)} events, need {n}")
    return events[-n:]                                          # the most recent slice: warm customer histories


async def main_async(api: str, rate: float, seconds: float, traffic: str = "generator") -> int:
    rng = random.Random(7)
    total = int(rate * seconds)
    if traffic == "generator" and not (ROOT / "ml" / "generator" / "run.py").exists():
        print("ml/generator not available: falling back to --traffic synthetic")
        traffic = "synthetic"
    pregenerated = generator_events(total) if traffic == "generator" else None
    print(f"traffic: {traffic}" + (f" ({sum(1 for e in pregenerated if e['event_type'] == 'transaction')} transactions)" if pregenerated else ""))
    ingest_ms: list[float] = []
    codes: dict[int, int] = {}
    txn_ids: list[str] = []
    async with SourceRoutedAsyncClient(api, timeout=30, limits=httpx.Limits(max_connections=64)) as c:   # mTLS: cert per source
        async def send(ev: dict) -> None:
            body = json.dumps(ev).encode()
            t0 = time.perf_counter()
            r = await c.post("/v1/events", content=body, headers=sign(ev["source"], body))
            ingest_ms.append((time.perf_counter() - t0) * 1000)
            codes[r.status_code] = codes.get(r.status_code, 0) + 1
            if r.status_code == 202 and ev["event_type"] == "transaction":
                txn_ids.append(ev["event_id"])

        print(f"sending {total} events at {rate:g}/s for {seconds:g}s to {api} ...", flush=True)
        start, tasks = time.perf_counter(), []
        for i in range(total):
            delay = start + i / rate - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
            tasks.append(asyncio.create_task(send(pregenerated[i] if pregenerated else make_event(rng))))
            if i and i % int(rate * 10) == 0:
                print(f"  {i} sent, {len(ingest_ms)} answered, p95 ingest so far {pct(ingest_ms, 0.95):.1f} ms", flush=True)
        await asyncio.gather(*tasks)
        sent_for = time.perf_counter() - start

    print("waiting for the worker to finish ...", flush=True)
    decision_ms: list[float] = []
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        with admin_engine().connect() as conn:
            rows = conn.execute(text(
                "SELECT EXTRACT(EPOCH FROM (po.set_at - e.received_at)) * 1000 FROM payment_outcomes po "
                "JOIN events e ON e.event_id = po.event_id WHERE po.event_id = ANY(:ids)"), {"ids": txn_ids}).scalars().all()
        if len(rows) >= len(txn_ids):
            decision_ms = [float(x) for x in rows]
            break
        await asyncio.sleep(2)
    else:
        decision_ms = [float(x) for x in rows]

    p95d = pct(decision_ms, 0.95)
    print("\n=== perf report ===")
    print(f"events sent       : {sum(codes.values())} in {sent_for:.1f}s ({sum(codes.values()) / sent_for:.1f}/s); HTTP codes {codes}")
    print(f"ingest  latency   : p50 {pct(ingest_ms, 0.5):6.1f} ms   p95 {pct(ingest_ms, 0.95):6.1f} ms   max {max(ingest_ms):6.1f} ms")
    print(f"decision latency  : p50 {pct(decision_ms, 0.5):6.1f} ms   p95 {p95d:6.1f} ms   max {max(decision_ms or [0]):6.1f} ms"
          f"   ({len(decision_ms)}/{len(txn_ids)} transactions decided)")
    print(f"mean decision     : {statistics.fmean(decision_ms) if decision_ms else float('nan'):.1f} ms")
    achieved = sum(codes.values()) / sent_for
    rate_ok = achieved >= 0.95 * rate                          # a starved client must not pass by sending less load
    ok = p95d < 150 and len(decision_ms) == len(txn_ids) and codes.get(202, 0) == sum(codes.values()) and rate_ok
    print("PERF OK (decision p95 < 150 ms)" if ok else
          "PERF TARGET MISSED (decision p95 must be < 150 ms, every event decided, and >= 95% of the target rate sent)")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rate", type=float, default=50)
    ap.add_argument("--seconds", type=float, default=120)
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--traffic", choices=["generator", "synthetic"], default="generator")
    a = ap.parse_args()
    return asyncio.run(main_async(a.api, a.rate, a.seconds, a.traffic))


if __name__ == "__main__":
    sys.exit(main())
