"""End-to-end smoke test against a running API (PRD §14.5). Resets the demo, plays the scenario through the real HTTP
routes (signed events + step-ups via the demo routes), listens on the WebSocket, then checks the result.

Usage:
  python scripts/smoke_test.py --scenario midnight_ato --mode api [--speed 60] [--api http://localhost:8000] [--no-reset]
  python scripts/smoke_test.py --all          # midnight_ato, benign_odd and mule_fanin, each after a reset
Needs DEMO_PASSWORD (from .env) for the seed users. Exit code 0 only if every check passes.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import httpx  # noqa: E402
import websockets  # noqa: E402

import scripts._env  # noqa: E402, F401
from api.autopilot import RunState, play  # noqa: E402
from engine.common.ids import new_id  # noqa: E402
from engine.common.tokenize import tok  # noqa: E402
from engine.contracts import ACTION_SEVERITY, BAND_ORDER, SEVERITY_HOLD  # noqa: E402
from scripts.sign import sign  # noqa: E402

IST = timezone(timedelta(hours=5, minutes=30))


class Checks:
    def __init__(self) -> None:
        self.failed = 0

    def __call__(self, label: str, ok: bool, detail: str = "") -> bool:
        print(f"  [{'ok' if ok else 'FAIL'}] {label}{(' - ' + detail) if detail and not ok else ''}", flush=True)
        self.failed += not ok
        return ok


async def _login(c: httpx.AsyncClient, email: str, password: str) -> dict[str, str]:
    r = await c.post("/v1/auth/login", json={"email": email, "password": password})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _listen(api: str, token: str, inbox: list[dict], stop: asyncio.Event) -> None:
    async with websockets.connect(api.replace("http", "ws", 1) + "/v1/stream") as ws:
        await ws.send(json.dumps({"token": token}))
        while not stop.is_set():
            try:
                inbox.append(json.loads(await asyncio.wait_for(ws.recv(), 0.5)))
            except TimeoutError:
                continue


async def _settle(c: httpx.AsyncClient, h: dict, txn_ids: list[str], timeout: float = 30) -> list[dict]:
    """Wait until every transaction has a payment outcome and the case list stops changing."""
    deadline, last = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        outcomes = [(await c.get(f"/v1/demo/payment-status/{t}")).json()["outcome"] for t in txn_ids]
        items = (await c.get("/v1/cases?limit=200", headers=h)).json()["items"]
        snap = json.dumps(items, sort_keys=True)
        if "pending" not in outcomes and snap == last:
            return items
        last = snap
        await asyncio.sleep(1)
    return (await c.get("/v1/cases?limit=200", headers=h)).json()["items"]


async def run_one(scenario: str, api: str, speed: float, reset: bool, tokens: dict[str, dict[str, str]]) -> int:
    print(f"--scenario {scenario} --mode api", flush=True)
    ok = Checks()
    admin, analyst, lead = tokens["admin"], tokens["analyst"], tokens["lead"]
    async with httpx.AsyncClient(base_url=api, timeout=60) as c:
        if reset:
            r = await c.post("/v1/demo/reset", headers=admin)
            if not ok("demo reset", r.status_code == 200, r.text):
                return ok.failed
        inbox, stop = [], asyncio.Event()
        listener = asyncio.create_task(_listen(api, analyst["Authorization"][7:], inbox, stop))
        await asyncio.sleep(0.5)
        st = RunState(run_id=new_id("run"), scenario=scenario, speed=speed)
        await play(c, scenario, datetime.now(IST), speed, sign, st)
        n_posted = sum(len(v) for v in st.posted.values())
        ok(f"{n_posted} events accepted (202) + {len(st.step_ups)} step-up action(s) handled via the demo routes",
           st.status == "done" and st.accepted == st.steps_total - len(st.step_ups) and n_posted == st.accepted, "\n".join(st.log[-8:]))
        txns = st.posted.get("transaction", [])
        items = await _settle(c, analyst, txns)
        await asyncio.sleep(1)
        stop.set()
        await asyncio.gather(listener, return_exceptions=True)

        cases = {}
        for it in items:
            tl = (await c.get(f"/v1/cases/{it['case_id']}/timeline", headers=analyst)).json()
            cases[it["case_id"]] = (it, tl)
        posted = {e for ids in st.posted.values() for e in ids}

        if scenario == "midnight_ato":
            holders = {cid for cid, (_, tl) in cases.items() if any(e["event_id"] in posted for e in tl["evidence"])}
            cid = next(iter(holders), None)
            item, tl = cases.get(cid, (None, None))
            ok("exactly 1 case contains all scenario evidence; anchor is Priya's cust token",
               len(holders) == 1 and item["anchor_entity"] == tok("cust", "C-1042"), f"cases holding scenario evidence: {len(holders)}")
            if item is None:
                return ok.failed
            ok("final band == CRITICAL", item["band"] == "CRITICAL", item["band"])
            dec = sorted(tl["decisions"], key=lambda d: d["created_at"])
            first_hold = next((d for d in dec if max(ACTION_SEVERITY[a] for a in d["actions"]) >= SEVERITY_HOLD), None)
            txn_ev = next((e for e in tl["evidence"] if e["event_id"] in txns), None)
            ok("first decision with severity >= HOLD precedes the transaction evidence",
               bool(first_hold and txn_ev and first_hold["created_at"] < txn_ev["ts"]),
               f"first hold {first_hold and first_hold['created_at']} vs transaction {txn_ev and txn_ev['ts']}")
            outcome = (await c.get(f"/v1/demo/payment-status/{txns[0]}")).json()["outcome"] if txns else None
            ok("payment outcome of the transaction == blocked", outcome == "blocked", str(outcome))
            ex = (await c.get(f"/v1/cases/{cid}/explanation", headers=analyst)).json()
            case = (await c.get(f"/v1/cases/{cid}", headers=analyst)).json()["case"]
            diff = abs(ex["parts"][-1]["running_log_odds"] - case["log_odds"])
            ok("explanation parts sum to case.log_odds (|diff| < 1e-6)", diff < 1e-6, f"diff {diff:.3g}")
            kyc = (await c.post(f"/v1/cases/{cid}/replay", json={"ablate": ["kyc"], "mode": "fused"}, headers=analyst)).json()
            ok("replay ablate=[kyc]: eip.ts >= baseline_eip.ts",
               bool(kyc["baseline_eip"]) and (kyc["eip"] is None or kyc["eip"]["ts"] >= kyc["baseline_eip"]["ts"]), json.dumps(kyc.get("eip")))
            silo = (await c.post(f"/v1/cases/{cid}/replay", json={"ablate": [], "mode": "siloed"}, headers=analyst)).json()
            txn_strong = any(e["detector"] == "txn" and e["p"] >= 0.5 for e in tl["evidence"])
            blocks = any("BLOCK_PENDING_PAYMENTS" in pt["actions"] for pt in silo["timeline"])
            ok("replay mode=siloed: no BLOCK_PENDING_PAYMENTS unless a txn evidence has p >= 0.5", txn_strong or not blocks)
            n_ws = sum(1 for m in inbox if m.get("type") == "case_update" and m["case"]["case_id"] == cid)
            ok("WebSocket received >= 1 case_update for the case", n_ws >= 1, f"{n_ws} messages")
        elif scenario == "benign_odd":
            priya = tok("cust", "C-1042")
            bands = [d["band"] for it, tl in cases.values() if it["customer"] == priya for d in tl["decisions"]] + \
                    [it["band"] for it in items if it["customer"] == priya]
            top = max(bands, key=BAND_ORDER.index) if bands else "LOW"
            ok("max band <= MEDIUM", BAND_ORDER.index(top) <= BAND_ORDER.index("MEDIUM"), top)
        elif scenario == "mule_fanin":
            outcomes = [(await c.get(f"/v1/demo/payment-status/{t}")).json()["outcome"] for t in txns]
            ok(f"all {len(txns)} transfers processed (payment outcome recorded)", len(txns) == 13 and "pending" not in outcomes, str(outcomes))
            mule = tok("cust", "C-MULE-02")
            mule_cases = [it for it in items if it["customer"] == mule or it["anchor_entity"] == mule]
            print(f"  [info] mule-side cases: {[(m['band'], round(m['p_attack'], 3)) for m in mule_cases] or 'none'} "
                  "(fan-in detection is Dev 2's graph/txn detectors)", flush=True)
        v = (await c.get("/v1/audit/verify", headers=lead)).json()
        ok("audit verify ok", v["ok"] is True, json.dumps(v))
    return ok.failed


def main() -> int:
    import os
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", default="midnight_ato", choices=["midnight_ato", "benign_odd", "mule_fanin"])
    ap.add_argument("--mode", default="api", choices=["api"])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--speed", type=float, default=60)
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--no-reset", action="store_true")
    a = ap.parse_args()
    password = os.environ.get("DEMO_PASSWORD")
    if not password:
        print("DEMO_PASSWORD is not set")
        return 2
    scenarios = ["midnight_ato", "benign_odd", "mule_fanin"] if a.all else [a.scenario]

    async def run_all() -> int:
        async with httpx.AsyncClient(base_url=a.api, timeout=60) as c:     # one login per user (login is 5/min per IP)
            tokens = {r: await _login(c, f"{r}@fraudmesh.local", password) for r in ("admin", "analyst", "lead")}
        failed = 0
        for s in scenarios:
            failed += await run_one(s, a.api, a.speed, not a.no_reset, tokens)
        return failed

    failed = asyncio.run(run_all())
    print("SMOKE OK" if not failed else f"SMOKE FAILED ({failed} check(s))")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
