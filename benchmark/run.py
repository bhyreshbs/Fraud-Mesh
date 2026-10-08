"""Benchmark (PRD §16.6): seed 7 with 30 attacks per family, run in-process through Pipeline + MemoryStore (direct
mode), then fused-vs-siloed recall per family, benign false-positive rate, false declines, alert compression, lead
time and the txn model metrics from ml/artifacts/manifest.json.

    python -m benchmark.run                   # writes benchmark/report.json (+ report_details.json)

Definitions (PRD §10.9, §12.4):
  caught_fused    a case holding any of the attack's events reached severity >= HOLD (fused replay, default
                  thresholds) before the attack's last event
  caught_siloed   the same with each evidence item judged alone (siloed mode: only a txn item with p >= 0.5 acts)
  median lead     over caught attacks: first S6 evidence (else the attack's last event) − earliest intervention
  false positives benign customers (no attack label) with any case reaching HIGH or above ÷ benign customers
  false declines  benign transactions made while one of the customer's cases held or blocked payments ÷ all of them
  compression     evidence items with p >= 0.05 ÷ cases holding at least one (§12.4: 6 alerts → 1 case = 6:1)
report_details.json adds the "at or before the attack's last event" view: a hold decided on an attack's final
transfer still stops that transfer (its payment_outcome is held/blocked), which §10.9's strict "before" does not count.
The models were trained on seed 1 (ml/train_*.py), so seed 7 is held-out data.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from engine.common.tokenize import to_stored_event
from engine.contracts import SEVERITY_HOLD, BandThresholds, BenchmarkReport, FamilyMetrics
from engine.detectors.models import load_manifest
from engine.fusion.fusion import ordered
from engine.pipeline import Pipeline
from engine.replay.replay import fused_timeline, siloed_timeline
from engine.replay.simulate import simulate_policy
from engine.store_memory import MemoryStore
from ml.generator.attacks import FAMILIES
from ml.generator.run import DEFAULT_END, generate

ROOT = Path(__file__).resolve().parents[1]
ALERT_P = 0.05


def build_store(seed: int, days: int, customers: int, attacks: int, end: datetime) -> tuple[MemoryStore, dict]:
    envelopes, labels = generate(days=days, customers=customers, seed=seed, end=end, attacks=attacks)
    store = MemoryStore()
    store.save_labels(labels)
    pipe = Pipeline(store)
    pipe.startup()
    t0 = time.perf_counter()
    for env in envelopes:
        ev = to_stored_event(env, env.occurred_at)
        store.insert_event(ev)
        pipe.process(ev)
    return store, {"events": len(envelopes), "pipeline_seconds": round(time.perf_counter() - t0, 1)}


def evaluate(store: MemoryStore, seed: int, days: int) -> tuple[BenchmarkReport, dict]:
    labels = store.get_labels()
    cases = store.list_cases()
    evidence = {c.case_id: ordered(store.list_evidence(c.case_id)) for c in cases}
    fused = {cid: fused_timeline(evs) for cid, evs in evidence.items()}
    cases_of_event: dict[str, set[str]] = defaultdict(set)
    evidence_of_event: dict[str, list] = defaultdict(list)
    for cid, evs in evidence.items():
        for e in evs:
            cases_of_event[e.event_id].add(cid)
            evidence_of_event[e.event_id].append(e)

    attacks: dict[str, dict] = {}
    for lb in labels.values():
        if lb.is_attack and lb.attack_id:
            a = attacks.setdefault(lb.attack_id, {"family": lb.scenario, "events": []})
            a["events"].append(lb.event_id)
    ts = {ev.event_id: ev.occurred_at for ev in store.iter_events() if ev.event_id in labels and labels[ev.event_id].is_attack}

    per_family: dict[str, dict] = {f: {"instances": 0, "fused": 0, "siloed": 0, "fused_at_or_before": 0,
                                       "siloed_at_or_before": 0, "leads": [], "money": 0, "money_at_or_before": 0,
                                       "cases": set()} for f in FAMILIES}
    for a in attacks.values():
        fam = per_family.setdefault(a["family"], {"instances": 0, "fused": 0, "siloed": 0, "fused_at_or_before": 0,
                                                  "siloed_at_or_before": 0, "leads": [], "money": 0,
                                                  "money_at_or_before": 0, "cases": set()})
        fam["instances"] += 1
        last = max(ts[e] for e in a["events"])
        cids = set().union(*(cases_of_event.get(e, set()) for e in a["events"]))
        fam["cases"] |= cids
        eips = sorted((fused[c].eip.ts, c) for c in cids if fused[c].eip is not None)
        own = [x for e in a["events"] for x in evidence_of_event.get(e, [])]
        silo = sorted(p.ts for p in siloed_timeline(own).points if p.severity >= SEVERITY_HOLD)
        fam["fused_at_or_before"] += bool(eips and eips[0][0] <= last)
        if eips and eips[0][0] <= last:            # a hold decided on the last transfer still stops that transfer
            s6_all = [e for c in cids for e in evidence[c] if e.stage == "S6_MONETIZATION"]
            fam["money_at_or_before"] += sum(e.amount_paise or 0 for e in s6_all if e.ts >= eips[0][0])
        fam["siloed_at_or_before"] += bool(silo and silo[0] <= last)
        fam["siloed"] += bool(silo and silo[0] < last)
        if eips and eips[0][0] < last:
            fam["fused"] += 1
            s6 = [e for c in cids for e in evidence[c] if e.stage == "S6_MONETIZATION"]
            first_s6 = min((e.ts for e in s6), default=last)
            fam["leads"].append(int((first_s6 - eips[0][0]).total_seconds()))
            fam["money"] += sum(e.amount_paise or 0 for e in s6 if e.ts >= eips[0][0])

    sim = simulate_policy(store, BandThresholds())
    alerting = {cid: sum(e.p >= ALERT_P for e in evs) for cid, evs in evidence.items()}
    alert_cases = [n for n in alerting.values() if n]
    manifest = {a["file"]: a for a in load_manifest()["artifacts"]}
    txn = manifest.get("txn_v1.joblib", {})

    report = BenchmarkReport(
        seed=seed, days=days,
        families={f: FamilyMetrics(instances=v["instances"], caught_fused=v["fused"], caught_siloed=v["siloed"],
                                   median_lead_time_s=int(statistics.median(v["leads"])) if v["leads"] else None)
                  for f, v in per_family.items()},
        benign_customers=sim.benign_customers_total, benign_flagged_high=sim.benign_customers_flagged,
        false_positive_rate=round(sim.benign_customers_flagged / sim.benign_customers_total, 6) if sim.benign_customers_total else 0.0,
        false_declines_rate=round(sim.legit_payments_stopped / sim.legit_payments_total, 6) if sim.legit_payments_total else 0.0,
        alert_compression=round(sum(alert_cases) / len(alert_cases), 4) if alert_cases else 0.0,
        txn_pr_auc=float(txn.get("pr_auc") or 0.0), txn_roc_auc=float(txn.get("roc_auc") or 0.0), txn_ece=float(txn.get("ece") or 0.0))

    details = {
        "definitions": __doc__.split("Definitions (PRD §10.9, §12.4):")[1].strip(),
        "families": {f: {"instances": v["instances"], "caught_fused": v["fused"], "caught_siloed": v["siloed"],
                         "caught_fused_at_or_before_last_event": v["fused_at_or_before"],
                         "caught_siloed_at_or_before_last_event": v["siloed_at_or_before"],
                         "recall_fused": round(v["fused"] / v["instances"], 4) if v["instances"] else None,
                         "recall_siloed": round(v["siloed"] / v["instances"], 4) if v["instances"] else None,
                         "cases": len(v["cases"]), "money_protected_paise": v["money"],
                         "money_protected_at_or_before_last_event_paise": v["money_at_or_before"],
                         "lead_times_s": sorted(v["leads"])} for f, v in per_family.items()},
        "cases_total": len(cases), "alerts_p_ge_0_05": sum(alert_cases), "cases_with_alerts": len(alert_cases),
        "legit_payments_total": sim.legit_payments_total, "legit_payments_stopped": sim.legit_payments_stopped,
        "money_protected_paise": sim.money_protected_paise, "txn_model": {k: txn.get(k) for k in ("sha256", "pr_auc", "roc_auc", "ece")},
        "note": "Synthetic data (ml/generator); models trained on seed 1, evaluated on seed 7. Not a real-world estimate.",
    }
    return report, details


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmark.run")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--customers", type=int, default=2000)
    ap.add_argument("--attacks", type=int, default=30)
    ap.add_argument("--end", default=DEFAULT_END)
    ap.add_argument("--out", default=str(ROOT / "benchmark" / "report.json"))
    a = ap.parse_args(argv)
    t0 = time.perf_counter()
    store, info = build_store(a.seed, a.days, a.customers, a.attacks, datetime.fromisoformat(a.end))
    report, details = evaluate(store, a.seed, a.days)
    details.update(info, total_seconds=round(time.perf_counter() - t0, 1),
                   run={"seed": a.seed, "days": a.days, "customers": a.customers, "attacks_per_family": a.attacks, "end": a.end})
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report.model_dump(mode="json"), indent=1) + "\n", encoding="utf-8")
    out.with_name(out.stem + "_details.json").write_text(json.dumps(details, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    fams = ", ".join(f"{f} {m.caught_fused}/{m.instances} fused vs {m.caught_siloed} siloed" for f, m in report.families.items())
    print(f"{info['events']} events in {details['total_seconds']}s — {fams}; FPR {report.false_positive_rate:.4f}, "
          f"false declines {report.false_declines_rate:.4f}, compression {report.alert_compression}:1 → {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
