"""Benchmark (PRD §16.6): report.json validates as BenchmarkReport; the evaluation is sound on a small run."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from benchmark.run import build_store, evaluate
from engine.contracts import BenchmarkReport
from engine.detectors.models import load_manifest

ROOT = Path(__file__).resolve().parents[2]
END = datetime.fromisoformat("2026-10-09T00:30:00+05:30")


@pytest.fixture(scope="module")
def small():
    store, info = build_store(seed=7, days=14, customers=300, attacks=2, end=END)
    return evaluate(store, seed=7, days=14)


def test_committed_report_validates_and_matches_the_prd_run():
    report = BenchmarkReport.model_validate_json((ROOT / "benchmark" / "report.json").read_text())
    assert (report.seed, report.days) == (7, 14)
    assert set(report.families) == {"ato", "mule_fanin", "structuring"}
    assert all(m.instances == 30 for m in report.families.values())
    assert all(0 <= m.caught_fused <= m.instances and 0 <= m.caught_siloed <= m.instances for m in report.families.values())
    txn = next(a for a in load_manifest()["artifacts"] if a["file"] == "txn_v1.joblib")
    assert (report.txn_pr_auc, report.txn_roc_auc, report.txn_ece) == (txn["pr_auc"], txn["roc_auc"], txn["ece"])
    assert 0 <= report.false_positive_rate <= 1 and 0 <= report.false_declines_rate <= 1 and report.alert_compression >= 1
    details = json.loads((ROOT / "benchmark" / "report_details.json").read_text())
    for fam, m in report.families.items():
        d = details["families"][fam]
        assert (d["caught_fused"], d["caught_siloed"]) == (m.caught_fused, m.caught_siloed)
        assert d["caught_fused_at_or_before_last_event"] >= m.caught_fused


def test_small_run_counts_every_instance(small):
    report, details = small
    BenchmarkReport.model_validate_json(report.model_dump_json())
    assert {f: m.instances for f, m in report.families.items()} == {"ato": 2, "mule_fanin": 2, "structuring": 2}
    assert report.benign_customers > 250 and report.benign_flagged_high == 0
    assert details["families"]["mule_fanin"]["cases"] == 2                  # one case per attack


def test_small_run_mule_and_structuring_are_stopped(small):
    _, details = small
    assert details["families"]["mule_fanin"]["caught_fused"] == 2
    assert details["families"]["structuring"]["caught_fused_at_or_before_last_event"] == 2
    assert details["families"]["structuring"]["money_protected_at_or_before_last_event_paise"] > 0


def test_alert_compression_definition(small):
    report, details = small
    assert report.alert_compression == pytest.approx(details["alerts_p_ge_0_05"] / details["cases_with_alerts"], abs=1e-4)
