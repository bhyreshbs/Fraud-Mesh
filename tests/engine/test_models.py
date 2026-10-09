"""Model artifacts and training (PRD §16.3)."""
from __future__ import annotations

import json
from datetime import datetime

from engine.detectors.models import load_artifact, load_manifest, model_dir, sha256_file
from engine.features.features import TXN_FEATURES
from ml import train_behaviour, train_txn
from ml.generator.run import generate, write_jsonl


def test_manifest_lists_both_artifacts_with_matching_hashes():
    m = {a["file"]: a for a in load_manifest()["artifacts"]}
    assert set(m) == {"txn_v1.joblib", "behaviour_v1.joblib"}
    for f, entry in m.items():
        assert sha256_file(model_dir() / f) == entry["sha256"]
        for k in ("features", "pr_auc", "roc_auc", "ece"):
            assert k in entry
    assert m["txn_v1.joblib"]["features"] == TXN_FEATURES


def test_txn_ece_on_test_days_is_at_most_0_05():
    entry = next(a for a in load_manifest()["artifacts"] if a["file"] == "txn_v1.joblib")
    assert entry["ece"] <= 0.05
    # Trained on several datasets: each domain's held-out (later) test period has its own bar. A PR-AUC pooled over
    # domains with different fraud rates and difficulty is not meaningful on its own.
    per_domain = entry.get("per_domain") or {"synthetic": {"pr_auc": entry["pr_auc"], "ece": entry["ece"],
                                                           "positives": entry["test_positives"], "n": entry["rows"]["test"]}}
    assert per_domain["synthetic"]["pr_auc"] > 0.9                    # the bank events the live engine scores
    for name, m in per_domain.items():
        assert m["ece"] <= 0.05, name
        assert m["pr_auc"] >= 2 * m["positives"] / m["n"], name         # at least twice random on every dataset


def test_artifacts_load_and_verify():
    for f in ("txn_v1.joblib", "behaviour_v1.joblib"):
        obj, sha = load_artifact(f)
        assert obj is not None and len(sha) == 64


def test_training_scripts_run_end_to_end(tmp_path):
    envs, labels = generate(days=14, customers=250, seed=3, end=datetime.fromisoformat("2026-10-09T00:30:00+05:30"),
                            attacks=8)
    data, lab = tmp_path / "train.jsonl", tmp_path / "train_labels.jsonl"
    write_jsonl(str(data), envs)
    write_jsonl(str(lab), labels)
    out = tmp_path / "artifacts"
    t = train_txn.train(str(data), str(lab), str(out))
    b = train_behaviour.train(str(data), str(lab), str(out))
    manifest = json.loads((out / "manifest.json").read_text())
    assert [a["file"] for a in manifest["artifacts"]] == ["behaviour_v1.joblib", "txn_v1.joblib"]
    assert t["rows"]["train"] > 0 and t["rows"]["test"] > 0 and b["rows"]["train"] > 0
    assert load_artifact("txn_v1.joblib", out)[0] is not None
