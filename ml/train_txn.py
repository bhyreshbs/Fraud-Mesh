"""Train the txn model (PRD §16.3): LightGBM on TXN_FEATURES, 300 trees, learning rate 0.05, 31 leaves,
scale_pos_weight, early stopping on average precision (calibration days), isotonic calibration.

    python -m ml.train_txn --data data/train.jsonl --labels data/train_labels.jsonl --out ml/artifacts
Training data: python -m ml.generator.run --seed 1 --attacks 40 --out data/train.jsonl --labels data/train_labels.jsonl
"""
from __future__ import annotations

import argparse
import sys

import lightgbm as lgb
import numpy as np
from sklearn.isotonic import IsotonicRegression

from engine.features.features import TXN_FEATURES
from ml.train_common import feature_rows, load_events, metrics, save_artifact, split

ARTIFACT = "txn_v1.joblib"
SEED = 7


def train(data: str, labels: str, out: str) -> dict:
    events, lab = load_events(data, labels)
    rows = feature_rows(events, lab, lambda ev, f: ev.event_type == "transaction")
    X = np.array([[f[k] for k in TXN_FEATURES] for f in rows.feats])
    y = np.array([int(lb.is_attack) for lb in rows.labels])
    tr, ca, te = split(rows.day)
    pos, neg = int(y[tr].sum()), int((1 - y[tr]).sum())
    params = {"objective": "binary", "learning_rate": 0.05, "num_leaves": 31, "scale_pos_weight": neg / max(pos, 1),
              "metric": "average_precision", "seed": SEED, "deterministic": True, "force_row_wise": True,
              "num_threads": 1, "verbose": -1}
    booster = lgb.train(params, lgb.Dataset(X[tr], y[tr], feature_name=TXN_FEATURES), num_boost_round=300,
                        valid_sets=[lgb.Dataset(X[ca], y[ca], feature_name=TXN_FEATURES)],
                        callbacks=[lgb.early_stopping(30, verbose=False)])
    iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(booster.predict(X[ca]), y[ca])
    p_test = np.clip(iso.predict(booster.predict(X[te])), 1e-4, 1 - 1e-4)
    m = metrics(y[te], p_test)
    entry = save_artifact({"booster": booster, "calibrator": iso, "features": TXN_FEATURES}, out, ARTIFACT, {
        "model": "lightgbm+isotonic", "features": TXN_FEATURES, "pr_auc": m["pr_auc"], "roc_auc": m["roc_auc"],
        "ece": m["ece"], "best_iteration": booster.best_iteration, "split": "days 1-9 train, 10-11 calibrate, 12-14 test",
        "rows": {"train": int(tr.sum()), "calibrate": int(ca.sum()), "test": int(te.sum())},
        "test_positives": m["positives"]})
    return entry


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ml.train_txn")
    ap.add_argument("--data", default="data/train.jsonl")
    ap.add_argument("--labels", default="data/train_labels.jsonl")
    ap.add_argument("--out", default="ml/artifacts")
    a = ap.parse_args(argv)
    e = train(a.data, a.labels, a.out)
    print(f"{e['file']}: PR-AUC {e['pr_auc']}, ROC-AUC {e['roc_auc']}, ECE {e['ece']}, trees {e['best_iteration']}, "
          f"sha256 {e['sha256'][:12]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
