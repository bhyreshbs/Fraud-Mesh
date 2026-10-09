"""Train the txn model (PRD §16.3): LightGBM on TXN_FEATURES, 300 trees, learning rate 0.05, 31 leaves,
scale_pos_weight, early stopping on average precision (calibration split), isotonic calibration.

    python -m ml.train_txn --data data/train.jsonl --labels data/train_labels.jsonl --out ml/artifacts \\
        [--ieee <dir with train_transaction.csv>] [--amlsim <AMLSim sample/ dir>] [--cache data/features]
Training data: python -m ml.generator.run --seed 1 --attacks 40 --out data/train.jsonl --labels data/train_labels.jsonl

With --ieee / --amlsim the model is trained on several datasets ("domains"). Every domain is split by time, so the
test part is always a later period than anything the model saw: the synthetic data by day (1-9 train, 10-11
calibrate, 12-14 test), each external dataset by order (first 60% train, next 15% calibrate, last 25% test).
Each domain weighs the same in training and calibration, whatever its size, and the manifest reports the test
metrics per domain as well as over all test rows.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.isotonic import IsotonicRegression

from engine.features.features import TXN_FEATURES
from ml.datasets.common import Domain
from ml.train_common import feature_rows, load_events, metrics, save_artifact, split

ARTIFACT = "txn_v1.joblib"
SEED = 7
SYNTHETIC_SPLIT = "days 1-9 train, 10-11 calibrate, 12-14 test"
EXTERNAL_SPLIT = "by time: first 60% train, next 15% calibrate, last 25% test"


def _synthetic(data: str, labels: str) -> tuple[Domain, tuple[np.ndarray, np.ndarray, np.ndarray]]:
    events, lab = load_events(data, labels)
    rows = feature_rows(events, lab, lambda ev, f: ev.event_type == "transaction")
    X = np.array([[f[k] for k in TXN_FEATURES] for f in rows.feats])
    y = np.array([int(lb.is_attack) for lb in rows.labels])
    ts = np.array([ev.occurred_at.timestamp() for ev in rows.events])
    return Domain("synthetic", X, y, ts), split(rows.day)


def _balanced(parts: list[tuple[np.ndarray, np.ndarray]]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Stack (X, y) parts with weights that give every part the same total weight (mean weight 1)."""
    X, y = np.vstack([p[0] for p in parts]), np.concatenate([p[1] for p in parts])
    total = len(y)
    w = np.concatenate([np.full(len(p[1]), total / (len(parts) * max(len(p[1]), 1))) for p in parts])
    return X, y, w


def train(data: str, labels: str, out: str, extra: list[Domain] | tuple = ()) -> dict:
    synth, synth_split = _synthetic(data, labels)
    domains = [(synth, synth_split, SYNTHETIC_SPLIT)] + [(d, d.split(), EXTERNAL_SPLIT) for d in extra]
    Xtr, ytr, wtr = _balanced([(d.X[tr], d.y[tr]) for d, (tr, _, _), _ in domains])
    Xca, yca, wca = _balanced([(d.X[ca], d.y[ca]) for d, (_, ca, _), _ in domains])
    pos, neg = wtr[ytr == 1].sum(), wtr[ytr == 0].sum()
    params = {"objective": "binary", "learning_rate": 0.05, "num_leaves": 31, "scale_pos_weight": neg / max(pos, 1e-9),
              "metric": "average_precision", "seed": SEED, "deterministic": True, "force_row_wise": True,
              "num_threads": 1, "verbose": -1}
    booster = lgb.train(params, lgb.Dataset(Xtr, ytr, weight=wtr, feature_name=TXN_FEATURES), num_boost_round=300,
                        valid_sets=[lgb.Dataset(Xca, yca, weight=wca, feature_name=TXN_FEATURES)],
                        callbacks=[lgb.early_stopping(30, verbose=False)])
    iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(booster.predict(Xca), yca, sample_weight=wca)

    def scored(d: Domain, mask: np.ndarray) -> np.ndarray:
        return np.clip(iso.predict(booster.predict(d.X[mask])), 1e-4, 1 - 1e-4)

    per_domain, all_y, all_p = {}, [], []
    for d, (tr, ca, te), how in domains:
        p = scored(d, te)
        all_y.append(d.y[te]), all_p.append(p)
        per_domain[d.name] = {**metrics(d.y[te], p), "split": how,
                              "rows": {"train": int(tr.sum()), "calibrate": int(ca.sum()), "test": int(te.sum())}}
    # Headline metrics = the bank-event (synthetic) test split: the events the live engine scores, and what the
    # Metrics page and benchmark report show. Every dataset's own test metrics and the pooled ones are kept too.
    m = per_domain["synthetic"]
    pooled = metrics(np.concatenate(all_y), np.concatenate(all_p))
    rows = {k: sum(v["rows"][k] for v in per_domain.values()) for k in ("train", "calibrate", "test")}
    entry = save_artifact({"booster": booster, "calibrator": iso, "features": TXN_FEATURES}, out, ARTIFACT, {
        "model": "lightgbm+isotonic", "features": TXN_FEATURES, "pr_auc": m["pr_auc"], "roc_auc": m["roc_auc"],
        "ece": m["ece"], "best_iteration": booster.best_iteration,
        "split": SYNTHETIC_SPLIT if not extra else f"per domain, by time ({SYNTHETIC_SPLIT}; external: {EXTERNAL_SPLIT})",
        "training_data": [d.name for d, _, _ in domains], "rows": rows, "test_positives": m["positives"],
        **({"headline": "synthetic (bank events) test split", "per_domain": per_domain,
            "pooled_test": {k: pooled[k] for k in ("pr_auc", "roc_auc", "ece", "n", "positives")}} if extra else {})})
    return entry


def _cached(name: str, cache: str | None, build) -> Domain:
    """Featurising a full external dataset takes minutes: reuse <cache>/<name>.npz when present."""
    path = Path(cache) / f"{name}.npz" if cache else None
    if path is not None and path.exists():
        z = np.load(path)
        return Domain(name, z["X"], z["y"], z["ts"])
    d = build()
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(path, X=d.X, y=d.y, ts=d.ts)
    return d


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ml.train_txn")
    ap.add_argument("--data", default="data/train.jsonl")
    ap.add_argument("--labels", default="data/train_labels.jsonl")
    ap.add_argument("--out", default="ml/artifacts")
    ap.add_argument("--ieee", help="folder with IEEE-CIS train_transaction.csv and train_identity.csv")
    ap.add_argument("--amlsim", help="AMLSim sample/ folder with the 20K_* samples extracted")
    ap.add_argument("--cache", help="folder to cache featurised external datasets (.npz)")
    a = ap.parse_args(argv)
    extra = []
    if a.ieee:
        from ml.datasets import ieee_cis
        extra.append(_cached("ieee_cis", a.cache, lambda: ieee_cis.load(a.ieee)))
    if a.amlsim:
        from ml.datasets import amlsim
        extra.append(_cached("amlsim", a.cache, lambda: amlsim.load(a.amlsim)))
    for d in extra:
        print(f"{d.name}: {len(d.y):,} transactions, {int(d.y.sum()):,} fraud", file=sys.stderr)
    e = train(a.data, a.labels, a.out, extra)
    print(f"{e['file']}: bank-events test PR-AUC {e['pr_auc']}, ROC-AUC {e['roc_auc']}, ECE {e['ece']}, trees {e['best_iteration']}, "
          f"sha256 {e['sha256'][:12]}", file=sys.stderr)
    for name, m in e.get("per_domain", {}).items():
        print(f"  {name:10} test PR-AUC {m['pr_auc']}  ROC-AUC {m['roc_auc']}  ECE {m['ece']}  "
              f"({m['rows']['test']:,} test rows, {m['positives']:,} fraud)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
