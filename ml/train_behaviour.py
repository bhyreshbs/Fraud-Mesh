"""Train the behaviour model (PRD §10.4, §16.3): logistic regression on device_first_seen, asn_first_seen,
km_from_home/1000, hour_deviation/12, failed_logins_1h, isotonic-calibrated.

Rows are successful logins of customers with at least 5 past logins (the detector's COLD_START rule decides the
rest live). The positive class is an account-takeover login (label is_attack and scenario "ato"): mule and
structuring attacks log in from the customer's own device and are the txn and graph detectors' job.

    python -m ml.train_behaviour --data data/train.jsonl --labels data/train_labels.jsonl --out ml/artifacts
"""
from __future__ import annotations

import argparse
import sys

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

from engine.detectors.behaviour import BEHAVIOUR_FEATURES, COLD_START_LOGINS, behaviour_vector
from ml.train_common import feature_rows, load_events, metrics, save_artifact, split

ARTIFACT = "behaviour_v1.joblib"


def train(data: str, labels: str, out: str) -> dict:
    events, lab = load_events(data, labels)
    rows = feature_rows(events, lab, lambda ev, f: ev.event_type == "login" and ev.payload.get("result") == "success"
                        and f["past_logins_30d"] >= COLD_START_LOGINS)
    X = np.array([behaviour_vector(f) for f in rows.feats])
    y = np.array([int(lb.is_attack and lb.scenario == "ato") for lb in rows.labels])
    tr, ca, te = split(rows.day)
    model = LogisticRegression(class_weight="balanced", max_iter=2000, random_state=7).fit(X[tr], y[tr])
    iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(model.predict_proba(X[ca])[:, 1], y[ca])
    p_test = np.clip(iso.predict(model.predict_proba(X[te])[:, 1]), 1e-4, 1 - 1e-4)
    m = metrics(y[te], p_test)
    return save_artifact({"model": model, "calibrator": iso, "features": BEHAVIOUR_FEATURES}, out, ARTIFACT, {
        "model": "logistic_regression+isotonic", "features": BEHAVIOUR_FEATURES,
        "coefficients": dict(zip(BEHAVIOUR_FEATURES, [round(float(c), 4) for c in model.coef_[0]], strict=True)),
        "pr_auc": m["pr_auc"], "roc_auc": m["roc_auc"], "ece": m["ece"],
        "split": "days 1-9 train, 10-11 calibrate, 12-14 test",
        "rows": {"train": int(tr.sum()), "calibrate": int(ca.sum()), "test": int(te.sum())},
        "positives": {"train": int(y[tr].sum()), "calibrate": int(y[ca].sum()), "test": m["positives"]}})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ml.train_behaviour")
    ap.add_argument("--data", default="data/train.jsonl")
    ap.add_argument("--labels", default="data/train_labels.jsonl")
    ap.add_argument("--out", default="ml/artifacts")
    a = ap.parse_args(argv)
    e = train(a.data, a.labels, a.out)
    print(f"{e['file']}: PR-AUC {e['pr_auc']}, ROC-AUC {e['roc_auc']}, ECE {e['ece']}, coef {e['coefficients']}, "
          f"sha256 {e['sha256'][:12]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
