"""External training datasets (ml/datasets): tiny stand-in files in the real column layouts, so CI needs no downloads."""
from __future__ import annotations

from datetime import datetime

import numpy as np
import pandas as pd

from engine.features.features import TXN_FEATURES
from ml.datasets import amlsim, ieee_cis
from ml.datasets.common import Domain
from ml.generator.run import generate, write_jsonl
from ml.train_txn import train

PAYEE_IS_NEW, FAN_IN, TXN_COUNT_1H = (TXN_FEATURES.index(k) for k in ("payee_is_new", "payee_fan_in_24h", "txn_count_1h"))


def test_ieee_cis_maps_customers_payees_and_labels(tmp_path):
    pd.DataFrame({"TransactionID": [1, 2, 3, 4], "isFraud": [0, 0, 1, 0], "TransactionDT": [86400, 86500, 86600, 90000],
                  "TransactionAmt": [10.0, 12.0, 900.0, 11.0], "ProductCD": ["W", "W", "C", "W"],
                  "card1": [111, 111, 111, 222], "addr1": [300.0, 300.0, 300.0, None],
                  "P_emaildomain": ["gmail.com", "gmail.com", "gmail.com", None]}).to_csv(tmp_path / "train_transaction.csv", index=False)
    pd.DataFrame({"TransactionID": [3], "DeviceInfo": ["SM-G9600"]}).to_csv(tmp_path / "train_identity.csv", index=False)
    d = ieee_cis.load(tmp_path)
    assert d.X.shape == (4, len(TXN_FEATURES)) and d.y.tolist() == [0, 0, 1, 0]
    assert d.X[:, PAYEE_IS_NEW].tolist() == [1.0, 1.0, 1.0, 1.0]       # first purchase of each product line
    assert d.X[1, TXN_COUNT_1H] == 1.0                                  # same card holder, 100 s later
    assert d.X[3, TXN_COUNT_1H] == 0.0                                  # another card holder (missing addr/email)


def test_amlsim_labels_pattern_transfers_and_sees_the_fan_in(tmp_path):
    s = tmp_path / "20K_fanin200" / "20K_fanin200"
    s.mkdir(parents=True)
    pd.DataFrame({"nodeid": [0, 1, 2, 3, 9], "isFraud": [1, 1, 1, 0, 1], "init_balance": [1.0] * 5,
                  "fraudStep": [3, 3, 3, -1, 3]}).to_csv(s / "nodes.csv", index=False)
    pd.DataFrame({"sourceNodeId": [0, 1, 2, 3], "targetNodeId": [9, 9, 9, 9], "value": [100.0, 120.0, 110.0, 50.0],
                  "time": [3, 3, 3, 3]}).to_csv(s / "transactions.csv", index=False)
    d = amlsim.load(tmp_path)
    assert d.y.tolist() == [1, 1, 1, 0]                                 # pattern node -> pattern node only
    assert d.X[:, FAN_IN].tolist() == [0.0, 1.0, 2.0, 3.0]              # distinct other senders to node 9 in 24 h


def test_split_is_by_time_and_training_reports_every_domain(tmp_path):
    envs, labels = generate(days=14, customers=150, seed=5, end=datetime.fromisoformat("2026-10-09T00:30:00+05:30"), attacks=6)
    write_jsonl(str(tmp_path / "t.jsonl"), envs)
    write_jsonl(str(tmp_path / "l.jsonl"), labels)
    rng = np.random.default_rng(1)
    X = rng.random((400, len(TXN_FEATURES)))
    y = (X[:, 0] > 0.9).astype(np.int8)
    ext = Domain("toy", X, y, np.arange(400.0))
    tr, ca, te = ext.split()
    assert (tr.sum(), ca.sum(), te.sum()) == (240, 60, 100) and np.flatnonzero(te).min() > np.flatnonzero(ca).max()
    e = train(str(tmp_path / "t.jsonl"), str(tmp_path / "l.jsonl"), str(tmp_path / "out"), [ext])
    assert e["training_data"] == ["synthetic", "toy"] and set(e["per_domain"]) == {"synthetic", "toy"}
    assert e["per_domain"]["toy"]["rows"] == {"train": 240, "calibrate": 60, "test": 100}
