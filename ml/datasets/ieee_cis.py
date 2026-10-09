"""IEEE-CIS Fraud Detection (Vesta, Kaggle 2019): ~590k real card-not-present transactions, 3.5% fraud.

Mapping to FraudMesh:
  customer  card1 + addr1 + P_emaildomain (the usual "card holder" key for this dataset; anonymised values)
  time      TransactionDT (seconds from a reference date) from T0
  amount    TransactionAmt in USD x 83 INR, in paise
  payee     the product line (ProductCD) as a merchant account: a customer's first purchase of a line is a new payee
  device    DeviceInfo from train_identity.csv when present; each purchase is preceded by a login (a session)
Only train_transaction.csv / train_identity.csv carry labels, so only those are used.
"""
from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pandas as pd

from ml.datasets.common import T0, Domain, Txn, featurize

USD_INR = 83.0


def _txns(directory: Path) -> Iterator[Txn]:
    t = pd.read_csv(directory / "train_transaction.csv", usecols=["TransactionID", "isFraud", "TransactionDT",
                                                                   "TransactionAmt", "ProductCD", "card1", "addr1",
                                                                   "P_emaildomain"])
    ident = pd.read_csv(directory / "train_identity.csv", usecols=["TransactionID", "DeviceInfo"])
    t = t.merge(ident, on="TransactionID", how="left").sort_values(["TransactionDT", "TransactionID"], kind="stable")
    uid = t.card1.map(str) + "_" + t.addr1.map(str) + "_" + t.P_emaildomain.map(str)
    for dt, amt, prod, u, dev, fraud in zip(t.TransactionDT, t.TransactionAmt, t.ProductCD, uid, t.DeviceInfo, t.isFraud, strict=True):
        yield Txn(ts=T0 + timedelta(seconds=int(dt)), customer=f"C-IEEE-{u}", account=f"A-IEEE-{u}",
                  payee=f"A-MERCH-{prod}", amount_paise=round(float(amt) * USD_INR * 100), is_fraud=bool(fraud),
                  device=dev if isinstance(dev, str) else None)


def load(directory: str | Path) -> Domain:
    """directory holds train_transaction.csv and train_identity.csv (unzipped from the Kaggle download)."""
    return featurize("ieee_cis", _txns(Path(directory)), with_login=True)
