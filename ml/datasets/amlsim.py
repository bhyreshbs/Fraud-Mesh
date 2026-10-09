"""IBM AMLSim sample networks (github.com/IBM/AMLSim, sample/*.tgz): 20,000 accounts each, with labelled laundering
patterns — fan-in (many senders -> one mule account, FraudMesh's mule_fanin family), cycles, and both.

Mapping to FraudMesh:
  customer / account   one per AMLSim node, prefixed by the sample name (the samples are separate networks)
  time                 `time` is a day number; payments are spread over the day deterministically
  amount               AMLSim units are arbitrary: scaled so the median payment is ₹1,500 (the synthetic median)
  label                fraud when both endpoints are laundering-pattern nodes (the pattern's own transfers)
"""
from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pandas as pd

from ml.datasets.common import T0, Domain, Txn, featurize

SAMPLES = ("20K_fanin200", "20K_cycle200", "20K_fanin200cycle200")
MEDIAN_PAISE = 150_000


def _frame(directory: Path) -> pd.DataFrame:
    parts = []
    for s in SAMPLES:
        d = directory / s / s if (directory / s / s).exists() else directory / s
        if not (d / "transactions.csv").exists():
            continue
        tx, nodes = pd.read_csv(d / "transactions.csv"), pd.read_csv(d / "nodes.csv")
        fraud = dict(zip(nodes.nodeid, nodes.isFraud, strict=True))
        tx["fraud"] = [bool(fraud[a] and fraud[b]) for a, b in zip(tx.sourceNodeId, tx.targetNodeId, strict=True)]
        tx["sample"] = s
        parts.append(tx)
    if not parts:
        raise FileNotFoundError(f"no AMLSim sample under {directory} (expected {', '.join(SAMPLES)})")
    df = pd.concat(parts, ignore_index=True)
    df["minute"] = (df.index.to_numpy() * 97) % 1440
    df["scale"] = df.groupby("sample").value.transform(lambda v: MEDIAN_PAISE / v.median())
    return df.sort_values(["time", "minute"], kind="stable")


def _txns(directory: Path) -> Iterator[Txn]:
    df = _frame(directory)
    for s, a, b, v, k, day, m, fraud in zip(df["sample"], df.sourceNodeId, df.targetNodeId, df.value, df.scale, df.time,
                                            df.minute, df.fraud, strict=True):
        yield Txn(ts=T0 + timedelta(days=int(day), minutes=int(m)), customer=f"C-AML-{s}-{a}", account=f"A-AML-{s}-{a}",
                  payee=f"A-AML-{s}-{b}", amount_paise=round(float(v) * float(k)), is_fraud=bool(fraud))


def load(directory: str | Path) -> Domain:
    """directory is AMLSim's sample/ folder with the .tgz files extracted (one sub-folder per sample)."""
    return featurize("amlsim", _txns(Path(directory)))
