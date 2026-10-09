"""v3 core 3.2b: event-time customer+payee windows (dedupe, late events, 24 h boundary) and the STRUCTURING rule."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from engine.common.tokenize import to_stored_event
from engine.contracts import Envelope
from engine.detectors.txn import structuring
from engine.features.features import FEATURE_NAMES, TXN_FEATURES, FeatureWindows
from engine.features.txn_windows import TXN_WINDOW_FEATURES, TxnWindows, near_limit_of
from engine.fusion.v3_core import load_v3_core

IST = timezone(timedelta(hours=5, minutes=30))
T0 = datetime(2026, 10, 1, 10, 0, tzinfo=IST)
CFG = load_v3_core()["structuring"]
_n = 0


def txn(amount, minutes=0.0, payee="A-GOLD", cust="C-1", acct="A-1", event_id=None):
    global _n
    _n += 1
    env = Envelope(event_id=event_id or f"evt_v3s{_n:08d}", event_type="transaction", source="simulator",
                   occurred_at=T0 + timedelta(minutes=minutes), subject={"customer_ref": cust, "account_ref": acct},
                   context={"ip": "49.207.10.21", "device_id": "fp_a"},
                   payload={"amount_paise": amount, "payee_account": payee, "channel": "NEFT"})
    return to_stored_event(env, env.occurred_at)


def feed(tw, events):
    out = None
    for e in events:
        out = tw.compute(e)
        tw.update(e)
    return out


def test_model_features_unchanged_and_window_features_appended():
    assert len(TXN_FEATURES) == 11 and "tw_pair_sum_24h_paise" not in TXN_FEATURES
    assert FEATURE_NAMES[:len(TXN_FEATURES)] == TXN_FEATURES                    # model inputs stay first, unchanged
    assert set(TXN_WINDOW_FEATURES) <= set(FEATURE_NAMES)                        # appended (other v3 features may follow)


def test_near_limit_definition_matches_prd():
    assert near_limit_of(9_500_000, CFG["limits_paise"], 0.95) == 10_000_000
    assert near_limit_of(10_000_000, CFG["limits_paise"], 0.95) is None            # [0.95 L, L)
    assert near_limit_of(9_499_999, CFG["limits_paise"], 0.95) is None
    assert near_limit_of(49_900_000, CFG["limits_paise"], 0.95) == 50_000_000


def test_rolling_sum_count_velocity_and_repeats():
    f = feed(TxnWindows(), [txn(49_000_000, 0), txn(48_500_000, 30), txn(1_000_000, 50), txn(49_500_000, 90)])
    assert f["tw_pair_count_24h"] == 4 and f["tw_pair_sum_24h_paise"] == 148_000_000
    assert f["tw_near_limit_count_24h"] == 3 and f["tw_near_limit_same_limit_max_24h"] == 3
    assert f["tw_near_limit_limit_paise"] == 50_000_000 and f["tw_near_limit_sum_24h_paise"] == 147_000_000
    assert f["tw_pair_count_1h"] == 3                                               # 30, 50, 90 within [30, 90]
    assert f["tw_near_limit_rate_per_h"] == pytest.approx(3 / 1.5)


def test_exactly_24h_is_inside_and_one_second_more_is_outside():
    tw = TxnWindows()
    feed(tw, [txn(49_000_000, 0)])
    assert tw.compute(txn(49_000_000, 24 * 60))["tw_near_limit_count_24h"] == 2
    assert tw.compute(txn(49_000_000, 24 * 60 + 1 / 60))["tw_near_limit_count_24h"] == 1


def test_duplicate_event_is_not_double_counted():
    tw = TxnWindows()
    first = txn(49_000_000, 0, event_id="evt_v3sdup0001")
    feed(tw, [first, first])                                    # delivered twice
    again = tw.compute(first)                                   # and computed a third time
    assert again["tw_pair_count_24h"] == 1 and again["tw_near_limit_count_24h"] == 1
    assert tw.compute(txn(49_000_000, 10))["tw_near_limit_count_24h"] == 2


def test_late_event_is_placed_by_event_time():
    tw = TxnWindows()
    feed(tw, [txn(49_000_000, 0), txn(49_000_000, 600)])
    late = txn(48_000_000, 300)                                 # arrives last, happened in between
    f = tw.compute(late)
    assert f["tw_near_limit_count_24h"] == 2                    # t=0 and itself; t=600 is in its future
    tw.update(late)
    assert tw.compute(txn(49_000_000, 610))["tw_near_limit_count_24h"] == 4


def test_customers_and_payees_are_never_merged():
    tw = TxnWindows()
    feed(tw, [txn(49_000_000, 0, cust="C-1"), txn(49_000_000, 1, cust="C-2", acct="A-2"),
              txn(49_000_000, 2, payee="A-OTHER")])
    f = tw.compute(txn(49_000_000, 3, cust="C-1"))
    assert f["tw_near_limit_count_24h"] == 2 and f["tw_pair_count_24h"] == 2


def test_feature_windows_carry_the_new_features():
    fw = FeatureWindows()
    out = None
    for e in [txn(49_000_000, 0), txn(49_000_000, 60)]:
        out = fw.compute(e)
        fw.update(e)
    assert out["near_limit_count_24h"] == out["tw_near_limit_count_24h"] == 2


def test_structuring_rule():
    assert structuring({"near_limit_count_24h": 1.0}, CFG) is None
    p, detail = structuring({"near_limit_count_24h": 2.0}, CFG)                     # PRD path, no window features
    assert p == 0.0 and "2 transfers" in detail
    f = feed(TxnWindows(), [txn(49_000_000, 0), txn(49_000_000, 60)])
    p, detail = structuring(f, CFG)
    assert p == CFG["split_p"] and "split over the limit" in detail             # Rs 9.8L moved under the Rs 5L limit
    g = feed(TxnWindows(), [txn(9_600_000, 0), txn(49_000_000, 60)])              # different limits, not split
    p, detail = structuring(g, CFG)
    assert p == 0.0 and "split" not in detail
