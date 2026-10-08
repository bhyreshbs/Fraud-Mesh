"""Feature definitions (PRD §10.3), one synthetic sequence per feature."""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import pytest

from engine.common.tokenize import to_stored_event
from engine.contracts import Envelope
from engine.features.features import NONE_RECENT_MIN, FeatureWindows, circular_hours, haversine_km

IST = timezone(timedelta(hours=5, minutes=30))
T0 = datetime(2026, 10, 1, 20, 0, tzinfo=IST)
_n = 0
BLR = (12.9716, 77.5946)


def e(event_type, payload, minutes=0.0, cust="C-1", acct="A-1", ip="49.207.10.21", dev="fp_a", asn="AS1", coords=BLR):
    global _n
    _n += 1
    ctx = {"ip": ip, "device_id": dev, "asn": asn}
    if coords:
        ctx.update(lat=coords[0], lon=coords[1])
    env = Envelope(event_id=f"evt_feat{_n:08d}", event_type=event_type, source="simulator",
                   occurred_at=T0 + timedelta(minutes=minutes), subject={"customer_ref": cust, "account_ref": acct},
                   context=ctx, payload=payload)
    return to_stored_event(env, env.occurred_at)


def login(minutes=0.0, result="success", **kw):
    return e("login", {"result": result, "auth_method": "password"}, minutes, **kw)


def txn(amount, payee="A-P1", minutes=0.0, **kw):
    return e("transaction", {"amount_paise": amount, "payee_account": payee, "channel": "IMPS"}, minutes, **kw)


def run(fw, events):
    out = None
    for ev in events:
        out = fw.compute(ev)
        fw.update(ev)
    return out


def test_helpers():
    assert circular_hours(23.5, 0.5) == 1.0 and circular_hours(9, 20) == 11
    assert haversine_km(*BLR, 19.076, 72.8777) == pytest.approx(845, abs=5)


def test_defaults_without_history():
    f = FeatureWindows().compute(txn(800_000))
    assert f["amount_to_median_30d"] == 1.0 and f["minutes_since_payee_added"] == NONE_RECENT_MIN
    assert f["device_first_seen"] == 1.0 and f["minutes_since_new_device"] == 0.0 and f["past_logins_30d"] == 0
    assert f["log_amount"] == pytest.approx(math.log1p(8000))


def test_amount_median_count_and_sums():
    fw = FeatureWindows()
    f = run(fw, [txn(100_000, minutes=-60 * 30), txn(300_000, minutes=-50), txn(200_000, minutes=-10), txn(1_000_000)])
    assert f["amount_to_median_30d"] == pytest.approx(1_000_000 / 200_000)
    assert f["txn_count_1h"] == 2 and f["txn_sum_24h_paise"] == 500_000              # the 30 h old one is outside 24 h


def test_payee_features():
    fw = FeatureWindows()
    run(fw, [e("payee_added", {"payee_account": "A-NEW"}, -30)])
    f = run(fw, [txn(100, payee="A-NEW", minutes=-5, cust="C-9", acct="A-9"), txn(100, payee="A-NEW")])
    assert f["payee_is_new"] == 1 and f["minutes_since_payee_added"] == pytest.approx(30)
    assert f["payee_fan_in_24h"] == 1                                                   # C-9, not the sender itself
    other = FeatureWindows()
    run(other, [e("payee_added", {"payee_account": "A-OLD"}, -60 * 25)])
    g = other.compute(txn(100, payee="A-OLD"))
    assert g["payee_is_new"] == 0 and g["minutes_since_payee_added"] == pytest.approx(60 * 25)


def test_near_limit_count_includes_this_transfer():
    fw = FeatureWindows()
    f = run(fw, [txn(49_000_000, payee="A-S", minutes=-60), txn(48_000_000, payee="A-S", minutes=-30),
                 txn(49_900_000, payee="A-S")])
    assert f["near_limit_count_24h"] == 3 and f["payee_sum_24h_paise"] == 97_000_000
    assert FeatureWindows().compute(txn(46_000_000))["near_limit_count_24h"] == 0


def test_device_asn_and_new_device_minutes():
    fw = FeatureWindows()
    run(fw, [login(-100, dev="fp_a", asn="AS1")])
    f = run(fw, [login(-30, dev="fp_new", asn="AS2"), e("mfa_change", {"factor": "sms", "action": "replace"}, 0, dev="fp_new")])
    assert f["device_first_seen"] == 0 and f["minutes_since_new_device"] == pytest.approx(30)
    g = fw.compute(login(1, dev="fp_other", asn="AS3"))
    assert g["device_first_seen"] == 1 and g["asn_first_seen"] == 1 and g["minutes_since_new_device"] == 0


def test_hour_deviation_and_login_count():
    fw = FeatureWindows()
    run(fw, [login(-60 * 24 * d) for d in range(1, 6)])                                # five 20:00 logins
    f = fw.compute(login(60 * 4 + 30))                                                   # 00:30 IST
    assert f["past_logins_30d"] == 5 and f["hour_deviation"] == pytest.approx(4.5)


def test_km_from_home_and_travel_speed():
    fw = FeatureWindows()
    run(fw, [login(-60 * 24 * 3), login(-60 * 2)])
    f = fw.compute(login(0, coords=(19.076, 72.8777)))
    assert f["km_from_home"] == pytest.approx(845, abs=5)
    assert f["travel_speed_kmh"] == pytest.approx(f["km_from_home"] / 2, rel=0.01)
    assert FeatureWindows().compute(login(0, coords=None))["km_from_home"] == 0


def test_failed_logins_and_ip_failed_customers():
    fw = FeatureWindows()
    run(fw, [login(-50, result="failure", cust=f"C-{i}", acct=f"A-{i}") for i in range(2, 11)] + [login(-120, result="failure")])
    f = fw.compute(login(0, result="failure", cust="C-99", acct="A-99"))
    assert f["ip_failed_customers_1h"] == 10                                           # 9 in the hour + this one
    assert fw.compute(login(0))["failed_logins_1h"] == 0                                # C-1's failure is 2 h old
    assert fw.compute(login(0, cust="C-3", acct="A-3"))["failed_logins_1h"] == 1          # one fresh failure


def test_minutes_since_mfa_change():
    fw = FeatureWindows()
    run(fw, [e("mfa_change", {"factor": "sms", "action": "replace"}, -20)])
    assert fw.compute(login(0))["minutes_since_mfa_change"] == pytest.approx(20)
    assert fw.compute(login(60 * 24 * 8))["minutes_since_mfa_change"] == NONE_RECENT_MIN


def test_cid_profile_reads_include_this_one():
    fw = FeatureWindows()
    read = {"actor_type": "support_console", "actor_identity": "svc-1", "action": "ReadCustomerProfile",
            "target_customer": "C-1", "src_ip": "10.0.1.5", "result": "success"}
    evs = [e("cloud_audit", read, i * 0.2, cust=None, acct=None, coords=None) for i in range(19)]
    run(fw, evs)
    assert fw.compute(e("cloud_audit", read, 4, cust=None, acct=None, coords=None))["cid_profile_reads_10m"] == 20
    assert fw.compute(e("cloud_audit", read, 30, cust=None, acct=None, coords=None))["cid_profile_reads_10m"] == 1


def test_windows_expire():
    fw = FeatureWindows()
    run(fw, [txn(100_000, minutes=-60 * 24 * 31)])
    assert fw.compute(txn(500_000))["amount_to_median_30d"] == 1.0
