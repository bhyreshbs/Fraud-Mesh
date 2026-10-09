"""Synthetic data generator (PRD §12.1, §16.1)."""
from __future__ import annotations

import ipaddress
import statistics
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import pytest

from engine.common.tokenize import to_stored_event
from engine.contracts import Envelope, Label, validate_payload
from engine.graph.resolve import load_cgnat_networks
from ml.generator.population import CITIES
from ml.generator.run import generate, main

END = datetime.fromisoformat("2026-10-09T00:30:00+05:30")
STRUCTURING_LIMITS = (10_000_000, 20_000_000, 50_000_000)


@pytest.fixture(scope="module")
def small():
    return generate(days=7, customers=150, seed=7, end=END, attacks=0)


@pytest.fixture(scope="module")
def attacked():
    return generate(days=7, customers=150, seed=7, end=END, attacks=2)


def _dump(rows) -> list[str]:
    return [r.model_dump_json() for r in rows]


# ---------------------------------------------------------------------------- output format
def test_envelopes_are_valid_ordered_and_inside_the_window(small):
    envs, labels = small
    assert envs and len(envs) == len(labels)
    for e in envs:
        Envelope.model_validate_json(e.model_dump_json())
        validate_payload(e.event_type, e.payload)
        to_stored_event(e, e.occurred_at)
    assert all(e.source == "simulator" for e in envs)
    assert [(e.occurred_at, e.event_id) for e in envs] == sorted((e.occurred_at, e.event_id) for e in envs)
    assert all(END - timedelta(days=7) <= e.occurred_at < END for e in envs)
    assert all(e.occurred_at.utcoffset() == END.utcoffset() for e in envs)
    assert len({e.event_id for e in envs}) == len(envs)


def test_labels_align_with_events_and_are_benign_without_attacks(small):
    envs, labels = small
    assert [lb.event_id for lb in labels] == [e.event_id for e in envs]
    assert all(isinstance(lb, Label) and lb.scenario == "background" and not lb.is_attack and lb.attack_id is None
               for lb in labels)


def test_event_mix(small):
    envs, _ = small
    kinds = Counter(e.event_type for e in envs)
    assert kinds["login"] > 0 and kinds["transaction"] > 0 and kinds["payee_added"] > 0
    assert set(kinds) <= {"login", "transaction", "payee_added", "mfa_change"}


# ---------------------------------------------------------------------------- determinism
def test_fixed_seed_is_deterministic(small):
    again = generate(days=7, customers=150, seed=7, end=END, attacks=0)
    assert _dump(again[0]) == _dump(small[0]) and _dump(again[1]) == _dump(small[1])


def test_different_seed_differs(small):
    other, _ = generate(days=7, customers=150, seed=1, end=END, attacks=0)
    assert _dump(other) != _dump(small[0])


def test_attacks_leave_the_background_unchanged(small, attacked):
    benign = [e for e, lb in zip(*attacked, strict=True) if not lb.is_attack]
    assert _dump(benign) == _dump(small[0])


# ---------------------------------------------------------------------------- population
def _by_customer(envs):
    out = defaultdict(list)
    for e in envs:
        if e.subject.customer_ref:
            out[e.subject.customer_ref].append(e)
    return out


def test_population_properties(small):
    envs, _ = small
    customers = _by_customer(envs)
    assert len(customers) == 150
    home_nets: dict[str, set] = {}
    cgnat = set(load_cgnat_networks())
    for ref, evs in customers.items():
        logins = [e for e in evs if e.event_type == "login"]
        assert {e.context.city for e in logins} <= set(CITIES)
        assert len({e.context.city for e in logins}) == 1                         # one home city
        assert len({e.context.asn for e in logins}) == 1                          # one ASN
        nets = {ipaddress.ip_network(f"{e.context.ip}/24", strict=False) for e in logins}
        assert len(nets) == 1 and not nets & cgnat                                # home IP in its own /24
        home_nets[ref] = nets
        assert all(e.context.lat is not None and e.context.lon is not None for e in logins)
    all_nets = [n for nets in home_nets.values() for n in nets]
    assert len(all_nets) == len(set(all_nets))                                    # no two customers share a /24


def test_devices_login_hours_amounts_and_payees(small):
    envs, _ = small
    customers = _by_customer(envs)
    devices_per_customer = []
    hour_offsets = []
    for evs in customers.values():
        devs = {e.context.device_id for e in evs if e.event_type == "login"}
        new_devs = sum(1 for e in evs if e.event_type == "mfa_change")
        devices_per_customer.append(len(devs) - new_devs)
        for e in evs:
            if e.event_type == "login":
                h = e.occurred_at.hour + e.occurred_at.minute / 60
                hour_offsets.append(min(abs(h - 9), abs(h - 20), 24 - abs(h - 20)))
    assert max(devices_per_customer) <= 3                                          # 1–2, plus a rare phone change
    assert statistics.median(hour_offsets) < 1.5                                   # near 09:00 or 20:00
    amounts = [e.payload["amount_paise"] for e in envs if e.event_type == "transaction"]
    assert 500_000 <= statistics.median(amounts) <= 1_200_000                      # around ₹8,000
    payees_per_customer = [len({e.payload["payee_account"] for e in evs if e.event_type == "transaction"})
                           for evs in customers.values()]
    assert max(payees_per_customer) <= 10 + 7                                      # 3–10 regulars + occasional new


def test_priya_is_a_generated_customer(small):
    envs, _ = small
    priya = [e for e in envs if e.subject.customer_ref == "C-1042"]
    assert priya and {e.subject.account_ref for e in priya} == {"A-88213"}
    logins = [e for e in priya if e.event_type == "login"]
    assert {e.context.ip for e in logins} == {"49.207.10.21"}
    assert {e.context.device_id for e in logins} <= {"fp_priya_phone", "fp_priya_laptop"}
    assert {e.context.asn for e in logins} == {"AS24560 Airtel"}


# ---------------------------------------------------------------------------- attacks
def _instances(envs, labels):
    out = defaultdict(list)
    for e, lb in zip(envs, labels, strict=True):
        if lb.is_attack:
            out[(lb.scenario, lb.attack_id)].append(e)
    return out


def test_attacks_inject_n_instances_of_each_family(attacked):
    inst = _instances(*attacked)
    assert Counter(fam for fam, _ in inst) == {"ato": 2, "mule_fanin": 2, "structuring": 2}
    assert all(aid.startswith(f"atk_{fam}_") for fam, aid in inst)
    victims = {e.subject.customer_ref for evs in inst.values() for e in evs}
    assert "C-1042" not in victims


def test_ato_shape(attacked):
    for (fam, _), evs in _instances(*attacked).items():
        if fam != "ato":
            continue
        ok_login = [e for e in evs if e.event_type == "login" and e.payload["result"] == "success"]
        txn = [e for e in evs if e.event_type == "transaction"]
        added = [e for e in evs if e.event_type == "payee_added"]
        assert len(ok_login) == 1 and len(txn) == 1 and len(added) == 1
        assert any(e.event_type in ("mfa_change", "profile_change") for e in evs)
        assert txn[0].payload["payee_account"] == added[0].payload["payee_account"]
        assert ok_login[0].occurred_at < added[0].occurred_at < txn[0].occurred_at
        assert ok_login[0].occurred_at.hour < 5                                   # at night (IST)


def test_mule_fanin_shape(attacked):
    for (fam, _), evs in _instances(*attacked).items():
        if fam != "mule_fanin":
            continue
        txns = [e for e in evs if e.event_type == "transaction"]
        mule = Counter(e.payload["payee_account"] for e in txns).most_common(1)[0][0]
        inbound = [e for e in txns if e.payload["payee_account"] == mule]
        onward = [e for e in txns if e.payload["payee_account"] != mule]
        assert len({e.subject.customer_ref for e in inbound}) >= 6
        assert max(e.occurred_at for e in inbound) - min(e.occurred_at for e in inbound) <= timedelta(hours=2)
        assert len(onward) == 1 and onward[0].occurred_at > max(e.occurred_at for e in inbound)
        ratio = onward[0].payload["amount_paise"] / sum(e.payload["amount_paise"] for e in inbound)
        assert 0.85 <= ratio <= 0.95


def test_structuring_shape(attacked):
    for (fam, _), evs in _instances(*attacked).items():
        if fam != "structuring":
            continue
        txns = [e for e in evs if e.event_type == "transaction"]
        assert len(txns) == 3 and len({e.payload["payee_account"] for e in txns}) == 1
        assert txns[-1].occurred_at - txns[0].occurred_at < timedelta(hours=24)
        amounts = [e.payload["amount_paise"] for e in txns]
        assert any(all(0.95 * lim <= a < lim for a in amounts) for lim in STRUCTURING_LIMITS)


def test_bad_arguments():
    with pytest.raises(ValueError):
        generate(days=0, customers=10, seed=7, end=END)
    with pytest.raises(ValueError):
        generate(days=7, customers=10, seed=7, end=datetime(2026, 10, 9))       # naive
    with pytest.raises(ValueError):
        generate(days=7, customers=10, seed=7, end=END, attacks=-1)


# ---------------------------------------------------------------------------- CLI, exact PRD command
def test_prd_cli_command(tmp_path):
    """§12.1 command at full scale: about 60k events for 14 days × 2,000 customers, well under 2 minutes."""
    out, lab = tmp_path / "data" / "background.jsonl", tmp_path / "data" / "background_labels.jsonl"
    argv = ["--days", "14", "--customers", "2000", "--seed", "7", "--end", "2026-10-09T00:30:00+05:30",
            "--attacks", "0", "--out", str(out), "--labels", str(lab)]
    t0 = time.perf_counter()
    assert main(argv) == 0
    elapsed = time.perf_counter() - t0
    env_lines, label_lines = out.read_text().splitlines(), lab.read_text().splitlines()
    assert 50_000 <= len(env_lines) <= 70_000
    assert len(label_lines) == len(env_lines)
    assert elapsed < 120
    first, last = Envelope.model_validate_json(env_lines[0]), Envelope.model_validate_json(env_lines[-1])
    assert first.occurred_at >= END - timedelta(days=14) and last.occurred_at < END
    assert Label.model_validate_json(label_lines[0]).event_id == first.event_id


def test_cli_rejects_a_naive_end(tmp_path, capsys):
    rc = main(["--end", "2026-10-09T00:30:00", "--out", str(tmp_path / "a"), "--labels", str(tmp_path / "b")])
    assert rc == 2 and "offset" in capsys.readouterr().err
