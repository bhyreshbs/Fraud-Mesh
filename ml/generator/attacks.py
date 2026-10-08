"""Attack injectors for training and benchmark data (PRD §12.1 `--attacks N`).

Each family follows the shape of its demo scenario, with randomised victims, timing and amounts:
  ato          new-device login at night (optionally after failed guesses), MFA or profile change, optional weak
               KYC and support-console limit raise, then a new payee and a large transfer
  mule_fanin   6–12 customers pay one mule account within 2 h; the mule forwards ~90% onward
  structuring  three transfers to one new payee, each just under a reporting limit, within 24 h
Every event of an instance is labelled with its family as `scenario` and a shared attack_id.
"""
from __future__ import annotations

import random
from datetime import datetime, time, timedelta

from ml.generator.background import Sink, channel_for, home_context, subject_of
from ml.generator.population import CITIES, Customer, NetworkAllocator, new_device_id, new_external_account

FAMILIES = ("ato", "mule_fanin", "structuring")
HOSTING_ASNS: list[tuple[str, int]] = [("AS64500 HostCo", 45), ("AS14061 DigitalOcean", 91), ("AS16276 OVH", 193)]
STRUCTURING_LIMITS_PAISE = (10_000_000, 20_000_000, 50_000_000)
SPAN = {"ato": timedelta(hours=5), "mule_fanin": timedelta(hours=3), "structuring": timedelta(hours=24)}


def _start_time(sink: Sink, rng: random.Random, span: timedelta, tz, night: bool = False) -> datetime:
    """A start time such that the whole instance lies inside [start, end)."""
    latest = sink.end - span - timedelta(minutes=5)
    if latest <= sink.start:
        raise ValueError("the time window is too short for attack injection; use more --days")
    for _ in range(1000):
        if night:
            day = (sink.start + timedelta(seconds=rng.uniform(0, (latest - sink.start).total_seconds()))).astimezone(tz).date()
            t = datetime.combine(day, time(0, 0), tzinfo=tz) + timedelta(minutes=rng.randint(0, 240))
        else:
            t = sink.start + timedelta(seconds=rng.uniform(0, (latest - sink.start).total_seconds()))
        if sink.start <= t <= latest:
            return t
    raise ValueError("could not place an attack inside the time window")


def _phone(rng: random.Random) -> str:
    return f"+91 9{rng.randrange(10**8, 10**9)}"


def inject_ato(sink: Sink, k: int, victim: Customer, alloc: NetworkAllocator, tz, rng: random.Random) -> None:
    aid, fam = f"atk_ato_{k:03d}", "ato"
    asn, octet = rng.choice(HOSTING_ASNS)
    attacker = {"ip": alloc.next_ip(octet, rng), "device_id": new_device_id(rng), "asn": asn}
    subj = subject_of(victim)
    t = _start_time(sink, rng, SPAN["ato"], tz, night=True)

    def emit(event_type: str, at: datetime, payload: dict, subject: dict | None = None, context: dict | None = None):
        sink.emit(event_type, at, payload, subject=subj if subject is None else subject,
                  context=attacker if context is None else context, scenario=fam, attack_id=aid)

    if rng.random() < 0.5:                                     # password guessing first
        for i in range(rng.randint(3, 6)):
            emit("login", t + timedelta(seconds=20 * i), {"result": "failure", "auth_method": "password"})
    t += timedelta(minutes=2)
    emit("login", t, {"result": "success", "auth_method": "password+otp"})
    t += timedelta(minutes=rng.randint(2, 6))
    if rng.random() < 0.7:
        emit("mfa_change", t, {"factor": "sms", "action": "replace", "new_phone": _phone(rng)},
             subject={"customer_ref": victim.customer_ref})
    else:
        emit("profile_change", t, {"field": rng.choice(("email", "phone", "password"))},
             subject={"customer_ref": victim.customer_ref})
    if rng.random() < 0.4:
        t += timedelta(minutes=rng.randint(3, 8))
        emit("kyc_result", t, {"liveness_score": round(rng.uniform(0.2, 0.45), 2),
                               "face_match_score": round(rng.uniform(0.6, 0.85), 2),
                               "doc_tamper_score": round(rng.uniform(0.05, 0.3), 2),
                               "injection_suspected": rng.random() < 0.1, "reason": "re_verification"},
             subject={"customer_ref": victim.customer_ref})
    if rng.random() < 0.3:
        t += timedelta(minutes=rng.randint(2, 6))
        emit("cloud_audit", t, {"actor_type": "support_console", "actor_identity": f"svc-support-{rng.randint(1, 30):02d}",
                                "action": "UpdateTransferLimit", "target_customer": victim.customer_ref,
                                "src_ip": attacker["ip"], "result": "success"}, subject={}, context={})
    mule_acct = new_external_account(rng, prefix="M")
    t += timedelta(minutes=rng.randint(3, 10))
    emit("payee_added", t, {"payee_account": mule_acct, "payee_name_match": False if rng.random() < 0.5 else None,
                            "nickname": rng.choice(("Rent", "Loan", "Invest", "Refund"))})
    t += timedelta(minutes=rng.randint(1, 8))
    amount = min(99_000_000, max(5_000_000, victim.median_amount_paise * rng.randint(5, 20)))
    emit("transaction", t, {"amount_paise": amount, "payee_account": mule_acct, "channel": "IMPS"})


def inject_mule_fanin(sink: Sink, k: int, senders: list[Customer], alloc: NetworkAllocator, tz,
                      rng: random.Random) -> None:
    aid, fam = f"atk_mule_fanin_{k:03d}", "mule_fanin"
    city = rng.choice(sorted(CITIES))
    mule = Customer(customer_ref=f"C-M{rng.randrange(10**5, 10**6)}", account_ref=new_external_account(rng, prefix="M"),
                    city=city, lat=CITIES[city][0], lon=CITIES[city][1], home_ip=alloc.next_ip(49, rng),
                    asn="AS55836 Jio", devices=[new_device_id(rng)], login_hour=21.0, median_amount_paise=500_000,
                    payees=[])
    t0 = _start_time(sink, rng, SPAN["mule_fanin"], tz)
    total = 0
    for sender, offset in zip(senders, sorted(rng.uniform(0, 115) for _ in senders), strict=True):
        at = t0 + timedelta(minutes=offset)
        dev = sender.devices[0]
        sink.emit("payee_added", at, {"payee_account": mule.account_ref, "nickname": rng.choice(("Refund desk", "Job fee", "Prize"))},
                  subject=subject_of(sender), context=home_context(sender, dev, rng), scenario=fam, attack_id=aid)
        amount = rng.randrange(150, 950) * 10_000                   # ₹15,000 – ₹95,000
        total += amount
        sink.emit("transaction", at + timedelta(seconds=40), {"amount_paise": amount, "payee_account": mule.account_ref,
                                                              "channel": channel_for(amount, rng)},
                  subject=subject_of(sender), context=home_context(sender, dev, rng), scenario=fam, attack_id=aid)
    onward = new_external_account(rng, prefix="X")
    at = t0 + timedelta(minutes=118)
    ctx = home_context(mule, mule.devices[0], rng)
    sink.emit("login", at, {"result": "success", "auth_method": "password+otp"}, subject=subject_of(mule), context=ctx,
              scenario=fam, attack_id=aid)
    sink.emit("payee_added", at + timedelta(minutes=1), {"payee_account": onward, "nickname": "Trade"},
              subject=subject_of(mule), context=ctx, scenario=fam, attack_id=aid)
    sink.emit("transaction", at + timedelta(minutes=3), {"amount_paise": round(total * rng.uniform(0.88, 0.92) / 100) * 100,
                                                         "payee_account": onward, "channel": "IMPS"},
              subject=subject_of(mule), context=ctx, scenario=fam, attack_id=aid)


def inject_structuring(sink: Sink, k: int, c: Customer, tz, rng: random.Random) -> None:
    aid, fam = f"atk_structuring_{k:03d}", "structuring"
    limit = rng.choice(STRUCTURING_LIMITS_PAISE)
    payee = new_external_account(rng)
    dev = c.devices[0]
    t = _start_time(sink, rng, SPAN["structuring"], tz)
    sink.emit("login", t, {"result": "success", "auth_method": "password+otp"}, subject=subject_of(c),
              context=home_context(c, dev, rng), scenario=fam, attack_id=aid)
    sink.emit("payee_added", t + timedelta(minutes=1), {"payee_account": payee, "payee_name_match": True,
                                                         "nickname": rng.choice(("Supplier", "Contractor", "Gold"))},
              subject=subject_of(c), context=home_context(c, dev, rng), scenario=fam, attack_id=aid)
    t += timedelta(minutes=3)
    for i in range(3):
        if i:
            t += timedelta(minutes=rng.randint(20, 400))
            sink.emit("login", t - timedelta(minutes=1), {"result": "success", "auth_method": "password+otp"},
                      subject=subject_of(c), context=home_context(c, dev, rng), scenario=fam, attack_id=aid)
        amount = round(limit * rng.uniform(0.95, 0.999) / 100) * 100
        sink.emit("transaction", t, {"amount_paise": amount, "payee_account": payee,
                                     "channel": rng.choice(("IMPS", "NEFT"))},
                  subject=subject_of(c), context=home_context(c, dev, rng), scenario=fam, attack_id=aid)


def inject_attacks(sink: Sink, n: int, customers: list[Customer], alloc: NetworkAllocator, tz,
                   rng: random.Random) -> dict[str, int]:
    """n instances of each family. Victims are distinct while the population allows; Priya is never one."""
    if n <= 0:
        return dict.fromkeys(FAMILIES, 0)
    pool = [c for c in customers if not c.is_demo]
    if not pool:
        raise ValueError("attack injection needs at least one non-demo customer (--customers >= 2)")
    order = rng.sample(pool, len(pool))
    picked = 0

    def take() -> Customer:
        nonlocal picked
        c = order[picked % len(order)]
        picked += 1
        return c

    for k in range(1, n + 1):
        inject_ato(sink, k, take(), alloc, tz, rng)
        inject_mule_fanin(sink, k, [take() for _ in range(min(rng.randint(6, 12), len(pool)))], alloc, tz, rng)
        inject_structuring(sink, k, take(), tz, rng)
    return dict.fromkeys(FAMILIES, n)
