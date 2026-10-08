"""Demo identity table (PRD §4) and the demo-only in-memory state used by /v1/demo/* and step-up.

Raw values live here only in memory, for the simulated bank app and phones. Nothing raw is written to the database.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from engine.common.tokenize import tok

# device_id -> context the bank app's identity switcher implies (PRD §4 table + §12.2 identities)
DEVICE_CONTEXT: dict[str, dict] = {
    "fp_priya_phone": {"ip": "49.207.10.21", "asn": "AS24560 Airtel", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946},
    "fp_priya_laptop": {"ip": "49.207.10.21", "asn": "AS24560 Airtel", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946},
    "fp_attacker_01": {"ip": "185.220.101.7", "asn": "AS64500 HostCo"},
    "fp_mule_shared": {"ip": "103.21.4.9", "asn": "AS55836 Jio", "city": "Bengaluru", "lat": 12.93, "lon": 77.62},
}

# customer_ref -> account_ref for the named demo customers
CUSTOMERS: dict[str, str] = {"C-1042": "A-88213", "C-RAVI-01": "A-RAVI-778", "C-MULE-01": "A-MULE-01"}

# the registered device that receives push challenges for each demo customer
REGISTERED_DEVICE: dict[str, str] = {"C-1042": "fp_priya_phone", "C-RAVI-01": "fp_mule_shared", "C-MULE-01": "fp_mule_shared"}


def fill_context(context: dict) -> dict:
    """Fill ip/asn/city/lat/lon from the table when the device is known; explicit values win."""
    known = DEVICE_CONTEXT.get(context.get("device_id") or "")
    if not known:
        return context
    return {**context, **{k: v for k, v in known.items() if context.get(k) in (None, "")}}


def phone_key(raw: str) -> str:
    return "".join(c for c in raw if c.isdigit())[-10:]


def mask_phone(raw: str | None) -> str:
    if not raw:
        return "registered mobile number"
    digits = phone_key(raw)
    return f"+91 ••••• •{digits[-4:]}" if len(digits) >= 4 else "registered mobile number"


@dataclass
class SmsMessage:
    text: str
    at: datetime


@dataclass
class DemoState:
    """Per-process memory filled from /v1/demo/emit traffic."""
    customer_ref: dict[str, str] = field(default_factory=dict)       # cust token -> raw customer_ref
    phone: dict[str, str] = field(default_factory=dict)              # cust token -> raw SMS phone (latest)
    last_context: dict[str, dict] = field(default_factory=dict)      # cust token -> raw context of last app event
    inbox: dict[str, list[SmsMessage]] = field(default_factory=dict) # phone_key -> messages

    def __post_init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        for d in (self.customer_ref, self.phone, self.last_context, self.inbox):
            d.clear()
        for ref in CUSTOMERS:
            self.customer_ref[tok("cust", ref)] = ref

    def remember(self, customer_ref: str | None, context: dict) -> str | None:
        if not customer_ref:
            return None
        t = tok("cust", customer_ref)
        self.customer_ref[t] = customer_ref
        if context:
            self.last_context[t] = context
        return t

    def deliver_sms(self, phone: str, text: str, at: datetime) -> None:
        self.inbox.setdefault(phone_key(phone), []).append(SmsMessage(text, at))

    def device_for_token(self, device_token: str | None) -> str | None:
        for raw in DEVICE_CONTEXT:
            if device_token and tok("dev", raw) == device_token:
                return raw
        return None


demo_state = DemoState()
