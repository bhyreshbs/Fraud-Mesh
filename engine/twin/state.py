"""Virtual banking state (Digital Twin phase 1): customers, accounts, devices, IPs, phones and payees of a case, updated
event by event. Every policy simulation starts from its own copy (copy.deepcopy), so strategies never interfere.

Values are tokens (cust:…, dev:…), exactly as stored; the twin never sees raw PII.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from engine.contracts import StoredEvent

SIM_SWAP_RECENT_H = 72                     # same window as the auth detector's RECENT_SIM_SWAP


@dataclass
class CustomerState:
    sessions: set[str] = field(default_factory=set)          # devices with a live session
    sms_attacker_controlled: bool = False                    # OTPs now reach the attacker (SMS swap / SIM swap)
    profile_changes: list[str] = field(default_factory=list)
    kyc: str | None = None                                   # "weak" | "passed"
    payees_added: list[str] = field(default_factory=list)
    limit_raised_by: str | None = None                       # support / cloud identity that raised the limit
    payments_out_paise: int = 0


@dataclass
class VirtualBank:
    customers: dict[str, CustomerState] = field(default_factory=dict)
    tags: dict[str, set[str]] = field(default_factory=dict)  # entity token -> state tags

    def _tag(self, token: str | None, tag: str) -> None:
        if token:
            self.tags.setdefault(token, set()).add(tag)

    def customer(self, token: str) -> CustomerState:
        return self.customers.setdefault(token, CustomerState())

    def apply(self, ev: StoredEvent, actor: str) -> list[str]:
        """Update the state with one event that happened; return the state changes in plain words."""
        p, out = ev.payload, []
        c = self.customer(ev.customer) if ev.customer else None
        if ev.event_type == "login" and c is not None:
            if p.get("result") == "success" and ev.device:
                c.sessions.add(ev.device)
                out.append("new session on " + ("an unknown device" if actor == "attacker" else "the customer's device"))
                if actor == "attacker":
                    self._tag(ev.device, "attacker device")
                    self._tag(ev.ip, "attacker network")
            elif p.get("result") == "failure":
                self._tag(ev.ip, "password guessing")
                out.append("failed login")
        elif ev.event_type == "network_ids_alert":
            self._tag(p.get("src_ip") or ev.ip, "IDS alert source")
            out.append("network sensor flags the source IP")
        elif ev.event_type == "mfa_change" and c is not None:
            if p.get("factor") == "sms" and p.get("action") in ("replace", "add"):
                c.sms_attacker_controlled = actor == "attacker"
                self._tag(p.get("new_phone"), "attacker phone" if actor == "attacker" else "new phone")
                out.append("registered SMS number replaced" + (": OTPs now reach the attacker" if actor == "attacker" else ""))
            else:
                out.append(f"MFA {p.get('factor')} {p.get('action')}")
        elif ev.event_type == "sim_signal" and c is not None:
            if float(p.get("sim_change_age_h", 1e9)) < SIM_SWAP_RECENT_H:
                c.sms_attacker_controlled = True
                self._tag(ev.customer, "recent SIM swap")
                out.append("SIM swapped recently: OTPs may reach the attacker")
        elif ev.event_type == "profile_change" and c is not None:
            c.profile_changes.append(str(p.get("field")))
            out.append(f"{p.get('field')} changed")
        elif ev.event_type == "kyc_result" and c is not None:
            weak = (p.get("liveness_score", 1) < 0.5 or p.get("face_match_score", 1) < 0.7 or p.get("doc_tamper_score", 0) > 0.5
                    or p.get("injection_suspected"))
            c.kyc = "weak" if weak else "passed"
            out.append("re-KYC with weak liveness / document signals" if weak else "re-KYC passed")
        elif ev.event_type == "cloud_audit":
            who, target = p.get("actor_identity"), p.get("target_customer")
            self._tag(who, "support identity acting from " + ("an untrusted IP" if p.get("src_ip") else "the console"))
            if p.get("action") == "UpdateTransferLimit" and target:
                self.customer(target).limit_raised_by = who
                out.append("transfer limit raised by a support-console identity")
            else:
                out.append(f"cloud action {p.get('action')}")
        elif ev.event_type == "payee_added" and c is not None:
            payee = p.get("payee_account")
            c.payees_added.append(payee)
            self._tag(payee, "new payee")
            if p.get("payee_name_match") is False:
                self._tag(payee, "name mismatch")
            out.append("new payee added")
        elif ev.event_type == "transaction" and c is not None:
            out.append(f"transfer of {int(p.get('amount_paise', 0)) // 100:,} INR attempted")
        elif ev.event_type == "step_up_result":
            out.append(f"step-up {p.get('method')}: {p.get('result')}")
        if actor == "attacker" and ev.customer:
            self._tag(ev.customer, "under attack")
        return out
