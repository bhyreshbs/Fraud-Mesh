"""Payment rails: where a transaction's FraudMesh payment outcome is mirrored onto a processor.

FraudMesh-side rail states (column payment_rail.state):  CREATED -> AUTHORIZED -> CAPTURED | VOIDED
  CREATED     the order exists at the processor but no funds are authorized yet
  AUTHORIZED  funds are authorized and held (PayPal's authorization status "CREATED"/"PENDING")
  CAPTURED    the authorization was captured (money moves)
  VOIDED      the authorization was voided (money never moves)

Two implementations of the PaymentRail protocol:
  MockPayPalRail     default, offline, deterministic, in-memory; responses are PayPal REST v2 shaped.
  PayPalSandboxRail  the real PayPal REST v2 sandbox (api-m.sandbox.paypal.com), only when configured.

Privacy: nothing sent to a rail identifies a person. The order carries the FraudMesh event_id as reference_id and a
constant description; the payee is known to the mock only as its token (acct:...) and is never sent to PayPal.

Money: FraudMesh amounts are integer paise. A rail amount is in minor units of the rail currency, converted 1:1
(150000 paise -> 150000 minor units -> "1500.00" in INR or USD). There is no FX: sandbox money is not real money,
and the 1:1 rule keeps the amounts readable. Zero-decimal currencies (JPY, HUF, TWD) are sent as whole units of
amount_paise // 100, so the displayed number still matches the rupee amount.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

import httpx

log = logging.getLogger("fraudmesh.payments")

STATES = ("CREATED", "AUTHORIZED", "CAPTURED", "VOIDED")
ZERO_DECIMAL = {"JPY", "HUF", "TWD"}
SANDBOX_BASE = "https://api-m.sandbox.paypal.com"
ORDER_DESCRIPTION = "FraudMesh payment"              # constant: never customer data


class RailError(Exception):
    """A rail call failed. `retryable` is False for business errors (e.g. capturing a voided authorization)."""

    def __init__(self, code: str, message: str = "", *, retryable: bool = False, status: int | None = None) -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code, self.retryable, self.status = code, retryable, status


def format_amount(amount_paise: int, currency: str) -> str:
    """paise -> the PayPal amount.value string for `currency` (1:1 minor units, see module docstring)."""
    if amount_paise <= 0:
        raise ValueError("amount_paise must be positive")
    if currency.upper() in ZERO_DECIMAL:
        return str(max(1, amount_paise // 100))
    return f"{amount_paise // 100}.{amount_paise % 100:02d}"


class PaymentRail(Protocol):
    name: str
    currency: str

    def authorize(self, event_id: str, amount_paise: int, currency: str | None = None,
                  payee_token: str | None = None) -> str:
        """Create an order for the event and authorize it; returns the authorization id. Idempotent per event_id."""
        ...

    def capture(self, auth_id: str, request_id: str | None = None) -> str:
        """Capture an authorization; returns the new state ("CAPTURED"). Capturing a captured one is a no-op."""
        ...

    def void(self, auth_id: str, request_id: str | None = None) -> str:
        """Void an authorization; returns the new state ("VOIDED"). Voiding a voided one is a no-op."""
        ...

    def get(self, auth_id: str) -> str:
        """The authorization's current state, one of STATES."""
        ...


# ---------------------------------------------------------------------------------------------- offline mock
@dataclass
class _MockAuth:
    order_id: str
    auth_id: str
    event_id: str
    amount: dict
    payee_token: str | None
    status: str = "AUTHORIZED"
    history: list[str] = field(default_factory=lambda: ["CREATED", "AUTHORIZED"])
    capture_id: str | None = None


def _det_id(prefix: str, *parts: str, n: int = 17) -> str:
    """PayPal ids are 17 upper-case alphanumerics; here they are derived from the event so the mock is deterministic."""
    return prefix + hashlib.sha256("|".join(parts).encode()).hexdigest().upper()[: n - len(prefix)]


class MockPayPalRail:
    """Offline stand-in for PayPal: same state machine and response shapes, no network, deterministic ids.

    State lives in memory. After a restart the service re-registers authorizations it knows from the payment_rail
    table (`restore`) so a held payment can still be captured or voided."""

    name = "mock"

    def __init__(self, currency: str = "INR") -> None:
        self.currency = currency.upper()
        self._auths: dict[str, _MockAuth] = {}
        self._by_event: dict[str, str] = {}
        self._lock = threading.Lock()
        self.calls: list[tuple[str, str]] = []              # (operation, id) — for tests and debugging

    # PayPal-shaped documents ------------------------------------------------------------------
    def order(self, event_id: str) -> dict:
        a = self._auths[self._by_event[event_id]]
        return {"id": a.order_id, "intent": "AUTHORIZE", "status": "COMPLETED",
                "purchase_units": [{"reference_id": a.event_id, "description": ORDER_DESCRIPTION, "amount": a.amount,
                                    "payments": {"authorizations": [self.authorization(a.auth_id)]}}]}

    def authorization(self, auth_id: str) -> dict:
        a = self._get(auth_id)
        paypal_status = {"AUTHORIZED": "CREATED"}.get(a.status, a.status)   # PayPal calls a live authorization CREATED
        return {"id": a.auth_id, "status": paypal_status, "amount": a.amount}

    # PaymentRail ---------------------------------------------------------------------------------
    def authorize(self, event_id: str, amount_paise: int, currency: str | None = None,
                  payee_token: str | None = None) -> str:
        cur = (currency or self.currency).upper()
        with self._lock:
            self.calls.append(("authorize", event_id))
            if event_id in self._by_event:                    # PayPal-Request-Id semantics: same event, same order
                return self._by_event[event_id]
            a = _MockAuth(order_id=_det_id("MOCKO", event_id), auth_id=_det_id("MOCKA", event_id), event_id=event_id,
                          amount={"currency_code": cur, "value": format_amount(amount_paise, cur)}, payee_token=payee_token)
            self._auths[a.auth_id] = a
            self._by_event[event_id] = a.auth_id
            return a.auth_id

    def capture(self, auth_id: str, request_id: str | None = None) -> str:
        with self._lock:
            self.calls.append(("capture", auth_id))
            a = self._get(auth_id)
            if a.status == "VOIDED":
                raise RailError("AUTHORIZATION_VOIDED", "a voided authorization cannot be captured", status=422)
            if a.status == "AUTHORIZED":
                a.status, a.capture_id = "CAPTURED", _det_id("MOCKC", auth_id)
                a.history.append("CAPTURED")
            return a.status

    def void(self, auth_id: str, request_id: str | None = None) -> str:
        with self._lock:
            self.calls.append(("void", auth_id))
            a = self._get(auth_id)
            if a.status == "CAPTURED":
                raise RailError("PREVIOUSLY_CAPTURED", "a captured authorization cannot be voided", status=422)
            if a.status == "AUTHORIZED":
                a.status = "VOIDED"
                a.history.append("VOIDED")
            return a.status

    def get(self, auth_id: str) -> str:
        with self._lock:
            return self._get(auth_id).status

    def restore(self, auth_id: str, event_id: str, state: str) -> None:
        """Re-register an authorization known from the database (process restart)."""
        with self._lock:
            if auth_id in self._auths:
                return
            self._auths[auth_id] = _MockAuth(order_id=_det_id("MOCKO", event_id), auth_id=auth_id, event_id=event_id,
                                             amount={}, payee_token=None, status=state, history=[state])
            self._by_event[event_id] = auth_id

    def _get(self, auth_id: str) -> _MockAuth:
        a = self._auths.get(auth_id)
        if a is None:
            raise RailError("RESOURCE_NOT_FOUND", "unknown authorization", status=404)
        return a


# ---------------------------------------------------------------------------------------------- PayPal sandbox
_RETRY_STATUS = {429, 500, 502, 503, 504}


class PayPalSandboxRail:
    """PayPal REST v2 (sandbox): OAuth2 client credentials -> Orders v2 (intent AUTHORIZE) -> Payments v2 capture/void.

    Flow per transaction:
      POST /v1/oauth2/token                                  (cached until expires_in - 60 s)
      POST /v2/checkout/orders            {"intent": "AUTHORIZE", ...}     PayPal-Request-Id: <event_id>
      POST /v2/checkout/orders/{id}/authorize                              PayPal-Request-Id: <event_id>-authorize
           (skipped when the create response already carries an authorization, i.e. a vaulted payment source)
      POST /v2/payments/authorizations/{auth_id}/capture                   PayPal-Request-Id: <event_id>-capture
      POST /v2/payments/authorizations/{auth_id}/void                      PayPal-Request-Id: <event_id>-void
    Note: PayPal only authorizes an order whose payer approved it. With no payer in the loop, set
    PAYPAL_VAULT_ID to a sandbox vaulted payment-method id (an opaque token) so the order is authorized server-side;
    otherwise PayPal answers 422 ORDER_NOT_APPROVED and the row records that error.

    Retries: 429 / 5xx / transport errors, up to max_retries more attempts with exponential backoff (Retry-After
    honoured, capped). A 401 drops the cached token and retries once. Secrets never appear in logs or errors."""

    name = "paypal_sandbox"

    def __init__(self, client_id: str, client_secret: str, *, currency: str = "USD", base_url: str = SANDBOX_BASE,
                 vault_id: str | None = None, timeout_s: float = 10.0, max_retries: int = 3, backoff_s: float = 0.5,
                 transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if not client_id or not client_secret:
            raise ValueError("PayPal client id and secret are required")
        self.currency = currency.upper()
        self._basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        self._vault_id = vault_id
        self._max_retries, self._backoff_s, self._sleep, self._clock = max_retries, backoff_s, sleep, clock
        self._client = httpx.Client(base_url=base_url, transport=transport,
                                    timeout=httpx.Timeout(timeout_s, connect=min(timeout_s, 5.0)))
        self._token: str | None = None
        self._token_exp = 0.0
        self._token_lock = threading.Lock()
        self._auth_event: dict[str, str] = {}

    def __repr__(self) -> str:                                  # never print credentials
        return f"PayPalSandboxRail(base_url={str(self._client.base_url)!r}, currency={self.currency!r})"

    def close(self) -> None:
        self._client.close()

    # ---------------------------------------------------------------- token
    def _access_token(self, force: bool = False) -> str:
        with self._token_lock:
            if not force and self._token and self._clock() < self._token_exp:
                return self._token
            r = self._send("POST", "/v1/oauth2/token", headers={"Authorization": f"Basic {self._basic}",
                                                                "Content-Type": "application/x-www-form-urlencoded"},
                           data={"grant_type": "client_credentials"}, op="token")
            body = r.json()
            self._token = body["access_token"]
            self._token_exp = self._clock() + max(0, int(body.get("expires_in", 0)) - 60)
            return self._token

    # ---------------------------------------------------------------- transport with retries
    def _send(self, method: str, path: str, *, op: str, **kw) -> httpx.Response:
        attempt = 0
        while True:
            try:
                r = self._client.request(method, path, **kw)
            except httpx.TransportError as e:
                if attempt >= self._max_retries:
                    raise RailError("TRANSPORT_ERROR", f"{op}: {type(e).__name__}", retryable=True) from None
                self._wait(attempt, None, op, type(e).__name__)
                attempt += 1
                continue
            if r.status_code in _RETRY_STATUS and attempt < self._max_retries:
                self._wait(attempt, r.headers.get("Retry-After"), op, str(r.status_code))
                attempt += 1
                continue
            if r.status_code >= 400:
                raise self._error(r, op)
            return r

    def _wait(self, attempt: int, retry_after: str | None, op: str, why: str) -> None:
        delay = self._backoff_s * (2 ** attempt)
        if retry_after and retry_after.isdigit():
            delay = max(delay, float(retry_after))
        delay = min(delay, 30.0)
        log.warning("paypal %s: %s, retry %d in %.1fs", op, why, attempt + 1, delay)
        self._sleep(delay)

    @staticmethod
    def _error(r: httpx.Response, op: str) -> RailError:
        try:
            body = r.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        issue = ""
        if isinstance(body.get("details"), list) and body["details"] and isinstance(body["details"][0], dict):
            issue = str(body["details"][0].get("issue", ""))
        code = issue or body.get("name") or body.get("error") or f"HTTP_{r.status_code}"   # e.g. AUTHORIZATION_VOIDED
        msg = f"{op}: HTTP {r.status_code} {body.get('name', '')}".rstrip()
        if body.get("debug_id"):
            msg += f" debug_id={body['debug_id']}"
        return RailError(str(code), msg, retryable=r.status_code in _RETRY_STATUS, status=r.status_code)

    def _api(self, method: str, path: str, *, op: str, request_id: str | None = None, json: dict | None = None) -> httpx.Response:
        for retry_auth in (False, True):
            headers = {"Authorization": f"Bearer {self._access_token(force=retry_auth)}", "Content-Type": "application/json"}
            if request_id:
                headers["PayPal-Request-Id"] = request_id
            try:
                return self._send(method, path, headers=headers, json=json, op=op)
            except RailError as e:
                if e.status == 401 and not retry_auth:              # token revoked or expired early: fetch a new one
                    continue
                raise
        raise RailError("UNAUTHENTICATED", f"{op}: token rejected")       # pragma: no cover

    # ---------------------------------------------------------------- PaymentRail
    def authorize(self, event_id: str, amount_paise: int, currency: str | None = None,
                  payee_token: str | None = None) -> str:
        cur = (currency or self.currency).upper()
        body: dict = {"intent": "AUTHORIZE",
                      "purchase_units": [{"reference_id": event_id, "description": ORDER_DESCRIPTION,
                                          "amount": {"currency_code": cur, "value": format_amount(amount_paise, cur)}}]}
        if self._vault_id:
            body["payment_source"] = {"paypal": {"vault_id": self._vault_id}}
        order = self._api("POST", "/v2/checkout/orders", op="create_order", request_id=event_id, json=body).json()
        auth = _first_authorization(order)
        if auth is None:
            order = self._api("POST", f"/v2/checkout/orders/{order['id']}/authorize", op="authorize",
                              request_id=f"{event_id}-authorize", json={}).json()
            auth = _first_authorization(order)
        if auth is None:
            raise RailError("NO_AUTHORIZATION", f"order status {order.get('status')}")
        self._auth_event[auth["id"]] = event_id
        return auth["id"]

    def capture(self, auth_id: str, request_id: str | None = None) -> str:
        rid = request_id or f"{self._auth_event.get(auth_id, auth_id)}-capture"
        try:
            self._api("POST", f"/v2/payments/authorizations/{auth_id}/capture", op="capture", request_id=rid,
                      json={"final_capture": True})
        except RailError as e:
            if e.code != "AUTHORIZATION_ALREADY_CAPTURED":       # capturing twice is a no-op, like the mock
                raise
        return "CAPTURED"

    def void(self, auth_id: str, request_id: str | None = None) -> str:
        rid = request_id or f"{self._auth_event.get(auth_id, auth_id)}-void"
        try:
            self._api("POST", f"/v2/payments/authorizations/{auth_id}/void", op="void", request_id=rid)
        except RailError as e:
            if e.code != "AUTHORIZATION_VOIDED":                  # voiding twice is a no-op, like the mock
                raise
        return "VOIDED"

    def get(self, auth_id: str) -> str:
        body = self._api("GET", f"/v2/payments/authorizations/{auth_id}", op="get").json()
        return _PAYPAL_AUTH_STATE.get(body.get("status", ""), "AUTHORIZED")


# PayPal authorization statuses -> FraudMesh rail states
_PAYPAL_AUTH_STATE = {"CREATED": "AUTHORIZED", "PENDING": "AUTHORIZED", "PARTIALLY_CAPTURED": "CAPTURED",
                      "CAPTURED": "CAPTURED", "VOIDED": "VOIDED", "DENIED": "VOIDED", "EXPIRED": "VOIDED"}


def _first_authorization(order: dict) -> dict | None:
    for pu in order.get("purchase_units") or []:
        auths = (pu.get("payments") or {}).get("authorizations") or []
        if auths:
            return auths[0]
    return None
