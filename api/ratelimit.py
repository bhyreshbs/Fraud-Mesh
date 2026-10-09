"""Rate limits (PRD §9.7, slowapi): ingestion 100/s per source (and client IP); other routes 20/s per user; login 5/min per
IP, plus 10/min per account.

Routes with their own @limiter.limit(...) (ingestion, login) use only that limit. Every other /v1 HTTP route gets the
default 20/s through default_limit_exceeded(), called from a middleware in api/main.py. (slowapi's own
SlowAPIMiddleware cannot see endpoints behind FastAPI's included routers in current versions, so it is not used.)
Users are identified by the JWT `sub`; unauthenticated callers by client IP. Counters live in slowapi's storage, so
limiter.reset() clears both kinds.
"""
from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse
from limits import parse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from api.errors import error_response

INGEST_LIMIT = "100/second"
DEFAULT_LIMIT = "20/second"
LOGIN_LIMIT = "5/minute"
LOGIN_ACCOUNT_LIMIT = "10/minute"     # per account, so many IPs cannot share one password-guessing budget


def user_or_ip(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        from api.security import decode_access_token
        try:
            return "user:" + decode_access_token(auth[7:]).user_id
        except Exception:
            pass
    return "ip:" + get_remote_address(request)


def per_source(request: Request) -> str:
    """Per source AND client IP. The limit runs before the signature check, so X-FM-Source is still unverified here:
    keyed on the header alone, anyone could send junk with a real sender's source name and use up its budget."""
    return "source:" + request.headers.get("x-fm-source", "unknown") + "|ip:" + get_remote_address(request)


def per_ip(request: Request) -> str:
    return "ip:" + get_remote_address(request)


limiter = Limiter(key_func=user_or_ip, storage_uri="memory://", headers_enabled=False)
_DEFAULT_ITEM = parse(DEFAULT_LIMIT)
_LOGIN_ACCOUNT_ITEM = parse(LOGIN_ACCOUNT_LIMIT)
OWN_LIMIT_PATHS = {"/v1/events", "/v1/events/batch", "/v1/auth/login"}


def default_limit_exceeded(request: Request) -> bool:
    """True when this request is over the default 20/s budget of its user (or IP)."""
    path = request.url.path
    if not limiter.enabled or request.method == "OPTIONS" or not path.startswith("/v1/") or path in OWN_LIMIT_PATHS:
        return False
    return not limiter.limiter.hit(_DEFAULT_ITEM, "default", user_or_ip(request))


def login_account_limited(email: str) -> bool:
    """True when this account has used up its login attempts (counted for every attempt, from any IP)."""
    return limiter.enabled and not limiter.limiter.hit(_LOGIN_ACCOUNT_ITEM, "login-account", email.strip().lower())


def rate_limited_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    resp = error_response(request, "RATE_LIMITED", f"rate limit exceeded: {exc.detail}", 429)
    resp.headers["Retry-After"] = "1"
    return resp
