"""POST /v1/auth/login, /refresh, /logout (PRD §9.1) + v3 phase 6.3 session management.

Sessions are server-side (api/sessions.py): login creates one, refresh rotates its single-use refresh token (reuse ->
the session is revoked), logout revokes it, and every access token carries its `sid`, so a revoked session's tokens
stop working at once (api/security.require_live_session).

Session routes (bearer):   GET  /v1/auth/sessions                         the caller's live sessions (no secrets)
                           POST /v1/auth/sessions/revoke-all              sign the caller out everywhere
                   (admin) POST /v1/auth/users/{user_id}/sessions/revoke  sign a user out everywhere

CSRF: /refresh is authenticated by the fm_refresh cookie alone, so it (and /login, against login CSRF) checks the
request's origin: a browser request must come from an allowed origin (CORS_ORIGINS / CORS_ORIGIN_REGEX / the API's
own origin) and carry the X-FM-CSRF header (a custom header cannot be sent cross-origin without a CORS preflight,
which only the allowed origins pass). Requests with no Origin, Referer or Sec-Fetch-Site header are not from a
browser and cannot carry a victim's cookie by CSRF, so they pass (curl, scripts, tests). The cookie stays
HttpOnly + SameSite=strict (+ Secure with FM_TLS=1).
"""
from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Path, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from api import firebase_boundary, security, sessions
from api.errors import ApiError
from api.ratelimit import LOGIN_ACCOUNT_LIMIT, LOGIN_LIMIT, limiter, login_account_limited, per_ip
from api.schemas import LoginRequest, TokenResponse
from api.security import REFRESH_COOKIE, Principal, current_user, require_role
from engine.common.settings import settings

router = APIRouter(prefix="/v1/auth", tags=["auth"])
CSRF_HEADER = "x-fm-csrf"


def tls_enabled() -> bool:
    """FM_TLS=1 (set by deploy/docker-compose.yml, where the TLS proxy fronts the API): the refresh cookie is Secure.
    Off by default so the plain http://localhost dev setup keeps working."""
    return os.getenv("FM_TLS", "0").strip() == "1"


# ------------------------------------------------------------------ CSRF (origin check + custom header)
def _origin_of(url: str) -> str | None:
    try:
        u = urlsplit(url)
    except ValueError:
        return None
    return f"{u.scheme}://{u.netloc}".lower() if u.scheme and u.netloc else None


def origin_allowed(origin: str, request: Request) -> bool:
    origin = origin.rstrip("/").lower()
    if origin in {o.rstrip("/").lower() for o in settings.cors_origins}:
        return True
    regex = os.getenv("CORS_ORIGIN_REGEX")
    if regex and re.fullmatch(regex, origin):
        return True
    return origin == f"{request.url.scheme}://{request.url.netloc}".lower()      # same origin (e.g. /docs)


def check_csrf(request: Request) -> None:
    h = request.headers
    origin, referer, site = h.get("origin"), h.get("referer"), h.get("sec-fetch-site")
    if origin is None and referer is None and site is None:
        return                                                  # not a browser: no ambient cookie to abuse
    if origin is not None:
        if origin == "null" or not origin_allowed(origin, request):
            raise ApiError("FORBIDDEN", "cross-origin request refused (CSRF)")
    elif referer is not None:
        ref_origin = _origin_of(referer)
        if ref_origin is None or not origin_allowed(ref_origin, request):
            raise ApiError("FORBIDDEN", "cross-origin request refused (CSRF)")
    elif site not in ("same-origin", "same-site", "none"):
        raise ApiError("FORBIDDEN", "cross-site request refused (CSRF)")
    if h.get(CSRF_HEADER) != "1":
        raise ApiError("FORBIDDEN", "missing X-FM-CSRF header")


def _provider() -> str:
    try:
        return firebase_boundary.auth_provider()
    except firebase_boundary.FirebaseNotConfigured as e:          # a misconfigured FM_AUTH_PROVIDER fails closed
        raise ApiError("ENGINE_UNAVAILABLE", str(e), 503) from e


# ------------------------------------------------------------------ cookies + responses
def _set_refresh_cookie(resp: Response, token: str, max_age: int) -> None:
    resp.set_cookie(REFRESH_COOKIE, token, max_age=max_age, httponly=True, samesite="strict",
                    secure=tls_enabled(), path="/v1/auth")


def _clear_refresh_cookie(resp: Response) -> None:
    resp.delete_cookie(REFRESH_COOKIE, path="/v1/auth", secure=tls_enabled(), httponly=True, samesite="strict")


def _token_response(resp: Response, issued: sessions.Issued) -> TokenResponse:
    _set_refresh_cookie(resp, issued.refresh_token, issued.cookie_max_age)
    p = Principal(issued.user_id, issued.role, issued.queues, sid=issued.session_id)
    return TokenResponse(access_token=security.create_access_token(p), role=p.role)


def _user_agent(request: Request) -> str | None:
    return (request.headers.get("user-agent") or "")[:256] or None


# ------------------------------------------------------------------ login / refresh / logout
@router.post("/login", response_model=TokenResponse)
@limiter.limit(LOGIN_LIMIT, key_func=per_ip)
async def login(body: LoginRequest, request: Request, response: Response) -> TokenResponse:
    check_csrf(request)
    if _provider() != "local":
        raise ApiError("FORBIDDEN", "password sign-in is disabled (FM_AUTH_PROVIDER=firebase)")
    if login_account_limited(body.email):
        raise ApiError("RATE_LIMITED", f"too many login attempts for this account: {LOGIN_ACCOUNT_LIMIT}")
    p = await asyncio.to_thread(security.authenticate, body.email, body.password)
    store = request.app.state.store
    if p is None:
        raise ApiError("UNAUTHENTICATED", "invalid email or password")
    issued = await asyncio.to_thread(sessions.create_session, p.user_id, p.role, p.queues, user_agent=_user_agent(request))
    await asyncio.to_thread(store.append_audit, p.user_id, "LOGIN", p.user_id,
                            {"ip": "redacted", "request_id": request.state.request_id})
    return _token_response(response, issued)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, response: Response) -> TokenResponse:
    check_csrf(request)
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise ApiError("UNAUTHENTICATED", "missing refresh cookie")
    try:
        issued = await asyncio.to_thread(sessions.refresh, token)
    except sessions.SessionError as e:
        raise ApiError("UNAUTHENTICATED", "refresh token invalid or expired") from e
    return _token_response(response, issued)


@router.post("/logout", status_code=204)
async def logout(request: Request, p: Principal = Depends(current_user)) -> Response:
    await asyncio.to_thread(sessions.revoke_session, p.sid, "logout")
    cookie_sid = await asyncio.to_thread(sessions.session_of_refresh, request.cookies.get(REFRESH_COOKIE))
    if cookie_sid and cookie_sid != p.sid:
        await asyncio.to_thread(sessions.revoke_session, cookie_sid, "logout")
    resp = Response(status_code=204)
    _clear_refresh_cookie(resp)
    return resp


# ------------------------------------------------------------------ session management
class SessionInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    current: bool
    provider: str
    user_agent: str | None
    created_at: datetime
    last_used_at: datetime
    idle_expires_at: datetime
    expires_at: datetime


class SessionList(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sessions: list[SessionInfo]


class RevokedCount(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revoked: int = Field(ge=0)


@router.get("/sessions", response_model=SessionList)
async def list_sessions(p: Principal = Depends(current_user)) -> SessionList:
    rows = await asyncio.to_thread(sessions.list_active, p.user_id)
    return SessionList(sessions=[SessionInfo(current=r["session_id"] == p.sid, **r) for r in rows])


@router.post("/sessions/revoke-all", response_model=RevokedCount)
async def revoke_all(response: Response, p: Principal = Depends(current_user)) -> RevokedCount:
    n = await asyncio.to_thread(sessions.revoke_all_for_user, p.user_id, "user_revoke_all", p.user_id)
    _clear_refresh_cookie(response)
    return RevokedCount(revoked=n)


@router.post("/users/{user_id}/sessions/revoke", response_model=RevokedCount)
async def admin_revoke(user_id: str = Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_:.@-]+$"),
                       p: Principal = Depends(require_role("admin"))) -> RevokedCount:
    n = await asyncio.to_thread(sessions.revoke_all_for_user, user_id, "admin_revoke", p.user_id)
    return RevokedCount(revoked=n)


# ------------------------------------------------------------------ optional Firebase sign-in (FM_AUTH_PROVIDER=firebase)
firebase_router = APIRouter(prefix="/v1/auth", tags=["auth"])


class FirebaseLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id_token: str = Field(min_length=20, max_length=4096)


@firebase_router.post("/firebase", response_model=TokenResponse)
@limiter.limit(LOGIN_LIMIT, key_func=per_ip)
async def firebase_login(body: FirebaseLoginRequest, request: Request, response: Response) -> TokenResponse:
    """Mounted only when FM_AUTH_PROVIDER=firebase (api/main.py). A verified Firebase ID token maps to an EXISTING
    users row by verified email; the role is the lower of the row's role and the token's fm_role claim."""
    check_csrf(request)
    try:
        claims = await asyncio.to_thread(firebase_boundary.verify_firebase_id_token, body.id_token)
    except firebase_boundary.FirebaseNotConfigured as e:
        raise ApiError("ENGINE_UNAVAILABLE", str(e), 503) from e
    except firebase_boundary.FirebaseTokenInvalid as e:
        raise ApiError("UNAUTHENTICATED", "invalid Firebase ID token") from e
    p = await asyncio.to_thread(firebase_boundary.principal_from_claims, claims)
    if p is None:
        raise ApiError("UNAUTHENTICATED", "no FraudMesh user for this Firebase identity")
    issued = await asyncio.to_thread(sessions.create_session, p.user_id, p.role, p.queues,
                                     user_agent=_user_agent(request), provider="firebase")
    await asyncio.to_thread(request.app.state.store.append_audit, p.user_id, "LOGIN", p.user_id,
                            {"ip": "redacted", "provider": "firebase", "request_id": request.state.request_id})
    return _token_response(response, issued)
