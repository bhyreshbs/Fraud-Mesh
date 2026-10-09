"""POST /v1/auth/login, /refresh, /logout (PRD §9.1)."""
from __future__ import annotations

import asyncio
import os

from fastapi import APIRouter, Depends, Request, Response

from api import security
from api.errors import ApiError
from api.ratelimit import LOGIN_ACCOUNT_LIMIT, LOGIN_LIMIT, limiter, login_account_limited, per_ip
from api.schemas import LoginRequest, TokenResponse
from api.security import REFRESH_COOKIE, REFRESH_TTL_S, Principal, current_user

router = APIRouter(prefix="/v1/auth", tags=["auth"])


def tls_enabled() -> bool:
    """FM_TLS=1 (set by deploy/docker-compose.yml, where the TLS proxy fronts the API): the refresh cookie is Secure.
    Off by default so the plain http://localhost dev setup keeps working."""
    return os.getenv("FM_TLS", "0").strip() == "1"


def _set_refresh_cookie(resp: Response, token: str) -> None:
    resp.set_cookie(REFRESH_COOKIE, token, max_age=REFRESH_TTL_S, httponly=True, samesite="strict",
                    secure=tls_enabled(), path="/v1/auth")


def _token_response(resp: Response, p: Principal, refresh: str) -> TokenResponse:
    _set_refresh_cookie(resp, refresh)
    return TokenResponse(access_token=security.create_access_token(p), role=p.role)


@router.post("/login", response_model=TokenResponse)
@limiter.limit(LOGIN_LIMIT, key_func=per_ip)
async def login(body: LoginRequest, request: Request, response: Response) -> TokenResponse:
    if login_account_limited(body.email):
        raise ApiError("RATE_LIMITED", f"too many login attempts for this account: {LOGIN_ACCOUNT_LIMIT}")
    p = await asyncio.to_thread(security.authenticate, body.email, body.password)
    store = request.app.state.store
    if p is None:
        raise ApiError("UNAUTHENTICATED", "invalid email or password")
    await asyncio.to_thread(store.append_audit, p.user_id, "LOGIN", p.user_id,
                            {"ip": "redacted", "request_id": request.state.request_id})
    return _token_response(response, p, security.issue_refresh(p.user_id))


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, response: Response) -> TokenResponse:
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise ApiError("UNAUTHENTICATED", "missing refresh cookie")
    user_id, new_token = security.rotate_refresh(token)
    p = await asyncio.to_thread(security.load_principal, user_id)
    if p is None:
        security.revoke_refresh(new_token)
        raise ApiError("UNAUTHENTICATED", "user no longer exists")
    return _token_response(response, p, new_token)


@router.post("/logout", status_code=204)
async def logout(request: Request, p: Principal = Depends(current_user)) -> Response:
    security.revoke_refresh(request.cookies.get(REFRESH_COOKIE))
    resp = Response(status_code=204)
    resp.delete_cookie(REFRESH_COOKIE, path="/v1/auth", secure=tls_enabled(), httponly=True, samesite="strict")
    return resp
