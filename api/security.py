"""JWT, Argon2id, roles (PRD §9.1, §15.1 task 5). Headers and rate limits live in api/middleware.py and api/ratelimit.py."""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, Request
from sqlalchemy import text

from api import keys
from api.db import session
from api.errors import ApiError
from engine.common.settings import settings

ACCESS_TTL_S = 900
REFRESH_TTL_S = 8 * 3600
REFRESH_COOKIE = "fm_refresh"
ROLE_RANK = {"analyst": 0, "lead": 1, "admin": 2}

_hasher = PasswordHasher()          # argon2-cffi defaults to Argon2id
_DUMMY_HASH = _hasher.hash("fraudmesh-timing-equaliser")


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: str
    queues: tuple[str, ...]
    expires_at: datetime | None = None          # the access token's exp (set when decoded from a token)


# ------------------------------------------------------------------ passwords
def hash_password(pw: str) -> str:
    return _hasher.hash(pw)


def verify_password(pw_hash: str, pw: str) -> bool:
    try:
        return _hasher.verify(pw_hash, pw)
    except (VerificationError, InvalidHashError):
        return False


def authenticate(email: str, password: str) -> Principal | None:
    with session.transaction() as c:
        row = c.execute(text("SELECT user_id, pw_hash, role, queues FROM users WHERE email = :e"),
                        {"e": email.strip().lower()}).mappings().first()
    if row is None:
        verify_password(_DUMMY_HASH, password)        # same work either way: no user-enumeration timing signal
        return None
    if not verify_password(row["pw_hash"], password):
        return None
    return Principal(row["user_id"], row["role"], tuple(row["queues"]))


def load_principal(user_id: str) -> Principal | None:
    with session.transaction() as c:
        row = c.execute(text("SELECT user_id, role, queues FROM users WHERE user_id = :u"), {"u": user_id}).mappings().first()
    return Principal(row["user_id"], row["role"], tuple(row["queues"])) if row else None


# ------------------------------------------------------------------ access tokens (15 min; HS256 default, EdDSA opt-in)
# FM_JWT_ALG=HS256 (default, PRD §9.1, JWT_SECRET) or EdDSA (Ed25519 keys at FM_JWT_PRIVATE_KEY / FM_JWT_PUBLIC_KEY,
# default data/keys/jwt.key|.pub from scripts/make_certs.py). Read at call time. Decoding accepts ONLY the configured
# algorithm, so an HS256 token is refused in EdDSA mode and vice versa (no algorithm confusion).
JWT_ALGS = ("HS256", "EdDSA")
JWT_ISSUER = "fraudmesh"


def jwt_alg() -> str:
    alg = (os.getenv("FM_JWT_ALG") or "HS256").strip()
    if alg not in JWT_ALGS:
        raise ApiError("ENGINE_UNAVAILABLE", f"FM_JWT_ALG must be one of {', '.join(JWT_ALGS)}", 503)
    return alg


def _secret() -> str:
    if not settings.jwt_secret:
        raise ApiError("ENGINE_UNAVAILABLE", "JWT_SECRET is not configured", 503)
    return settings.jwt_secret


def _signing_key(alg: str):
    if alg == "HS256":
        return _secret()
    key = keys.jwt_private_key()
    if key is None:
        raise ApiError("ENGINE_UNAVAILABLE", "FM_JWT_ALG=EdDSA but the JWT private key is missing", 503)
    return key


def _verifying_key(alg: str):
    if alg == "HS256":
        return _secret()
    key = keys.jwt_public_key()
    if key is None:
        raise ApiError("ENGINE_UNAVAILABLE", "FM_JWT_ALG=EdDSA but the JWT public key is missing", 503)
    return key


def create_access_token(p: Principal) -> str:
    now = datetime.now(UTC)
    alg = jwt_alg()
    claims = {"iss": JWT_ISSUER, "sub": p.user_id, "role": p.role, "queues": list(p.queues), "iat": now,
              "exp": now + timedelta(seconds=ACCESS_TTL_S)}
    return jwt.encode(claims, _signing_key(alg), algorithm=alg)


def decode_access_token(token: str) -> Principal:
    alg = jwt_alg()
    try:
        c = jwt.decode(token, _verifying_key(alg), algorithms=[alg], issuer=JWT_ISSUER,
                       options={"require": ["iss", "sub", "role", "exp"]})
    except jwt.PyJWTError as e:
        raise ApiError("UNAUTHENTICATED", "invalid or expired token") from e
    if c.get("role") not in ROLE_RANK:
        raise ApiError("UNAUTHENTICATED", "invalid token role")
    return Principal(c["sub"], c["role"], tuple(c.get("queues") or ("default",)), datetime.fromtimestamp(c["exp"], UTC))


# ------------------------------------------------------------------ refresh tokens (rotating; SHA-256 hashes in memory)
_refresh: dict[str, tuple[str, datetime]] = {}
_refresh_lock = threading.Lock()


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_refresh(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    with _refresh_lock:
        for h in [h for h, (_, exp) in _refresh.items() if exp < now]:   # tokens that were never used again
            del _refresh[h]
        _refresh[_h(token)] = (user_id, now + timedelta(seconds=REFRESH_TTL_S))
    return token


def rotate_refresh(token: str) -> tuple[str, str]:
    """Consume a refresh token (single use) and return (user_id, new_token)."""
    with _refresh_lock:
        entry = _refresh.pop(_h(token), None)
    if entry is None or entry[1] < datetime.now(UTC):
        raise ApiError("UNAUTHENTICATED", "refresh token invalid or expired")
    return entry[0], issue_refresh(entry[0])


def revoke_refresh(token: str | None) -> None:
    if token:
        with _refresh_lock:
            _refresh.pop(_h(token), None)


# ------------------------------------------------------------------ dependencies
def current_user(request: Request) -> Principal:
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ApiError("UNAUTHENTICATED", "missing bearer token")
    p = decode_access_token(token)
    request.state.user_id = p.user_id
    return p


def require_role(min_role: str):
    def _dep(p: Principal = Depends(current_user)) -> Principal:
        if ROLE_RANK[p.role] < ROLE_RANK[min_role]:
            raise ApiError("FORBIDDEN", f"requires role {min_role} or higher")
        return p
    return _dep
