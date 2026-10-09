"""Optional Firebase boundary (v3). OFF by default; Postgres + FraudMesh's own JWT/Argon2 auth stay primary.

Nothing here is connected to a real Firebase project in this repository: no project id, no credentials and no
firebase-admin dependency are shipped. Everything is exercised in tests with fakes.

FM_AUTH_PROVIDER = local (default) | firebase
    firebase: POST /v1/auth/firebase is mounted (api/main.py) and password login answers 403. A Firebase ID token is
    verified by verify_firebase_id_token(); principal_from_claims() maps it to an EXISTING users row by its verified
    email, and the role is the LOWER of the users row's role and the token's `fm_role` custom claim (the claim is
    required). FraudMesh then issues its own session + access token exactly as for a password login, so every other
    control (sid revocation, roles, queues, audit) is unchanged.
FM_FIREBASE_PROJECT_ID   the Firebase project; verify_firebase_id_token() raises FirebaseNotConfigured without it.
    firebase-admin is imported lazily, only then; it must be installed separately. Credentials come from Google
    Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS outside the repo, or workload identity) — never
    a service-account key in code or git (scripts/check_secrets.py fails the build on a committed private key).
FM_AUDIT_MIRROR = off (default) | firestore
    get_audit_mirror() returns a FirestoreAuditMirror; sync_audit_mirror() copies COMMITTED audit_log rows (with their
    hash-chain fields) to it. The mirror is a read-only copy for off-site retention: Postgres stays the system of
    record and /v1/audit/verify still verifies Postgres. Nothing calls sync_audit_mirror() on a schedule yet.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, Protocol

from sqlalchemy import text

from api.db import session as db

PROVIDERS = ("local", "firebase")
ROLE_RANK = {"analyst": 0, "lead": 1, "admin": 2}
ROLE_CLAIM = "fm_role"


class FirebaseNotConfigured(RuntimeError):
    pass


class FirebaseTokenInvalid(Exception):
    pass


def auth_provider() -> str:
    value = (os.getenv("FM_AUTH_PROVIDER") or "local").strip().lower()
    if value not in PROVIDERS:
        raise FirebaseNotConfigured(f"FM_AUTH_PROVIDER must be one of {', '.join(PROVIDERS)}")
    return value


# ------------------------------------------------------------------ ID-token verification
_verifier: Callable[[str], dict] | None = None        # tests inject a fake; production uses firebase-admin
_app: Any = None


def set_verifier(fn: Callable[[str], dict] | None) -> None:
    """Test hook: replace the firebase-admin verifier with a fake (None restores the real one)."""
    global _verifier
    _verifier = fn


def _firebase_admin_verify(token: str) -> dict:
    global _app
    project = (os.getenv("FM_FIREBASE_PROJECT_ID") or "").strip()
    if not project:
        raise FirebaseNotConfigured("Firebase is not configured: set FM_FIREBASE_PROJECT_ID")
    try:
        import firebase_admin                                  # optional dependency, imported only here
        from firebase_admin import auth as fb_auth
    except ImportError as e:
        raise FirebaseNotConfigured("Firebase is not configured: the firebase-admin package is not installed") from e
    if _app is None:
        _app = firebase_admin.initialize_app(options={"projectId": project}, name="fraudmesh")   # ADC credentials
    try:
        return fb_auth.verify_id_token(token, app=_app, check_revoked=True)
    except (ValueError, fb_auth.InvalidIdTokenError, fb_auth.ExpiredIdTokenError, fb_auth.RevokedIdTokenError,
            fb_auth.UserDisabledError, fb_auth.CertificateFetchError) as e:
        raise FirebaseTokenInvalid(type(e).__name__) from e


def verify_firebase_id_token(token: str) -> dict:
    """Verified claims of a Firebase ID token (signature, aud = project, iss, exp, revocation), or an exception:
    FirebaseNotConfigured (no project id / firebase-admin missing) or FirebaseTokenInvalid."""
    if not isinstance(token, str) or not token:
        raise FirebaseTokenInvalid("empty token")
    if _verifier is not None:
        return _verifier(token)
    return _firebase_admin_verify(token)


def principal_from_claims(claims: dict):
    """Map verified claims to an existing FraudMesh user. None = refuse (unknown or unverified email, missing or
    invalid role claim). Never creates users: provisioning stays an admin action in Postgres."""
    from api.security import Principal
    email = claims.get("email")
    claim_role = claims.get(ROLE_CLAIM)
    if not isinstance(email, str) or claims.get("email_verified") is not True or claim_role not in ROLE_RANK:
        return None
    with db.transaction() as c:
        row = c.execute(text("SELECT user_id, role, queues FROM users WHERE email = :e"),
                        {"e": email.strip().lower()}).mappings().first()
    if row is None:
        return None
    role = min(row["role"], claim_role, key=ROLE_RANK.__getitem__)          # least privilege of the two
    return Principal(row["user_id"], role, tuple(row["queues"]))


# ------------------------------------------------------------------ Firestore audit mirror (interface; no-op default)
class AuditMirror(Protocol):
    def mirror(self, rows: list[dict]) -> None: ...


class NoopAuditMirror:
    def mirror(self, rows: list[dict]) -> None:
        return None


class FirestoreAuditMirror:
    """Writes audit rows to Firestore collection `collection`, one document per seq. `client` is injectable (tests);
    by default firebase_admin.firestore is imported lazily (requires FM_FIREBASE_PROJECT_ID + firebase-admin)."""

    def __init__(self, collection: str = "fraudmesh_audit", client: Any = None) -> None:
        self.collection = collection
        self._client = client

    def _db(self):
        if self._client is None:
            project = (os.getenv("FM_FIREBASE_PROJECT_ID") or "").strip()
            if not project:
                raise FirebaseNotConfigured("Firestore mirror: set FM_FIREBASE_PROJECT_ID")
            try:
                import firebase_admin
                from firebase_admin import firestore
            except ImportError as e:
                raise FirebaseNotConfigured("Firestore mirror: the firebase-admin package is not installed") from e
            try:
                app = firebase_admin.get_app("fraudmesh")
            except ValueError:
                app = firebase_admin.initialize_app(options={"projectId": project}, name="fraudmesh")
            self._client = firestore.client(app)
        return self._client

    def mirror(self, rows: list[dict]) -> None:
        client = self._db()
        batch = client.batch()
        coll = client.collection(self.collection)
        for r in rows:
            batch.set(coll.document(str(r["seq"])), r)
        batch.commit()


_mirror: AuditMirror | None = None


def set_audit_mirror(m: AuditMirror | None) -> None:
    global _mirror
    _mirror = m


def get_audit_mirror() -> AuditMirror:
    if _mirror is not None:
        return _mirror
    mode = (os.getenv("FM_AUDIT_MIRROR") or "off").strip().lower()
    return FirestoreAuditMirror() if mode == "firestore" else NoopAuditMirror()


def sync_audit_mirror(mirror: AuditMirror | None = None, after_seq: int = 0, limit: int = 1000) -> int:
    """Copy committed audit rows with seq > after_seq to the mirror; returns the last seq copied (after_seq if none).
    Reads only committed data, so a rolled-back transaction never reaches the mirror."""
    m = mirror or get_audit_mirror()
    with db.transaction() as c:
        rows = c.execute(text("SELECT seq, ts, actor, action, object_id, details, prev_hash, row_hash FROM audit_log "
                              "WHERE seq > :s ORDER BY seq LIMIT :n"), {"s": after_seq, "n": max(1, min(limit, 5000))}).mappings().all()
    if not rows:
        return after_seq
    docs = [{**dict(r), "ts": r["ts"].isoformat()} for r in rows]
    m.mirror(docs)
    return docs[-1]["seq"]
