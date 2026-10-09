"""Optional Firebase boundary (api/firebase_boundary.py): off by default, fake verifier and fake Firestore client only.
firebase-admin is not required (and not installed in CI)."""
from __future__ import annotations

import importlib.util

import pytest
from fastapi.testclient import TestClient

from api import firebase_boundary as fb


@pytest.fixture(autouse=True)
def _reset():
    yield
    fb.set_verifier(None)
    fb.set_audit_mirror(None)


def _claims(email="lead@fraudmesh.local", role="lead", verified=True):
    return {"email": email, "email_verified": verified, "fm_role": role, "uid": "fb-uid-1"}


def test_defaults_are_local_and_not_configured(monkeypatch):
    monkeypatch.delenv("FM_AUTH_PROVIDER", raising=False)
    monkeypatch.delenv("FM_FIREBASE_PROJECT_ID", raising=False)
    assert fb.auth_provider() == "local"
    with pytest.raises(fb.FirebaseNotConfigured, match="FM_FIREBASE_PROJECT_ID"):
        fb.verify_firebase_id_token("x" * 40)
    monkeypatch.setenv("FM_AUTH_PROVIDER", "okta")
    with pytest.raises(fb.FirebaseNotConfigured):
        fb.auth_provider()
    assert isinstance(fb.get_audit_mirror(), fb.NoopAuditMirror)


@pytest.mark.skipif(importlib.util.find_spec("firebase_admin") is not None, reason="firebase-admin installed")
def test_missing_package_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("FM_FIREBASE_PROJECT_ID", "demo-project")
    with pytest.raises(fb.FirebaseNotConfigured, match="firebase-admin"):
        fb.verify_firebase_id_token("x" * 40)


def test_claims_mapping_is_least_privilege(client):
    p = fb.principal_from_claims(_claims(role="admin"))              # db role lead, claim admin -> lead
    assert p.user_id == "usr_lead" and p.role == "lead"
    p = fb.principal_from_claims(_claims(email="ADMIN@fraudmesh.local", role="analyst"))
    assert p.user_id == "usr_admin" and p.role == "analyst"
    for bad in (_claims(verified=False), _claims(role=None), _claims(role="root"), _claims(email="nobody@x.io"),
                {"email_verified": True, "fm_role": "lead"}):
        assert fb.principal_from_claims(bad) is None


def test_firebase_mode_app(monkeypatch):
    monkeypatch.setenv("FM_AUTH_PROVIDER", "firebase")
    import api.main
    app = api.main.create_app()
    tokens = {"good-token-aaaaaaaaaaaaaaaa": _claims(), "unknown-user-aaaaaaaaaaa": _claims(email="nobody@x.io")}

    def fake(token: str) -> dict:
        if token not in tokens:
            raise fb.FirebaseTokenInvalid("bad")
        return tokens[token]
    fb.set_verifier(fake)
    with TestClient(app) as c:
        r = c.post("/v1/auth/login", json={"email": "lead@fraudmesh.local", "password": "test-password-123"})
        assert r.status_code == 403                                     # password sign-in disabled in firebase mode
        assert c.post("/v1/auth/firebase", json={"id_token": "forged-token-aaaaaaaaaaaa"}).status_code == 401
        assert c.post("/v1/auth/firebase", json={"id_token": "unknown-user-aaaaaaaaaaa"}).status_code == 401
        r = c.post("/v1/auth/firebase", json={"id_token": "good-token-aaaaaaaaaaaaaaaa"})
        assert r.status_code == 200 and r.json()["role"] == "lead"
        assert c.get("/v1/cases", headers={"Authorization": "Bearer " + r.json()["access_token"]}).status_code == 200
        assert c.post("/v1/auth/refresh").status_code == 200            # same FraudMesh session machinery


def test_firebase_route_absent_by_default(client):
    assert client.post("/v1/auth/firebase", json={"id_token": "x" * 40}).status_code == 404


class _FakeFirestore:
    def __init__(self):
        self.docs: dict[str, dict] = {}

    def collection(self, name):
        class _C:
            def document(self, doc_id):
                return (name, doc_id)
        return _C()

    def batch(self):
        store = self

        class _B:
            def __init__(self):
                self.ops = []

            def set(self, ref, data):
                self.ops.append((ref, data))

            def commit(self):
                for (coll, doc_id), data in self.ops:
                    store.docs[f"{coll}/{doc_id}"] = data
        return _B()


def test_firestore_audit_mirror_with_a_fake_client(client, auth_headers):
    auth_headers("lead")                                               # one LOGIN audit row
    fake = _FakeFirestore()
    mirror = fb.FirestoreAuditMirror(collection="audit", client=fake)
    last = fb.sync_audit_mirror(mirror, after_seq=0)
    assert last >= 1 and f"audit/{last}" in fake.docs
    doc = fake.docs[f"audit/{last}"]
    assert doc["action"] == "LOGIN" and len(doc["row_hash"]) == 64 and isinstance(doc["ts"], str)
    assert fb.sync_audit_mirror(mirror, after_seq=last) == last         # nothing new
