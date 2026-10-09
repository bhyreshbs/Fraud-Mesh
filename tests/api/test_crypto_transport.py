"""Opt-in asymmetric crypto and transport security (docs/CONTRACT_REQUESTS.md 2026-10-10, README "Transport security
and keys"): Ed25519 ingestion signatures, FM_INGEST_AUTH, EdDSA access tokens, the proxy's client-certificate headers,
the Secure refresh cookie, scripts/make_certs.py and scripts/tls.py. HMAC and HS256 stay the defaults."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ssl
import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from api import keys, security
from api.routers.ingest import server_headers, verify_signature
from engine.common.ids import new_id
from engine.common.settings import settings
from scripts import make_certs, tls
from scripts.sign import sign
from tests.api.conftest import TEST_PASSWORD

SOURCES = make_certs.SOURCES


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    out = tmp_path_factory.mktemp("fmpki")
    make_certs.make_all(out, say=lambda *_: None)
    return out


@pytest.fixture
def ed_env(monkeypatch, pki):
    """Senders sign Ed25519 with the generated keys; the API verifies with the matching public keys."""
    monkeypatch.setenv("FM_SIGN_ALG", "ed25519")
    monkeypatch.setenv("FM_SIGNING_KEY_DIR", str(pki / "keys"))
    monkeypatch.setenv("FM_SIGNING_PUBLIC_KEY_DIR", str(pki / "keys"))
    return pki


def _login_env(source: str = "demo-bank-web") -> dict:
    return {"event_id": new_id("evt"), "event_type": "login", "source": source, "occurred_at": "2026-10-09T00:41:07+05:30",
            "subject": {"customer_ref": "C-1042", "account_ref": "A-88213"},
            "context": {"ip": "185.220.101.7", "device_id": "fp_attacker_01"},
            "payload": {"result": "success", "auth_method": "password"}}


def _post(client, env: dict | None = None, headers: dict | None = None, body: bytes | None = None, extra: dict | None = None):
    env = env or _login_env()
    raw = json.dumps(env).encode()
    h = headers if headers is not None else sign(env["source"], raw)
    return client.post("/v1/events", content=body if body is not None else raw, headers={**h, **(extra or {})})


def _code(r) -> str:
    return r.json()["error"]["code"]


# ------------------------------------------------------------------ Ed25519 ingestion signatures
def test_ed25519_signed_event_is_accepted(client, ed_env):
    raw = json.dumps(env := _login_env()).encode()
    h = sign("demo-bank-web", raw)
    assert h["X-FM-Signature-Alg"] == "ed25519" and len(h["X-FM-Signature"]) == 128
    r = client.post("/v1/events", content=raw, headers=h)
    assert r.status_code == 202, r.text
    assert r.json()["event_id"] == env["event_id"]


def test_ed25519_tampered_body_is_rejected(client, ed_env):
    env = _login_env()
    h = sign("demo-bank-web", json.dumps(env).encode())
    tampered = json.dumps({**env, "payload": {"result": "failure", "auth_method": "password"}}).encode()
    r = _post(client, env, headers=h, body=tampered)
    assert r.status_code == 401 and _code(r) == "SIGNATURE_INVALID"


def test_ed25519_wrong_key_is_rejected(client, ed_env, tmp_path):
    other = Ed25519PrivateKey.generate()                     # not the key whose .pub the API holds
    raw = json.dumps(_login_env()).encode()
    r = _post(client, headers=keys.ed25519_signed_headers("demo-bank-web", other, raw), body=raw)
    assert r.status_code == 401 and _code(r) == "SIGNATURE_INVALID"
    # another source's (valid) key does not sign for this source either
    r = _post(client, headers=keys.ed25519_signed_headers("demo-bank-web", keys.private_key("simulator"), raw), body=raw)
    assert r.status_code == 401 and _code(r) == "SIGNATURE_INVALID"


def test_ed25519_without_public_key_is_rejected(client, ed_env, monkeypatch, tmp_path):
    raw = json.dumps(_login_env()).encode()
    h = sign("demo-bank-web", raw)
    monkeypatch.setenv("FM_SIGNING_PUBLIC_KEY_DIR", str(tmp_path))          # empty dir: no demo-bank-web.pub
    r = _post(client, headers=h, body=raw)
    assert r.status_code == 401 and _code(r) == "SIGNATURE_INVALID"


def test_ed25519_stale_timestamp(client, ed_env):
    raw = json.dumps(_login_env()).encode()
    h = keys.ed25519_signed_headers("demo-bank-web", keys.private_key("demo-bank-web"), raw, int(time.time()) - 301)
    r = _post(client, headers=h, body=raw)
    assert r.status_code == 401 and _code(r) == "STALE_TIMESTAMP"


def test_ingest_auth_ed25519_rejects_hmac(client, ed_env, monkeypatch):
    monkeypatch.setenv("FM_INGEST_AUTH", "ed25519")
    monkeypatch.setenv("FM_SIGN_ALG", "hmac")
    r = _post(client)
    assert r.status_code == 401 and _code(r) == "SIGNATURE_INVALID"
    monkeypatch.setenv("FM_SIGN_ALG", "ed25519")
    assert _post(client).status_code == 202


def test_hmac_is_still_accepted_by_default(client, monkeypatch):
    monkeypatch.delenv("FM_INGEST_AUTH", raising=False)
    monkeypatch.delenv("FM_SIGN_ALG", raising=False)
    raw = json.dumps(_login_env()).encode()
    h = sign("demo-bank-web", raw)
    assert "X-FM-Signature-Alg" not in h
    assert client.post("/v1/events", content=raw, headers=h).status_code == 202
    # an explicit "hmac" algorithm header is the same rule
    raw = json.dumps(_login_env()).encode()
    assert client.post("/v1/events", content=raw, headers={**sign("demo-bank-web", raw), "X-FM-Signature-Alg": "hmac"}).status_code == 202


def test_ingest_auth_hmac_rejects_ed25519_and_unknown_algorithms(client, ed_env, monkeypatch):
    monkeypatch.setenv("FM_INGEST_AUTH", "hmac")
    r = _post(client)
    assert r.status_code == 401 and _code(r) == "SIGNATURE_INVALID"
    monkeypatch.delenv("FM_INGEST_AUTH")
    raw = json.dumps(_login_env()).encode()
    r = _post(client, headers={**sign("demo-bank-web", raw), "X-FM-Signature-Alg": "rsa"}, body=raw)
    assert r.status_code == 401 and _code(r) == "SIGNATURE_INVALID"


def test_sign_falls_back_to_hmac_without_a_key(monkeypatch, tmp_path):
    monkeypatch.setenv("FM_SIGN_ALG", "ed25519")
    monkeypatch.setenv("FM_SIGNING_KEY_DIR", str(tmp_path))
    h = sign("demo-bank-web", b"{}", 1700000000)
    assert "X-FM-Signature-Alg" not in h
    from api.signing import signature
    assert h["X-FM-Signature"] == signature(settings.hmac_secrets["demo-bank-web"], "1700000000", b"{}")


def test_key_files_are_only_looked_up_for_known_sources(ed_env):
    assert keys.public_key("demo-bank-web") is not None
    assert keys.public_key("../keys/jwt") is None and keys.private_key("jwt") is None


def test_server_side_signing_follows_the_mode(ed_env, monkeypatch):
    body = b'{"x":1}'
    h = server_headers("demo-bank-web", body)
    assert h["X-FM-Signature-Alg"] == "ed25519"
    assert verify_signature({k.lower(): v for k, v in h.items()}, body) == "demo-bank-web"
    monkeypatch.setenv("FM_INGEST_AUTH", "hmac")                     # HMAC only: the server signs HMAC
    h = server_headers("demo-bank-web", body)
    assert "X-FM-Signature-Alg" not in h
    assert verify_signature({k.lower(): v for k, v in h.items()}, body) == "demo-bank-web"
    monkeypatch.setenv("FM_INGEST_AUTH", "ed25519")
    monkeypatch.setenv("FM_SIGNING_KEY_DIR", str(ed_env / "certs"))  # no Ed25519 key here: refuse rather than sign HMAC
    with pytest.raises(Exception) as e:
        server_headers("demo-bank-web", body)
    assert getattr(e.value, "code", "") == "ENGINE_UNAVAILABLE"


def test_demo_emit_works_in_ed25519_only_mode(client, ed_env, monkeypatch):
    monkeypatch.setenv("FM_INGEST_AUTH", "ed25519")
    r = client.post("/v1/demo/emit", json={"event_type": "login", "subject": {"customer_ref": "C-1042", "account_ref": "A-88213"},
                                           "context": {"device_id": "fp_priya_phone"},
                                           "payload": {"result": "success", "auth_method": "password"}})
    assert r.status_code in (200, 202), r.text


# ------------------------------------------------------------------ client certificate (FM_REQUIRE_CLIENT_CERT=1)
@pytest.mark.parametrize("extra", [
    {},                                                                                     # header missing
    {"X-Client-Cert-Verify": "NONE", "X-Client-Cert-DN": "CN=demo-bank-web,O=FraudMesh Demo"},
    {"X-Client-Cert-Verify": "FAILED:certificate has expired", "X-Client-Cert-DN": "CN=demo-bank-web,O=FraudMesh Demo"},
    {"X-Client-Cert-Verify": "SUCCESS", "X-Client-Cert-DN": "CN=cloud-audit,O=FraudMesh Demo"},  # CN != X-FM-Source
    {"X-Client-Cert-Verify": "SUCCESS", "X-Client-Cert-DN": "O=FraudMesh Demo"},              # no CN
])
def test_client_cert_required_rejects(client, monkeypatch, extra):
    monkeypatch.setenv("FM_REQUIRE_CLIENT_CERT", "1")
    r = _post(client, extra=extra)
    assert r.status_code == 401 and _code(r) == "SIGNATURE_INVALID"


def test_client_cert_required_accepts_matching_cn(client, monkeypatch):
    monkeypatch.setenv("FM_REQUIRE_CLIENT_CERT", "1")
    ok = {"X-Client-Cert-Verify": "SUCCESS", "X-Client-Cert-DN": "CN=demo-bank-web,O=FraudMesh Demo"}
    assert _post(client, extra=ok).status_code == 202
    batch = json.dumps({"events": [_login_env(), _login_env()]}).encode()
    r = client.post("/v1/events/batch", content=batch, headers=sign("demo-bank-web", batch))
    assert r.status_code == 401 and _code(r) == "SIGNATURE_INVALID"
    r = client.post("/v1/events/batch", content=batch, headers={**sign("demo-bank-web", batch), **ok})
    assert r.status_code == 202 and r.json()["accepted"] == 2


def test_client_cert_not_checked_by_default(client, monkeypatch):
    monkeypatch.delenv("FM_REQUIRE_CLIENT_CERT", raising=False)
    assert _post(client).status_code == 202


def test_client_cert_cn_parsing():
    assert keys.client_cert_cn("CN=network-ids,O=FraudMesh Demo") == "network-ids"
    assert keys.client_cert_cn("/O=FraudMesh Demo/CN=network-ids") == "network-ids"           # legacy nginx format
    assert keys.client_cert_cn("O=evil\\,CN=network-ids") is None                              # escaped: not an RDN
    assert keys.client_cert_cn("CN=a,CN=b") is None
    assert keys.client_cert_cn("") is None


# ------------------------------------------------------------------ EdDSA access tokens
@pytest.fixture
def eddsa(monkeypatch, pki):
    def on() -> None:
        monkeypatch.setenv("FM_JWT_ALG", "EdDSA")
        monkeypatch.setenv("FM_JWT_PRIVATE_KEY", str(pki / "keys" / "jwt.key"))
        monkeypatch.setenv("FM_JWT_PUBLIC_KEY", str(pki / "keys" / "jwt.pub"))
    return on


def _login(client) -> str:
    r = client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": TEST_PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_eddsa_round_trip(client, eddsa):
    eddsa()
    token = _login(client)
    assert jwt.get_unverified_header(token)["alg"] == "EdDSA"
    assert jwt.decode(token, options={"verify_signature": False})["iss"] == "fraudmesh"
    assert client.get("/v1/cases", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert security.decode_access_token(token).user_id == "usr_analyst"


def test_hs256_token_rejected_when_eddsa_configured(client, eddsa):
    hs = _login(client)                                            # default: HS256
    assert jwt.get_unverified_header(hs)["alg"] == "HS256"
    eddsa()
    r = client.get("/v1/cases", headers={"Authorization": f"Bearer {hs}"})
    assert r.status_code == 401 and _code(r) == "UNAUTHENTICATED"


def test_eddsa_token_rejected_when_hs256_configured(client, eddsa, monkeypatch):
    eddsa()
    ed = _login(client)
    monkeypatch.setenv("FM_JWT_ALG", "HS256")
    r = client.get("/v1/cases", headers={"Authorization": f"Bearer {ed}"})
    assert r.status_code == 401 and _code(r) == "UNAUTHENTICATED"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def test_no_algorithm_confusion_with_the_public_key(eddsa, pki):
    """Classic attack: HS256 'signed' with the EdDSA public key as the HMAC secret must not verify."""
    eddsa()
    now = int(time.time())
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = _b64(json.dumps({"iss": "fraudmesh", "sub": "usr_admin", "role": "admin", "queues": ["default"],
                              "iat": now, "exp": now + 600}).encode())
    pub_pem = (pki / "keys" / "jwt.pub").read_bytes()
    sig = _b64(hmac.new(pub_pem, f"{header}.{claims}".encode(), hashlib.sha256).digest())
    with pytest.raises(Exception) as e:
        security.decode_access_token(f"{header}.{claims}.{sig}")
    assert getattr(e.value, "code", "") == "UNAUTHENTICATED"
    unsigned = f"{_b64(json.dumps({'alg': 'none'}).encode())}.{claims}."
    with pytest.raises(Exception) as e:
        security.decode_access_token(unsigned)
    assert getattr(e.value, "code", "") == "UNAUTHENTICATED"


def test_token_without_issuer_is_rejected():
    now = datetime.now(UTC)
    token = jwt.encode({"sub": "usr_analyst", "role": "analyst", "queues": ["default"], "iat": now,
                        "exp": now + timedelta(minutes=5)}, settings.jwt_secret, algorithm="HS256")
    with pytest.raises(Exception) as e:
        security.decode_access_token(token)
    assert getattr(e.value, "code", "") == "UNAUTHENTICATED"


def test_eddsa_missing_key_is_503(client, monkeypatch, tmp_path):
    monkeypatch.setenv("FM_JWT_ALG", "EdDSA")
    monkeypatch.setenv("FM_JWT_PRIVATE_KEY", str(tmp_path / "nope.key"))
    r = client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": TEST_PASSWORD})
    assert r.status_code == 503 and _code(r) == "ENGINE_UNAVAILABLE"


# ------------------------------------------------------------------ Secure refresh cookie (FM_TLS=1)
def test_refresh_cookie_secure_only_with_tls(client, monkeypatch):
    monkeypatch.delenv("FM_TLS", raising=False)
    r = client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": TEST_PASSWORD})
    assert "secure" not in r.headers["set-cookie"].lower()
    monkeypatch.setenv("FM_TLS", "1")
    r = client.post("/v1/auth/login", json={"email": "analyst@fraudmesh.local", "password": TEST_PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie


# ------------------------------------------------------------------ scripts/make_certs.py
def _cert(path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_make_certs_chain_verifies(pki):
    ca = _cert(pki / "certs" / "ca.crt")
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    server = _cert(pki / "certs" / "server.crt")
    server.verify_directly_issued_by(ca)
    sans = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert {"localhost", "api", "web", "bank", "db", "proxy"} <= set(sans.get_values_for_type(x509.DNSName))
    assert "127.0.0.1" in {str(i) for i in sans.get_values_for_type(x509.IPAddress)}
    assert ExtendedKeyUsageOID.SERVER_AUTH in server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    for s in SOURCES:
        c = _cert(pki / "certs" / f"{s}.crt")
        c.verify_directly_issued_by(ca)
        assert c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == s
        assert ExtendedKeyUsageOID.CLIENT_AUTH in c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        pub = serialization.load_pem_public_key((pki / "keys" / f"{s}.pub").read_bytes())
        priv = serialization.load_pem_private_key((pki / "keys" / f"{s}.key").read_bytes(), password=None)
        pub.verify(priv.sign(b"m"), b"m")                                  # the pair matches


def test_mutual_tls_handshake_with_generated_certs(pki):
    """A real TLS 1.3 handshake in memory: the client checks the server cert and hostname against the CA, the server
    requires and verifies the client cert, and the peer CN is the source name."""
    certs = pki / "certs"
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(certs / "server.crt", certs / "server.key")
    sctx.load_verify_locations(certs / "ca.crt")
    sctx.verify_mode = ssl.CERT_REQUIRED
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.load_verify_locations(certs / "ca.crt")
    cctx.load_cert_chain(certs / "network-ids.crt", certs / "network-ids.key")
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    client_tls = cctx.wrap_bio(c_in, c_out, server_hostname="localhost")
    server_tls = sctx.wrap_bio(s_in, s_out, server_side=True)
    done = {"c": False, "s": False}
    for _ in range(20):
        for name, end in (("c", client_tls), ("s", server_tls)):
            if not done[name]:
                try:
                    end.do_handshake()
                    done[name] = True
                except ssl.SSLWantReadError:
                    pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if all(done.values()):
            break
    assert all(done.values())
    client_tls.write(b"ping")                       # TLS 1.3: the server checks the client cert on first read
    s_in.write(c_out.read())
    assert server_tls.read() == b"ping"
    peer = dict(x[0] for x in server_tls.getpeercert()["subject"])
    assert peer["commonName"] == "network-ids"


def test_make_certs_is_idempotent_and_force_regenerates(tmp_path):
    first = make_certs.make_all(tmp_path, say=lambda *_: None)
    assert "certs/ca.crt" in first and "keys/jwt.key" in first
    ca_before = (tmp_path / "certs" / "ca.crt").read_bytes()
    assert make_certs.make_all(tmp_path, say=lambda *_: None) == []
    (tmp_path / "certs" / "simulator.crt").unlink()                     # one missing leaf: reissued by the same CA
    assert make_certs.make_all(tmp_path, say=lambda *_: None) == ["certs/simulator.crt", "certs/simulator.key"]
    assert (tmp_path / "certs" / "ca.crt").read_bytes() == ca_before
    assert len(make_certs.make_all(tmp_path, force=True, say=lambda *_: None)) == len(first)
    assert (tmp_path / "certs" / "ca.crt").read_bytes() != ca_before


# ------------------------------------------------------------------ scripts/tls.py
def _ca_subjects(ctx: ssl.SSLContext) -> set[str]:
    return {dict(x[0] for x in c["subject"]).get("commonName", "") for c in ctx.get_ca_certs()}


def test_httpx_kwargs(monkeypatch, pki, tmp_path):
    monkeypatch.delenv("FM_TLS_CA", raising=False)
    monkeypatch.setenv("FM_TLS_CERT_DIR", str(tmp_path))                 # no client certs here
    assert tls.httpx_kwargs() == {} and tls.httpx_kwargs("network-ids") == {}
    assert tls.ssl_context() is None
    monkeypatch.setenv("FM_TLS_CA", str(pki / "certs" / "ca.crt"))
    kw = tls.httpx_kwargs()
    assert set(kw) == {"verify"} and isinstance(kw["verify"], ssl.SSLContext)
    assert _ca_subjects(kw["verify"]) == {"FraudMesh Local CA"}
    assert kw["verify"].verify_mode == ssl.CERT_REQUIRED and kw["verify"].check_hostname
    monkeypatch.setenv("FM_TLS_CERT_DIR", str(pki / "certs"))
    assert tls.client_cert_files("network-ids") == (str(pki / "certs" / "network-ids.crt"), str(pki / "certs" / "network-ids.key"))
    assert tls.client_cert_files("../certs/ca") is None and tls.client_cert_files("server") is None
    import httpx
    with httpx.Client(**tls.httpx_kwargs("network-ids")):                # accepted by httpx as-is
        pass
    monkeypatch.setenv("FM_TLS_CA", str(tmp_path / "missing.crt"))
    with pytest.raises(FileNotFoundError):
        tls.httpx_kwargs()


def test_httpx_kwargs_client_cert_is_presented(pki, monkeypatch):
    """The SSLContext from httpx_kwargs(source) presents <source>.crt in a real handshake against a server that requires
    a client certificate from the local CA."""
    import socket
    import threading
    monkeypatch.setenv("FM_TLS_CA", str(pki / "certs" / "ca.crt"))
    monkeypatch.setenv("FM_TLS_CERT_DIR", str(pki / "certs"))
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(pki / "certs" / "server.crt", pki / "certs" / "server.key")
    sctx.load_verify_locations(pki / "certs" / "ca.crt")
    sctx.verify_mode = ssl.CERT_REQUIRED
    srv = socket.create_server(("127.0.0.1", 0))
    got: dict = {}

    def serve() -> None:
        try:
            conn, _ = srv.accept()
            with sctx.wrap_socket(conn, server_side=True) as t:
                t.recv(1)                                  # TLS 1.3: the client certificate is checked by now
                got["cn"] = dict(x[0] for x in t.getpeercert()["subject"])["commonName"]
                t.sendall(b"y")
        except Exception as e:                             # surfaced by the assert below
            got["error"] = repr(e)

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    ctx = tls.httpx_kwargs("cloud-audit")["verify"]
    with socket.create_connection(srv.getsockname(), timeout=5) as s, ctx.wrap_socket(s, server_hostname="localhost") as t:
        t.sendall(b"x")
        assert t.recv(1) == b"y"
    th.join(5)
    srv.close()
    assert got.get("cn") == "cloud-audit", got
