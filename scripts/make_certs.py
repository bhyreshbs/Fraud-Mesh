"""Local PKI and signing keys for the TLS / mTLS / Ed25519 / EdDSA demo (README "Transport security and keys").

Writes (data/ is gitignored; nothing here is ever committed):
  data/certs/ca.crt, ca.key                 local CA (ECDSA P-256), trusted by the proxy, Postgres clients and senders
  data/certs/server.crt, server.key         TLS server cert: localhost, 127.0.0.1, ::1, api, web, bank, db, proxy
  data/certs/<source>.crt, <source>.key     mTLS client cert per sender source (CN = source name)
  data/keys/<source>.key, <source>.pub      Ed25519 ingestion signing keypair per source (PEM)
  data/keys/jwt.key, jwt.pub                Ed25519 keypair for EdDSA access tokens

Idempotent: existing files are kept (a missing leaf is issued by the existing CA). --force regenerates everything.
Usage: python scripts/make_certs.py [--force] [--out-dir data]
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ("demo-bank-web", "cloud-audit", "network-ids", "simulator")
SERVER_DNS = ("localhost", "api", "web", "bank", "db", "proxy")
SERVER_IPS = ("127.0.0.1", "::1")
ORG = "FraudMesh Demo"
CA_DAYS, LEAF_DAYS = 5 * 365, 397          # browsers reject leaf certificates valid for more than 398 days


def _write(path: Path, data: bytes, private: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if private:
        try:
            os.chmod(path, 0o600)              # best effort (no-op semantics on Windows)
        except OSError:
            pass


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _pem_pub(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(certs: Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(_name("FraudMesh Local CA")).issuer_name(_name("FraudMesh Local CA"))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    _write(certs / "ca.key", _pem_key(key), private=True)
    _write(certs / "ca.crt", cert.public_bytes(serialization.Encoding.PEM), private=False)
    return key, cert


def load_ca(certs: Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate] | None:
    try:
        key = serialization.load_pem_private_key((certs / "ca.key").read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate((certs / "ca.crt").read_bytes())
    except (OSError, ValueError):
        return None
    return key, cert


def issue(ca_key, ca_cert: x509.Certificate, certs: Path, name: str, cn: str, server: bool) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=LEAF_DAYS))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False, key_agreement=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),
                        critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if server:
        sans = [x509.DNSName(d) for d in SERVER_DNS] + [x509.IPAddress(ipaddress.ip_address(i)) for i in SERVER_IPS]
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    else:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    cert = b.sign(ca_key, hashes.SHA256())
    _write(certs / f"{name}.key", _pem_key(key), private=True)
    _write(certs / f"{name}.crt", cert.public_bytes(serialization.Encoding.PEM), private=False)


def ed25519_pair(keys: Path, name: str) -> None:
    key = Ed25519PrivateKey.generate()
    _write(keys / f"{name}.key", _pem_key(key), private=True)
    _write(keys / f"{name}.pub", _pem_pub(key), private=False)


def make_all(out: Path, force: bool = False, say=print) -> list[str]:
    """Create whatever is missing (everything with force). Returns the relative paths written."""
    certs, keys = out / "certs", out / "keys"
    written: list[str] = []

    def missing(*paths: Path, again: bool = False) -> bool:
        return force or again or not all(p.is_file() for p in paths)

    ca = None if force else load_ca(certs)
    new_ca = ca is None                                 # a new CA invalidates every certificate it did not sign
    if new_ca:
        ca = make_ca(certs)
        written += ["certs/ca.crt", "certs/ca.key"]
    ca_key, ca_cert = ca
    if missing(certs / "server.crt", certs / "server.key", again=new_ca):
        issue(ca_key, ca_cert, certs, "server", "localhost", server=True)
        written += ["certs/server.crt", "certs/server.key"]
    for s in SOURCES:
        if missing(certs / f"{s}.crt", certs / f"{s}.key", again=new_ca):
            issue(ca_key, ca_cert, certs, s, s, server=False)
            written += [f"certs/{s}.crt", f"certs/{s}.key"]
    for name in (*SOURCES, "jwt"):
        if missing(keys / f"{name}.key", keys / f"{name}.pub"):
            ed25519_pair(keys, name)
            written += [f"keys/{name}.key", f"keys/{name}.pub"]
    for w in written:
        say(f"[new] {out / w}")
    if not written:
        say(f"[ok] everything already present under {out} (use --force to regenerate)")
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true", help="regenerate the CA, every certificate and every key")
    ap.add_argument("--out-dir", default=str(ROOT / "data"))
    a = ap.parse_args()
    make_all(Path(a.out_dir), force=a.force)
    return 0


if __name__ == "__main__":
    sys.exit(main())
