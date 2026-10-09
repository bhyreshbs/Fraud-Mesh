"""v3 phase 14: AES-256-GCM field encryption (api/crypto_box.py), its use on feedback.note and the manual-action reason,
audit rows keeping a SHA-256 instead of the text, and the hashing review (no MD5)."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from sqlalchemy import text

from api import crypto_box, queries
from api.db.session import admin_engine

ROOT = Path(__file__).resolve().parents[2]
K1, K2 = "a1" * 32, "b2" * 32
WHERE = {"table": "feedback", "column": "note", "row_id": "7"}


@pytest.fixture
def keys(monkeypatch):
    def _set(keys: dict | None, active: str | None):
        if keys is None:
            monkeypatch.delenv("FM_DATA_KEYS", raising=False)
        else:
            monkeypatch.setenv("FM_DATA_KEYS", json.dumps(keys))
        if active is None:
            monkeypatch.delenv("FM_DATA_KEY_ACTIVE", raising=False)
        else:
            monkeypatch.setenv("FM_DATA_KEY_ACTIVE", active)
    _set(None, None)
    return _set


def test_off_by_default_is_plaintext(keys):
    assert not crypto_box.enabled()
    assert crypto_box.encrypt_text("hello", **WHERE) == "hello"
    assert crypto_box.decrypt_text("hello", **WHERE) == "hello"
    assert crypto_box.redact_audit("MANUAL_ACTION", {"reason": "r"}) == {"reason": "r"}


def test_round_trip_aad_binding_tamper_and_rotation(keys):
    keys({"k1": K1}, "k1")
    ct = crypto_box.encrypt_text("analyst note <b>", **WHERE)
    assert ct.startswith("fmenc:v1:k1:") and "analyst" not in ct
    assert ct != crypto_box.encrypt_text("analyst note <b>", **WHERE)               # random nonce
    assert crypto_box.decrypt_text(ct, **WHERE) == "analyst note <b>"
    for other in ({**WHERE, "row_id": "8"}, {**WHERE, "column": "reason"}, {**WHERE, "table": "decisions"}):
        with pytest.raises(crypto_box.DecryptError):
            crypto_box.decrypt_text(ct, **other)                                      # moved to another row/column
    body = ct.rsplit(":", 1)[1]
    flipped = ct[:-len(body)] + ("A" if body[0] != "A" else "B") + body[1:]
    with pytest.raises(crypto_box.DecryptError):
        crypto_box.decrypt_text(flipped, **WHERE)
    keys({"k1": K1, "k2": K2}, "k2")                                                  # rotation
    assert crypto_box.decrypt_text(ct, **WHERE) == "analyst note <b>"
    re_ct = crypto_box.reencrypt(ct, **WHERE)
    assert crypto_box.key_id_of(re_ct) == "k2" and crypto_box.decrypt_text(re_ct, **WHERE) == "analyst note <b>"
    keys({"k2": K2}, "k2")                                                            # old kid removed
    with pytest.raises(crypto_box.DecryptError):
        crypto_box.decrypt_text(ct, **WHERE)


@pytest.mark.parametrize("cfg", [({"k1": "zz"}, "k1"), ({"k1": "ab" * 16}, "k1"), ({"k1": K1}, None), ({"k1": K1}, "k9"),
                                 ({"bad kid!": K1}, "bad kid!"), (None, "k1")])
def test_bad_configuration_fails_closed(keys, cfg):
    keys(*cfg)
    with pytest.raises(crypto_box.CryptoConfigError):
        crypto_box.encrypt_text("x", **WHERE)


def test_feedback_and_manual_reason_encrypted_at_rest(client, auth_headers, seeded, keys):
    keys({"k1": K1}, "k1")
    h = auth_headers("lead")
    cid = seeded[2]
    reason = "customer called <img src=x onerror=alert(1)>"
    r = client.post(f"/v1/cases/{cid}/actions", json={"actions": ["HOLD_OUTBOUND_PAYMENTS"], "reason": reason}, headers=h)
    assert r.status_code == 200 and r.json()["override_reason"] == reason
    r = client.post(f"/v1/cases/{cid}/feedback", json={"verdict": "INCONCLUSIVE", "note": "secret note"}, headers=h)
    assert r.status_code == 200
    with admin_engine().connect() as c:
        stored_reason = c.execute(text("SELECT data->>'override_reason' FROM decisions WHERE data->>'policy_rule' = 'manual_override'")).scalar()
        stored_note = c.execute(text("SELECT note FROM feedback WHERE case_id = :c"), {"c": cid}).scalar()
        audit_rows = c.execute(text("SELECT action, details FROM audit_log WHERE action IN ('MANUAL_ACTION','FEEDBACK')")).all()
    assert crypto_box.is_encrypted(stored_reason) and "customer" not in stored_reason
    assert crypto_box.is_encrypted(stored_note) and "secret" not in stored_note
    assert queries.feedback_notes(cid) == ["secret note"]
    details = {a: d for a, d in audit_rows}
    assert "reason" not in details["MANUAL_ACTION"] and details["MANUAL_ACTION"]["reason_sha256"] == crypto_box.sha256_hex(reason)
    assert "note" not in details["FEEDBACK"] and details["FEEDBACK"]["note_sha256"] == crypto_box.sha256_hex("secret note")
    tl = client.get(f"/v1/cases/{cid}/timeline", headers=h).json()                   # decrypted for authorised readers
    assert reason in [d.get("override_reason") for d in tl["decisions"]]
    assert client.get("/v1/audit/verify", headers=h).json()["ok"] is True             # chain intact with digests


def test_without_keys_storage_is_unchanged(client, auth_headers, seeded, keys):
    h = auth_headers("lead")
    cid = seeded[2]
    client.post(f"/v1/cases/{cid}/feedback", json={"verdict": "INCONCLUSIVE", "note": "plain"}, headers=h)
    with admin_engine().connect() as c:
        assert c.execute(text("SELECT note FROM feedback WHERE case_id = :c"), {"c": cid}).scalar() == "plain"


def test_no_md5_or_sha1_in_security_code():
    weak = re.compile(r"\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)\b", re.I)
    for folder in ("api", "scripts", "engine"):
        for p in (ROOT / folder).rglob("*.py"):
            assert not weak.search(p.read_text(encoding="utf-8")), p
