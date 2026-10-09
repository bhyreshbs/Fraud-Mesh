"""v3 phase 12 static checks: frontend XSS sinks, committed secrets, CSP without inline scripts."""
from __future__ import annotations

import re
from pathlib import Path

from scripts import check_frontend_xss, check_secrets

ROOT = Path(__file__).resolve().parents[2]


def test_frontends_have_no_html_or_script_sinks():
    assert check_frontend_xss.scan() == []


def test_xss_scanner_catches_planted_sinks(tmp_path):
    src = tmp_path / "web" / "src"
    src.mkdir(parents=True)
    (src / "Bad.tsx").write_text("\n".join([
        "<div dangerouslySetInnerHTML={{ __html: x }} />",
        "el.innerHTML = name;",
        "eval(code);",
        "const f = new Function(body);",
        "<a href={payee.url}>x</a>",
        "location = 'javascript:alert(1)';",
        "<a href={safeUrl(u)}>ok</a>",
        "<b>{nickname}</b>",
    ]), encoding="utf-8")
    found = check_frontend_xss.scan(tmp_path)
    assert len(found) == 6, found


def test_no_secrets_in_tracked_files():
    assert check_secrets.scan() == []


def test_secret_scanner_catches_planted_secrets():
    pem = "-----BEGIN " + "PRIVATE KEY-----"
    samples = [pem, '"private_key": "' + pem, "AKIA" + "ABCDEFGHIJKLMNOP", "ghp_" + "a" * 36,
               "JWT_SECRET=" + "c" * 64, "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12]
    for s in samples:
        assert check_secrets.scan_text("x.py", s), s
    assert check_secrets.scan_text("x.py", 'os.environ["JWT_SECRET"] = "cd" * 32') == []


def test_spa_csp_has_no_inline_or_remote_scripts():
    conf = (ROOT / "deploy" / "nginx-spa.conf").read_text(encoding="utf-8")
    csp = re.search(r'set \$csp "([^"]+)"', conf).group(1)
    script = re.search(r"script-src ([^;]+)", csp).group(1).split()
    assert script == ["'self'"]
    for d in ("object-src 'none'", "frame-ancestors 'none'", "base-uri 'self'"):
        assert d in csp
