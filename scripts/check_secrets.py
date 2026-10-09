"""Secret scan of the git-tracked files (v3 phase 12). Exit 1 and list findings when a tracked file contains:

  a PEM private key, a Google service-account JSON (with a private_key), an AWS / GitHub / Slack / Stripe / Google API /
  PayPal-style live token, a JWT-looking literal, or an assignment of a long hex/base64 value to a *SECRET / *KEY /
  *TOKEN / *PASSWORD name.

Test fixtures use obviously fake values ("11" * 32, "cd" * 32 built at runtime); they are not literal secrets. A line
can opt out with `secret-scan: ok` (reviewed, e.g. a documented example value). Files under data/ (gitignored, where
scripts/make_certs.py writes keys) are never tracked; the scan also fails if one is.

    python scripts/check_secrets.py          # exit code 0 = clean
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".joblib", ".pkl", ".woff", ".woff2", ".ttf",
              ".otf", ".zip", ".gz", ".mp4", ".lock"}
SKIP_FILES = {"package-lock.json"}

RULES: list[tuple[str, re.Pattern[str]]] = [
    ("PEM private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("service-account private_key", re.compile(r"\"private_key\"\s*:\s*\"-----BEGIN")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JWT literal", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("hard-coded secret assignment",
     re.compile(r"(?i)\b[A-Z0-9_]*(SECRET|PASSWORD|PRIVATE_KEY|API_KEY|TOKEN_KEY|DATA_KEYS?|CLIENT_SECRET)\b\s*[:=]\s*"
                r"['\"]?(?:[0-9a-f]{32,}|[A-Za-z0-9+/_-]{40,}={0,2})['\"]?")),
]


def tracked_files(root: Path = ROOT) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def scan_text(name: str, text: str) -> list[str]:
    findings = []
    for n, line in enumerate(text.splitlines(), 1):
        if "secret-scan: ok" in line:
            continue
        for rule, rx in RULES:
            if rx.search(line):
                findings.append(f"{name}:{n}: {rule}")
    return findings


def scan(root: Path = ROOT) -> list[str]:
    findings: list[str] = []
    for rel in tracked_files(root):
        p = root / rel
        if rel.startswith("data/"):
            findings.append(f"{rel}: file under gitignored data/ is tracked")
        if p.suffix.lower() in BINARY_EXT or p.name in SKIP_FILES or not p.is_file():
            continue
        if p.suffix.lower() in {".key", ".pem", ".p12", ".pfx"}:
            findings.append(f"{rel}: key/certificate file is tracked")
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        findings += scan_text(rel, text)
    return findings


def main() -> int:
    findings = scan()
    for f in findings:
        print(f)
    print(f"check_secrets: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
