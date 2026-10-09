"""Static XSS check for the two React apps (v3 phase 12). Exit 1 and list findings when a source file under web/src or
bank-demo/src uses an HTML/script sink:

  dangerouslySetInnerHTML, .innerHTML / .outerHTML assignment, insertAdjacentHTML, document.write, eval(,
  new Function(, setTimeout/setInterval with a string, srcdoc=, a javascript: URL, or an href/src attribute bound to
  an expression (href={...}) that is not wrapped in safeUrl(...).

React escapes text children, so rendering untrusted strings as {value} is safe; these sinks are the ways around that.
A line can opt out with a trailing comment `xss-ok: <reason>` (reviewed exceptions only).

    python scripts/check_frontend_xss.py            # prints findings, exit code 0 = clean
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APPS = ("web/src", "bank-demo/src")
EXTS = {".ts", ".tsx", ".js", ".jsx"}
SKIP_PARTS = {"types"}                      # generated contract types: no code paths

RULES: list[tuple[str, re.Pattern[str]]] = [
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML")),
    ("innerHTML/outerHTML assignment", re.compile(r"\.(inner|outer)HTML\s*\+?=")),
    ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML\s*\(")),
    ("document.write", re.compile(r"document\.write(ln)?\s*\(")),
    ("eval", re.compile(r"(?<![\w.])eval\s*\(")),
    ("new Function", re.compile(r"new\s+Function\s*\(")),
    ("string timer", re.compile(r"set(Timeout|Interval)\s*\(\s*['\"`]")),
    ("srcdoc", re.compile(r"srcDoc\s*=|srcdoc\s*=", re.I)),
    ("javascript: URL", re.compile(r"javascript:", re.I)),
    ("href/src bound to an expression", re.compile(r"\b(href|src|action|formAction)\s*=\s*\{(?!\s*safeUrl\()")),
]


def scan(root: Path = ROOT) -> list[str]:
    findings: list[str] = []
    for app in APPS:
        base = root / app
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix not in EXTS or SKIP_PARTS & set(path.relative_to(base).parts):
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if "xss-ok:" in line:
                    continue
                for name, rx in RULES:
                    if rx.search(line):
                        findings.append(f"{path.relative_to(root).as_posix()}:{n}: {name}: {line.strip()[:160]}")
    return findings


def main() -> int:
    findings = scan()
    for f in findings:
        print(f)
    print(f"check_frontend_xss: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
