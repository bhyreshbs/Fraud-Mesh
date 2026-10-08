"""CI check: sha256(engine/contracts.py) must equal docs/CONTRACT_HASH (PRD §5, §14.2).

Line endings are normalised to LF before hashing so Windows checkouts (autocrlf) hash the same as Linux CI.
Usage: python scripts/verify_contracts.py [--write]
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "engine" / "contracts.py"
HASH_FILE = ROOT / "docs" / "CONTRACT_HASH"


def contract_sha256() -> str:
    return hashlib.sha256(CONTRACTS.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def main() -> int:
    actual = contract_sha256()
    if "--write" in sys.argv:
        HASH_FILE.write_text(actual + "\n", encoding="utf-8")
        print(f"wrote {actual}")
        return 0
    expected = HASH_FILE.read_text(encoding="utf-8").strip() if HASH_FILE.exists() else ""
    if actual != expected:
        print(f"CONTRACT HASH MISMATCH\n  engine/contracts.py: {actual}\n  docs/CONTRACT_HASH:  {expected}")
        return 1
    print(f"contract hash ok {actual}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
