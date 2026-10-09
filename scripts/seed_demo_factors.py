"""Seed MFA factors for the named demo customers (PRD §8): sms + device_push enrolled 90 days ago; Priya's push is on
fp_priya_phone. Idempotent. reset_demo.sh also seeds every generated customer.

Usage: python scripts/seed_demo_factors.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scripts._env  # noqa: E402, F401
from api.seeding import seed_demo_factors  # noqa: E402

if __name__ == "__main__":
    print("seeded factors:", seed_demo_factors())
