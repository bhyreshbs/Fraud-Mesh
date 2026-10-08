# Contract requests (append-only)

Format: `## <date> — <who>` then **What**, **Why**, **Local workaround**.

## 2026-10-08 — DEV1
**What:** Dev 1 scripts read one extra env var, `DEMO_PASSWORD`, for the three seed users (PRD §4 says seed passwords come "from env" but names no variable).
**Why:** `scripts/reset_demo.sh` / `scripts/seed_users.py` must set passwords without committing them.
**Local workaround:** Used only inside `scripts/` (Dev 1). The engine never reads it. Not added to `engine/common/settings.py`.
