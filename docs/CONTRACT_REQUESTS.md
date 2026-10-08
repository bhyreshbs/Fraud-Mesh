# Contract requests (append-only)

Format: `## <date> — <who>` then **What**, **Why**, **Local workaround**.

## 2026-10-08 — DEV1
**What:** Dev 1 scripts read one extra env var, `DEMO_PASSWORD`, for the three seed users (PRD §4 says seed passwords come "from env" but names no variable).
**Why:** `scripts/reset_demo.sh` / `scripts/seed_users.py` must set passwords without committing them.
**Local workaround:** Used only inside `scripts/` (Dev 1). The engine never reads it. Not added to `engine/common/settings.py`.

## 2026-10-08 — DEV1
**What:** Who writes the `FEEDBACK` audit row? PRD §10.11 says feedback writes one (engine side); §15.4 lists `FEEDBACK` among audit rows written by the API.
**Why:** Both writing it would double every feedback entry in the hash chain.
**Local workaround:** The API (`POST /v1/cases/{id}/feedback`) writes `FEEDBACK` with verdict, note and the before/after reliabilities from `FeedbackResult`. Proposal: `engine.feedback.apply_feedback` does not write its own `FEEDBACK` row.

## 2026-10-08 — DEV1
**What:** The §8 schema has `evidence.event_id REFERENCES events(event_id)`, but the Store protocol has no method to insert events.
**Why:** `tests/engine/test_store_contract.py` with `STORE=pg` cannot save evidence unless the referenced event row exists.
**Local workaround:** `PgStore.insert_event(StoredEvent)` exists as a non-protocol helper (used by ingestion and scripts). Proposal: the store-contract test calls `getattr(store, "insert_event", None)` for its events before saving evidence (MemoryStore may implement it as a no-op).
