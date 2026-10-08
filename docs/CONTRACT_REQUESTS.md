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

## 2026-10-09 — DEV1
**What:** Dev-only env var `FM_DEV_PIPELINE=1` (read only by `api/main.py`) swaps the Phase 0 Pipeline stub for `api/dev_pipeline.py:ScriptedPipeline`.
**Why:** Lets Dev 1 click the Midnight ATO story through the bank app, phones and console before Dev 2's engine is merged (D1-P3 "against the live API" checks).
**Local workaround:** Off by default, never set in compose or CI, not part of `engine/`. Remove it once the real `engine/pipeline.py` lands at Checkpoint 1.

## 2026-10-09 — DEV1 (D1-P4)
**What:** (1) Unhandled server errors return `500 {"error": {"code": "INTERNAL_ERROR", …}}`; §4 lists no code for 500.
(2) `append_audit` serialises the chain with `pg_advisory_xact_lock` and reads the head with a plain SELECT, not `SELECT … FOR UPDATE` as §8 says.
**Why:** (1) Every non-2xx must use the §4 format and carry the security headers. (2) Migration `0002_roles` gives the app role INSERT + SELECT only on `audit_log`, and `FOR UPDATE` requires UPDATE privilege; the advisory lock gives the same linear chain.
**Local workaround:** Both live in Dev 1 files only (`api/main.py`, `api/audit.py`). No contract model changes.

## 2026-10-09 — DEV1 (D1-P5)
**What:** (1) `ml/scenario.py` and `scenarios/*.yaml` are not merged yet, so `api/scenario_source.py` imports `ml.scenario` when present and otherwise uses a DEV1 fallback with the same §16.1 signatures, reading `scenarios/<id>.yaml` or the fallback copies in `fixtures/api/scenarios/` (midnight_ato verbatim from §12.2; mule_fanin and benign_odd from the §12.2 descriptions).
(2) §16.1 says `expand(midnight_ato, default_start, "direct")` yields **10** Envelopes; the §12.2 file has **9** steps (7 events + 2 step_up_respond), so the fallback yields 9. Dev 2: please confirm the expected count.
(3) API-generated `step_up_result` events are stamped `max(now, case.last_event_ts + 1 s)`: players stamp scenario events with scenario time (start + at_min), so a wall-clock answer must not land before the events that caused it.
(4) `device_push` challenges expire after 30 min (OTP stays 5 min): §12.2 answers the push 14 scenario-minutes after it is created.
**Why:** Keep play.py / load.py / reset / autopilot working end to end before D2-P1 and D2-P2 land.
**Local workaround:** All in Dev 1 paths. When Dev 2 merges `ml/scenario.py` and `scenarios/`, they take over automatically; delete `fixtures/api/scenarios/` and the fallback branch then.

## 2026-10-09 — DEV1 (D1-P6)
**What:** Until Dev 2's real `engine.api` (D2-P5) lands, `replay_case`, `explain_case` and `simulate_policy` are Phase 0 stubs that return fixed fixtures. With `FM_DEV_PIPELINE=1` the routes and the Investigator AI use `api/dev_analysis.py` instead (§10.9/§10.10 rules over stored evidence). It reproduces the §12.4 replay checks: without kyc P 0.583, lost 350 s; without netsec P 0.538; siloed 0 blocks / 6 alerts; ₹4,80,000 protected. Baseline lead time is 770 s, not 780 s, because §12.2 places the KYC step 10 s after the step-up (00:52:10).
**Why:** D1-P6 "done when" needs replay toggles and simulator sliders that change numbers.
**Local workaround:** All selection goes through `api/engine_calls.py`; without the flag, Dev 2's `engine.api` is called exactly as §6.3 says. The autopilot also saves ground-truth labels for the events it plays (the simulator scores against labels).
