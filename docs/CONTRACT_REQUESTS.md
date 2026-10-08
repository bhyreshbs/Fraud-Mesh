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

## 2026-10-09 — DEV2 (D2-P1)
**What:** Midnight ATO envelope count. §16.1 "Done when" says `expand(midnight_ato, default_start, "direct")` yields **10** Envelopes. The §12.2 file (copied verbatim) has 9 steps: 7 with `type` and 2 `step_up_respond`, so direct mode yields **9** Envelopes (the 8 golden evidence items of §12.4 plus the "Not me" step_up_result). The preload adds 3 more (12 in total). §14.5's "10 events accepted" in API mode also does not match: 7 posted Envelopes + 2 API-generated step_up_results = 9 (or 3 preload + 7 = 10 if the preload is counted).
**Why:** Neither 9 nor 12 is 10, and adding or removing a step would change the golden path in §12.4.
**Local workaround:** No change to the scenario. `tests/engine/test_scenario.py` asserts 9 valid Envelopes in the exact §12.4 order and timing. Proposal: correct §16.1 to "9 Envelopes", and Dev 1 checks the count used by `scripts/smoke_test.py` (§14.5).

## 2026-10-09 — DEV2 (D2-P1)
**What:** `engine/detectors/rules/cgnat.txt` is listed as a D2-P3 deliverable (§16.3 item 3), but the D2-P1 graph acceptance test ("a CGNAT IP links nobody", §16.1) and §7.1 need it now.
**Why:** The graph cannot apply the §7.1 CGNAT rule without the list.
**Local workaround:** The file is added in D2-P1 (Dev 2 path, no contract change): IPv4 /24s (shorter prefixes expand to /24s), IPv6 /64s, `#` comments. Its ranges are synthetic demo carrier ranges. No scenario or generated customer uses them.

## 2026-10-09 — DEV2 (D2-P1)
**What:** §7.1 says a `login` creates LOGGED_IN_FROM, CONNECTED_VIA and OWNS, without saying whether a **failed** login counts.
**Why:** If failed logins created LOGGED_IN_FROM, a credential-stuffing device that tried 10 customers would link all 10 victims (and create SHARES_DEVICE between them), merging unrelated cases through the attacker's device.
**Local workaround:** `engine/graph/resolve.py`: a failed login creates OWNS and CONNECTED_VIA only. LOGGED_IN_FROM (and therefore SHARES_DEVICE) needs `result == "success"`. Proposal: state this in §7.1.

## 2026-10-09 — DEV2 (D2-P1)
**What:** The generator includes Priya (C-1042 / A-88213, `fp_priya_phone` + `fp_priya_laptop`, 49.207.10.21, AS24560 Airtel, Bengaluru) as one of the `--customers` generated customers. She is never chosen as an attack victim. Every other customer is `C-1000NN` / `A-5000NN` with a fresh /24 that never overlaps a scenario IP or a CGNAT range.
**Why:** §12.3 seeds MFA factors "for every generated customer … for Priya, device_push on fp_priya_phone", and the behaviour detector (§10.4) gives customers with fewer than 5 past logins COLD_START. Without background history the demo victim would be cold-start at the attacker's login.
**Local workaround:** Built into `ml/generator/population.py`. With `--attacks 0`, labels are `scenario="background"`. Attack events are labelled with their family (`ato`, `mule_fanin`, `structuring`) as `scenario` and `atk_<family>_<NNN>` as `attack_id`.

## 2026-10-09 — DEV2 (D2-P1)
**What:** Shared Store-test helpers. `tests/engine/test_store_contract.py` adopts Dev 1's proposal above: it calls `getattr(store, "insert_event", None)` before saving evidence, and `save_labels` for the labels round-trip (skipping if absent). `MemoryStore` implements both with PgStore's semantics (duplicate event → False; labels first-write-wins). With `STORE=pg` it reuses `tests/api/conftest.py` (`_PG_OK`, `TEST_DB_URL`, `RUNTIME_TABLES`) and `api.db.session.admin_engine` to migrate and truncate the `_test` database.
**Why:** The protocol has no event or label writer, and the pg test needs a migrated database.
**Local workaround:** Verified locally on PostgreSQL 16: `STORE=pg` and `STORE=memory` both pass 20/20. Dev 1: please keep those four names stable, or tell Dev 2 when they change.

## 2026-10-09 — DEV2 (D2-P1)
**What:** Graph details §10.2 leaves open (Dev 2 internals, recorded so the joiner and graph detector agree).
(1) "Linked to customers" for hubs: cust → itself; acct → owners + owners of accounts it paid or was paid by; dev → owners of accounts that logged in from it; ip → customers of devices connected via it; phone → HAS_PHONE customers + customers of devices that reset to it.
(2) `neighbours_within` does not include the start token.
(3) `seed_distance` walks edges with confidence > 0 (no `min_conf` in §10.2); a seed itself is at distance 0.
(4) A SHARES_DEVICE edge counts in searches only while the two customers still share a device that is not excluded. Otherwise the pairwise edges created before a device crossed 20 customers would link its customers around the hub rule.
(5) Each edge type has one key per direction (A SENT B and B SENT A are two edges, as in the `edges` table).
**Why:** Needed for deterministic, testable behaviour.
**Local workaround:** Implemented in `engine/graph/store.py` and covered by `tests/engine/test_graph.py`.

## 2026-10-09 — DEV2 (D2-P1)
**What:** The BOTH-FROZEN `.gitignore` entry `data/` also matches `scenarios/data/`, so the required `scenarios/data/ids_alerts.jsonl` (§3, §12.2) is silently ignored by `git add`.
**Why:** A fresh clone would be missing the IDS alert lines that Dev 1's Suricata adapter replays (§7.4, §14.4).
**Local workaround:** The file is committed with `git add -f`, so it is tracked despite the pattern. Proposal: change the entry to `/data/` (only the generator output folder at the repo root) at the next contract merge.

## 2026-10-09 — DEV2 (D2-P2)
**What:** Golden lead time. §12.4 says the baseline earliest intervention is item 5 (KYC, "00:52") with a **780 s** lead before the 01:05 transfer. §12.2 timing puts two steps at at_min 13 (step-up response at 00:52:00, KYC at 00:52:10), so live (through the scenario and Pipeline) the HOLD lands at 00:52:10, a **770 s** lead.
**Why:** The table rounds times to HH:MM. Both values are internally consistent with their own section.
**Local workaround:** No scenario change. `fixtures/engine/demo_evidence.json` uses the table's times (KYC at 00:52:00), so the pure replay test (D2-P5) reproduces 780 s. The FixtureDetector matches fixture items to events by minute plus the event types that detector handles (§10.4). `tests/engine/test_pipeline_fixture.py` asserts the live HOLD is at the KYC step and the lead time is 770 s. Proposal: §12.4 says "≈ 13 minutes (780 s on the table's minute grid; 770 s live)". Dev 1's `smoke_test.py` should assert ordering, not an exact 780.

## 2026-10-09 — DEV2 (D2-P2)
**What:** The Phase 0 Dev 2 fixtures (§16.0) were never committed: `fixtures/engine/demo_evidence.json`, `fixtures/engine/demo_expected.json` and `tests/engine/test_fixtures_valid.py`.
**Why:** The D2-P2 golden fusion test reads them.
**Local workaround:** Added in D2-P2 (Dev 2 paths). Expected values are copied from the §12.4 table (3 decimals), not computed by the engine. `demo_expected.json` also holds the §12.4 replay checks for D2-P5.

## 2026-10-09 — DEV2 (D2-P2)
**What:** (1) `floor_SEED_PAYEE` needs "graph evidence with seed distance 0". The graph detector's reason codes in §10.4 only list SEED_DISTANCE_1/_2/_3, so fusion keys the floor on reason code `SEED_DISTANCE_0`, which the D2-P3 graph detector will emit for a payee that is itself a seed. (2) `Pipeline.__init__(store, detectors=None, features=None)`: the two extra keyword arguments are optional and default to the real ones from D2-P3 on; `Pipeline(store)` is unchanged for Dev 1. Until D2-P3 merges, `Pipeline(store)` builds the graph and case machinery but has no detectors, so it returns `[]` like the stub. (3) The sticky 72 h joining rule is present but disabled (`STICKY_ENABLED = False`) until D2-P4, as §16.2 allows. (4) `graph_elements` raises `KeyError` for an unknown case (Dev 1 already maps it to 404). Excluded nodes are shown but not expanded.
**Why:** Recorded so D2-P3/D2-P4 and Dev 1 agree.
**Local workaround:** None needed; all Dev 2 internals.

## 2026-10-09 — DEV2 (D2-P3)
**What:** Phase split of the §10.4 rules. §16.3 asks for "the seven detectors"; §16.4 (D2-P4) separately lists the PayPal-derived rules with their tests. D2-P3 therefore ships all seven detectors with their core rules and models, plus every §10.3 feature those rules read. The seven PayPal-derived rules land in D2-P4: IMPOSSIBLE_TRAVEL (behaviour), PROFILE_CHANGE_AFTER_NEW_DEVICE, MFA_FAIL_THEN_PASS and PUSH_SPAM (auth), CREDENTIAL_STUFFING_IP (netsec), STRUCTURING (txn), PAYEE_NAME_MISMATCH / MULE_FLOW (graph).
**Why:** Keeps each phase's scope as the PRD splits it.
**Local workaround:** None; the Midnight ATO path uses none of those rules.

## 2026-10-09 — DEV2 (D2-P3)
**What:** §10.3 feature details the PRD leaves open (all in `engine/features/features.py`, shared by training and serving):
(1) `payee_is_new` / `minutes_since_payee_added` key on (customer, payee): "new to this sender".
(2) `near_limit_count_24h` and `ip_failed_customers_1h` include the current event, so "3 × ₹4.9 lakh" and "10 customers, 1 IP" trigger on the event that completes the pattern. Every other window counts earlier events only.
(3) Two extra features: `past_logins_30d` (the COLD_START rule, < 5) and `cid_profile_reads_10m` (the bulk_profile_read_support_console rule, >= 20).
(4) `travel_speed_kmh` uses a 1-minute minimum gap.
(5) The median login hour is a plain median over 30 d; `hour_deviation` is circular.
**Why:** Needed for deterministic features and identical training/serving vectors (`tests/engine/test_feature_parity.py`).
**Local workaround:** None needed.

## 2026-10-09 — DEV2 (D2-P3)
**What:** Models and rule files.
(1) The behaviour model's positive class is an account-takeover login (`is_attack` and scenario `ato`), trained on successful logins of customers with >= 5 past logins; mule and structuring attacks log in from the customer's own device.
(2) `calibration.json` keeps every §10.4 key and adds `graph.SEED_DISTANCE_0 = 0.30` (= the graph CAP) for a payee that is itself a seed.
(3) `corporate_ranges.txt` (demo) holds `10.0.0.0/16` and `203.0.113.0/24`. Because cloud_audit `src_ip` is stored as a token, "untrusted" compares ip tokens of those ranges' /24s.
(4) `ml/artifacts/manifest.json` = `{"artifacts": [{"file", "sha256", "features", "pr_auc", "roc_auc", "ece", ...}]}`, which matches what `api/routers/health.py` reads.
(5) A relative MODEL_DIR that does not exist from the working directory resolves against the repo root.
(6) The synthetic attacks are very separable (test PR-AUC 0.994 txn, 1.0 behaviour), so the isotonic calibrators are near step functions. That is fine for the demo, but these numbers are not a real-world estimate.
**Why:** Recorded for CP1 and the benchmark slides.
**Local workaround:** None needed.

## 2026-10-09 — DEV2 (D2-P3) — for Dev 1
**What:** `Pipeline(store)` now runs the real detectors and feature windows. `api/dev_pipeline.py` / `FM_DEV_PIPELINE` can be retired at CP1, as planned. Measured in-process on the 62k-event background: 74.5 s for `load.py --direct`-style processing (budget 180 s), decision p95 1.5 ms, `startup()` 6 s.
**Why:** CP1 readiness.
**Local workaround:** None.
