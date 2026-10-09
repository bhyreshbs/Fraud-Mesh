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

## 2026-10-09 — DEV1 (D1-P7)
**What:** (1) §14.5's first smoke line says "10 events accepted (202)". The §12.2 midnight_ato file posts 7 signed events, and the API generates the 2 step_up_result events, so smoke_test.py reports "7 events accepted (202) + 2 step-up action(s)". Same root as the 9-vs-10 note in D1-P5.
(2) Performance (scripts/perf.py, 50 events/s for 120 s). The platform with the Phase 0 pipeline (ingest -> queue -> worker -> payment outcome) has decision **p95 36.9 ms** on Docker Desktop for Windows. That leaves about 110 ms of the §1 budget for `Pipeline.process`. The dev stand-in does about 8 SQL statements per event and sustains only about 38 events/s there, because each round trip costs about 1.6 ms in the Docker Desktop VM. For Dev 2: keep `process()` to a handful of Store calls. PgStore now buffers `save_evidence` inside `store.transaction()` into one multi-row upsert at commit, and `append_audit` / `save_case` use 2 statements each.
**Why / workaround:** Informational, no contract change. CI's `e2e` job measures both on Linux.

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

## 2026-10-09 — DEV2 (D2-P4)
**What:** How the PayPal-derived rules read the PRD where §10.4 is terse.
(1) MULE_FLOW: "fan-in ≥ 5" is `payee_fan_in_24h` (distinct other senders to the payee in the prior 24 h). "Pass-through 0.8–1.2" is the payee account's own outbound ÷ inbound in 24 h. The payee features are computed for `payee_added` events too, because the graph detector scores those.
(2) PAYEE_NAME_MISMATCH / MULE_FLOW without any seed path start from p = 0, so `max(0 × 1.5, 0.03)` gives 0.03: either rule alone emits evidence, and both together give 0.045.
(3) CREDENTIAL_STUFFING_IP "once per IP per hour" is the feature `ip_stuffing_flagged_1h`, which lives in the feature windows so `startup()` replay rebuilds it. The rule fires on the failure that brings the IP to 10 distinct customers.
(4) STRUCTURING counts the current transfer, so it fires from the second near-limit transfer.
(5) IMPOSSIBLE_TRAVEL applies to cold-start customers too, as `max(population rate, 0.08)`.
(6) The sticky rule is on: same customer, S2 or later, within the 72 h lookback.
**Why:** Deterministic, testable behaviour; each rule has a synthetic-sequence test in `tests/engine/test_rules.py`.
**Local workaround:** None needed. Measured: none of these rules fire on the Midnight ATO path; the 62k benign background still yields only LOW cases; on the seed-1 training data (40 attacks per family) each of the 120 attacks forms exactly one case, 118 of them HIGH or above.

## 2026-10-09 — DEV2 (D2-P5) — touches a DEV1 file, approved by the human
**What:** `tests/api/test_worker_stepup.py::test_feedback_and_detectors` asserted the txn reliability is still 0.85 after a CONFIRMED_FRAUD verdict. That held only for the Phase 0 `apply_feedback` stub, which never wrote to the store. The real engine follows §10.11: every detector with a contribution > 0.5 gets alpha += 1, so txn goes 17/20 → 18/21 ≈ 0.857, and §14.4 expects "Detectors page shows changed reliability".
**Why:** The real `engine/api.py` replaces the stub in D2-P5 (§16.5).
**Local workaround:** With the human's approval, one expected value in that DEV1 test changed from 0.85 to 18/21, with a comment citing §10.11. Nothing else in `tests/api` changed. Dev 1, please review.

## 2026-10-09 — DEV2 (D2-P5)
**What:** engine.api details.
(1) `apply_feedback` writes no FEEDBACK audit row: the API route already writes it, as Dev 1 proposed above, so the chain gets exactly one row.
(2) A CONFIRMED_FRAUD verdict seeds the case's dev/ip/cid tokens and every acct except the accounts the case customer OWNS (from the graph). The unknowing payee's account is seeded too, as §10.11 says.
(3) `explain_case` has no Pipeline argument, so it rebuilds the graph from the store's edges for `seed_paths`. Raw IPs are never stored, so `{ip_short}` in the S0 sentence names the IP token, shortened.
(4) The replay `lead_time_s` and `money_protected_paise` always use the case's S6 evidence, even when txn is ablated: the money moved either way.
(5) Simulation definitions (§10.9 table): "caught" = a case holding any of the attack's events reached severity >= HOLD before the attack's last event; "stopped" = one of the customer's cases was held/blocked when the benign transfer happened.
(6) The four `fixtures/engine/*_example.json` files are now real engine outputs on the golden case (`python -m ml.build_fixtures`). `demo_evidence.json` tokens use the default TOKEN_KEY; `ml/build_fixtures.golden_evidence()` re-tokenizes them for the active key.
**Why:** Recorded for Dev 1's Explanation, Replay, Ask and Simulator screens.
**Local workaround:** None needed.

## 2026-10-09 — DEV2 (D2-P6) — benchmark finding, needs a team decision before the slides
**What:** `benchmark/report.json` (seed 7, 30 attacks per family, held out from the seed-1 training data) uses the exact §10.9 definition: caught = severity >= HOLD strictly *before* the attack's last event. Result: ato 9/30 fused vs 0/30 siloed; mule_fanin 30/30 vs 30/30; structuring 0/30 fused vs 30/30 siloed. No benign customer was flagged HIGH (0 of 1,656) and no legitimate payment (of 24,503) was stopped. Alert compression is 3.5:1.
**Why it looks like this (not a bug; verified per instance):**
(1) §10.5 caps one item at +3 × r. A lone txn signal (p = 1.0, r = 0.85) reaches only P ≈ 0.12 (LOW), and further items of the same family count half. Structuring is pure txn evidence, so fusion reaches HIGH only on the 3rd transfer. That decision does hold the 3rd transfer, but it is the attack's last event, so strict "before" scores 0.
(2) For ATO, fusion holds early (as in the demo) when a KYC or cloud step precedes the transfer. Login + MFA change only reaches MEDIUM (step-up), then CRITICAL at the transfer itself.
(3) Siloed mode blocks on any txn p >= 0.5. The synthetic txn model is near-perfect (PR-AUC 0.994), so siloed blocks the first structuring transfer.
`benchmark/report_details.json` also reports "at or before the last event", where a hold decided on the final transfer still stops that transfer: ato 26/30 fused vs 29/30 siloed; mule 30 vs 30; structuring 30 vs 30. Money protected is reported both ways.
**Options (contract changes, not made):** (a) Present the §10.9 numbers plus the at-or-before view and explain the design: fusion is built so no single weak signal acts alone. (b) Count "at or before the last event" in §10.9, and in the simulator too. (c) A policy rule or floor for a single very strong txn signal, e.g. `txn p >= 0.9 → HOLD`; this would change the golden band path and needs a new golden test. Dev 2 recommends (a) or (b); (c) changes the pitch.
**Local workaround:** None. The report follows §10.9 as written.

## 2026-10-09 — DEV1 (CP1 integration)
**What:** Dev 1-only env vars for tests/tooling, never read by engine/: `FM_BG_DAYS`, `FM_BG_CUSTOMERS` (size of the
reset's §12.1 background; defaults 14 / 2000 = PRD) and `FM_RUN_SLOW=1` (runs @pytest.mark.slow, e.g. the full-size reset).
**Why:** with Dev 2's generator merged, every POST /v1/demo/reset loads ~62k events through PgStore + the engine; the
API tests and the CI smoke test need small resets. The full-size reset is checked separately (CI job `slow`, < 240 s).
**Notes from the CP1 merge:** Dev 2's strict `ml.scenario.labels_for` (rejects envelopes not in the scenario) exposed a
Dev 1 test fixture that labelled a tampered envelope — fixed on the Dev 1 side. No engine changes needed.

## 2026-10-09 — DEV1 → DEV2 (CP1): decision latency with the real engine is over budget
**Failing check:** CI run 37861431831, job `e2e`, step "Perf - real engine, decision p95 < 150 ms at 50 events/s"
(`python scripts/perf.py --rate 50 --seconds 120`, exit 1: `PERF TARGET MISSED`). At 50 events/s the single worker
needs < 20 ms per event or a queue builds up; everything else on integration/cp1 is green (python, slow, smoke, frontend).
**Profile** (600 perf-like events — 400 customers, 80% transactions — through the real `Pipeline.process` on PgStore,
inside Docker next to Postgres): `process()` mean 68.9 ms, p50 54.9, p95 183.2, max 321.0; 6.1 SQL statements/event.
Python hotspots (cumulative over the 600 events):
- `engine/graph/store.py:146 linked_customers` — 12.2 s (~20 ms/event; 56,129 calls ≈ 94 per event), through
  `engine/graph/store.py:106 _typed_neighbours` 7.8 s and `engine/graph/resolve.py:33 kind_of` (2.1M calls)
- LightGBM `__inner_predict_np2d` — 3.3 s (~5 ms/event, 924 calls)
**Ask (Dev 2):** make the graph checks incremental or cached per event (e.g. maintain linked-customer counts / hub
flags when edges are applied instead of recomputing neighbourhoods; compute once per event instead of per call), then
re-run `scripts/perf.py` against the API. Target: process() p95 well under ~100 ms here, < 20 ms mean on CI.
**Dev 1 side, already done on integration/cp1:** PgStore `upsert_edges` is one statement (entities + edges),
`get_reliability` is cached (invalidated by `add_reliability` and the demo reset), `save_evidence` is batched per
transaction, `save_case` is 2 statements, middleware is pure ASGI. Platform-only decision p95 was 36.9 ms.

## 2026-10-09 — DEV1 → DEV2 (CP1): engine/graph/store.py changed by DEV1 (human-approved) — please review
**What:** `EntityGraph.is_hub()` is now cached. A hub stays cached until `load()` (linked customers only grow: edges
are only added or merged). A non-hub answer is dropped when an edge is added within 2 hops of the node, which is the
full reach of `linked_customers()` (ip → dev → acct -OWNS- cust). There are no other engine changes and no behaviour
change. New test `tests/engine/test_graph_hub_cache.py`: after each of 3,000 random edge additions (with hub
transitions), every cached answer equals a fresh `linked_customers()` computation. All 287 Dev 2 tests are still
green, including golden fusion and midnight direct.
**Why:** the CI e2e perf step failed: `linked_customers` was recomputed ~94x per event (~20 ms/event).
Recomputes dropped from 56,129 to 13,295 per 600 events.
**Also on the Dev 1 side:** PgStore passes entity-token lists as one string (`string_to_array` in SQL) instead of
driver-serialised arrays, and `find_open_cases` / `save_case` got cheaper. Real-engine `process()` profile: mean
68.9 → ~55 ms, p95 183 → ~142 ms under Docker Desktop. Remaining engine cost: LightGBM ~4 ms/event (inherent).

## 2026-10-09 — DEV1 → DEV2 (CP1): root cause of the e2e perf failure, and an engine finding
**Root cause (from the CI job log, run 37864614069, job e2e):** smoke passed for all three scenarios; perf decided only
1341/4802 transactions (decision p95 187 s). The old perf traffic (400 synthetic customers paying 25 shared payees) made
the §10.6 joiner chain customers through each payee until it reached the hub threshold (> 20 customers). Reproduced on
Linux: after 40 s there was ONE case with 629 evidence rows, 1,341 entities and 329 customers (6 CASE_MERGED). Every
event re-fused and re-saved that case, so per-event work grew with the run.
**Dev 1 fix:** `scripts/perf.py` now posts realistic traffic by default, a fresh slice of Dev 2's own §12.1 generator
(seed 101, 2,000 customers). On Linux: 6,000 events at 50/s, all 2,908 transactions decided, decision p50 22.3 ms,
p95 59.3 ms, 30 small cases, 0 merges. The synthetic stress mode is kept as `--traffic synthetic`.
**Engine finding for Dev 2 (not blocking CP1):** a shared payee links up to 20 customers before it becomes a hub, so
real merchants or popular payees could chain unrelated customers into one ever-growing case (with quadratic cost per
event). Options: count hub degree including the current event, lower the threshold for acct nodes, or stop joining
through payee accounts that have more than N distinct payers. Use `python scripts/perf.py --traffic synthetic` to reproduce.

## 2026-10-09 — DEV2 (post-CP1): review of the DEV1 engine change and the open findings
**(1) `EntityGraph.is_hub()` cache (engine/graph/store.py) — reviewed, accepted.** `linked_customers()` reads at most
3 edges from the node (ip → dev → acct -OWNS- cust, phone → dev → acct -OWNS- cust). The cache drops non-hub answers
within 2 hops of *both* endpoints of every new edge, so every edge on such a path has an endpoint in range. Nothing in
engine/, ml/ or benchmark/ removes edges or nodes outside `load()`, so "a hub stays a hub" holds. Updating an existing
edge (count, last_seen, confidence) does not change `linked_customers()`, which ignores time. `tests/engine/test_graph_hub_cache.py`
covers hub transitions; engine suite 289 passed.
**(2) Shared-payee chaining (from the CP1 e2e root cause) — kept as specified, not changed.** A payee account with
2–20 payers joins its payers' cases, which is the §10.6 rule doing what §12.2's `mule_fanin` needs (12 victims → one mule
account → one case). Any cutoff below 13 payers breaks that scenario, and changing the §10.2 hub threshold (> 20) is
a contract change. Realistic traffic is unaffected: merchants are `mer` nodes (always excluded), and the §12.1 generator
at 50 events/s produced 30 small cases with 0 merges. Recorded as a known limitation for the slides' future work:
"popular P2P payees with 13–20 payers can chain unrelated customers; a production system would add payee reputation."
**(3) Benchmark definition (D2-P6 options a/b/c) — still a team decision.** Dev 2 recommends (a): present the §10.9
numbers as written, plus the "at or before the last event" view from `benchmark/report_details.json`. No code changes.
**(4) 9 vs 10 envelopes for `expand(midnight_ato, …, "direct")`** — confirmed 9 (7 events + 2 step_up_respond) at CP1.

## 2026-10-10 — DEV1: payment rail (PayPal sandbox / offline mock) — additive, opt-in, no contract change
**What:** `api/payments/` mirrors each transaction's §6.4 payment outcome onto a payment rail: `completed` → authorize
+ capture, `blocked` → authorize + void, `held` → authorize only; a later `FALSE_POSITIVE` verdict captures the held
payment, `CONFIRMED_FRAUD` voids it. Runs off the worker path (queued after `engine_lock` is released); failures are
audited (`PAYMENT_RAIL_ERROR`) and retried, never raised into the worker.
**New (Dev 1 files only):** table `payment_rail` (migration `0003_payment_rail`: event_id PK, case_id, rail, auth_id,
state CREATED/AUTHORIZED/CAPTURED/VOIDED, target, reason, amount_paise, currency, payee_token (acct: token), attempts,
last_error, created_at, updated_at); route `GET /v1/cases/{case_id}/payments` (analyst+, queue-filtered, 404 outside
the caller's queues); audit actions `PAYMENT_RAIL_ERROR`, `PAYMENT_CAPTURED`, `PAYMENT_VOIDED`,
`PAYMENT_RELEASE_SCHEDULED`, `PAYMENT_VOID_SCHEDULED`; Dev 1 env vars `FM_PAYMENT_RAIL` (mock | paypal_sandbox | off,
default mock), `FM_PAYMENT_CURRENCY`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_BASE_URL`, `PAYPAL_VAULT_ID`,
`FM_PAYMENT_MAX_ATTEMPTS`.
**Unchanged:** engine/contracts.py, the §9.5 `GET /v1/demo/payment-status/{event_id}` shape (`{"outcome": ...}`),
`payment_outcomes`, the §4 env-var table and .env.example (the new variables are optional; not added to the frozen file).
**Ask for Dev 2:** none. If the team wants the variables listed in .env.example or §4, that is a frozen-file change to
decide together.
## 2026-10-10 — DEV1 → DEV2: built in Dev 2's paths at the user's request — please review before merge
**What:** Two Review 1 future-work items, built by DEV1 inside engine/, scenarios/ and tests/engine/ because the user asked
for it. No BOTH-FROZEN file, enum value, event type, contract field or CONTRACT_VERSION changed (verify_contracts: hash ok).
(1) **Payee reputation** (fixes the CP1 "Shared-payee chaining" limitation). New `engine/graph/reputation.py`, thresholds in
`engine/detectors/rules/payee_reputation.yaml`. An acct node is reputable only if, at the event's time and from graph edges
alone: its oldest edge is >= 30 d old; >= 3 payer accounts first added/paid it >= 7 d ago and they are >= 50% of its payers;
payers first seen in the last 24 h are <= 50% of its payers; no pass-through (a new outbound SENT counterparty in 24 h while
also gaining a new payer in 24 h); it is not a seed and no seed is within 2 hops. Behaviour changes: `Joiner.join_tokens`
treats a reputable payee (not owned by the evidence's customer) like an excluded node — not a join token and not walked
(`EntityGraph.neighbours_within` got an optional `skip` predicate; default behaviour unchanged). The graph detector's
MULE_FLOW does not fire for a reputable payee. A brand-new payee is never reputable, so mule_fanin (12 victims → young mule
→ one case) is unchanged, and so is `scripts/perf.py --traffic synthetic` (its shared payees have no history, so they still
chain until they become hubs). Tests: `tests/engine/test_payee_reputation.py`.
(2) **APP scam scenario** `scenarios/scam_app.yaml`: Priya on her own phone and home IP; payee_added A-SAFE-4471 with
payee_name_match false, nickname "RBI safe account"; ₹4,90,000 two minutes later; trusted push PASSED; a second ₹4,90,000
"try again"; preload = 5 earlier payers of the same account 20–8 h before. Engine config/code: `patterns.yaml` new
`pat_APP_SCAM1` (sequence S5 → S6 within 30 min, bonus 1.0), using two new optional pattern keys in `patterns.py`:
`first_reason_any: [PAYEE_NAME_MISMATCH]` and `absent_stages: [S2_CONTROL_TAKEOVER]` (so ATO cases never match it).
`policy.yaml` new rule `app_scam_hold` between `high` and `medium`: `when: {pattern_any: [pat_APP_SCAM1]}` →
HOLD_OUTBOUND_PAYMENTS, STEP_UP_TRUSTED_FACTOR, OPEN_CASE_P2 (new optional `pattern_any` in `policy.py`, matched against
case.pattern_hits; `replay.py` passes the replayed pattern hits). Why the rule: the genuine customer passes the trusted
step-up (it proves identity, not intent), which lowers P below HIGH; the hold must survive that. Tests:
`tests/engine/test_scam_direct.py`. Existing Dev 2 test assertions changed (additive only): `test_patterns.py` pattern-id
set, `test_policy.py` rule-id list, `test_scenario.py` ALL list. DEV1 side: `api/scenario_source.py` SCENARIO_IDS +=
scam_app; `/v1/engine/config` rules expose `pattern_any`; `web/src/screens/Demo.tsx` scenario card (the Settings screen does
not render `pattern_any` yet).
**Why:** User request (Review 1 future work). Golden values unchanged: test_golden_fusion, test_midnight_direct,
test_pipeline_fixture, test_replay and test_benchmark are green; Midnight ATO and benign_odd never match pat_APP_SCAM1.
**Local workaround / limitations:** In API mode the autopilot plays the steps only (the reset loads the midnight_ato
preload), so MULE_FLOW does not fire there: the first transfer reaches MEDIUM (P 0.46) and is held by `app_scam_hold`
(direct mode with preload: HIGH, P 0.55). Run it after a reset: Priya's midnight case is sticky (S2+, 72 h) and would absorb
the scam evidence. The preload payers are labelled benign by `ml.scenario`'s preload rule although they paid the same mule.
## 2026-10-10 — DEV1 (FYI to DEV2, no engine change): opt-in asymmetric crypto and TLS around §7.2 and §9.1
**What:** additions to the frozen ingestion (§7.2) and auth (§9.1) contracts. All are off by default: HMAC signatures
and HS256 tokens work exactly as before and every existing test passes (one hand-built test token now adds `iss`).
- **§7.2 Ed25519 signatures:** new optional request header `X-FM-Signature-Alg: ed25519` (absent or `hmac` = the §7.2
  HMAC rule). Same message (`timestamp + "." + raw_body_bytes`); `X-FM-Signature` is the lowercase-hex Ed25519
  signature, verified with `<FM_SIGNING_PUBLIC_KEY_DIR>/<source>.pub`. `FM_INGEST_AUTH` = `hmac` | `ed25519` | `any`
  (default `any`). Errors keep the §4 codes (`SIGNATURE_INVALID`, `STALE_TIMESTAMP`); no new codes.
  `scripts/sign.py:sign(source, body, timestamp=None)` keeps its signature and signs Ed25519 only with
  `FM_SIGN_ALG=ed25519` and a key in `FM_SIGNING_KEY_DIR`. The API signs its own events with Ed25519 when it holds that
  source's private key (and `FM_INGEST_AUTH` is not `hmac`).
- **§7.2 client certificates:** with `FM_REQUIRE_CLIENT_CERT=1` (Docker only, behind the TLS proxy) `/v1/events*` also
  need the proxy's `X-Client-Cert-Verify: SUCCESS` and a certificate CN equal to `X-FM-Source`, else `SIGNATURE_INVALID`.
  The proxy itself answers 403 `FORBIDDEN` (§4 error format) when no client certificate from the local CA was presented.
- **§9.1 EdDSA tokens:** `FM_JWT_ALG` = `HS256` (default, `JWT_SECRET`) | `EdDSA` (Ed25519 keys at `FM_JWT_PRIVATE_KEY` /
  `FM_JWT_PUBLIC_KEY`). Decoding accepts only the configured algorithm. Tokens now also carry `iss: "fraudmesh"`, which
  decoding requires (other claims unchanged).
- **§2 topology / §4 env:** the Docker demo adds an nginx `proxy` service that terminates TLS on the same ports
  (8000, 5173, 5174); api/web/bank are no longer published; Postgres requires TLS on TCP and is bound to 127.0.0.1.
  `CORS_ORIGINS` / `VITE_API_BASE` in compose become `https://…`. New Dev 1 env vars (read by api/ and scripts/ at call
  time, not by engine.common.settings): `FM_INGEST_AUTH`, `FM_SIGN_ALG`, `FM_SIGNING_KEY_DIR`, `FM_SIGNING_PUBLIC_KEY_DIR`,
  `FM_JWT_ALG`, `FM_JWT_PRIVATE_KEY`, `FM_JWT_PUBLIC_KEY`, `FM_REQUIRE_CLIENT_CERT`, `FM_TLS`, `FM_TLS_CA`, `FM_TLS_CERT_DIR`.
  Keys and certificates come from `scripts/make_certs.py` into gitignored `data/`.
**Why:** the user asked for HTTPS everywhere, mutual TLS for event senders, Ed25519 event signatures, asymmetric JWTs and
protection against HTTPS→HTTP downgrade for the local Docker demo, while keeping the PRD defaults working.
**Local workaround:** none needed; the engine is untouched. Dev 2: please acknowledge, or say if §7.2/§9.1 in the PRD
should be amended to mention the opt-in modes.

## 2026-10-10 — DEV1 → DEV2: CONTRACT_VERSION 1.0.0 → 1.1.0 (additive, optional only) for FraudMesh v3 — user-approved, needs Dev 2 sign-off
**What (engine/contracts.py, engine/common/tokenize.py, docs/CONTRACT_HASH):** every addition is optional, so 1.0.0 senders,
fixtures and stored events still validate (engine suite and contract-sensitive API tests green after the bump).
- `EntityKind` += `"ses"` (tokenized session id); `Action` += `"SCAM_WARNING"` (severity 1), `"COOLING_OFF_HOLD"` (severity 2).
- `Envelope.schema_version` accepts `"1.0"` or `"1.1"` (default `"1.0"`).
- New `NetworkType` = residential | mobile | hosting | vpn | tor | unknown; new `Telemetry` model (pointer type, coarse keystroke
  interval mean/std, paste-in-sensitive-field flag, payment/beneficiary dwell, screen-resolution changes, demo-only
  remote-access/active-call flags — never characters, OTPs or clipboard contents).
- `Context` += optional `session_id`, `browser_timezone`, `locale`, `platform`, `webgl_renderer`, `screen`, `telemetry`.
- `StoredEvent` += optional `session` (ses token), `network_type`, `network_source`, `network_confidence`, `ip_timezone`,
  `browser_timezone`, `locale`, `platform`, `webgl_renderer`, `screen`, `telemetry`.
- `to_stored_event(env, received_at, network=None)`: optional `network` = enrichment of the RAW ip computed by the API before
  tokenization (the raw ip still never leaves the function untokenized); `session_id` becomes `tok("ses", …)`.
**Why:** v3 phases 5 (network type / geo-confidence), 6 (device consistency, SESSION_CONTEXT_CHANGE), 7 (APP-scam
interventions), 8 (behavioural telemetry), 13 (IP/device/session correlation). Rejected alternative: no contract change,
which would have deferred all client-side signals.

## 2026-10-10 — v3 core detection (Phases 3 + 11), built in Dev 2's paths at the user's request — please review
**No contract change:** engine/contracts.py, engine/common/*, enums, event types and CONTRACT_VERSION are untouched
(verify_contracts: hash ok). BenchmarkReport is unchanged; the new metrics go to `benchmark/report_v3.json`. All constants
live in the new `engine/detectors/rules/v3_core.yaml` (loader `engine/fusion/v3_core.py`); calibration.json is untouched.
**Behaviour changes (all configurable):**
- **3.1 ATO.** New fusion floor `floor_S2_THEN_NEW_PAYEE` (on): a positive S2 item, then a positive S5 item at most 24 h
  later (inclusive, event time), with no `STEP_UP_PASSED_TRUSTED` at or after that S2 item → band ≥ HIGH. It fires on the
  S5 (payee_added) evidence itself. New policy rule `ato_new_payee_hold` (`when: {floor_any: [...]}`, a new optional rule
  key) records the floor as `decision.policy_rule`; the explanation's floor part cites "ev_S5 after ev_S2". New pattern
  `pat_ATO2` (S1 → S2 → S5, whole chain within 24 h, bonus 0.5) with new optional pattern keys `total_within_min` and
  `unless_patterns: [pat_ATO1]` (not evaluated when pat_ATO1 matched, so one S1 → S2 link is not rewarded twice; the
  golden case keeps exactly `pat_ATO1, pat_CASE_IP_CLOUD`). pat_ATO1 is unchanged.
- **3.2 Structuring.** Floor `floor_TXN_HIGH_CONFIDENCE` (on): a non-degraded txn item with p ≥ 0.90 → HIGH, disarmed by a
  later trusted step-up; policy rule `txn_high_confidence_hold`. It is a MODEL-CONFIDENCE floor, not proof of
  structuring. New `engine/features/txn_windows.py`: event-time customer+payee windows (24 h sum and count, 1 h velocity,
  near-limit count, sum and rate, repeats under one limit), deduplicated by event_id, late events placed by event time,
  inclusive 24 h boundary, and keys that never merge customers. They are appended to FEATURE_NAMES as `tw_*`;
  TXN_FEATURES (the model input) is unchanged, so no retraining was needed. The txn STRUCTURING rule reads them;
  "split over the limit" (≥ 2 near-limit transfers under the same L and a 24 h total ≥ L) sets p ≥ 0.30.
- **11.4 Feedback.** `apply_feedback` keeps its signature and the §16.5 golden step (cyber 0.50 → 5/11). New guards:
  reliability bounds [0.20, 0.95], ≤ 1.0 per detector per feedback, ≤ 3.0 per detector per 24 h (feedback time), and
  decay toward the §8 prior (half-life 30 d) using the feedback timestamps passed in (`FeedbackGuard`, read from
  `pipeline.feedback_guard` when present). New `apply_feedback_with_provenance(...)` returns `(FeedbackResult, provenance)`.
- **11.5 Correlated evidence** (OFF by default): provenance groups in v3_core.yaml (`corr_NEW_DEVICE`: NEW_DEVICE,
  MFA_CHANGED_AFTER_NEW_DEVICE, PROFILE_CHANGE_AFTER_NEW_DEVICE, RECENT_NEW_DEVICE). Items from different families that
  share a customer within 60 min count once (the weaker one × 0.5) and are labelled in the explanation. It is off because
  it changes the §12.4 golden values: ev_demo_02 is discounted at item 3 (L −1.255 → −1.750), and ev_demo_03 from item 4
  on; item 6 drops from CRITICAL (P 0.809) to HIGH (P 0.754); the final L goes 5.910 → 5.588 (still CRITICAL). With it
  off, every golden value is exact.
- **11.6 Late evidence** (on): while payment_state is `held`, a new positive cyber/auth/kyc item (not a step-up answer)
  with the band ≥ HIGH adds BLOCK_PENDING_PAYMENTS and sets `policy_rule = late_evidence_block` (held → blocked).
  FALSE_POSITIVE → normal is unchanged. Rail semantics: held = authorised but not captured; blocking voids before
  settlement; the engine never reverses a captured payment. Replay re-orders by event time, so a late item replayed
  before the hold shows the hold, not the block (arrival order is not stored with the evidence).
**Existing test assertions changed (additive):** the test_patterns.py pattern-id set (+pat_ATO2), the test_policy.py
rule-id list (+2 floor rules) and the test_simulate.py strict-threshold case. Floors ignore thresholds: the Midnight
payee_added is now held 2 min before the transfer, so 1 attack is still caught with impossible thresholds. **Needs Dev 1:**
tests/api/test_investigator_replay.py::test_simulator_numbers_move_with_thresholds asserts `attacks_caught == 0` with
thresholds 0.999/0.9999; with the floor it is 1 (same reason), so that assertion needs the same update. API hook: the
FEEDBACK route should call `engine.feedback.apply_feedback_with_provenance(..., feedback_ts=<feedback time>,
source=...)` and put `provenance` in the audit details; the pipeline can carry `feedback_guard = FeedbackGuard()`.
**Benchmark (seed 7, 30 per family, strict §10.9 definition unchanged):** ato 9 → 18/30 (at-or-before 27 → 30),
mule_fanin 30 → 30, structuring 0 → 30/30; siloed unchanged (0/30/30). FPR went 0 → 0.000604 (1 of 1,656 benign
customers: one benign transfer scored p ≥ 0.90). False declines went 0 → 0.000449 (11 of 24,503: that customer's later
payments while held). Compression is unchanged at 3.4107. The remaining 12 ATO attacks add a payee with
`payee_name_match` unset, so the graph detector emits no S5 evidence at the payee_added and the floor cannot fire before
the transfer. Catching them needs a graph-side S5 signal for "payee added within 24 h of a security change" (owned by
the graph_det owner). IEEE-CIS PR-AUC stays 0.0969 as measured: prevalence is 3.45 %, so it is 2.8× a random scorer
(report_v3.json `txn_model_ieee_cis`).
