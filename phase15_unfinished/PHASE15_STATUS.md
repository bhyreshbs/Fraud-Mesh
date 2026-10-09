# Phase 15 — status handover (unfinished)

Phase 15 of the FraudMesh v3.0 upgrade (Digital Twin scenario library + performance) was stopped part-way to save
session usage. Nothing in this folder is wired into the running code: the branch `v3` is exactly the tested state
before Phase 15 (commit `7c404ea`) plus this folder. Apply the pieces below deliberately and test them.

## Where v3 stands (before Phase 15)

- Merged on `v3`: backend audit fixes, new console (`ui-threejs`), live Suricata follower, PayPal mock/sandbox rail,
  payee reputation + APP scam scenario, opt-in TLS/mTLS/Ed25519/EdDSA, contract 1.1.0, competitive analysis, and the
  v3 phases 3–14 (core detection, network/session, graph/scam/insider, app security) plus policy merge and API hooks.
- Last verified: engine suite 436 passed (after the policy merge); `tests/api/test_payment_rail.py` 24 passed after the
  API-hook commit. The full API + integration suite was NOT re-run after the last commit (`7c404ea`).
- Strict benchmark measured by the core-detection branch (before the graph/network/policy merges): ATO 18/30
  (was 9/30), structuring 30/30 (was 0/30), mule 30/30, FPR 1/1656. `benchmark/report.json` has NOT been re-run on the
  fully merged code.

## Completed in Phase 15

1. **Hijacked-session coverage** — `0001-session-hijack-coverage.patch` (agent commit `e6ac64b`, branch
   `v3/twin-perf`, based on `7c404ea`).
   - The auth detector also handles `payee_added`, `transaction` and `kyc_result`, but only for the session rules
     (`SESSION_CONTEXT_CHANGE`, `DEVICE_INCONSISTENT`). Its other rules don't fire on those types.
   - `FixtureDetector` keeps the PRD §10.4 handles, so the §12.4 golden values are unchanged.
   - Also fixes a `KeyError` in the closing narrative for the 1.1.0 actions `SCAM_WARNING` / `COOLING_OFF_HOLD`.
   - Files: `engine/detectors/{auth,base,fixture}.py`, `engine/explain/narrative.py`,
     `tests/engine/{test_detectors,test_explain,test_v3_net_session}.py`.
   - Test status: **not confirmed** — the agent committed it, but its suite results were not reported before the stop.
2. **Draft scenario files** — `scenarios_draft/` (8 of the 15 Phase 15 scenarios; written, never run):

   | File | Scenario # | Description |
   |---|---|---|
   | `structuring_split.yaml` | 2 | three transfers just under ₹1,00,000 to one new payee within 5 h |
   | `device_multi_account.yaml` | 4 | same device attacks multiple accounts, then a takeover payment |
   | `benign_vpn.yaml` | 6 | own phone, VPN exit abroad, payment to a known payee (must NOT block) |
   | `residential_proxy_ato.yaml` | 7 | home-ISP proxy exit in the victim's city, new device, email change, payee, transfer |
   | `session_replay_clone.yaml` | 8 | stolen session from a cloud host with cloned fingerprint; payee + transfer, no login |
   | `remote_access_demo.yaml` | 10 | remote access of Priya's own phone (demo telemetry): pasted payee, rushed transfer |
   | `late_evidence_feedback.yaml` | 14 | late cloud/KYC evidence after a held transfer, then a burst of wrong FALSE_POSITIVE verdicts |
   | `appsec_payloads.yaml` | 15 | SQLi/XSS strings in user agent, payee nickname and cloud action stored as data |

   Scenarios already on `v3` (no draft needed): 1 `midnight_ato`, 9 `scam_app`, 11 `mule_ring_noseed`,
   12 `popular_merchant_legit`, 13 `insider_trusted_network`. Still missing: 3 (30 legit users behind one shared IP)
   and 5 (distributed credential stuffing across rotating IPs) — these are multi-customer traffic and were planned to
   be generated in the runner (unit tests for both already exist in `tests/engine/test_v3_net_shared_ip.py`).

## Still to do

### Phase 15
1. Apply and test the patch: `git am phase15_unfinished/0001-session-hijack-coverage.patch`, then run `tests/engine`
   (golden fusion, midnight direct, scam, `test_detectors`, `test_v3_net_session` must pass).
2. Validate each draft scenario against `ml.scenario.load_scenario` / `expand`, move the good ones into `scenarios/`,
   and add their ids to `SCENARIO_IDS` in `api/scenario_source.py`.
3. Build `benchmark/twin_scenarios.py`. It plays all 15 scenarios in direct mode (MemoryStore + real Pipeline + preload
   + seeds), generating scenarios 3 and 5 synthetically, and writes `benchmark/twin_scenarios.json` and
   `docs/V3_SCENARIOS.md`. Per scenario, record:
   - expected behaviour;
   - detection stage;
   - final band;
   - detectors and reason codes;
   - FP/FN;
   - time to detection;
   - payment intervention;
   - money outcome;
   - CaseTwin `case_kind`.
   Say plainly that twin forecasts are synthetic, not proof.
4. `tests/engine/test_v3_twin_scenarios.py` must assert the CORRECT expected behaviour. Mark real gaps
   `xfail(strict=True, reason=...)`; never weaken a test to make it pass.
5. Performance:
   - Measure `Pipeline.process` p50/p95/p99 over the seed-7 stream; timing code goes in `benchmark/` or `scripts/`,
     never `engine/`.
   - Measure API decision latency with `scripts/perf.py --rate 50 --seconds 60`.
   - Evaluate the single FIFO worker. `engine_lock` and the shared in-memory graph make per-customer sharding unsafe;
     cached seed distances, window efficiency and EMA baselines are the other levers.
   - Implement only a proven, result-identical improvement, and write up the numbers in `docs/V3_PERFORMANCE.md`.

### Phases 16–18
6. Run the full suites: `tests/engine`, `tests/api`, `tests/integration`, and `STORE=pg tests/engine/test_store_contract.py`.
7. Re-run `python -m benchmark.run` on the fully merged code and commit `benchmark/report.json`, `report_details.json`
   and `report_v3.json` (only with real rerun results).
8. Smoke test against a live API: `scripts/smoke_test.py --all`, plus `scam_app` via `/v1/demo/run`.
9. Docs:
   - README: v3 features, env vars and commands.
   - A v3.0 changelog.
   - Fix the stale numbers in the README and Review 1 (ATO at-or-before 27/30, compression 3.41:1, before the v3
     rerun), then replace them with the v3 rerun results.
10. Open a PR from `v3` into `main` for review/CI. Never push to `main` directly.

## How to run (Windows, Git Bash)

- Python venv: `.venv/Scripts/python`.
- Postgres: a throwaway container `fraudmesh-test-db` on `127.0.0.1:5432` (fm/fm).
  - **Always use `127.0.0.1`**: `localhost` hangs on IPv6 on this machine.
- Tests: `DATABASE_URL=postgresql+psycopg://fm:fm@127.0.0.1:5432/fraudmesh .venv/Scripts/python -u -m pytest <paths> -p no:cacheprovider > out.txt 2>&1`.
  - Write output to a file; piped output buffers. Don't add `-q`.
  - Windows sometimes raises `WinError 10013` in test setup under load. Re-run those tests alone before calling them
    failures.
- Checks: `ruff check .`, `python scripts/verify_contracts.py`, and the CI guards in `.github/workflows/ci.yml`.

## Open decisions / notes for Dev 2
- Contract 1.1.0 and all engine changes made in Dev 2's paths are logged in `docs/CONTRACT_REQUESTS.md` (2026-10-10
  entries) and need Dev 2's sign-off.
- The correlated-evidence discount is built but off by default (it changes the §12.4 golden values).
- A blocked case now voids its held authorisations at once; a later FALSE_POSITIVE can't capture them.
