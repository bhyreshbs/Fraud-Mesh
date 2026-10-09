# Changelog

## 3.0 — 2026-10-10

FraudMesh v3.0 hardens the 2.0 engine against the gaps found in review, adds network, session, scam, mule-ring and
insider intelligence, and adds application security. The architecture, API, console, Digital Twin and demo flows of
2.0 are kept. Engine contract **1.1.0** (additive and optional over 1.0.0; 1.0.0 senders and stored events still
validate). Decisions and per-phase details: [docs/CONTRACT_REQUESTS.md](docs/CONTRACT_REQUESTS.md) (2026-10-10 entries).

### Measured results (seed-7 benchmark, strict §10.9 definition unchanged, rerun on the merged v3 code)

| | 2.0 | 3.0 |
|---|---|---|
| Account takeover caught strictly before the last event | 9 / 30 | **19 / 30** (30 / 30 at or before) |
| Structuring | 0 / 30 | **30 / 30** |
| Mule fan-in | 30 / 30 | 30 / 30 |
| Genuine customers flagged HIGH | 0 / 1,656 | 1 / 1,656 (FPR 0.06 %) |
| Legitimate payments stopped | 0 / 24,503 | 11 / 24,503 (0.045 %, the same customer's later payments while held) |
| Alert compression | 3.41 : 1 | 3.59 : 1 |
| Txn model PR-AUC on IEEE-CIS (real card data) | 0.097 | 0.097 (unchanged; prevalence 3.45 %, 2.8× random) |

Files: `benchmark/report.json`, `report_details.json`, `report_v3.json` (precision, recall, F1, early detection, lead
time, money prevented, friction). Digital Twin scenario library: 14 of 15 scenarios meet their expected behaviour
([docs/V3_SCENARIOS.md](docs/V3_SCENARIOS.md)). Engine latency: [docs/V3_PERFORMANCE.md](docs/V3_PERFORMANCE.md).
All of this is synthetic or public-dataset evidence; none of it is a comparison with commercial products.

### Detection

- **Account takeover (phase 3.1).** Floor `floor_S2_THEN_NEW_PAYEE`: a control-takeover signal followed within 24 h by a
  new payee raises the case to at least HIGH at the payee step, unless a trusted step-up passed in between. Pattern
  `pat_ATO2` (new device → security change → new payee within 24 h) alongside the unchanged `pat_ATO1`.
- **Structuring (3.2).** Event-time customer+payee windows (`engine/features/txn_windows.py`: 24 h sum and count,
  velocity, near-limit count and repeats, deduplicated by event id, late events placed by event time). Floor
  `floor_TXN_HIGH_CONFIDENCE` (calibrated txn p ≥ 0.90 → HIGH); documented as a model-confidence floor, not proof of
  structuring.
- **Shared IPs and credential stuffing (4).** Time-windowed shared-IP classifier (device / account / session / client
  diversity in 24 h) that stops carrier IPs from joining strangers while keeping them as context. Account-centric,
  device-centric and global login-failure windows: `ACCOUNT_DISTRIBUTED_FAILURES`, `ACCOUNT_LOW_SLOW_FAILURES`,
  `DEVICE_MULTI_ACCOUNT_FAILURES`, `GLOBAL_LOGIN_FAILURE_SPIKE`. 30 users behind one carrier IP: no flag, no link.
- **Network intelligence (5).** The raw IP is classified at ingestion (residential / mobile / hosting / vpn / tor /
  unknown, with source and confidence) from local files only, then tokenized; the raw IP is never stored or logged.
  Geo-confidence weighting for VPN / hosting / Tor; browser vs IP time-zone mismatch as a weak signal. A VPN alone
  never blocks.
- **Device and session (6).** Device-consistency checks on the optional client fields (platform, WebGL, screen, time
  zone, locale) and `SESSION_CONTEXT_CHANGE` when a session's network and device context change together. Phase 15
  extends the session rules to hijacked sessions that go straight to a payee, payment or re-KYC.
- **APP scams (7).** A separate path for payments the genuine customer authorises: first payment to a payee, amount
  far above baseline, young or reported payee, fan-in from unrelated customers, recent security change, pasted payee
  details, rushed payment, demo-only remote-access / active-call flags. Interventions `SCAM_WARNING` and
  `COOLING_OFF_HOLD`; a passed step-up does not release the hold (it proves identity, not intent). The twin labels
  each case `account_takeover`, `app_scam`, `legitimate` or `unclassified`.
- **Behavioural telemetry (8).** The bank app sends coarse telemetry only (pointer type, keystroke-interval mean/std,
  paste-in-sensitive-field flag, dwell times, screen changes); never characters, OTPs or clipboard contents.
- **Mule rings (9).** Seed-independent signals: fan-in to new accounts, pass-through, fan-out, dormant activation,
  rapid hops, rings; time-decayed edges. Safe joining through payees (two bridges, or one suspicious bridge with
  corroboration) replaces the crude popular-payee cutoff. Personalized PageRank is built but off (no benchmark gain,
  +0.3 ms/event).
- **Insider abuse (10).** Staff changes right after a new-device login, repeated sensitive actions and off-hours
  actions fire even from the trusted corporate network. Two-person approval for limit increases on MEDIUM+ cases;
  out-of-queue case access is audited.
- **Reliability (11).** Missing history is explicit (`has_login_history`), never a measured zero. Feedback-poisoning
  guards: reliability bounds [0.20, 0.95], per-update and per-24 h caps, decay to the prior, provenance in the audit
  row. Correlated-evidence discount built but off by default (it changes the PRD golden values). Late cloud / auth /
  KYC evidence on a held case blocks it before settlement (`late_evidence_block`); a captured payment is never reversed.

### Security (phases 6.3, 12, 13, 14)

- Server-side sessions with opaque random ids, rotation, revocation and expiry; CSRF header for cookie-authenticated
  routes; single-flight token refresh in the console.
- SQL-injection and XSS audit: parameterised queries, allow-listed identifiers, no raw HTML rendering; regression tests
  for login, search, cases and ingestion; frontend XSS and secret scanners (`scripts/check_frontend_xss.py`,
  `scripts/check_secrets.py`).
- AES-256-GCM for selected stored fields (`api/crypto_box.py`, key ids and rotation, off by default); Argon2id
  passwords; HMAC-SHA256 tokens for phone numbers and other low-entropy identifiers; no MD5 left.
- Opt-in TLS, mTLS for event senders, Ed25519 event signatures and EdDSA JWTs; hardened nginx proxy.
- What can and cannot be collected from browsers, apps and servers: [docs/V3_DATA_COLLECTION.md](docs/V3_DATA_COLLECTION.md)
  (no MAC addresses, no raw IPs in storage, no JA4 / TCP / WebRTC fingerprints).

### Digital Twin and performance (phase 15)

- Scenario library of 15 scenarios played through the real engine (`python -m benchmark.twin_scenarios`); eight new
  scenario files in `scenarios/`.
- Engine latency measured per event (`python -m benchmark.perf_pipeline`); see docs/V3_PERFORMANCE.md.

### Integrations that need credentials or approval (not connected)

- **Firebase:** an auth / audit-mirror boundary with fake-client tests only (`api/firebase_boundary.py`). No project,
  credentials or `firebase-admin` dependency.
- **Payee / mobile-number risk registry** (e.g. DoT Financial Fraud Risk Indicator): provider interface plus a synthetic
  fixture provider (`FM_PAYEE_RISK_PROVIDER=fixture`). No live registry.
- **PayPal:** offline mock by default; the sandbox adapter needs sandbox credentials.
- **IP intelligence feeds:** IP2Proxy LITE / GeoLite2-ASN are read only when a local path is configured; not committed.

### Known limitations

- `session_replay_clone`: a stolen session replayed with a perfectly cloned device from a hosting network is not
  stopped (strict xfail in `tests/engine/test_v3_twin_scenarios.py`). Needs a session-level network-type escalation
  rule or device-bound sessions.
- 11 of 30 ATO attacks are still caught only on the final transfer (at-or-before 30/30): they add a payee without a name
  check, so no payee-step evidence exists before the transfer.
- The twin's case_kind labels the structuring scenario and the no-seed mule ring `app_scam`: it has only
  account_takeover / app_scam / legitimate / unclassified, so customer-driven laundering and mule activity fall into the
  APP bucket. Detection and holds are unaffected; the label is descriptive only.
- APP-scam warnings open 124 extra LOW cases on benign customers in the benchmark (first payment far above baseline to
  a new payee); tune `app_scam.yaml warn_at` if that is too much friction.
- WebAuthn / passkeys and device-bound sessions are designed, not built (docs/SECURITY.md).
- Contract 1.1.0 and the engine changes made in Dev 2's paths await Dev 2's sign-off (docs/CONTRACT_REQUESTS.md).

### New environment variables (all optional)

`FM_IP2PROXY_CSV`, `FM_GEOLITE2_ASN_MMDB`, `FM_PAYEE_RISK_PROVIDER`, `FM_LIMIT_TWO_PERSON`,
`FM_LIMIT_TWO_PERSON_MIN_BAND`, `FM_CASE_DENIED_ALERT_N`, `FM_SESSION_MAX_AGE_S`, `FM_SESSION_CHECK_TTL_S`,
`FM_DATA_KEYS`, `FM_DATA_KEY_ACTIVE`, `FM_AUTH_PROVIDER`, `FM_FIREBASE_PROJECT_ID`, `FM_AUDIT_MIRROR`, `FM_TLS`,
`FM_TLS_CA`, `FM_TLS_CERT_DIR`, `FM_REQUIRE_CLIENT_CERT`, `FM_INGEST_AUTH`, `FM_SIGN_ALG`, `FM_JWT_ALG`,
`FM_JWT_PRIVATE_KEY`, `FM_JWT_PUBLIC_KEY`.

## 2.0 — 2026-10-09

Correlation engine with seven detectors, reliability-weighted fusion, case joiner and policy; transaction model trained
on synthetic, IEEE-CIS and AMLSim data; Digital Twin; investigator console and bank demo app; live two-laptop demo.
See the README.
