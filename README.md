# HR2-OI-9C037B24 — FraudMesh 2.0
HACKERING 2.0 Round 2 Project Repository for Team Global Maxima (Open Innovation Track)

# FraudMesh 2.0

FraudMesh turns weak fraud, identity, KYC, device and security signals into **one explainable attack case per attack**,
and acts **before money moves**. A login from a new device, an SMS-number change, a weak KYC selfie, a support-console
limit raise and a new payee each look harmless in their own team's tool. FraudMesh joins them through an entity graph,
fuses them into one probability, holds or blocks payments, explains every decision event by event, replays what would
have happened under other policies, and shows the earliest moment it could have intervened.

> "FraudMesh doesn't replace fraud detectors. It turns scattered signals across fraud, identity, KYC and cyber into one
> attack decision, explains it event by event, and shows the earliest moment it could have stopped it."

The original build spec is [docs/PRD.md](docs/PRD.md) (source of truth: [docs/PRD.pdf](docs/PRD.pdf)); decisions and
deviations made during the build are logged in [docs/CONTRACT_REQUESTS.md](docs/CONTRACT_REQUESTS.md).
This README describes the system **as built** (October 2026), including what was added after the PRD: real-data model
training, the Digital Twin, the redesigned console and the live two-laptop demo.

**Contents:** [Capabilities](#1-what-the-system-can-do) · [Architecture](#2-architecture) ·
[How a decision is made](#3-how-a-decision-is-made) · [ML models and results](#4-machine-learning-models-and-measured-results) ·
[Digital Twin](#5-digital-twin) · [Console and bank app](#6-investigator-console-and-bank-demo-app) ·
[Demo](#7-running-the-demo) · [Security](#8-security-and-privacy) · [API](#9-api-reference) · [Setup](#10-setup) ·
[Tests and CI](#11-tests-and-ci) · [Repository map](#12-repository-map) · [Limitations](#13-known-limitations-and-honest-findings) ·
[Future research](#14-future-research-directions)

---

## 1. What the system can do

| Capability | What it does | Where |
|---|---|---|
| Signed, private ingestion | 11 event types arrive HMAC-signed per source; every phone, email, IP, device and account is replaced by an HMAC token before storage. No raw PII is stored. | `api/routers/ingest.py`, `engine/common/tokenize.py` |
| Entity graph | Customers, accounts, devices, IPs, phones, payees, staff identities and their links (logged in from, connected via, sent to, shares device…). Hubs, merchants and carrier IPs are excluded so they never join strangers. | `engine/graph/` |
| 7 detectors | Network IDS, login behaviour (ML), auth/MFA, KYC, cloud audit, entity graph, transactions (ML). Each emits evidence with a probability, reasons and an ATT&CK technique. | `engine/detectors/` |
| Case joining | Evidence that shares an entity (within 2 graph hops, 6 h; 72 h for a customer whose case reached control takeover) joins one case; overlapping cases merge. One attack = one case. | `engine/cases/joiner.py` |
| Fusion | Reliability-weighted log-odds over all evidence, sequence-pattern bonuses and hard floors give one P(attack) and a band (LOW / MEDIUM / HIGH / CRITICAL). | `engine/fusion/` |
| Kill-chain stages | S0 Recon → S1 Initial access → S2 Control takeover → S3 Identity manipulation → S4 Escalation → S5 Positioning → S6 Monetization. | `engine/cases/stages.py` |
| Policy and actions | MEDIUM: step-up check. HIGH: hold outbound payments + push to the registered device. CRITICAL: block payments, freeze new payees, revoke sessions. | `engine/policy/policy.yaml`, `api/worker.py` |
| Step-up verification | SMS OTP or push to the registered phone; the customer can tap **"Not me"** (forces CRITICAL). | `api/stepup.py`, bank-demo phones |
| Explanation | Exact log-odds waterfall (every bar is that evidence's contribution) and a template narrative where every sentence cites evidence IDs. | `engine/explain/` |
| Replay | Earliest intervention point, detector ablation ("without KYC"), siloed vs fused comparison. | `engine/replay/` |
| Policy simulator | Move the band thresholds and re-score every stored case. | `engine/replay/simulate.py` |
| Learning from analysts | "Confirm fraud" / "False positive" update each detector's reliability (Beta α/β) and mark fraud seeds in the graph. | `engine/feedback.py` |
| Investigator AI | Answers "Why did you block this?", "What if we ignored KYC?", "Earliest intervention point?" from fixed tools and templates; every sentence must cite real IDs; prompt-injection safe. | `api/investigator/` |
| **Digital Twin** | Replays a case into a virtual copy of the bank and compares 8 prevention strategies on isolated copies, with a stage-by-stage forecast. | `engine/twin/` |
| Benchmark | 14 days × 2,000 customers with 90 held-out attacks; fused vs siloed detection, false positives, alert compression, lead time. | `benchmark/` |
| Live console | Investigator console updates over WebSocket; nothing needs a reload. | `web/` |
| Live two-laptop demo | Priya on one laptop, the attacker on another (same Wi-Fi); a demo IDS sensor, a Demo panel showing only the live case, and an 18-second reset. | `api/demo_baseline.py`, `web/src/screens/DemoPanel.tsx` |
| Audit | Hash-chained, append-only audit log of every decision and analyst action, verifiable on demand. | `api/audit.py` |

## 2. Architecture

One FastAPI service, one PostgreSQL database and two static web apps, all in Docker Compose. The fraud engine is a
pure-Python library that the API's single worker calls once per event. No Kafka, no Redis, no graph database: the
queue is in-process and the graph lives in memory, rebuilt from the `edges` table at startup. The whole demo runs offline.

```
 Bank app + phones (5174)      scripts / autopilot / generator      Suricata IDS + cloud-audit lines
            \                              |                                  /
             v                             v                                 v
   API  POST /v1/events   (verify HMAC → validate envelope → tokenize PII → INSERT events)
             |
   Worker (one asyncio task, FIFO)  →  engine Pipeline.process(event)
             |                           graph → features → 7 detectors → case joiner → fusion → stages → policy
             |                           (all persistence through the Store protocol: PgStore / MemoryStore)
             |  → step-up challenges (OTP / push) → payment outcome (completed / held / blocked) → WebSocket broadcast
             v
   Routers: cases, explanation, replay, ask, feedback, simulate, metrics, twin, engine config, demo, audit, health
             |
   Investigator console (5173)  ←  REST + WebSocket /v1/stream
```

| Container | Port | What |
|---|---|---|
| `db` | 5432 | PostgreSQL 16 |
| `api` | 8000 | FastAPI + worker + engine (`uvicorn api.main:app`) |
| `web` | 5173 | Investigator console (React 18 + Vite + Tailwind, Stitch "Warm Neumorphic Glass" design) |
| `bank` | 5174 | NammaBank demo bank app + simulated phones (Priya's and the attacker's) |

**Seams (frozen):** `engine/contracts.py` (data models, hash-checked in CI), the `Store` protocol and the
`Pipeline` / `engine.api` functions. `engine/` never imports `api/` and never reads the wall clock ("now" is the
event's `occurred_at`), which keeps replays deterministic.

**Stack:** Python 3.11/3.12, FastAPI, Pydantic v2, SQLAlchemy 2, psycopg 3, Alembic, PostgreSQL 16, NetworkX, NumPy,
LightGBM, scikit-learn, SHAP, PyJWT, Argon2; React 18, TypeScript, Vite, Tailwind, TanStack Query, Recharts, Cytoscape.js,
FingerprintJS; Docker Compose; GitHub Actions.

## 3. How a decision is made

### Events (11 types, `engine/contracts.py`)
`login`, `mfa_change`, `mfa_challenge`, `sim_signal`, `kyc_result`, `profile_change`, `payee_added`, `transaction`,
`cloud_audit`, `network_ids_alert`, `step_up_result`. Sources: `demo-bank-web`, `network-ids`, `cloud-audit`, `simulator`.

### Detectors
| Detector | Looks at | Example reasons | Stage |
|---|---|---|---|
| `netsec` | IDS alerts, failed logins | IDS_SEV2, CREDENTIAL_STUFFING_IP (T1110.004) | S0 |
| `behaviour` | Successful logins (logistic regression + isotonic) | NEW_DEVICE, NEW_ASN, FAR_FROM_HOME, ODD_HOUR, IMPOSSIBLE_TRAVEL | S1 |
| `auth` | MFA / profile / SIM changes, step-up results | MFA_CHANGED_AFTER_NEW_DEVICE, MFA_FAIL_THEN_PASS, PUSH_SPAM, RECENT_SIM_SWAP, CUSTOMER_DENIED | S2 |
| `kyc` | Re-KYC results | LOW_LIVENESS, LOW_FACE_MATCH, DOC_TAMPER, INJECTION_SUSPECTED | S3 |
| `cyber` | Cloud / support-console audit (Sigma-style rules) | cloud_limit_raise_untrusted_ip (T1098), mfa_reset_by_support_untrusted_ip | S4 / S2 |
| `graph` | Payees: distance to confirmed mules, mule flow, name mismatch | SEED_DISTANCE_1/2/3, MULE_FLOW, PAYEE_NAME_MISMATCH | S5 |
| `txn` | Transfers (LightGBM + isotonic, SHAP top reasons) | AMOUNT_HIGH_VS_MEDIAN, NEW_PAYEE, PAYEE_FAN_IN, STRUCTURING | S6 |

Features come from **one** module shared by training and live scoring (`engine/features/features.py`), so there is no
train/serve skew. They are computed from the state *before* each event (amount vs 30-day median, payee fan-in, minutes
since a new device, km from home, travel speed, failed logins per hour…).

### Fusion (`engine/fusion/fusion.py`)
```
ℓᵢ = rᵢ · clip( logit(pᵢ) − logit(π), −2, +3 )        π = base rate 0.01, rᵢ = detector reliability α/(α+β)
L  = logit(π) + Σ δᵢ·ℓᵢ + Σ pattern bonuses            δ = 1 for the strongest item of a family, 0.5 for the rest
P  = 1 / (1 + e^(−L))
```
- **Patterns** (`patterns.yaml`): `pat_ATO1` new-device login → MFA/profile change within 30 min (+0.5);
  `pat_CASE_IP_CLOUD` cloud action from an IP already in the case (+0.3).
- **Floors** (can only raise the band): customer said "Not me" → CRITICAL; payee is a confirmed fraud seed → HIGH;
  3 stages within 30 min → MEDIUM.

### Bands and policy (`engine/policy/policy.yaml`, thresholds 0.20 / 0.50 / 0.80)
| Band | Actions |
|---|---|
| LOW | allow (CAPTCHA for credential stuffing) |
| MEDIUM | step-up, any factor |
| HIGH | hold outbound payments, step-up on the trusted (registered) device, open P2 case |
| CRITICAL | block pending payments, freeze new payees, revoke sessions, open P1 case |

A transfer's outcome is decided with the case state **after** the decision on that same transfer, so a transfer that
pushes its case to HIGH is itself held.

### The reference story: Midnight account takeover (`scenarios/midnight_ato.yaml`)
| Step | Event | Risk (reference run) | Response |
|---|---|---|---|
| 1 | IDS: credential stuffing from 185.220.101.7 | LOW 1.7% | none |
| 2 | Attacker logs in as Priya from a new laptop on a hosting network | LOW 4.5% | log |
| 3 | SMS number replaced by the attacker's | MEDIUM 22% (`pat_ATO1`) | step-up |
| 4 | OTP passes, because it went to the attacker's swapped number | MEDIUM 40% | counted as a clue |
| 5 | Re-KYC with weak liveness (0.38) | **HIGH 67%** | **hold payments**, push to Priya: earliest intervention, 13 min before the money moves |
| 6 | Support console raises the limit from the same IP | CRITICAL 81% (`pat_CASE_IP_CLOUD`) | block, freeze, revoke |
| 7 | Payee Ravi added: one hop from a confirmed mule device | CRITICAL 97% | |
| 8 | ₹4,80,000 transfer | CRITICAL 99.7% | **blocked** |
| 9 | Priya taps "Not me" | CRITICAL (floor) | case → Investigating |

Two more scenarios: `mule_fanin` (12 customers pay one mule account, which forwards 90%) and `benign_odd` (Priya
travels with a new phone, approves the push on her registered phone; must never exceed MEDIUM).

## 4. Machine-learning models and measured results

### Transaction model (`ml/artifacts/txn_v1.joblib`, LightGBM + isotonic)
Trained on three datasets, each split **by time** so every test period is later than anything the model saw.
Each dataset weighs the same in training.

| Dataset | Transactions | Fraud | Split | Test PR-AUC | Test ROC-AUC |
|---|---|---|---|---|---|
| Synthetic bank events (`ml.generator`, seed 1, 40 attacks per family) | 30,165 | 561 | days 1-9 / 10-11 / 12-14 | 0.9995 | 1.000 |
| [IEEE-CIS Fraud Detection](https://www.kaggle.com/c/ieee-fraud-detection) (real card-not-present) | 590,540 | 20,663 | 60% / 15% / 25% | 0.097 | 0.759 |
| [IBM AMLSim](https://github.com/IBM/AMLSim) samples (fan-in, cycle, both) | 356,613 | 15,006 | 60% / 15% / 25% | 0.742 | 0.867 |

- The model trained on synthetic data alone scored ROC-AUC **0.50 (random)** on the IEEE-CIS and AMLSim test periods; adding them made it 0.76 and 0.87.
- `ml/datasets/` converts each dataset to FraudMesh events and runs them through the engine's own feature module.
- **Evaluated and rejected:** PaySim (its fraud is defined by draining the sender's balance, which our 11 features do not see; 99.7% of its senders appear once) and the Feedzai Bank Account Fraud suite (account-opening applications: no matching detector).
- Calibration error (ECE) ≤ 0.006 on every test set.
- The manifest (`ml/artifacts/manifest.json`) stores the headline (bank events) metrics plus `per_domain` and `pooled_test`.

### Login behaviour model (`ml/artifacts/behaviour_v1.joblib`)
Logistic regression + isotonic on 5 login features, trained on synthetic data (21,391 logins, 28 attack logins).
No real login dataset has been added yet (see future research).

### Benchmark (`benchmark/report.json`: seed 7, 14 days, 2,000 customers, 90 held-out attacks)
| Family | Caught fused | Caught siloed | Median lead time |
|---|---|---|---|
| Account takeover | 9 / 30 | 0 / 30 | 11 min |
| Mule fan-in | 30 / 30 | 30 / 30 | — |
| Structuring | 0 / 30 | 30 / 30 | — |

"Caught" uses the strict PRD definition: severity ≥ HOLD **before** the attack's last event. Counted "at or before
the last event" (`benchmark/report_details.json`), every family is 26–30/30. Genuine customers flagged HIGH: **0 of
1,656**; legitimate payments stopped: **0 of 24,503**; alert compression **3.4 : 1**.

When the same 90 attacks are loaded into the live demo (`FM_BG_ATTACKS=30`), **every attack forms exactly one case**:
45 CRITICAL, 41 HIGH, 4 MEDIUM, plus 74 LOW cases from genuine customers (none above LOW).

### Performance
Decision latency (event received → payment outcome) at 50 events/s on GitHub's Linux runners: p50 ≈ 5 ms,
p95 ≈ 5–55 ms; the target is p95 < 150 ms. `scripts/perf.py` drives realistic generator traffic.

## 5. Digital Twin

A simulation-first **cyber-financial digital twin** (`engine/twin/`), built from the events FraudMesh already stores
(read-only; no new data sources). Console: the **Digital Twin** page and the **Twin** tab of every case.

1. **Virtual state** (`state.py`): sessions, SMS numbers / SIMs, payees, limits, devices, IPs and staff identities,
   updated event by event; entities get tags such as "attacker device", "OTPs now reach the attacker", "1 hop from a known mule".
2. **Attack and policy simulator** (`simulate.py`): replays a case on an **isolated copy** of the starting state under
   8 strategies: no controls · siloed detectors · SMS OTP at MEDIUM · freeze payees at MEDIUM · hold at HIGH ·
   block at CRITICAL · the live FraudMesh policy · FraudMesh + strong txn block (a candidate rule). It reports money
   lost and protected, when and at which stage the attacker was stopped, lead time before the transfer, and friction
   for genuine customers. Attacker vs customer is decided from labels when present, else from `*_NEW_DEVICE` evidence
   and the graph's first-seen dates.
3. **Forecast** (`predict.py`): stage-to-stage transitions learned from 120 labelled attacks (`python -m ml.train_twin`
   → `ml/artifacts/twin_transitions.json`): likely next stage, chance of reaching the money, typical minutes to get there.

Findings on the 90 held-out attacks: no controls lose ₹5.56 Cr; the live FraudMesh policy protects 65%; siloed txn
blocking protects 99.8%; **FraudMesh + strong txn block protects 99.9%**. On Midnight ATO, SMS OTP alone loses the
full ₹4,80,000 (the attacker swapped the number first), while the live policy locks the attacker out 13 minutes
before the transfer. These are simulated outcomes under documented assumptions (shown in the UI), not guarantees.

## 6. Investigator console and bank demo app

**Console (`web/`, port 5173)**, Stitch "Warm Neumorphic Glass" design, all data from the API, live over WebSocket:

| Screen | What it shows |
|---|---|
| Overview | Active / escalated cases, money prevented, model precision, case velocity, priority cases, risk distribution, detector health |
| Case Queue | KPI tiles, search, band tabs, cases sorted by band then most recent, IST times with dates, a LIVE badge on recently active cases |
| Investigations | Dossier list + the full case workbench: header, stage strip, risk-over-time chart, tabs **Timeline · Graph · Explanation · Replay · Twin · Ask**, analyst verdict bar |
| Detection Engine | The 7 detectors (reliability, α/β), per-dataset model metrics, recently escalated cases |
| Metrics & Analytics | Money prevented, precision, compression, false-positive rate, fused vs siloed by family, live impact by band, policy simulator |
| Digital Twin | Virtual bank size and state, riskiest cases, the selected case replayed under every strategy |
| Demo | The live two-laptop demo: only the live case(s), live events, Reset |
| Demo Simulator (admin) | Autopilot scenarios, execution pipeline, live telemetry, intervention result, detectors fired |
| System Health | API, database, pipeline, model artifact, contract, login, RBAC, audit chain, WebSocket checks |
| Settings | Read-only live configuration: bands, policy rules, patterns, models, security, services |

Users: `analyst@`, `lead@`, `admin@fraudmesh.local`, password = `DEMO_PASSWORD` in `.env`. Lead+ can take manual
actions and verify the audit chain; admin can reset and run scenarios.

**Bank demo app (`bank-demo/`, port 5174)**, a fictional "NammaBank": an identity switcher (Priya's phone / Attacker
laptop / this browser), login, security (SMS number), KYC, payees, transfers (shows "Blocked – contact your bank"), and
two simulated phones: `/phone/priya` (receives the push, "Not me") and `/phone/attacker` (receives OTPs after the swap).
It never holds a signing secret: `/v1/demo/emit` signs server-side.

## 7. Running the demo

### A. Live two-laptop demo (recommended)
1. Bring the stack up and make sure the data is in place (a full reset with `FM_BG_ATTACKS=30` gives the 164
   benchmark cases with Priya clean). A full reset automatically saves the **demo baseline**; the Demo page can also
   save the current data as the baseline.
2. **Laptop 1 (Priya):** `http://<host>:5174/phone/priya`.
3. **Laptop 2 (attacker):** `http://<host>:5174`, identity **Attacker laptop**; OTPs arrive at `/phone/attacker`.
   Log in → change the SMS number → add payee `A-RAVI-778` → transfer ₹4,80,000.
4. **Dashboard:** `http://<host>:5173` → **Demo**. The attacker's login makes the **demo IDS sensor** raise a
   credential-stuffing alert from his IP (as Suricata would), so the case starts at Recon; it climbs to CRITICAL, the
   transfer is blocked, and the case appears in the Case Queue (top of CRITICAL, LIVE badge), Investigations, Metrics
   and the Digital Twin.
5. **Reset** (Demo page, admin) restores the baseline snapshot in ~18 s: only the live case disappears, everywhere at
   once (the API broadcasts `demo_reset` to every open console); the benchmark data is not reloaded.

Measured on this build: IDS → behaviour → auth (`MFA_CHANGED_AFTER_NEW_DEVICE`) → graph (`SEED_DISTANCE_1`) → txn,
**CRITICAL 98.2%**, transfer **blocked**, reset in **18.2 s**, 164 benchmark cases intact.

### B. Autopilot
Console → **Demo Simulator** (admin) → pick a scenario → *Trigger scenario* (speed 8 plays the 27-minute Midnight ATO
in about 3.4 minutes), or `python scripts/play.py midnight_ato --speed 8`.

### C. By hand with scripts
`scripts/send_signal.py ids|cloud` sends the two non-bank-app Midnight ATO signals; the rest is clicked in the bank app.

### Resets
| Reset | Time (laptop) | What it does |
|---|---|---|
| **Reset** (Demo page, `POST /v1/demo/reset-live`) | ~18 s | Restore the demo baseline snapshot (Postgres schema `demo_baseline`) and rebuild the engine's memory. Undoes only what happened after the baseline. |
| **Reset sandbox** (Demo Simulator, `POST /v1/demo/reset`, `scripts/reset_demo.sh`) | ~9 min | Truncate everything, regenerate 14 days × 2,000 customers (~63k events) and score every event through the engine one by one; then save a new baseline. Under 4 min on Linux. |

Users, the code, the trained model and `.env` are never touched by either reset.

## 8. Security and privacy

- HMAC-SHA256 signed ingestion (`X-FM-Source`, `X-FM-Timestamp`, `X-FM-Signature`): tampered body → 401, replay → 409.
- PII tokenization: phone, email, IP, device and account are stored only as HMAC tokens.
- JWT access tokens (15 min) + rotating HttpOnly refresh cookie; Argon2 password hashes; roles analyst / lead / admin;
  every case route is filtered by the caller's queues (anything else is a 404, so IDs cannot be probed).
- Rate limits: ingestion 100/s per source, login 5/min per IP, 20/s per user elsewhere → `429 RATE_LIMITED`.
- Security headers on every response (CSP, HSTS, nosniff, no-referrer, frame deny) and an `X-Request-ID`.
- Hash-chained audit log; the API's database role can only INSERT and SELECT it; `GET /v1/audit/verify` recomputes the chain.
- Investigator AI uses fixed tools and templates; customer-supplied text (e.g. a payee named "Ignore previous
  instructions…") never reaches an instruction path.
- CORS: explicit origins, plus an optional `CORS_ORIGIN_REGEX` limited to private LAN ranges for the Wi-Fi demo.

## 9. API reference

| Method + path | Role | Purpose |
|---|---|---|
| `POST /v1/auth/login`, `/refresh`, `/logout` | — | Sessions |
| `POST /v1/events`, `/v1/events/batch` | signed source | Ingest events |
| `GET /v1/cases`, `/v1/cases/{id}` | analyst | Queue and case detail |
| `GET /v1/cases/{id}/timeline`, `/graph`, `/explanation` | analyst | Evidence, decisions, step-ups; Cytoscape graph; waterfall + narrative |
| `POST /v1/cases/{id}/replay`, `/ask`, `/feedback` | analyst | Replay / ablation, Investigator AI, analyst verdict |
| `POST /v1/cases/{id}/actions` | lead | Manual hold / block / freeze / revoke |
| `GET /v1/cases/{id}/twin`, `GET /v1/twin/overview` | analyst | Digital Twin |
| `GET /v1/detectors`, `/v1/metrics/summary`, `POST /v1/simulate` | analyst | Detector reliability, metrics + benchmark, policy simulator |
| `GET /v1/engine/config` | analyst | Read-only bands, policy rules, patterns, model manifest |
| `GET /v1/audit/verify` | lead | Recompute the audit hash chain |
| `GET /v1/health` | — | db, pipeline_ready, contract version, model SHA-256 |
| `WS /v1/stream` | analyst (token in first message) | `case_update`, `challenge_update`, `demo_reset` |
| `/v1/demo/*` (only when `DEMO_MODE=1`) | mixed | `emit` (bank app; includes the demo IDS sensor), `payment-status`, `step-up/pending`, `sms-inbox`, `step-up/{id}/respond`, `run/{scenario}` (admin), `reset` (admin), `baseline` (admin), `live` (analyst), `reset-live` (admin) |

## 10. Setup

### Docker (normal way)
```bash
python scripts/make_env.py            # writes .env with fresh secrets; prints the seed-user password
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml exec api python scripts/seed_users.py
```
Open http://localhost:5173. Then reset the demo once (console → Demo Simulator → Reset sandbox, or
`docker compose -f deploy/docker-compose.yml exec api scripts/reset_demo.sh`) to load the background data.

### Other devices on the same Wi-Fi
The containers listen on all interfaces. Others open `http://<this laptop's Wi-Fi IP>:5173` and `:5174`. The apps call
the API on the host they were loaded from; the API accepts those origins when `.env` sets `CORS_ORIGIN_REGEX` (private
LAN ranges, ports 5173/5174 only; off by default). Recreate the api container after changing `.env`. If another device
cannot connect, allow inbound TCP 5173, 5174 and 8000 in Windows Firewall; phone hotspots may isolate clients.

### Local development (no Docker for the app)
```powershell
docker compose -f deploy/docker-compose.yml up -d db
py -3.12 -m venv .venv
.venv\Scripts\pip install -r api\requirements.txt -r engine\requirements.txt ruff
.venv\Scripts\python scripts\make_env.py
.venv\Scripts\alembic -c api\db\alembic.ini upgrade head
.venv\Scripts\python scripts\seed_users.py
.venv\Scripts\uvicorn api.main:app --port 8000 --env-file .env --reload
cd web; npm install; npm run dev          # http://localhost:5173
cd bank-demo; npm install; npm run dev    # http://localhost:5174
```
Stop local dev servers before using the Docker web containers: both bind 5173/5174 and `localhost` reaches the dev server first.

### Environment variables (`.env`)
| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL`, `HMAC_SECRETS`, `TOKEN_KEY`, `JWT_SECRET`, `DEMO_PASSWORD` | written by `make_env.py` | Connection and secrets |
| `BASE_RATE`, `BAND_MEDIUM`, `BAND_HIGH`, `BAND_CRITICAL` | 0.01 / 0.20 / 0.50 / 0.80 | Fusion base rate and band thresholds |
| `DEMO_MODE` | 1 | Mount `/v1/demo/*` |
| `CORS_ORIGINS` | localhost:5173,5174 | Allowed console / bank origins |
| `CORS_ORIGIN_REGEX` | unset | Extra origins for the Wi-Fi demo (private LAN only) |
| `FM_BG_DAYS`, `FM_BG_CUSTOMERS` | 14, 2000 | Size of the reset's background |
| `FM_BG_ATTACKS` | 0 | Attacks per family loaded into the background (30 = the benchmark's 90) |

### Retraining
```powershell
.venv\Scripts\python -m ml.generator.run --seed 1 --attacks 40 --out data/train.jsonl --labels data/train_labels.jsonl
.venv\Scripts\python -m ml.train_txn --ieee "<dir with train_transaction.csv>" --amlsim "<AMLSim sample/ dir>" --cache data/features
.venv\Scripts\python -m ml.train_behaviour
.venv\Scripts\python -m ml.train_twin
.venv\Scripts\python -m benchmark.run
```
Raw datasets are not in the repository (size and licences); about 15 minutes the first time, 1 minute with the feature cache.

## 11. Tests and CI

```powershell
.venv\Scripts\python scripts\verify_contracts.py     # engine/contracts.py hash == docs/CONTRACT_HASH
.venv\Scripts\ruff check .
.venv\Scripts\python -m pytest tests/engine -q       # ~300 tests: detectors, fusion, joiner, golden values, models, datasets, twin
.venv\Scripts\python -m pytest tests/api -q          # ~95 tests: auth, ingest, RBAC/IDOR, SQLi, injection, demo, twin, live demo (needs the db container)
.venv\Scripts\python -m pytest tests/integration -q  # Midnight ATO end to end through the API
.venv\Scripts\python scripts\smoke_test.py --all     # PRD §14.5 checks against a running API
.venv\Scripts\python scripts\perf.py --rate 50 --seconds 120
cd web; npm run build; cd ..\bank-demo; npm run build
```
GitHub Actions (`.github/workflows/ci.yml`) runs five jobs on every push: `python` (contract, guards, ruff, all suites,
store contract on Postgres), `e2e` (uvicorn + Postgres, smoke test of all three scenarios, perf at 50 events/s),
`slow` (full-size reset < 4 min), and `frontend` builds for `web` and `bank-demo`.

## 12. Repository map

| Path | What |
|---|---|
| `engine/` | The fraud engine: `contracts.py` (frozen models), `common/` (settings, ids, tokenize), `graph/`, `features/`, `detectors/` (+ `rules/` calibration and Sigma-style rules), `cases/` (joiner, stages), `fusion/` (+ patterns.yaml), `policy/` (+ policy.yaml), `explain/`, `replay/` (replay + simulator), `feedback.py`, `twin/`, `pipeline.py`, `store_memory.py`, `api.py` |
| `api/` | FastAPI app: `routers/`, `worker.py`, `store_pg.py`, `stepup.py`, `investigator/`, `adapters/suricata.py`, `audit.py`, `security.py`, `middleware.py`, `demo_*` (identities, reset, baseline), `autopilot.py`, `db/` (Alembic) |
| `ml/` | `generator/` (synthetic bank + attacks), `scenario.py`, `datasets/` (IEEE-CIS, AMLSim adapters), `train_txn.py`, `train_behaviour.py`, `train_twin.py`, `artifacts/` |
| `scenarios/` | `midnight_ato.yaml`, `mule_fanin.yaml`, `benign_odd.yaml`, IDS sample lines |
| `benchmark/` | `run.py`, `report.json`, `report_details.json` |
| `web/`, `bank-demo/` | The two React apps |
| `scripts/` | Env, seeding, signing, play / load / reset, smoke, perf, contract checks |
| `deploy/` | Docker Compose, Dockerfiles, nginx |
| `tests/` | `engine/`, `api/`, `integration/` |
| `docs/` | PRD, contract hash, contract requests and decision log |

Original ownership (PRD §3): Dev 1 owned `api/`, `web/`, `bank-demo/`, `scripts/`, `deploy/`, `tests/api|integration`;
Dev 2 owned `engine/`, `ml/`, `scenarios/`, `benchmark/`, `tests/engine`; `engine/contracts.py`, `engine/common/*`,
`CLAUDE.md`, `docs/PRD.md` are frozen for both.

## 13. Known limitations and honest findings

- **Synthetic core.** The cross-silo attack chains (IDS + login + MFA + KYC + cloud + payment for one customer) are
  synthetic: no public dataset links these silos for the same customer. Each detector's realism is limited by its data.
- **Single-signal attacks.** Fusion deliberately won't act on one weak signal, so structuring and early mule transfers
  are caught late under the strict benchmark definition (structuring 0/30 strict vs 30/30 siloed). The Digital Twin
  shows a "strong txn block" rule closes the gap (99.9% protected); it is not in the live policy yet.
- **Real-data accuracy.** On IEEE-CIS the txn model reaches ROC 0.76 / PR-AUC 0.10 with 11 banking features (Kaggle
  winners used about 400 card/email/device features). The login model is trained on synthetic data only.
- **Dormant-account artefact.** `hour_deviation` is exactly 0 when a customer has no login in 30 days; the IEEE-trained
  model treats that as risk (p ≈ 0.19, stays LOW alone). Documented in a test.
- **Shared-payee chaining.** A payee with 2–20 payers joins its payers' cases by design (that is how mule fan-in is
  caught); very popular P2P payees could chain unrelated customers until they become hubs (> 20).
- **Probabilities are calibrated on mixed domains**; the headline metrics use the bank-event test split.
- **Laptop speed.** The full reset takes ~9 min on Windows / Docker Desktop (each event crosses the VM boundary);
  hence the 18-second baseline reset for demos.
- **Demo-only pieces.** The demo IDS sensor, the bank app and the phones stand in for Suricata, a real core banking
  front end, a telco and a push provider.
- **Twin assumptions.** The twin's outcomes depend on stated behaviour assumptions (e.g. the customer denies a push
  within 10 minutes); they are not predictions of real attacker behaviour.

## 14. Future research directions

1. **Real login data for the behaviour model:** the RBA login dataset (Wiegand et al., 33M logins, IP / ASN / device /
   user agent, account-takeover labels, CC BY 4.0, Zenodo 6782156). Expected: honest ROC on real logins.
2. **Richer transaction features:** a balance-drain ratio (would make PaySim usable), device/email/card mismatch,
   merchant-category novelty; measure gain per feature on IEEE-CIS while keeping the bank-event headline.
3. **Domain-aware calibration:** calibrate on the deployment domain only, or per-domain isotonic, so cross-dataset
   training improves ranking without shifting live probabilities.
4. **Policy research with the twin:** search thresholds and rules (e.g. txn ≥ 0.9 block, payee freeze timing) to
   maximise money protected under a friction budget; validate on held-out attacks before changing `policy.yaml`.
5. **Graph learning:** learned mule-risk scores (GNNs, personalized PageRank from seeds, community detection) to replace
   fixed seed distance; payee reputation to stop popular-payee chaining.
6. **Sequence models:** learn stage transitions conditioned on features (Markov → HMM / transformer over event
   sequences) for earlier, better-calibrated forecasts; compare lead time with the rule patterns.
7. **Scams / authorised push payment fraud:** the customer is the actor (no new device); needs behavioural and
   conversational signals; the twin already separates "attacker" from "scammed customer".
8. **Online learning from analyst feedback:** beyond Beta reliability, periodic retraining from confirmed cases with
   drift monitoring.
9. **Live integrations:** a real Suricata sensor, cloud audit streams (CloudTrail / Azure AD), telco SIM-swap APIs,
   PayPal sandbox payments with authorize-then-capture (planned design: hold → authorize only, block → void).
10. **Scale:** Kafka for ingestion, partitioned workers per customer shard, a graph database for very large networks;
    keep per-event p95 under 150 ms.
11. **Fairness and false-decline analysis:** the Bank Account Fraud suite's bias variants for onboarding-risk research.

## 15. Useful scripts

| Script | Purpose |
|---|---|
| `scripts/make_env.py` | Write `.env` with fresh secrets |
| `scripts/seed_users.py` | Upsert the three demo users |
| `scripts/sign.py` | `sign(source, body) -> headers`: the only code that builds ingestion signatures |
| `scripts/send_event.py` | Manual ingestion check (signed → 202, tampered → 401, repeat → 409) |
| `scripts/send_signal.py` | `ids` / `cloud`: the two non-bank-app Midnight ATO signals |
| `scripts/play.py`, `scripts/load.py`, `scripts/reset_demo.sh` | Play a scenario, bulk-load events, full reset |
| `scripts/smoke_test.py`, `scripts/perf.py` | §14.5 smoke checks, latency test |
| `scripts/seed_demo_factors.py` | SMS + push factors for the named demo customers |
| `scripts/gen_ts_types.py` | Regenerate the TypeScript contract types |
| `scripts/verify_contracts.py` | CI contract-hash check |
| `python -m api.adapters.suricata <eve.jsonl> --post` | Suricata EVE alerts → signed events |

## Live Suricata sensor

`api.adapters.suricata` replays a saved `eve.jsonl`; `api.adapters.suricata_live` follows a real sensor's `eve.json`
as it grows and posts each `alert` line as a signed `network_ids_alert` event (source `network-ids`).

```bash
python -m api.adapters.suricata_live /var/log/suricata/eve.json --api http://127.0.0.1:8000 --batch 100
# options: --from-start  --state data/suricata_live.state  --batch N (1 = /v1/events, >1 = /v1/events/batch, max 500)
#          --poll 0.5  --once (process what is in the file now, then exit)
```

- Follows the file like `tail -F`: waits for it to appear, waits for a half-written last line, and starts again at
  byte 0 when the file is rotated (new inode) or truncated. Non-alert and malformed lines are counted and skipped.
- Starts at the end of the file (new alerts only) unless `--from-start`. The byte offset and file identity are saved
  to the state file after every successful post, so a restart neither resends nor skips alerts. Delivery is
  at-least-once: lines in flight during a crash are sent again after the restart, with new event ids.
- Connection errors, 429 (honouring `Retry-After`) and 503 `ENGINE_UNAVAILABLE` (API backlog full) are retried with
  capped exponential backoff and jitter; a line the API refuses for good (401/422) is logged and skipped.
- Signs with `scripts/sign.py` (HMAC key from `.env`); uses `scripts/tls.py` for TLS / mTLS when it is present.
- Limitation: the follower re-opens the path on every poll, so with rename-style rotation, lines the sensor writes to
  the renamed file after the last poll are not read. Rotate with `copytruncate` (handled as truncation) or keep the
  poll interval short.
