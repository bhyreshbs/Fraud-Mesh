# HR2-OI-9C037B24 — FraudMesh 2.0
HACKERING 2.0 Round 2 Project Repository for Team Global Maxima (Open Innovation Track)

# FraudMesh 2.0

FraudMesh turns weak fraud, identity, KYC, device and security signals into one explainable attack case per attack,
and acts before money moves. The spec is [docs/PRD.md](docs/PRD.md) (source of truth: [docs/PRD.pdf](docs/PRD.pdf)).

| Container | Port | What |
|---|---|---|
| `db` | 5432 | PostgreSQL 16 |
| `api` | 8000 | FastAPI + the engine (`uvicorn api.main:app`) |
| `web` | 5173 | Investigator console (React + Vite, Stitch designs) |
| `bank` | 5174 | NammaBank demo app + simulated phones |

## Quick start (Docker)

```bash
python scripts/make_env.py            # writes .env with fresh secrets; prints the seed-user password
docker compose -f deploy/docker-compose.yml up --build
# in a second terminal, once the api is up:
docker compose -f deploy/docker-compose.yml exec api python scripts/seed_users.py
```

Open http://localhost:5173 and sign in as `analyst@fraudmesh.local`, `lead@fraudmesh.local` or `admin@fraudmesh.local`
with the `DEMO_PASSWORD` value from `.env`.

## Local development (no Docker for the app)

Windows PowerShell shown; on macOS/Linux use `.venv/bin/` instead of `.venv\Scripts\`.

```powershell
docker compose -f deploy/docker-compose.yml up -d db       # only Postgres in Docker
py -3.12 -m venv .venv
.venv\Scripts\pip install -r api\requirements.txt -r engine\requirements.txt ruff
.venv\Scripts\python scripts\make_env.py                   # once
.venv\Scripts\alembic -c api\db\alembic.ini upgrade head
.venv\Scripts\python scripts\seed_users.py
.venv\Scripts\uvicorn api.main:app --port 8000 --env-file .env --reload

cd web;       npm install; npm run dev      # http://localhost:5173
cd bank-demo; npm install; npm run dev      # http://localhost:5174
```

Set `VITE_USE_FIXTURES=1` (in `web/.env.local`) to run the console against `fixtures/api/*.json` without the API.

### Clicking through the Midnight ATO story before Dev 2's engine lands

The Phase 0 `Pipeline` stub produces no cases, so bank-app events alone change nothing in the console. For manual UI
testing only, start the API with the scripted stand-in (`api/dev_pipeline.py`: fixed PRD §10.4 probabilities and the
§10.5–10.8 fusion/policy rules; not the engine, never used in CI):

```powershell
.venv\Scripts\python scripts\dev_reset.py --fixture-case     # clean slate + users + demo MFA factors (+ golden fixture cases)
$env:FM_DEV_PIPELINE = "1"; .venv\Scripts\uvicorn api.main:app --port 8000 --env-file .env
```

Then open the console (http://localhost:5173), the bank app (http://localhost:5174, identity switcher → *Attacker laptop*),
the attacker's phone (http://localhost:5174/phone/attacker) and Priya's phone (http://localhost:5174/phone/priya).

## Checks (same as CI, PRD §14.2)

```powershell
.venv\Scripts\python scripts\verify_contracts.py     # engine/contracts.py hash == docs/CONTRACT_HASH
.venv\Scripts\ruff check .
.venv\Scripts\python -m pytest tests/api -q          # needs the db container; uses a separate fraudmesh_test database
cd web; npm run build
```

Send one signed event by hand:

```powershell
.venv\Scripts\python scripts\send_event.py           # signed login -> 202, tampered -> 401, repeat -> 409
```

## Demo tooling (D1-P5, PRD §12.3, §15.5)

```powershell
bash scripts/reset_demo.sh                                # §12.3 reset (or: docker compose -f deploy/docker-compose.yml exec api scripts/reset_demo.sh), then restart the API
.venv\Scripts\python scripts\play.py midnight_ato --speed 8   # play a scenario into a running API (signed events + step-ups via demo routes)
.venv\Scripts\python scripts\load.py --file data\background.jsonl --labels data\background_labels.jsonl --direct
.venv\Scripts\python scripts\load.py --scenario midnight_ato --preload-only --start 2026-10-09T00:39:00+05:30
.venv\Scripts\python -m api.adapters.suricata fixtures\api\ids_alerts_sample.jsonl --post   # Suricata EVE alerts -> signed events
```

`FM_BG_DAYS` / `FM_BG_CUSTOMERS` shrink the reset's background (default 14 days x 2000 customers, ~62k events).

In the console, **Demo control** (`/demo`, admin) does the same with buttons: *Reset demo* (`POST /v1/demo/reset`, also
rebuilds the API's in-memory pipeline, so no restart) and *Run scenario* (`POST /v1/demo/run/{id}`, speed 8 plays the
27-minute Midnight ATO in about 3.4 minutes). Scenarios come from Dev 2's `ml.scenario` + `scenarios/` once merged;
until then from the fallback copies in `fixtures/api/scenarios/`. The 60k-event background needs Dev 2's generator.

`FM_BG_ATTACKS=30` (in `.env`, then recreate the api container) makes Reset demo also load the benchmark's 90 attacks
(30 account takeovers, 30 mule fan-ins, 30 structuring) into the background, so the queue shows what the engine finds
on held-out data: 47 CRITICAL, 40 HIGH, 3 MEDIUM, 79 LOW. Priya is never an attack victim. The default (0) is the PRD reset.

## Digital twin (console: Digital twin page and the case Twin tab)

A simulation-first **cyber-financial digital twin** built from the events FraudMesh already stores; there are no new
data sources and nothing is written. It lives in `engine/twin/` and is served by `GET /v1/twin/overview` and
`GET /v1/cases/{id}/twin` (analyst+, same queue rules as `/v1/cases`).

1. **Virtual state** (`state.py`): customers, sessions, SMS numbers and SIMs, payees, limits, devices, IPs and staff
   identities, updated event by event. Each entity gets tags such as "attacker device", "OTPs reach the attacker",
   "1 hop from a known mule".
2. **Attack and policy simulator** (`simulate.py`): replays a case on an **isolated copy** of the starting state under
   8 strategies: no controls, siloed detectors, SMS OTP, freeze payees, hold, block, the live FraudMesh policy, and a
   candidate "FraudMesh + strong txn block". It reports money lost and protected, when and where the attacker was
   stopped, lead time before the transfer, and friction for genuine customers. Payment controls apply to the
   transfer that triggered them, step-ups to later steps, exactly as the live worker does.
3. **Forecast** (`predict.py`): stage-to-stage transitions learned from labelled attacks (`python -m ml.train_twin`
   writes `ml/artifacts/twin_transitions.json`). It gives the likely next stage, the chance of reaching the money and
   the typical minutes to get there, with the sample size shown.

On the 90 held-out attacks the twin shows: no controls lose ₹5.56 Cr; the live FraudMesh policy protects 65%; siloed
txn blocking protects 99.8%; FraudMesh + strong txn block protects 99.9%. These are simulated outcomes under the
documented assumptions (listed in the UI), not guarantees.

## ML training data (txn model)

The txn model (`ml/artifacts/txn_v1.joblib`, LightGBM + isotonic) is trained on three datasets, each split **by time**
so every test period is later than anything the model saw:

| Dataset | Transactions | Fraud | Split | Test PR-AUC | Test ROC-AUC |
|---|---|---|---|---|---|
| Synthetic bank events (`ml.generator`, seed 1) | 30,165 | 561 | days 1-9 / 10-11 / 12-14 | 0.9995 | 1.000 |
| [IEEE-CIS Fraud Detection](https://www.kaggle.com/c/ieee-fraud-detection) (real card-not-present) | 590,540 | 20,663 | 60% / 15% / 25% | 0.097 | 0.759 |
| [IBM AMLSim](https://github.com/IBM/AMLSim) samples (fan-in, cycle, both) | 356,613 | 15,006 | 60% / 15% / 25% | 0.742 | 0.867 |

The model trained on synthetic data alone scored ROC-AUC 0.50 (random) on the IEEE-CIS and AMLSim test periods.
`ml/datasets/` converts each dataset to FraudMesh events and computes features with the engine's own feature module,
so training and live scoring use identical features. Each dataset weighs the same in training. Raw data is not in
the repository; to retrain (about 15 min the first time, 1 min with the feature cache):

```powershell
.venv\Scripts\python -m ml.generator.run --seed 1 --attacks 40 --out data/train.jsonl --labels data/train_labels.jsonl
.venv\Scripts\python -m ml.train_txn --ieee "<dir with train_transaction.csv>" --amlsim "<AMLSim sample/ dir>" --cache data/features
.venv\Scripts\python -m benchmark.run
```

## Tests, smoke and performance (D1-P7, PRD §14.5, §15.7)

```powershell
.venv\Scripts\python -m pytest tests/api -q                                  # API, security, RBAC/IDOR, SQLi, injection, demo tooling
$env:FM_DEV_PIPELINE="1"; .venv\Scripts\python -m pytest tests/integration -q   # §12.4 end-to-end (skipped on the Phase 0 stub)
.venv\Scripts\python scripts\smoke_test.py --all                                # §14.5 checks against a running API (resets the demo)
.venv\Scripts\python scripts\perf.py --rate 50 --seconds 120                    # realistic generator traffic; --traffic synthetic = stress
```

CI runs all of this on Linux: the `e2e` job starts uvicorn + Postgres, runs the smoke test for all three scenarios and
two 2-minute perf runs (platform with the Phase 0 pipeline: decision p95 must be < 150 ms; dev stand-in: informational).

## Security (D1-P4, PRD §9.7, §15.4)

- Every response carries `Content-Security-Policy: default-src 'self'`, HSTS, `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and an `X-Request-ID`.
- Rate limits: ingestion 100/s per source, login 5/min per IP, every other route 20/s per user (or IP) → `429 RATE_LIMITED`.
- The API connects as the `fm_app` role (migration `0002_roles`): INSERT + SELECT only on `audit_log`.
- `GET /v1/audit/verify` (lead+) recomputes the hash chain and returns the first broken row.

## Useful scripts

| Script | Purpose |
|---|---|
| `scripts/make_env.py` | Write `.env` with fresh `HMAC_SECRETS`, `TOKEN_KEY`, `JWT_SECRET`, `DEMO_PASSWORD` |
| `scripts/seed_users.py` | Upsert the three demo users |
| `scripts/sign.py` | `sign(source, body) -> headers`: the only code that builds ingestion signatures |
| `scripts/send_event.py` | Manual ingestion check against a running API |
| `scripts/play.py`, `scripts/load.py`, `scripts/reset_demo.sh` | Demo tooling (see above) |
| `scripts/send_signal.py` | `ids` / `cloud`: send the two non-bank-app Midnight ATO signals, signed like their real sources |
| `scripts/seed_demo_factors.py` | sms + device_push factors (enrolled 90 days ago) for the named demo customers |
| `scripts/dev_reset.py` | Dev-only clean slate for manual testing (`--fixture-case` also loads the golden cases) |
| `scripts/seed_fixture_case.py` | Load the golden Midnight ATO case + queue rows into Postgres (UI data before Dev 2's engine lands) |
| `scripts/make_fixtures.py` | Rebuild `fixtures/api/*` and the Phase 0 `fixtures/engine/*_example.json` from the PRD §12.4 golden values |
| `scripts/gen_ts_types.py` | Regenerate `web/src/types/contracts.ts` (and the bank-demo copy) from the Pydantic models |
| `scripts/verify_contracts.py` | CI contract-hash check (`--write` after an agreed contract change) |

## Ownership

Dev 1 owns `api/`, `web/`, `bank-demo/`, `scripts/`, `deploy/`, `fixtures/api/`, `tests/api/`, `tests/integration/`.
Dev 2 owns `engine/` (except the frozen files), `ml/`, `scenarios/`, `benchmark/`, `fixtures/engine/`, `tests/engine/`.
`engine/contracts.py`, `engine/common/*`, `CLAUDE.md`, `docs/PRD.md` are BOTH-FROZEN. See PRD §3.
