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
scriptseset_demo.sh                                    # §12.3 reset (bash; local or: docker compose ... exec api scripts/reset_demo.sh), then restart the API
.venv\Scripts\python scripts\play.py midnight_ato --speed 8   # play a scenario into a running API (signed events + step-ups via demo routes)
.venv\Scripts\python scripts\load.py --file dataackground.jsonl --labels dataackground_labels.jsonl --direct
.venv\Scripts\python scripts\load.py --scenario midnight_ato --preload-only --start 2026-10-09T00:39:00+05:30
.venv\Scripts\python -m api.adapters.suricata fixturespi\ids_alerts_sample.jsonl --post   # Suricata EVE alerts -> signed events
```

In the console, **Demo control** (`/demo`, admin) does the same with buttons: *Reset demo* (`POST /v1/demo/reset`, also
rebuilds the API's in-memory pipeline, so no restart) and *Run scenario* (`POST /v1/demo/run/{id}`, speed 8 plays the
27-minute Midnight ATO in about 3.4 minutes). Scenarios come from Dev 2's `ml.scenario` + `scenarios/` once merged;
until then from the fallback copies in `fixtures/api/scenarios/`. The 60k-event background needs Dev 2's generator.

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
