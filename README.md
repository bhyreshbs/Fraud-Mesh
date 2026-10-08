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

## Useful scripts

| Script | Purpose |
|---|---|
| `scripts/make_env.py` | Write `.env` with fresh `HMAC_SECRETS`, `TOKEN_KEY`, `JWT_SECRET`, `DEMO_PASSWORD` |
| `scripts/seed_users.py` | Upsert the three demo users |
| `scripts/sign.py` | `sign(source, body) -> headers`: the only code that builds ingestion signatures |
| `scripts/send_event.py` | Manual ingestion check against a running API |
| `scripts/make_fixtures.py` | Rebuild `fixtures/api/*` and the Phase 0 `fixtures/engine/*_example.json` from the PRD §12.4 golden values |
| `scripts/gen_ts_types.py` | Regenerate `web/src/types/contracts.ts` (and the bank-demo copy) from the Pydantic models |
| `scripts/verify_contracts.py` | CI contract-hash check (`--write` after an agreed contract change) |

## Ownership

Dev 1 owns `api/`, `web/`, `bank-demo/`, `scripts/`, `deploy/`, `fixtures/api/`, `tests/api/`, `tests/integration/`.
Dev 2 owns `engine/` (except the frozen files), `ml/`, `scenarios/`, `benchmark/`, `fixtures/engine/`, `tests/engine/`.
`engine/contracts.py`, `engine/common/*`, `CLAUDE.md`, `docs/PRD.md` are BOTH-FROZEN. See PRD §3.
