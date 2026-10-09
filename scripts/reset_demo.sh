#!/usr/bin/env bash
# PRD §12.3 demo reset. Run from the repo root, locally or inside the api container:
#   scripts/reset_demo.sh                                   (local; uses .venv if present)
#   docker compose -f deploy/docker-compose.yml exec api scripts/reset_demo.sh
# Seed-user passwords come from DEMO_PASSWORD in the environment / .env and are never committed.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -x .venv/Scripts/python.exe ]; then PY=.venv/Scripts/python.exe
elif [ -x .venv/bin/python ]; then PY=.venv/bin/python
else PY=${PYTHON:-python}; fi
SECONDS=0
"$PY" scripts/reset_demo.py "$@"
echo "reset_demo.sh finished in ${SECONDS}s"
echo "next: restart the API worker (docker compose -f deploy/docker-compose.yml restart api) - or use POST /v1/demo/reset"
