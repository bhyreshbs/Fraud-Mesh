"""API test setup. Uses a separate database (<DATABASE_URL db>_test) that is migrated once and truncated per test.

Env vars are fixed here BEFORE engine.common.settings is imported, because settings are read at import time.
"""
from __future__ import annotations

import json
import os

TEST_HMAC = {"demo-bank-web": "11" * 32, "cloud-audit": "22" * 32, "network-ids": "33" * 32, "simulator": "44" * 32}
TEST_PASSWORD = "test-password-123"

_base = os.getenv("DATABASE_URL", "postgresql+psycopg://fm:fm@localhost:5432/fraudmesh")
TEST_DB_URL = _base if _base.rstrip("/").endswith("_test") else _base.rsplit("/", 1)[0] + "/" + _base.rsplit("/", 1)[1] + "_test"
os.environ.update({
    "DATABASE_URL": TEST_DB_URL,
    "HMAC_SECRETS": json.dumps(TEST_HMAC),
    "TOKEN_KEY": "ab" * 32,
    "JWT_SECRET": "cd" * 32,
    "DEMO_MODE": "1",
    "CORS_ORIGINS": "http://localhost:5173,http://localhost:5174",
    "DEMO_PASSWORD": TEST_PASSWORD,                    # what /v1/demo/reset reseeds the users with
})

import pytest  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from api.seeding import RUNTIME_TABLES, truncate_runtime  # noqa: E402,F401  (one list; tests/engine reuses the name)


def _create_and_migrate() -> bool:
    admin_url, dbname = TEST_DB_URL.rsplit("/", 1)
    try:
        eng = create_engine(admin_url + "/postgres", isolation_level="AUTOCOMMIT")
        with eng.connect() as c:
            if not c.execute(text("SELECT 1 FROM pg_database WHERE datname = :d"), {"d": dbname}).scalar():
                c.execute(text(f'CREATE DATABASE "{dbname}"'))
        eng.dispose()
    except Exception:
        return False
    from alembic import command
    from alembic.config import Config
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "..", "api", "db", "alembic.ini"))
    cfg.attributes["database_url"] = TEST_DB_URL
    command.upgrade(cfg, "head")
    return True


_PG_OK = _create_and_migrate()


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: full-size runs (e.g. the PRD 14 d x 2000 reset); only with FM_RUN_SLOW=1")


def pytest_collection_modifyitems(config, items):
    if os.getenv("FM_RUN_SLOW") != "1":
        skip_slow = pytest.mark.skip(reason="slow test: set FM_RUN_SLOW=1 (runs in the separate CI 'slow' job)")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)
    if _PG_OK:
        return
    skip = pytest.mark.skip(reason=f"PostgreSQL not reachable at {TEST_DB_URL}")
    for item in items:
        if "tests/api" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def no_background(monkeypatch):
    """POST /v1/demo/reset normally generates and loads the PRD §12.1 background (62k events). Tests that need it opt in
    (test_demo_tooling: tiny background; @pytest.mark.slow: the full PRD reset)."""
    import api.demo_reset
    monkeypatch.setattr(api.demo_reset, "BACKGROUND_ENABLED", False)


@pytest.fixture(autouse=True)
def clean_db():
    if not _PG_OK:
        yield
        return
    truncate_runtime()                                      # owner role: the app role cannot truncate audit_log
    from scripts.seed_users import seed_users
    seed_users(TEST_PASSWORD)
    from api.ratelimit import limiter  # rate limits are exercised in test_security.py only
    limiter.reset()
    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest.fixture
def seeded():
    """The golden Midnight ATO case + queue rows from fixtures/api, written through PgStore."""
    from scripts.seed_fixture_case import seed_fixture_case
    return seed_fixture_case()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from api.main import app
    with TestClient(app) as c:
        yield c


def login(client, role: str = "analyst") -> str:
    r = client.post("/v1/auth/login", json={"email": f"{role}@fraudmesh.local", "password": TEST_PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture
def auth_headers(client):
    def _h(role: str = "analyst") -> dict[str, str]:
        return {"Authorization": f"Bearer {login(client, role)}"}
    return _h
