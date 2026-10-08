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
})

import pytest  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

RUNTIME_TABLES = ["audit_log", "step_up_challenges", "mfa_factors", "users", "labels", "replays", "feedback",
                  "decisions", "evidence", "case_entities", "cases", "edges", "entities", "payment_outcomes", "events"]


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


def pytest_collection_modifyitems(config, items):
    if _PG_OK:
        return
    skip = pytest.mark.skip(reason=f"PostgreSQL not reachable at {TEST_DB_URL}")
    for item in items:
        if "tests/api" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def clean_db():
    if not _PG_OK:
        yield
        return
    from api.db.session import get_engine
    with get_engine().begin() as c:
        c.execute(text("TRUNCATE " + ", ".join(RUNTIME_TABLES) + " RESTART IDENTITY CASCADE"))
        c.execute(text("DELETE FROM detector_reliability"))
        c.execute(text("INSERT INTO detector_reliability (detector, alpha, beta) VALUES ('txn',17,3), ('behaviour',6,4), "
                       "('auth',7,3), ('kyc',6,4), ('cyber',5,5), ('netsec',5,5), ('graph',8,2)"))
    from scripts.seed_users import seed_users
    seed_users(TEST_PASSWORD)
    yield


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
