"""0004_auth_sessions — server-side sessions and rotating refresh tokens (v3 phase 6.3, api/sessions.py).

auth_sessions        one row per sign-in (a refresh-token "family"): who, the role/queues it was issued for, idle and
                     absolute expiry, revocation. Its session_id is the access token's `sid` claim.
auth_refresh_tokens  every refresh token ever issued for a session, stored ONLY as the SHA-256 of a 256-bit random
                     value. used_at is set when it is rotated; presenting a used token again (outside a short race
                     window) is reuse -> the whole session is revoked.

Neither table is in api/seeding.RUNTIME_TABLES or the demo baseline: a demo reset does not sign people out. No
foreign key to users (users is truncated and reseeded by tests and the demo reset); sessions of a missing user are
refused on refresh.

Least privilege (v3 phase 12): fm_app loses TRUNCATE on every table, now and by default for future tables. Every
TRUNCATE in the code runs on the owner/login role (api/seeding.truncate_runtime, api/demo_baseline, tests).

Revision ID: 0004_auth_sessions
Revises: 0003_payment_rail
"""
from alembic import op

revision = "0004_auth_sessions"
down_revision = "0003_payment_rail"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE auth_sessions (
  session_id       text PRIMARY KEY CHECK (session_id ~ '^ses_[0-9a-f]{32}$'),
  user_id          text NOT NULL,
  role             text NOT NULL CHECK (role IN ('analyst','lead','admin')),
  queues           text[] NOT NULL,
  provider         text NOT NULL DEFAULT 'local' CHECK (provider IN ('local','firebase')),
  user_agent       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_used_at     timestamptz NOT NULL DEFAULT now(),
  idle_expires_at  timestamptz NOT NULL,
  expires_at       timestamptz NOT NULL,
  revoked_at       timestamptz,
  revoked_reason   text,
  rotated_from     text
);
CREATE INDEX auth_sessions_user_idx ON auth_sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX auth_sessions_expiry_idx ON auth_sessions (expires_at);
CREATE TABLE auth_refresh_tokens (
  token_hash  text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  session_id  text NOT NULL REFERENCES auth_sessions(session_id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);
CREATE INDEX auth_refresh_tokens_session_idx ON auth_refresh_tokens (session_id);
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fm_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON auth_sessions, auth_refresh_tokens TO fm_app;
    REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM fm_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE TRUNCATE ON TABLES FROM fm_app;
  END IF;
END $$;
""")


def downgrade() -> None:
    op.execute("""
DROP TABLE IF EXISTS auth_refresh_tokens;
DROP TABLE IF EXISTS auth_sessions;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fm_app') THEN
    GRANT TRUNCATE ON ALL TABLES IN SCHEMA public TO fm_app;
    REVOKE TRUNCATE ON audit_log FROM fm_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT TRUNCATE ON TABLES TO fm_app;
  END IF;
END $$;
""")
