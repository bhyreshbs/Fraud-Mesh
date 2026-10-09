"""0003_payment_rail — opt-in payment-rail mirror of payment_outcomes (api/payments, docs/CONTRACT_REQUESTS.md).

One row per transaction event: which rail, the processor's authorization id (opaque), the rail state
(CREATED -> AUTHORIZED -> CAPTURED | VOIDED), the state the row should reach (`target`) and the last error.
No foreign key to events, so the demo baseline / reset code can truncate tables in any order; rows are removed
with the runtime tables (api/seeding.RUNTIME_TABLES). payee_token is an acct: token, never a raw account number.

Privileges: 0002_roles set ALTER DEFAULT PRIVILEGES for tables created by the migrating role, so fm_app already
gets SELECT/INSERT/UPDATE/DELETE/TRUNCATE here. The explicit GRANT below covers a database migrated by another role.

Revision ID: 0003_payment_rail
Revises: 0002_roles
"""
from alembic import op

revision = "0003_payment_rail"
down_revision = "0002_roles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE payment_rail (
  event_id      text PRIMARY KEY,
  case_id       text,
  rail          text NOT NULL,
  auth_id       text,
  state         text NOT NULL DEFAULT 'CREATED' CHECK (state IN ('CREATED','AUTHORIZED','CAPTURED','VOIDED')),
  target        text NOT NULL CHECK (target IN ('AUTHORIZED','CAPTURED','VOIDED')),
  reason        text,
  amount_paise  bigint NOT NULL,
  currency      text NOT NULL,
  payee_token   text,
  attempts      integer NOT NULL DEFAULT 0,
  last_error    text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX payment_rail_case_idx ON payment_rail (case_id);
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fm_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON payment_rail TO fm_app;
  END IF;
END $$;
""")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS payment_rail")
