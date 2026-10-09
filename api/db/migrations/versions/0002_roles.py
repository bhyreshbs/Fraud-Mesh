"""0002_roles — PRD §15.4 task 3: the app's DB role gets INSERT and SELECT only on audit_log.

`fm_app` is a NOLOGIN role; the API's engine switches every connection to it (SET ROLE, see api/db/session.py),
so application code cannot UPDATE, DELETE or TRUNCATE audit rows. Migrations and admin scripts use the login role.

Revision ID: 0002_roles
Revises: 0001_core
"""
from alembic import op

revision = "0002_roles"
down_revision = "0001_core"
branch_labels = None
depends_on = None

APP_ROLE = "fm_app"


def upgrade() -> None:
    op.execute(f"""
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN CREATE ROLE {APP_ROLE} NOLOGIN; END IF;
END $$;
GRANT {APP_ROLE} TO CURRENT_USER;
GRANT USAGE ON SCHEMA public TO {APP_ROLE};
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public TO {APP_ROLE};
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM {APP_ROLE};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON TABLES TO {APP_ROLE};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE};
""")


def downgrade() -> None:
    op.execute(f"""
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM {APP_ROLE};
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM {APP_ROLE};
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {APP_ROLE};
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {APP_ROLE};
REVOKE USAGE ON SCHEMA public FROM {APP_ROLE};
""")
