"""0001_core — PRD §8, verbatim.

Revision ID: 0001_core
Revises:
"""
from alembic import op

revision = "0001_core"
down_revision = None
branch_labels = None
depends_on = None

SQL = """
CREATE TABLE events (
  event_id       text PRIMARY KEY,
  event_type     text NOT NULL,
  source         text NOT NULL,
  occurred_at    timestamptz NOT NULL,
  received_at    timestamptz NOT NULL,
  customer       text,
  entity_tokens  text[] NOT NULL,
  data           jsonb NOT NULL
);
CREATE INDEX events_time_idx     ON events (occurred_at, event_id);
CREATE INDEX events_customer_idx ON events (customer, occurred_at);
CREATE INDEX events_tokens_gin   ON events USING gin (entity_tokens);

CREATE TABLE payment_outcomes (
  event_id  text PRIMARY KEY REFERENCES events(event_id),
  outcome   text NOT NULL CHECK (outcome IN ('completed','held','blocked')),
  case_id   text,
  set_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE entities (
  entity_id   text PRIMARY KEY,
  kind        text NOT NULL,
  fraud_seed  boolean NOT NULL DEFAULT false,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE edges (
  src text NOT NULL, dst text NOT NULL, edge_type text NOT NULL,
  confidence real NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL,
  count int NOT NULL DEFAULT 1,
  source_event_ids text[] NOT NULL,
  PRIMARY KEY (src, dst, edge_type)
);

CREATE TABLE cases (
  case_id        text PRIMARY KEY,
  status         text NOT NULL,
  band           text NOT NULL,
  p_attack       double precision NOT NULL,
  customer       text,
  queue          text NOT NULL DEFAULT 'default',
  last_event_ts  timestamptz NOT NULL,
  updated_at     timestamptz NOT NULL,
  data           jsonb NOT NULL
);
CREATE INDEX cases_queue_idx ON cases (status, band, updated_at DESC);

CREATE TABLE case_entities (
  case_id    text NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  entity_id  text NOT NULL,
  PRIMARY KEY (case_id, entity_id)
);
CREATE INDEX case_entities_entity_idx ON case_entities (entity_id);

CREATE TABLE evidence (
  evidence_id  text PRIMARY KEY,
  case_id      text NOT NULL REFERENCES cases(case_id),
  event_id     text NOT NULL REFERENCES events(event_id),
  detector     text NOT NULL,
  ts           timestamptz NOT NULL,
  data         jsonb NOT NULL
);
CREATE INDEX evidence_case_idx ON evidence (case_id, ts, evidence_id);

CREATE TABLE decisions (
  decision_id       text PRIMARY KEY,
  case_id           text NOT NULL REFERENCES cases(case_id),
  trigger_event_id  text NOT NULL,
  created_at        timestamptz NOT NULL,
  data              jsonb NOT NULL
);
CREATE INDEX decisions_case_idx ON decisions (case_id, created_at);

CREATE TABLE detector_reliability (
  detector  text PRIMARY KEY,
  alpha     double precision NOT NULL,
  beta      double precision NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO detector_reliability (detector, alpha, beta) VALUES
  ('txn',17,3), ('behaviour',6,4), ('auth',7,3), ('kyc',6,4), ('cyber',5,5), ('netsec',5,5), ('graph',8,2);

CREATE TABLE feedback (
  feedback_id  bigserial PRIMARY KEY,
  case_id      text NOT NULL REFERENCES cases(case_id),
  verdict      text NOT NULL CHECK (verdict IN ('CONFIRMED_FRAUD','FALSE_POSITIVE','INCONCLUSIVE')),
  analyst      text NOT NULL,
  note         text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  data         jsonb NOT NULL
);

CREATE TABLE replays (
  replay_id  text PRIMARY KEY,
  case_id    text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  data       jsonb NOT NULL
);

CREATE TABLE labels (
  event_id   text PRIMARY KEY,
  scenario   text NOT NULL,
  is_attack  boolean NOT NULL,
  attack_id  text
);

CREATE TABLE users (
  user_id   text PRIMARY KEY,
  email     text UNIQUE NOT NULL,
  pw_hash   text NOT NULL,
  role      text NOT NULL CHECK (role IN ('analyst','lead','admin')),
  queues    text[] NOT NULL DEFAULT ARRAY['default']
);

CREATE TABLE mfa_factors (
  factor_id    text PRIMARY KEY,
  customer     text NOT NULL,
  kind         text NOT NULL CHECK (kind IN ('sms','totp','device_push')),
  enrolled_at  timestamptz NOT NULL,
  changed_at   timestamptz,
  phone_token  text,
  device_token text,
  active       boolean NOT NULL DEFAULT true
);

CREATE TABLE step_up_challenges (
  challenge_id  text PRIMARY KEY,
  case_id       text NOT NULL,
  customer      text NOT NULL,
  method        text NOT NULL CHECK (method IN ('sms_otp','totp','device_push')),
  factor_id     text REFERENCES mfa_factors(factor_id),
  otp_hash      text,
  attempts      int NOT NULL DEFAULT 0,
  status        text NOT NULL CHECK (status IN ('pending','passed','failed','timeout','denied_by_customer')),
  created_at    timestamptz NOT NULL,
  expires_at    timestamptz NOT NULL
);
CREATE INDEX challenges_pending_idx ON step_up_challenges (customer, status);

CREATE TABLE audit_log (
  seq        bigserial PRIMARY KEY,
  ts         timestamptz NOT NULL DEFAULT now(),
  actor      text NOT NULL,
  action     text NOT NULL,
  object_id  text NOT NULL,
  details    jsonb NOT NULL,
  prev_hash  text NOT NULL,
  row_hash   text NOT NULL
);
"""

TABLES = ["audit_log", "step_up_challenges", "mfa_factors", "users", "labels", "replays", "feedback",
          "detector_reliability", "decisions", "evidence", "case_entities", "cases", "edges", "entities",
          "payment_outcomes", "events"]


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    for t in TABLES:
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
