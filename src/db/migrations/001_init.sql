-- 001_init.sql — Domain Blacklist Checker core schema (plan §6).
--
-- Expands the plan's minimal sketch into a production-ready schema with proper
-- types, constraints, foreign keys and indexes:
--
--   users(id, email, plan, api_key)
--   domains(id, name, first_seen)
--   checks(id, domain_id, user_id, score, raw_result jsonb, created_at)
--   monitors(id, user_id, domain_id, frequency, notify_email, active)
--   alerts(id, monitor_id, zone, status_change, created_at)
--
-- Targets PostgreSQL 13+ (identity columns, core gen_random_uuid). Safe to run
-- more than once — every object uses IF NOT EXISTS or is guarded.

-- gen_random_bytes() for API-key defaults.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- Enums (guarded so re-running the migration doesn't error).
-- ---------------------------------------------------------------------------
DO $$ BEGIN
  CREATE TYPE plan_tier AS ENUM ('free', 'pro', 'agency');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE check_verdict AS ENUM ('clean', 'listed', 'blacklisted', 'unknown');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE monitor_frequency AS ENUM ('hourly', 'daily', 'weekly');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Direction of a reputation change captured in an alert.
DO $$ BEGIN
  CREATE TYPE alert_change AS ENUM ('listed', 'delisted');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ---------------------------------------------------------------------------
-- Shared trigger: keep updated_at fresh on UPDATE.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email      TEXT        NOT NULL,
  plan       plan_tier   NOT NULL DEFAULT 'free',
  api_key    TEXT        NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(24), 'hex'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT users_email_not_blank CHECK (length(btrim(email)) > 0)
);

-- Case-insensitive uniqueness on email (one account per address).
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_key ON users (lower(email));

DROP TRIGGER IF EXISTS users_set_updated_at ON users;
CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- domains — one row per registrable domain we've ever seen.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS domains (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name            TEXT        NOT NULL UNIQUE,
  first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_checked_at TIMESTAMPTZ,
  -- Names are stored normalized (lowercase, no scheme/path) by the app layer.
  CONSTRAINT domains_name_normalized CHECK (name = lower(name) AND name !~ '\s')
);

-- ---------------------------------------------------------------------------
-- checks — one row per reputation check (raw result kept as JSONB).
-- user_id is nullable so anonymous / unauthenticated checks are still recorded.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS checks (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  domain_id    BIGINT        NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  user_id      BIGINT        REFERENCES users(id) ON DELETE SET NULL,
  score        SMALLINT      NOT NULL CHECK (score BETWEEN 0 AND 100),
  verdict      check_verdict NOT NULL,
  listed_count SMALLINT      NOT NULL DEFAULT 0 CHECK (listed_count >= 0),
  raw_result   JSONB         NOT NULL,
  created_at   TIMESTAMPTZ   NOT NULL DEFAULT now()
);

-- History for a domain, newest first.
CREATE INDEX IF NOT EXISTS checks_domain_created_idx ON checks (domain_id, created_at DESC);
-- "My recent checks" for an authenticated user.
CREATE INDEX IF NOT EXISTS checks_user_created_idx  ON checks (user_id, created_at DESC)
  WHERE user_id IS NOT NULL;
-- Ad-hoc querying inside the stored result (e.g. which checks hit a given zone).
CREATE INDEX IF NOT EXISTS checks_raw_gin_idx ON checks USING gin (raw_result jsonb_path_ops);

-- ---------------------------------------------------------------------------
-- monitors — a user watching a domain on a schedule.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS monitors (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id      BIGINT            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain_id    BIGINT            NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  frequency    monitor_frequency NOT NULL DEFAULT 'daily',
  notify_email TEXT,
  active       BOOLEAN           NOT NULL DEFAULT true,
  last_run_at  TIMESTAMPTZ,
  next_run_at  TIMESTAMPTZ       NOT NULL DEFAULT now(),
  created_at   TIMESTAMPTZ       NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ       NOT NULL DEFAULT now(),
  -- One monitor per (user, domain).
  CONSTRAINT monitors_user_domain_key UNIQUE (user_id, domain_id)
);

-- Scheduler poll: "which active monitors are due?"
CREATE INDEX IF NOT EXISTS monitors_due_idx ON monitors (next_run_at)
  WHERE active;

DROP TRIGGER IF EXISTS monitors_set_updated_at ON monitors;
CREATE TRIGGER monitors_set_updated_at BEFORE UPDATE ON monitors
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- alerts — a recorded reputation change for a monitor (drives notifications).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  monitor_id    BIGINT       NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  zone          TEXT         NOT NULL,
  subject       TEXT,                       -- the IP or domain that changed
  status_change alert_change NOT NULL,      -- became 'listed' or 'delisted'
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
  notified_at   TIMESTAMPTZ                 -- set when the notification was sent
);

-- Alert feed for a monitor, newest first.
CREATE INDEX IF NOT EXISTS alerts_monitor_created_idx ON alerts (monitor_id, created_at DESC);
-- Outbox: alerts still needing a notification.
CREATE INDEX IF NOT EXISTS alerts_unnotified_idx ON alerts (created_at)
  WHERE notified_at IS NULL;
