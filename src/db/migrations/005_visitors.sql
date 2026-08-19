-- 005_visitors.sql
--
-- Visitor presence records behind the admin Visitors page. The live
-- Active/Offline signal stays in memory (it is a heartbeat, not history), but
-- every browser record is mirrored here so a server restart no longer forgets
-- who has ever opened the site. One row per browser (the dbc_vid cookie).
--
-- `data` holds the whole visitor record as JSON (ip, user agent, parsed
-- browser/os/device, account, timezone, screen and the rest) so new fields do
-- not need a schema change. Safe to run more than once.

CREATE TABLE IF NOT EXISTS visitors (
  id         TEXT        PRIMARY KEY,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
  hits       INTEGER     NOT NULL DEFAULT 0,
  data       JSONB       NOT NULL DEFAULT '{}'::jsonb
);

-- The page lists newest first.
CREATE INDEX IF NOT EXISTS visitors_last_seen_idx ON visitors (last_seen DESC);
