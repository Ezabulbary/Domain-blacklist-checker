-- 004_shared_reports.sql
--
-- Shareable result links. A check (single or bulk) can be frozen as a snapshot
-- under a random id, and the /r/<id> page renders that snapshot for whoever
-- holds the link, typically a client who should see the result without having
-- access to the tool.
--
-- The id is the whole secret: 16 random bytes, hex. There is no listing
-- endpoint and no sequential id to walk, so a link grants exactly one report.
-- Snapshots expire (default 90 days) because a reputation report is a
-- statement about a moment, and a year-old "clean" being read as current would
-- mislead the person it was shared with. Safe to run more than once.

CREATE TABLE IF NOT EXISTS shared_reports (
  id         TEXT        PRIMARY KEY,
  kind       TEXT        NOT NULL CHECK (kind IN ('single', 'bulk')),
  payload    JSONB       NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);

-- Cleanup pass: "which snapshots are past their expiry".
CREATE INDEX IF NOT EXISTS shared_reports_expiry_idx ON shared_reports (expires_at);
