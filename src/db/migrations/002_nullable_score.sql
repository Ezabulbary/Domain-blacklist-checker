-- 002_nullable_score.sql
--
-- A check can now come back with no score at all. That happens when not one
-- blocklist gave a definitive answer, so there is nothing to compute a score
-- from. The old schema forced a number to be stored anyway, which meant an
-- unmeasurable check had to be recorded as either 100 (perfectly clean) or 0
-- (as bad as possible). Both are inventions.
--
-- NULL is the honest value: "we could not measure this". Queries that average
-- or rank scores skip NULLs by default, which is the behaviour we want.
--
-- The 0..100 range check is kept, and still applies whenever a score is present.
-- Safe to run more than once.

ALTER TABLE checks ALTER COLUMN score DROP NOT NULL;

-- Finding the checks that produced no usable answer, e.g. to spot a resolver
-- problem before it silently becomes "everything looks clean".
CREATE INDEX IF NOT EXISTS checks_unscored_idx ON checks (created_at DESC)
  WHERE score IS NULL;
