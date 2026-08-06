-- 003_api_keys.sql
--
-- Real API keys: named, scoped, several per user, revocable.
--
-- The old model was a single `users.api_key` column holding the key in plain
-- text. Three problems with that. A user could only ever have one key, so
-- rotating it broke everything using the old one at once. There was nowhere to
-- record what a key was for. And anyone who could read the users table could
-- authenticate as any user.
--
-- Here the key itself is never stored. We keep a SHA-256 hash and a short
-- non-secret prefix for display, so a leaked database yields no working keys,
-- and the full key is shown to its creator exactly once at creation.
--
-- Existing users.api_key values keep working, treated as legacy all:all keys,
-- so nothing breaks on upgrade. Safe to run more than once.

CREATE TABLE IF NOT EXISTS api_keys (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id      BIGINT      REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT        NOT NULL,
  -- SHA-256 of the key. The key itself is never written down.
  key_hash     TEXT        NOT NULL UNIQUE,
  -- First few characters, safe to display so a key can be recognised in a list.
  key_prefix   TEXT        NOT NULL,
  -- 'all:all' or specific resource:action scopes. Empty is not allowed: a key
  -- that can do nothing is a bug, not a configuration.
  scopes       TEXT[]      NOT NULL,
  last_used_at TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT api_keys_name_not_blank CHECK (length(btrim(name)) > 0),
  -- cardinality(), not array_length(). array_length() returns NULL for an empty
  -- array, NULL >= 1 is NULL, and a CHECK constraint only rejects FALSE, so the
  -- obvious spelling lets exactly the value it was written to stop straight
  -- through. cardinality() returns 0 and the check bites.
  CONSTRAINT api_keys_scopes_not_empty CHECK (cardinality(scopes) >= 1)
);

-- Repair the constraint for any database that took the first version of this
-- migration, where an empty scope array could still be inserted.
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_scopes_not_empty;
ALTER TABLE api_keys ADD  CONSTRAINT api_keys_scopes_not_empty CHECK (cardinality(scopes) >= 1);

-- The authentication lookup: hash the presented key, find the live row.
CREATE INDEX IF NOT EXISTS api_keys_hash_live_idx ON api_keys (key_hash)
  WHERE revoked_at IS NULL;

-- "Show me my keys", newest first.
CREATE INDEX IF NOT EXISTS api_keys_user_created_idx ON api_keys (user_id, created_at DESC);

-- Which keys actually carry a given scope, for auditing who can do what.
CREATE INDEX IF NOT EXISTS api_keys_scopes_gin_idx ON api_keys USING gin (scopes);
