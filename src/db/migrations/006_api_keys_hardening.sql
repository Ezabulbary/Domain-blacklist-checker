-- 006_api_keys_hardening.sql
--
-- Production hardening for API keys.
--
-- expires_at: an optional lifetime, chosen at creation. A leaked key that
-- expires is a bounded problem; one that lives forever is not. NULL keeps the
-- old "never expires" behavior for existing keys.
--
-- use_count / last_used_ip: usage accounting next to last_used_at, so the key
-- list can answer "is this key still used, by whom, from where" before someone
-- revokes it. Safe to run more than once.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at   TIMESTAMPTZ;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS use_count    BIGINT NOT NULL DEFAULT 0;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_ip TEXT;

-- Expiry sweeps and "expiring soon" views.
CREATE INDEX IF NOT EXISTS api_keys_expires_idx ON api_keys (expires_at)
  WHERE expires_at IS NOT NULL AND revoked_at IS NULL;
