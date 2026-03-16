-- 008 — Analytics toggle per case
ALTER TABLE cases ADD COLUMN IF NOT EXISTS analytics_enabled BOOLEAN NOT NULL DEFAULT true;