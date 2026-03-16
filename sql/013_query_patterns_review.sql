-- 013 — Add review fields to query_patterns for admin promotion workflow

ALTER TABLE query_patterns ADD COLUMN IF NOT EXISTS dismissed BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE query_patterns ADD COLUMN IF NOT EXISTS reviewed_by TEXT DEFAULT '';
ALTER TABLE query_patterns ADD COLUMN IF NOT EXISTS review_notes TEXT DEFAULT '';
