-- 011 — Support correlation cases (cross-case analysis)

ALTER TABLE cases ADD COLUMN IF NOT EXISTS case_type TEXT NOT NULL DEFAULT 'investigation'
    CHECK (case_type IN ('investigation', 'correlation'));

ALTER TABLE cases ADD COLUMN IF NOT EXISTS source_case_ids TEXT[] DEFAULT '{}';
