-- 014 — Decouple detection_rules from cases/findings FKs
-- Rules are global assets with provenance, not case-scoped objects.
-- They must survive case deletion.

-- Drop FK constraints if they exist
ALTER TABLE detection_rules DROP CONSTRAINT IF EXISTS detection_rules_case_id_fkey;
ALTER TABLE detection_rules DROP CONSTRAINT IF EXISTS detection_rules_finding_id_fkey;

-- Allow null case_id (rules can exist without a case)
ALTER TABLE detection_rules ALTER COLUMN case_id DROP NOT NULL;
ALTER TABLE detection_rules ALTER COLUMN case_id SET DEFAULT '';

-- Add case_name column for provenance (snapshot at creation time)
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS case_name TEXT DEFAULT '';
