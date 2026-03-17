-- 015 — Restricted REPL database role + Row-Level Security
--
-- Creates a sphinx_repl role with SELECT-only access to evidence tables
-- and INSERT on scratch_precomputed (for stash). RLS policies enforce
-- case-scoping at the database level using session variable app.readable_case_ids.

-- ── 1. sphinx_repl role ─────────────────────────────────────────────
-- The role is created by bootstrap_postgres.sh (with password from env).
-- This migration only sets up grants and RLS policies.

-- Allow connection to the sphinx database (idempotent)
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'sphinx_repl') THEN
        EXECUTE 'GRANT CONNECT ON DATABASE sphinx TO sphinx_repl';
    END IF;
END
$$;

-- Schema usage
GRANT USAGE ON SCHEMA public TO sphinx_repl;

-- ── 2. Table-level grants (least privilege) ─────────────────────────

-- Read-only on evidence tables
GRANT SELECT ON records TO sphinx_repl;
GRANT SELECT ON entities TO sphinx_repl;
GRANT SELECT ON findings TO sphinx_repl;
GRANT SELECT ON cases TO sphinx_repl;

-- Read-only on supporting tables the REPL tools need
GRANT SELECT ON scratch_precomputed TO sphinx_repl;
GRANT SELECT ON worklog_steps TO sphinx_repl;
GRANT SELECT ON tasks TO sphinx_repl;
GRANT SELECT ON detection_rules TO sphinx_repl;

-- REPL needs INSERT/UPDATE/DELETE on scratch_precomputed for stash/recall
GRANT INSERT, UPDATE, DELETE ON scratch_precomputed TO sphinx_repl;
GRANT USAGE, SELECT ON SEQUENCE scratch_precomputed_id_seq TO sphinx_repl;

-- Read-only on rlm_docs if it exists
DO $$
BEGIN
    IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'rlm_docs') THEN
        EXECUTE 'GRANT SELECT ON rlm_docs TO sphinx_repl';
    END IF;
END
$$;

-- Explicitly deny access to admin tables
-- (No GRANT = no access, but be explicit for clarity)
-- sphinx_repl has NO access to: users, case_assignments, plugin_migrations,
-- background_jobs, query_patterns, or any future admin tables.

-- ── 3. Row-Level Security on evidence tables ────────────────────────
-- The REPL sets `app.readable_case_ids` at connection time.
-- RLS policies restrict SELECT to only matching case_ids.

-- records
ALTER TABLE records ENABLE ROW LEVEL SECURITY;

CREATE POLICY repl_records_select ON records
    FOR SELECT TO sphinx_repl
    USING (case_id = ANY(string_to_array(current_setting('app.readable_case_ids', true), ',')));

-- Allow the sphinx (owner) role to bypass RLS
ALTER TABLE records FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_records_all ON records
    FOR ALL TO sphinx
    USING (true) WITH CHECK (true);

-- entities
ALTER TABLE entities ENABLE ROW LEVEL SECURITY;

CREATE POLICY repl_entities_select ON entities
    FOR SELECT TO sphinx_repl
    USING (case_id = ANY(string_to_array(current_setting('app.readable_case_ids', true), ',')));

ALTER TABLE entities FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_entities_all ON entities
    FOR ALL TO sphinx
    USING (true) WITH CHECK (true);

-- findings
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY repl_findings_select ON findings
    FOR SELECT TO sphinx_repl
    USING (case_id = ANY(string_to_array(current_setting('app.readable_case_ids', true), ',')));

ALTER TABLE findings FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_findings_all ON findings
    FOR ALL TO sphinx
    USING (true) WITH CHECK (true);

-- scratch_precomputed (REPL needs SELECT + INSERT + DELETE for stash)
ALTER TABLE scratch_precomputed ENABLE ROW LEVEL SECURITY;

CREATE POLICY repl_scratch_select ON scratch_precomputed
    FOR SELECT TO sphinx_repl
    USING (case_id = ANY(string_to_array(current_setting('app.readable_case_ids', true), ',')));

CREATE POLICY repl_scratch_insert ON scratch_precomputed
    FOR INSERT TO sphinx_repl
    WITH CHECK (case_id = ANY(string_to_array(current_setting('app.readable_case_ids', true), ',')));

CREATE POLICY repl_scratch_delete ON scratch_precomputed
    FOR DELETE TO sphinx_repl
    USING (case_id = ANY(string_to_array(current_setting('app.readable_case_ids', true), ',')));

ALTER TABLE scratch_precomputed FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_scratch_all ON scratch_precomputed
    FOR ALL TO sphinx
    USING (true) WITH CHECK (true);

-- cases (REPL can only see cases it has access to)
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;

CREATE POLICY repl_cases_select ON cases
    FOR SELECT TO sphinx_repl
    USING (id = ANY(string_to_array(current_setting('app.readable_case_ids', true), ',')));

ALTER TABLE cases FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_cases_all ON cases
    FOR ALL TO sphinx
    USING (true) WITH CHECK (true);
