-- 004 — Pre-computed analytics scratch tables

CREATE TABLE IF NOT EXISTS scratch_precomputed (
    id              SERIAL PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases(id),
    task_id         INTEGER REFERENCES tasks(id),
    name            TEXT NOT NULL,           -- e.g. top_talkers, alert_severity_counts
    plugin          TEXT DEFAULT '',         -- source plugin
    data            JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_precomputed_case_name
    ON scratch_precomputed(case_id, name);