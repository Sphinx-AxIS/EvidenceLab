-- Background job tracking for long-running operations (PCAP ingest, etc.)

CREATE TABLE IF NOT EXISTS background_jobs (
    id          SERIAL PRIMARY KEY,
    case_id     TEXT NOT NULL REFERENCES cases(id),
    job_type    TEXT NOT NULL,          -- 'pcap_ingest', etc.
    status      TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'done', 'partial', 'failed')),
    input_name  TEXT DEFAULT '',        -- e.g. uploaded filename
    summary     JSONB DEFAULT '{}',     -- tool results, record counts, errors
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bg_jobs_case ON background_jobs(case_id, created_at DESC);