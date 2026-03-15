-- 010 — Add job_id to records + extend background_jobs status for deletion

ALTER TABLE records ADD COLUMN IF NOT EXISTS job_id INTEGER REFERENCES background_jobs(id);

CREATE INDEX IF NOT EXISTS idx_records_job_id ON records(job_id) WHERE job_id IS NOT NULL;

-- Allow 'deleted' status on background_jobs (for admin data management)
ALTER TABLE background_jobs DROP CONSTRAINT IF EXISTS background_jobs_status_check;
ALTER TABLE background_jobs ADD CONSTRAINT background_jobs_status_check
    CHECK (status IN ('pending', 'running', 'done', 'partial', 'failed', 'deleted'));
