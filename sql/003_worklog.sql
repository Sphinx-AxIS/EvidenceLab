-- 003 — Worklog: tasks and step-level audit trail

CREATE TABLE IF NOT EXISTS tasks (
    id              SERIAL PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases(id),
    title           TEXT NOT NULL,
    description     TEXT DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'running', 'done', 'failed', 'cancelled')),
    assigned_to     TEXT REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS worklog_steps (
    id              SERIAL PRIMARY KEY,
    task_id         INTEGER NOT NULL REFERENCES tasks(id),
    step_number     INTEGER NOT NULL,
    intent          TEXT DEFAULT '',
    code            TEXT DEFAULT '',
    stdout          TEXT DEFAULT '',
    stderr          TEXT DEFAULT '',
    result          JSONB DEFAULT '{}',
    elapsed_s       REAL,
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_worklog_task ON worklog_steps(task_id, step_number);