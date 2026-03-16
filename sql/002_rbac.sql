-- 002 — RBAC: users, roles, case assignments

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'analyst'
                        CHECK (role IN ('admin', 'case_manager', 'analyst', 'llm_agent')),
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS case_assignments (
    user_id         TEXT NOT NULL REFERENCES users(id),
    case_id         TEXT NOT NULL REFERENCES cases(id),
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, case_id)
);