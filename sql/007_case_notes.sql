-- 007 — Case notes / analyst annotations

CREATE TABLE IF NOT EXISTS case_notes (
    id              SERIAL PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases(id),
    author_id       TEXT REFERENCES users(id),
    content         TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id);