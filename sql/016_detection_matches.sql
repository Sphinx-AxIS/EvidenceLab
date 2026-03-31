-- 016 — Persisted detection match results for Analytics / pivoting

CREATE TABLE IF NOT EXISTS detection_matches (
    id              BIGSERIAL PRIMARY KEY,
    case_id         TEXT NOT NULL,
    rule_id         INTEGER NOT NULL,
    rule_title      TEXT NOT NULL DEFAULT '',
    rule_type       TEXT NOT NULL CHECK (rule_type IN ('sigma', 'suricata')),
    record_id       INTEGER NOT NULL,
    record_type     TEXT NOT NULL DEFAULT '',
    ts              TIMESTAMPTZ,
    channel         TEXT DEFAULT '',
    event_id        TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, rule_id, record_id)
);

CREATE INDEX IF NOT EXISTS idx_detection_matches_case_ts
    ON detection_matches(case_id, ts DESC);

CREATE INDEX IF NOT EXISTS idx_detection_matches_case_rule
    ON detection_matches(case_id, rule_id, rule_type);

CREATE INDEX IF NOT EXISTS idx_detection_matches_case_record
    ON detection_matches(case_id, record_id);
