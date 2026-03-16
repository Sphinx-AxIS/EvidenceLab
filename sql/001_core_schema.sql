-- 001 — Core schema: cases, records, entities, findings
-- Idempotent (IF NOT EXISTS throughout)

CREATE TABLE IF NOT EXISTS cases (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    home_net        TEXT[] DEFAULT '{}',
    victim_ips      TEXT[] DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open', 'closed', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS records (
    id              SERIAL PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases(id),
    record_type     TEXT NOT NULL,           -- e.g. suricata_alert, win_evt_security
    source_plugin   TEXT DEFAULT '',         -- plugin that ingested this record
    raw             JSONB NOT NULL DEFAULT '{}',
    ts              TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_records_case_type ON records(case_id, record_type);
CREATE INDEX IF NOT EXISTS idx_records_ts ON records(ts);
CREATE INDEX IF NOT EXISTS idx_records_raw_gin ON records USING GIN(raw);

CREATE TABLE IF NOT EXISTS entities (
    id              SERIAL PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases(id),
    record_id       INTEGER REFERENCES records(id),
    entity_type     TEXT NOT NULL,           -- ip, hash, url, email, domain, host, user
    value           TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_entities_case_type ON entities(case_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);

CREATE TABLE IF NOT EXISTS findings (
    id              SERIAL PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases(id),
    task_id         INTEGER,
    title           TEXT NOT NULL,
    body            TEXT DEFAULT '',
    severity        TEXT DEFAULT 'info'
                        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    evidence_ids    INTEGER[] DEFAULT '{}',
    mitre_ids       TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);