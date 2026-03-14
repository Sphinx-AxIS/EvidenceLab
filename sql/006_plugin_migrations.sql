-- 006 — Plugin migration tracking

CREATE TABLE IF NOT EXISTS plugin_migrations (
    id              SERIAL PRIMARY KEY,
    plugin_name     TEXT NOT NULL,
    migration_file  TEXT NOT NULL,
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (plugin_name, migration_file)
);