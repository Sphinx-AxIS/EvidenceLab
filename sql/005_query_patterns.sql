-- 005 — Query learning: tracked patterns from worklog mining

CREATE TABLE IF NOT EXISTS query_patterns (
    id              SERIAL PRIMARY KEY,
    pattern_hash    TEXT UNIQUE NOT NULL,    -- hash of normalized query structure
    normalized      TEXT NOT NULL,           -- query with literals stripped
    example         TEXT DEFAULT '',         -- one real example for review
    frequency       INTEGER NOT NULL DEFAULT 1,
    promoted        BOOLEAN NOT NULL DEFAULT false,  -- admin-approved for precompute
    precompute_fn   TEXT DEFAULT '',         -- dotted path to precompute function
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now()
);