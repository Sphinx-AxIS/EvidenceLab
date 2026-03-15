-- 012 — Detection rules generated from investigation findings

CREATE TABLE IF NOT EXISTS detection_rules (
    id              SERIAL PRIMARY KEY,
    case_id         TEXT NOT NULL REFERENCES cases(id),
    finding_id      INTEGER REFERENCES findings(id),
    rule_type       TEXT NOT NULL CHECK (rule_type IN ('sigma', 'suricata')),
    status          TEXT NOT NULL DEFAULT 'draft'
                        CHECK (status IN ('draft', 'pending_review', 'approved', 'rejected', 'deployed')),
    title           TEXT NOT NULL,
    description     TEXT DEFAULT '',
    rule_content    TEXT NOT NULL,                -- Sigma YAML or Suricata rule text
    compiled_sql    TEXT DEFAULT '',              -- Sigma compiled to SQL (via pySigma)
    evidence_ids    INTEGER[] DEFAULT '{}',       -- records that informed this rule
    mitre_ids       TEXT[] DEFAULT '{}',
    sid             INTEGER,                      -- Suricata SID (9100000+ range)
    generated_by    TEXT DEFAULT 'llm',           -- 'llm' or 'manual'
    reviewed_by     TEXT DEFAULT '',
    review_notes    TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_det_rules_case ON detection_rules(case_id, status);
CREATE INDEX IF NOT EXISTS idx_det_rules_finding ON detection_rules(finding_id);
CREATE INDEX IF NOT EXISTS idx_det_rules_status ON detection_rules(status) WHERE status = 'deployed';
