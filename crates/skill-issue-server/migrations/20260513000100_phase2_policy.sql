ALTER TABLE scans ADD COLUMN IF NOT EXISTS risk_score INT;

CREATE TABLE IF NOT EXISTS policy_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    policy_id TEXT NOT NULL,
    action TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    asset_path TEXT,
    evidence TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_decisions_scan ON policy_decisions(scan_id);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_action ON policy_decisions(action);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_policy_id ON policy_decisions(policy_id);