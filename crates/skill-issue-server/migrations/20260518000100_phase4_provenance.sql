ALTER TABLE mcp_server_snapshots ADD COLUMN IF NOT EXISTS tool_schema_hash TEXT;

CREATE TABLE IF NOT EXISTS scan_provenance_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
    schema_version TEXT NOT NULL,
    source_root TEXT NOT NULL,
    source_url TEXT,
    source_ref TEXT,
    source_commit TEXT,
    source_dirty BOOLEAN NOT NULL DEFAULT FALSE,
    content_hash TEXT NOT NULL,
    lockfile_hash TEXT,
    provenance_score INT NOT NULL,
    production_approval BOOLEAN NOT NULL,
    report JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scan_provenance_score
    ON scan_provenance_records(provenance_score DESC);

CREATE INDEX IF NOT EXISTS idx_scan_provenance_source_commit
    ON scan_provenance_records(source_commit);