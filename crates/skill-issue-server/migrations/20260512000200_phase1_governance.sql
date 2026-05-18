ALTER TABLE scans ADD COLUMN IF NOT EXISTS source_label TEXT;
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);

DROP TABLE IF EXISTS scan_jobs;

CREATE TABLE IF NOT EXISTS mcp_server_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    source_label TEXT NOT NULL,
    asset_path TEXT NOT NULL,
    server_name TEXT NOT NULL,
    command TEXT,
    args TEXT[] NOT NULL DEFAULT '{}',
    env_keys TEXT[] NOT NULL DEFAULT '{}',
    command_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mcp_server_snapshots_lookup
    ON mcp_server_snapshots(source_label, asset_path, server_name, created_at DESC);

CREATE TABLE IF NOT EXISTS mcp_drift_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    asset_path TEXT NOT NULL,
    server_name TEXT NOT NULL,
    drift_kind TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mcp_drift_events_scan ON mcp_drift_events(scan_id);