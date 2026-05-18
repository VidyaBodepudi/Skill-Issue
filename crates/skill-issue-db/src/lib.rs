use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use skill_issue_core::{Asset, AssetKind, Finding, McpDriftEvent, McpServerSnapshot, Severity};
use skill_issue_policy::{PolicyAction, PolicyDecision, PolicyReport};
use skill_issue_provenance::ProvenanceReport;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

pub const MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../skill-issue-server/migrations");

#[derive(Debug, Clone)]
pub struct StoredScanOverview {
    pub id: Uuid,
    pub source_label: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub asset_count: i64,
    pub finding_count: i64,
    pub risk_score: Option<i32>,
    pub provenance_score: Option<i32>,
    pub highest_policy_action: Option<PolicyAction>,
}

#[derive(Debug, Clone)]
pub struct StoredScan {
    pub id: Uuid,
    pub source_label: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub policy_version: Option<String>,
    pub risk_score: Option<i32>,
    pub assets: Vec<Asset>,
    pub findings: Vec<Finding>,
    pub mcp_snapshots: Vec<McpServerSnapshot>,
    pub policy_decisions: Vec<PolicyDecision>,
    pub drift_events: Vec<McpDriftEvent>,
    pub provenance: Option<StoredProvenance>,
}

impl StoredScan {
    pub fn policy_report(&self) -> PolicyReport {
        PolicyReport {
            policy_version: self
                .policy_version
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            highest_action: self
                .policy_decisions
                .iter()
                .map(|decision| decision.action)
                .max()
                .unwrap_or(PolicyAction::Allow),
            risk_score: self.risk_score.unwrap_or_default().clamp(0, 100) as u8,
            decisions: self.policy_decisions.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredProvenance {
    pub schema_version: String,
    pub score: i32,
    pub production_approval: bool,
    pub source_url: Option<String>,
    pub source_ref: Option<String>,
    pub source_commit: Option<String>,
    pub source_dirty: bool,
    pub content_hash: String,
    pub lockfile_hash: Option<String>,
    pub report: serde_json::Value,
}

pub struct LocalScanRecord<'a> {
    pub actor: &'a str,
    pub source_label: &'a str,
    pub assets: &'a [Asset],
    pub findings: &'a [Finding],
    pub mcp_snapshots: &'a [McpServerSnapshot],
    pub policy_report: &'a PolicyReport,
    pub provenance: &'a ProvenanceReport,
}

pub async fn setup_job_storage(pool: &PgPool) -> Result<()> {
    sqlx::raw_sql(APALIS_POSTGRES_SETUP)
        .execute(pool)
        .await
        .context("failed to set up apalis postgres tables")?;
    Ok(())
}

const APALIS_POSTGRES_SETUP: &str = r#"
CREATE SCHEMA IF NOT EXISTS apalis;

CREATE TABLE IF NOT EXISTS apalis.workers (
    id TEXT NOT NULL,
    worker_type TEXT NOT NULL,
    storage_name TEXT NOT NULL,
    layers TEXT NOT NULL DEFAULT '',
    last_seen timestamptz not null default now()
);

CREATE INDEX IF NOT EXISTS apalis_workers_id_idx ON apalis.workers(id);
CREATE UNIQUE INDEX IF NOT EXISTS apalis_workers_unique_worker_id_idx ON apalis.workers (id);
CREATE INDEX IF NOT EXISTS apalis_workers_worker_type_idx ON apalis.workers(worker_type);
CREATE INDEX IF NOT EXISTS apalis_workers_last_seen_idx ON apalis.workers(last_seen);

CREATE TABLE IF NOT EXISTS apalis.jobs (
    job JSONB NOT NULL,
    id TEXT NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 25,
    run_at timestamptz NOT NULL default now(),
    last_error TEXT,
    lock_at timestamptz,
    lock_by TEXT,
    done_at timestamptz,
    CONSTRAINT fk_worker_lock_by FOREIGN KEY(lock_by) REFERENCES apalis.workers(id)
);

CREATE INDEX IF NOT EXISTS apalis_jobs_id_idx ON apalis.jobs(id);
CREATE INDEX IF NOT EXISTS apalis_jobs_status_idx ON apalis.jobs(status);
CREATE UNIQUE INDEX IF NOT EXISTS apalis_jobs_unique_job_id_idx ON apalis.jobs (id);
CREATE INDEX IF NOT EXISTS apalis_jobs_lock_by_idx ON apalis.jobs(lock_by);
CREATE INDEX IF NOT EXISTS apalis_jobs_job_type_idx ON apalis.jobs(job_type);

CREATE OR REPLACE FUNCTION apalis.get_job(worker_id TEXT, v_job_type TEXT)
RETURNS apalis.jobs AS $$
DECLARE
    v_job_id text;
    v_job_row apalis.jobs;
BEGIN
    SELECT id, job_type
    INTO v_job_id, v_job_type
    FROM apalis.jobs
    WHERE status = 'Pending'
    AND run_at < now()
    AND job_type = v_job_type
    ORDER BY run_at ASC limit 1 FOR UPDATE skip LOCKED;

    IF v_job_id IS NULL THEN
        RETURN NULL;
    END IF;

    UPDATE apalis.jobs
    SET status = 'Running', lock_by = worker_id, lock_at = now()
    WHERE id = v_job_id
    RETURNING * INTO v_job_row;
    RETURN v_job_row;
END;
$$ LANGUAGE plpgsql volatile;

CREATE OR REPLACE FUNCTION apalis.notify_new_jobs()
RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('apalis::job', 'insert');
    RETURN new;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS notify_workers ON apalis.jobs;
CREATE TRIGGER notify_workers AFTER INSERT ON apalis.jobs FOR EACH STATEMENT EXECUTE PROCEDURE apalis.notify_new_jobs();
"#;

pub async fn store_local_scan(pool: &PgPool, record: LocalScanRecord<'_>) -> Result<Uuid> {
    let mut tx = pool.begin().await?;
    let scan_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO scans (id, status, scanner_version, source_label, policy_version, risk_score, started_at, completed_at) VALUES ($1, 'completed', $2, $3, $4, $5, now(), now())",
    )
	.bind(scan_id)
	.bind(env!("CARGO_PKG_VERSION"))
	.bind(record.source_label)
    .bind(&record.policy_report.policy_version)
    .bind(record.policy_report.risk_score as i32)
	.execute(&mut *tx)
	.await?;

    let mut asset_ids = HashMap::new();
    for asset in record.assets {
        sqlx::query(
			"INSERT INTO assets (id, scan_id, path, kind, fingerprint, size_bytes) VALUES ($1, $2, $3, $4, $5, $6)",
		)
		.bind(asset.id)
		.bind(scan_id)
		.bind(&asset.path)
		.bind(asset.kind.to_string())
		.bind(&asset.fingerprint)
		.bind(asset.size_bytes as i64)
		.execute(&mut *tx)
		.await?;
        asset_ids.insert(asset.path.clone(), asset.id);
    }

    for finding in record.findings {
        sqlx::query(
			"INSERT INTO findings (id, scan_id, asset_id, rule_id, severity, title, description, evidence, tags, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
		)
		.bind(finding.id)
		.bind(scan_id)
		.bind(asset_ids.get(&finding.asset_path).copied())
		.bind(&finding.rule_id)
		.bind(finding.severity.to_string())
		.bind(&finding.title)
		.bind(&finding.description)
		.bind(&finding.evidence)
		.bind(&finding.tags)
		.bind(finding.created_at)
		.execute(&mut *tx)
		.await?;
    }

    for snapshot in record.mcp_snapshots {
        let previous = sqlx::query(
            "SELECT command_hash, tool_schema_hash FROM mcp_server_snapshots WHERE source_label = $1 AND asset_path = $2 AND server_name = $3 ORDER BY created_at DESC LIMIT 1",
		)
        .bind(record.source_label)
		.bind(&snapshot.asset_path)
		.bind(&snapshot.server_name)
		.fetch_optional(&mut *tx)
		.await?;

        sqlx::query(
            "INSERT INTO mcp_server_snapshots (scan_id, asset_id, source_label, asset_path, server_name, command, args, env_keys, command_hash, tool_schema_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
		)
		.bind(scan_id)
		.bind(asset_ids.get(&snapshot.asset_path).copied())
        .bind(record.source_label)
		.bind(&snapshot.asset_path)
		.bind(&snapshot.server_name)
		.bind(&snapshot.command)
		.bind(&snapshot.args)
		.bind(&snapshot.env_keys)
		.bind(&snapshot.command_hash)
        .bind(&snapshot.tool_schema_hash)
		.execute(&mut *tx)
		.await?;

        if let Some(row) = previous {
            let previous_hash: String = row.try_get("command_hash")?;
            let previous_schema_hash: Option<String> = row.try_get("tool_schema_hash")?;
            if previous_hash != snapshot.command_hash {
                sqlx::query(
					"INSERT INTO mcp_drift_events (scan_id, asset_path, server_name, drift_kind, previous_hash, current_hash, description) VALUES ($1, $2, $3, 'command_changed', $4, $5, $6)",
				)
				.bind(scan_id)
				.bind(&snapshot.asset_path)
				.bind(&snapshot.server_name)
				.bind(previous_hash)
				.bind(&snapshot.command_hash)
				.bind("MCP server command declaration changed since the previous scan for this source/path/server.")
				.execute(&mut *tx)
				.await?;
            }
            if previous_schema_hash != snapshot.tool_schema_hash {
                sqlx::query(
					"INSERT INTO mcp_drift_events (scan_id, asset_path, server_name, drift_kind, previous_hash, current_hash, description) VALUES ($1, $2, $3, 'tool_schema_changed', $4, $5, $6)",
				)
				.bind(scan_id)
				.bind(&snapshot.asset_path)
				.bind(&snapshot.server_name)
				.bind(previous_schema_hash.unwrap_or_else(|| "none".to_owned()))
				.bind(snapshot.tool_schema_hash.as_deref().unwrap_or("none"))
				.bind("MCP tool-schema declaration changed since the previous scan for this source/path/server.")
				.execute(&mut *tx)
				.await?;
            }
        }
    }

    let git = record.provenance.source.git.as_ref();
    sqlx::query(
        "INSERT INTO scan_provenance_records (scan_id, schema_version, source_root, source_url, source_ref, source_commit, source_dirty, content_hash, lockfile_hash, provenance_score, production_approval, report) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(scan_id)
    .bind(&record.provenance.schema_version)
    .bind(&record.provenance.source.root)
    .bind(git.and_then(|git| git.remote_url.as_deref()))
    .bind(git.and_then(|git| git.branch.as_deref()))
    .bind(git.and_then(|git| git.head_commit.as_deref()))
    .bind(git.is_some_and(|git| git.dirty))
    .bind(&record.provenance.content.content_digest_sha256)
    .bind(&record.provenance.content.lockfile_digest_sha256)
    .bind(record.provenance.score.value as i32)
    .bind(record.provenance.approval.production_approval)
    .bind(serde_json::to_value(record.provenance)?)
    .execute(&mut *tx)
    .await?;

    for decision in &record.policy_report.decisions {
        sqlx::query(
            "INSERT INTO policy_decisions (id, scan_id, finding_id, policy_id, action, title, description, subject_type, subject_key, asset_path, evidence, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(decision.id)
        .bind(scan_id)
        .bind(decision.finding_id)
        .bind(&decision.policy_id)
        .bind(decision.action.to_string())
        .bind(&decision.title)
        .bind(&decision.description)
        .bind(&decision.subject_type)
        .bind(&decision.subject_key)
        .bind(&decision.asset_path)
        .bind(&decision.evidence)
        .bind(decision.created_at)
        .execute(&mut *tx)
        .await?;
    }

    insert_audit_event_tx(
        &mut tx,
        record.actor,
        "scan.local.completed",
        "scan",
        Some(scan_id.to_string()),
        serde_json::json!({
            "source_label": record.source_label,
            "asset_count": record.assets.len(),
            "finding_count": record.findings.len(),
            "mcp_snapshot_count": record.mcp_snapshots.len()
            ,"policy_decision_count": record.policy_report.decisions.len()
            ,"risk_score": record.policy_report.risk_score
            ,"provenance_score": record.provenance.score.value
        }),
    )
    .await?;

    tx.commit().await?;
    Ok(scan_id)
}

pub async fn list_recent_scans(pool: &PgPool, limit: i64) -> Result<Vec<StoredScanOverview>> {
    let rows = sqlx::query(
		"SELECT s.id, COALESCE(s.source_label, 'unknown') AS source_label, s.status, s.created_at, s.completed_at, s.risk_score, MAX(spr.provenance_score) AS provenance_score, COUNT(DISTINCT a.id)::BIGINT AS asset_count, COUNT(DISTINCT f.id)::BIGINT AS finding_count, MAX(pd.action) FILTER (WHERE pd.action = 'block') AS has_block, MAX(pd.action) FILTER (WHERE pd.action = 'review') AS has_review, MAX(pd.action) FILTER (WHERE pd.action = 'warn') AS has_warn FROM scans s LEFT JOIN scan_provenance_records spr ON spr.scan_id = s.id LEFT JOIN assets a ON a.scan_id = s.id LEFT JOIN findings f ON f.scan_id = s.id LEFT JOIN policy_decisions pd ON pd.scan_id = s.id GROUP BY s.id ORDER BY s.created_at DESC LIMIT $1",
	)
	.bind(limit)
	.fetch_all(pool)
	.await?;

    rows.into_iter()
        .map(|row| {
            Ok(StoredScanOverview {
                id: row.try_get("id")?,
                source_label: row.try_get("source_label")?,
                status: row.try_get("status")?,
                created_at: row.try_get("created_at")?,
                completed_at: row.try_get("completed_at")?,
                asset_count: row.try_get("asset_count")?,
                finding_count: row.try_get("finding_count")?,
                risk_score: row.try_get("risk_score")?,
                provenance_score: row.try_get("provenance_score")?,
                highest_policy_action: highest_policy_action_from_row(&row)?,
            })
        })
        .collect()
}

pub async fn load_scan(pool: &PgPool, scan_id: Uuid) -> Result<Option<StoredScan>> {
    let Some(scan_row) = sqlx::query(
		"SELECT id, COALESCE(source_label, 'unknown') AS source_label, status, created_at, completed_at, policy_version, risk_score FROM scans WHERE id = $1",
	)
	.bind(scan_id)
	.fetch_optional(pool)
	.await? else {
		return Ok(None);
	};

    let asset_rows = sqlx::query(
		"SELECT id, path, kind, fingerprint, size_bytes FROM assets WHERE scan_id = $1 ORDER BY path ASC",
	)
	.bind(scan_id)
	.fetch_all(pool)
	.await?;
    let mut assets = Vec::with_capacity(asset_rows.len());
    for row in asset_rows {
        let kind_string: String = row.try_get("kind")?;
        assets.push(Asset {
            id: row.try_get("id")?,
            path: row.try_get("path")?,
            kind: AssetKind::from_str(&kind_string).unwrap_or(AssetKind::Unknown),
            fingerprint: row.try_get("fingerprint")?,
            size_bytes: row.try_get::<i64, _>("size_bytes")? as u64,
        });
    }

    let finding_rows = sqlx::query(
        "SELECT f.id, f.rule_id, f.severity, f.title, f.description, f.evidence, f.tags, f.created_at, COALESCE(a.path, '') AS asset_path FROM findings f LEFT JOIN assets a ON a.id = f.asset_id WHERE f.scan_id = $1 ORDER BY f.created_at ASC",
    )
	.bind(scan_id)
	.fetch_all(pool)
	.await?;
    let mut findings = Vec::with_capacity(finding_rows.len());
    for row in finding_rows {
        let severity_string: String = row.try_get("severity")?;
        findings.push(Finding {
            id: row.try_get("id")?,
            asset_path: row.try_get("asset_path")?,
            rule_id: row.try_get("rule_id")?,
            severity: Severity::from_str(&severity_string).unwrap_or(Severity::Info),
            title: row.try_get("title")?,
            description: row.try_get("description")?,
            evidence: row.try_get("evidence")?,
            tags: row.try_get("tags")?,
            created_at: row.try_get("created_at")?,
        });
    }

    let mcp_snapshots = load_mcp_snapshots(pool, scan_id).await?;
    let policy_decisions = load_policy_decisions(pool, scan_id).await?;
    let drift_events = load_mcp_drift_events(pool, scan_id).await?;
    let provenance = load_scan_provenance(pool, scan_id).await?;

    Ok(Some(StoredScan {
        id: scan_row.try_get("id")?,
        source_label: scan_row.try_get("source_label")?,
        status: scan_row.try_get("status")?,
        created_at: scan_row.try_get("created_at")?,
        completed_at: scan_row.try_get("completed_at")?,
        policy_version: scan_row.try_get("policy_version")?,
        risk_score: scan_row.try_get("risk_score")?,
        assets,
        findings,
        mcp_snapshots,
        policy_decisions,
        drift_events,
        provenance,
    }))
}

pub async fn load_scan_provenance(
    pool: &PgPool,
    scan_id: Uuid,
) -> Result<Option<StoredProvenance>> {
    let Some(row) = sqlx::query(
        "SELECT schema_version, source_url, source_ref, source_commit, source_dirty, content_hash, lockfile_hash, provenance_score, production_approval, report FROM scan_provenance_records WHERE scan_id = $1",
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await? else {
        return Ok(None);
    };

    Ok(Some(StoredProvenance {
        schema_version: row.try_get("schema_version")?,
        score: row.try_get("provenance_score")?,
        production_approval: row.try_get("production_approval")?,
        source_url: row.try_get("source_url")?,
        source_ref: row.try_get("source_ref")?,
        source_commit: row.try_get("source_commit")?,
        source_dirty: row.try_get("source_dirty")?,
        content_hash: row.try_get("content_hash")?,
        lockfile_hash: row.try_get("lockfile_hash")?,
        report: row.try_get("report")?,
    }))
}

fn highest_policy_action_from_row(row: &sqlx::postgres::PgRow) -> Result<Option<PolicyAction>> {
    for column in ["has_block", "has_review", "has_warn"] {
        let value: Option<String> = row.try_get(column)?;
        if let Some(action) = value {
            return Ok(Some(
                PolicyAction::from_str(&action).unwrap_or(PolicyAction::Warn),
            ));
        }
    }
    Ok(None)
}

pub async fn insert_audit_event(
    pool: &PgPool,
    actor: &str,
    action: &str,
    subject_type: &str,
    subject_id: Option<String>,
    metadata: serde_json::Value,
) -> Result<()> {
    sqlx::query(
		"INSERT INTO audit_events (actor, action, subject_type, subject_id, metadata) VALUES ($1, $2, $3, $4, $5)",
	)
	.bind(actor)
	.bind(action)
	.bind(subject_type)
	.bind(subject_id)
	.bind(metadata)
	.execute(pool)
	.await?;
    Ok(())
}

async fn insert_audit_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &str,
    action: &str,
    subject_type: &str,
    subject_id: Option<String>,
    metadata: serde_json::Value,
) -> Result<()> {
    sqlx::query(
		"INSERT INTO audit_events (actor, action, subject_type, subject_id, metadata) VALUES ($1, $2, $3, $4, $5)",
	)
	.bind(actor)
	.bind(action)
	.bind(subject_type)
	.bind(subject_id)
	.bind(metadata)
	.execute(&mut **tx)
	.await?;
    Ok(())
}

async fn load_mcp_snapshots(pool: &PgPool, scan_id: Uuid) -> Result<Vec<McpServerSnapshot>> {
    let rows = sqlx::query(
        "SELECT asset_path, server_name, command, args, env_keys, command_hash, tool_schema_hash FROM mcp_server_snapshots WHERE scan_id = $1 ORDER BY asset_path ASC, server_name ASC",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(McpServerSnapshot {
                asset_path: row.try_get("asset_path")?,
                server_name: row.try_get("server_name")?,
                command: row.try_get("command")?,
                args: row.try_get("args")?,
                env_keys: row.try_get("env_keys")?,
                command_hash: row.try_get("command_hash")?,
                tool_schema_hash: row.try_get("tool_schema_hash")?,
            })
        })
        .collect()
}

async fn load_mcp_drift_events(pool: &PgPool, scan_id: Uuid) -> Result<Vec<McpDriftEvent>> {
    let rows = sqlx::query(
		"SELECT id, asset_path, server_name, drift_kind, previous_hash, current_hash, description FROM mcp_drift_events WHERE scan_id = $1 ORDER BY created_at ASC",
	)
	.bind(scan_id)
	.fetch_all(pool)
	.await?;

    rows.into_iter()
        .map(|row| {
            Ok(McpDriftEvent {
                id: row.try_get("id")?,
                asset_path: row.try_get("asset_path")?,
                server_name: row.try_get("server_name")?,
                drift_kind: row.try_get("drift_kind")?,
                previous_hash: row.try_get("previous_hash")?,
                current_hash: row.try_get("current_hash")?,
                description: row.try_get("description")?,
            })
        })
        .collect()
}

async fn load_policy_decisions(pool: &PgPool, scan_id: Uuid) -> Result<Vec<PolicyDecision>> {
    let rows = sqlx::query(
        "SELECT id, policy_id, action, title, description, subject_type, subject_key, finding_id, asset_path, evidence, created_at FROM policy_decisions WHERE scan_id = $1 ORDER BY CASE action WHEN 'block' THEN 1 WHEN 'review' THEN 2 WHEN 'warn' THEN 3 ELSE 4 END, policy_id ASC, subject_key ASC",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let action: String = row.try_get("action")?;
            Ok(PolicyDecision {
                id: row.try_get("id")?,
                policy_id: row.try_get("policy_id")?,
                action: PolicyAction::from_str(&action).unwrap_or(PolicyAction::Warn),
                title: row.try_get("title")?,
                description: row.try_get("description")?,
                subject_type: row.try_get("subject_type")?,
                subject_key: row.try_get("subject_key")?,
                finding_id: row.try_get("finding_id")?,
                asset_path: row.try_get("asset_path")?,
                evidence: row.try_get("evidence")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}
