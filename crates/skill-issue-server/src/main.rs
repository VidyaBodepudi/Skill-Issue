mod views;

use anyhow::{bail, Context};
use apalis::prelude::Storage;
use apalis_sql::postgres::PostgresStorage;
use axum::body::Bytes;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use skill_issue_connectors::verify_github_signature;
use skill_issue_core::{ScanJob, ScanSummary};
use skill_issue_db::{
    insert_audit_event, list_recent_scans, load_scan, setup_job_storage, store_local_scan,
    LocalScanRecord,
};
use skill_issue_exports::{to_sarif, to_scan_json, ScanJsonInput};
use skill_issue_policy::PolicyScanMode;
use skill_issue_scanner::{run_scan, ScanOptions, ScanRun};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Serialize)]
struct StoredScanJsonExport<'a> {
    id: Uuid,
    source: &'a str,
    status: &'a str,
    created_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    summary: ScanSummary,
    assets: &'a [skill_issue_core::Asset],
    findings: &'a [skill_issue_core::Finding],
    mcp_snapshots: &'a [skill_issue_core::McpServerSnapshot],
    policy: skill_issue_policy::PolicyReport,
    drift_events: &'a [skill_issue_core::McpDriftEvent],
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<&'a serde_json::Value>,
}

#[derive(Clone)]
struct AppState {
    db: Option<PgPool>,
}

#[derive(Debug, Deserialize)]
struct LocalScanForm {
    path: String,
    format: Option<String>,
}

struct ServerScanRun {
    report: ScanRun,
    temp_root: Option<PathBuf>,
}

impl Drop for ServerScanRun {
    fn drop(&mut self) {
        if let Some(temp_root) = &self.temp_root {
            let _ = fs::remove_dir_all(temp_root);
        }
    }
}

struct PreparedScanTarget {
    source_label: String,
    root: PathBuf,
    temp_root: Option<PathBuf>,
}

struct GitHubRepoRef {
    owner: String,
    repo: String,
    label: String,
    clone_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let db = connect_database().await?;
    let state = AppState { db };
    let app = Router::new()
        .route("/", get(index))
        .route("/scans", get(scans_index))
        .route("/scans/{scan_id}", get(scan_detail))
        .route("/scans/{scan_id}/json", get(scan_json))
        .route("/scans/{scan_id}/provenance", get(scan_provenance_json))
        .route("/scans/{scan_id}/sarif", get(scan_sarif))
        .route("/healthz", get(healthz))
        .route("/scans/local", post(scan_local))
        .route("/jobs/local", post(enqueue_local_scan))
        .route("/webhooks/github", post(github_webhook))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind_address = env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:3000".to_owned());
    let address: SocketAddr = bind_address
        .parse()
        .context("BIND_ADDRESS must be host:port")?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    info!(%address, "skill issue server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn connect_database() -> anyhow::Result<Option<PgPool>> {
    let Ok(database_url) = env::var("DATABASE_URL") else {
        warn!("DATABASE_URL not set; starting without persistence");
        return Ok(None);
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("failed to connect to PostgreSQL")?;
    skill_issue_db::MIGRATOR
        .run(&pool)
        .await
        .context("failed running migrations")?;
    setup_job_storage(&pool).await?;
    Ok(Some(pool))
}

async fn index(State(state): State<AppState>) -> axum::response::Response {
    let recent_scans = match &state.db {
        Some(pool) => match list_recent_scans(pool, 10).await {
            Ok(scans) => scans,
            Err(error) => return error_response(error),
        },
        None => Vec::new(),
    };

    Html(
        views::layout(
            "Skill Issue",
            views::dashboard(state.db.is_some(), &recent_scans),
        )
        .into_string(),
    )
    .into_response()
}

async fn healthz(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "database": state.db.is_some(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn scans_index(State(state): State<AppState>) -> axum::response::Response {
    let Some(pool) = &state.db else {
        return error_response(anyhow::anyhow!("scan history requires DATABASE_URL"));
    };
    match list_recent_scans(pool, 100).await {
        Ok(scans) => {
            Html(views::layout("Scans", views::scan_history(&scans)).into_string()).into_response()
        }
        Err(error) => error_response(error),
    }
}

async fn scan_detail(
    Path(scan_id): Path<Uuid>,
    State(state): State<AppState>,
) -> axum::response::Response {
    let Some(pool) = &state.db else {
        return error_response(anyhow::anyhow!("stored scan details require DATABASE_URL"));
    };
    match load_scan(pool, scan_id).await {
        Ok(Some(scan)) => Html(views::stored_scan(&scan).into_string()).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Html(views::error_panel("scan not found").into_string()),
        )
            .into_response(),
        Err(error) => error_response(error),
    }
}

async fn scan_json(
    Path(scan_id): Path<Uuid>,
    State(state): State<AppState>,
) -> axum::response::Response {
    let Some(pool) = &state.db else {
        return error_response(anyhow::anyhow!("stored scan JSON requires DATABASE_URL"));
    };
    match load_scan(pool, scan_id).await {
        Ok(Some(scan)) => match stored_scan_json(&scan) {
            Ok(body) => {
                (StatusCode::OK, [("content-type", "application/json")], body).into_response()
            }
            Err(error) => error_response(error),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "scan not found").into_response(),
        Err(error) => error_response(error),
    }
}

async fn scan_sarif(
    Path(scan_id): Path<Uuid>,
    State(state): State<AppState>,
) -> axum::response::Response {
    let Some(pool) = &state.db else {
        return error_response(anyhow::anyhow!("stored scan SARIF requires DATABASE_URL"));
    };
    match load_scan(pool, scan_id).await {
        Ok(Some(scan)) => match to_sarif(&scan.findings) {
            Ok(body) => (
                StatusCode::OK,
                [("content-type", "application/sarif+json")],
                body,
            )
                .into_response(),
            Err(error) => error_response(error),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "scan not found").into_response(),
        Err(error) => error_response(error),
    }
}

async fn scan_provenance_json(
    Path(scan_id): Path<Uuid>,
    State(state): State<AppState>,
) -> axum::response::Response {
    let Some(pool) = &state.db else {
        return error_response(anyhow::anyhow!(
            "stored scan provenance requires DATABASE_URL"
        ));
    };
    match load_scan(pool, scan_id).await {
        Ok(Some(scan)) => match scan.provenance {
            Some(provenance) => match serde_json::to_string_pretty(&provenance.report) {
                Ok(body) => {
                    (StatusCode::OK, [("content-type", "application/json")], body).into_response()
                }
                Err(error) => error_response(error.into()),
            },
            None => (StatusCode::NOT_FOUND, "provenance not found").into_response(),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "scan not found").into_response(),
        Err(error) => error_response(error),
    }
}

async fn scan_local(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LocalScanForm>,
) -> axum::response::Response {
    let actor = trusted_actor(&headers);
    let scan = match run_local_scan(&form.path) {
        Ok(scan) => scan,
        Err(error) => return error_response(error),
    };

    match form.format.as_deref() {
        Some("json") => {
            if let Err(error) = persist_scan_if_available(&state, &actor, &scan.report).await {
                return error_response(error);
            }
            match to_scan_json(ScanJsonInput {
                source: &scan.report.source_label,
                mode: Some("developer"),
                assets: &scan.report.assets,
                findings: &scan.report.findings,
                mcp_snapshots: &scan.report.mcp_snapshots,
                policy: &scan.report.policy,
                provenance: &scan.report.provenance,
                judge_panel: scan.report.judge_panel.as_ref(),
            }) {
                Ok(body) => {
                    (StatusCode::OK, [("content-type", "application/json")], body).into_response()
                }
                Err(error) => error_response(error),
            }
        }
        Some("sarif") => {
            if let Err(error) = persist_scan_if_available(&state, &actor, &scan.report).await {
                return error_response(error);
            }
            match to_sarif(&scan.report.findings) {
                Ok(body) => (
                    StatusCode::OK,
                    [("content-type", "application/sarif+json")],
                    body,
                )
                    .into_response(),
                Err(error) => error_response(error),
            }
        }
        _ => {
            match persist_scan_if_available(&state, &actor, &scan.report).await {
                Ok(Some(scan_id)) => {
                    if let Some(pool) = &state.db {
                        if let Ok(Some(scan)) = load_scan(pool, scan_id).await {
                            return Html(views::stored_scan(&scan).into_string()).into_response();
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => return error_response(error),
            }

            let summary =
                ScanSummary::from_findings(scan.report.assets.len(), &scan.report.findings);
            Html(
                views::scan_results(
                    &scan.report.source_label,
                    &summary,
                    &scan.report.assets,
                    &scan.report.findings,
                )
                .into_string(),
            )
            .into_response()
        }
    }
}

fn stored_scan_json(scan: &skill_issue_db::StoredScan) -> anyhow::Result<String> {
    let export = StoredScanJsonExport {
        id: scan.id,
        source: &scan.source_label,
        status: &scan.status,
        created_at: scan.created_at,
        completed_at: scan.completed_at,
        summary: ScanSummary::from_findings(scan.assets.len(), &scan.findings),
        assets: &scan.assets,
        findings: &scan.findings,
        mcp_snapshots: &scan.mcp_snapshots,
        policy: scan.policy_report(),
        drift_events: &scan.drift_events,
        provenance: scan
            .provenance
            .as_ref()
            .map(|provenance| &provenance.report),
    };
    Ok(serde_json::to_string_pretty(&export)?)
}

async fn enqueue_local_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LocalScanForm>,
) -> axum::response::Response {
    let Some(pool) = &state.db else {
        return error_response(anyhow::anyhow!("job queue requires DATABASE_URL"));
    };
    let actor = trusted_actor(&headers);
    let mut storage: PostgresStorage<ScanJob> = PostgresStorage::new(pool.clone());
    match storage
        .push(ScanJob::LocalScan {
            path: form.path.clone(),
            actor: actor.clone(),
        })
        .await
    {
        Ok(parts) => {
            let task_id = parts.task_id.to_string();
            let _ = insert_audit_event(
                pool,
                &actor,
                "job.local_scan.enqueued",
                "job",
                Some(task_id.clone()),
                serde_json::json!({ "path": form.path }),
            )
            .await;
            Html(views::queued_job(&task_id).into_string()).into_response()
        }
        Err(error) => error_response(anyhow::anyhow!(error)),
    }
}

async fn github_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    if let Ok(secret) = env::var("GITHUB_WEBHOOK_SECRET") {
        let Some(signature) = headers
            .get("x-hub-signature-256")
            .and_then(|value| value.to_str().ok())
        else {
            return (StatusCode::UNAUTHORIZED, "missing GitHub signature").into_response();
        };
        if let Err(error) = verify_github_signature(&secret, &body, signature) {
            return (StatusCode::UNAUTHORIZED, error.to_string()).into_response();
        }
    }

    let event = headers
        .get("x-github-event")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    let delivery = headers
        .get("x-github-delivery")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");

    if let Some(pool) = &state.db {
        if let Err(error) = insert_audit_event(
            pool,
            "github-webhook",
            "webhook.github.received",
            "github_delivery",
            Some(delivery.to_owned()),
            serde_json::json!({ "event": event, "body_bytes": body.len() }),
        )
        .await
        {
            return error_response(error);
        }
    }

    (StatusCode::ACCEPTED, "accepted").into_response()
}

fn run_local_scan(source: &str) -> anyhow::Result<ServerScanRun> {
    let target = prepare_scan_target(source)?;
    let mut options = ScanOptions::new(PolicyScanMode::Developer, env!("CARGO_PKG_VERSION"));
    options.source_label = Some(target.source_label);
    let scan = run_scan(&target.root, options)?;

    Ok(ServerScanRun {
        report: scan,
        temp_root: target.temp_root,
    })
}

fn prepare_scan_target(source: &str) -> anyhow::Result<PreparedScanTarget> {
    let source = source.trim();
    if source.is_empty() {
        bail!("scan source is required");
    }

    if let Some(repo) = parse_github_repo(source) {
        return clone_github_repo(repo);
    }

    if looks_like_url(source) {
        bail!("unsupported repository URL `{source}`. Public GitHub repository URLs such as `https://github.com/owner/repo` are supported.");
    }

    let root = PathBuf::from(source);
    if !root.exists() {
        bail!("scan path `{source}` was not found from the Skill Issue server runtime. When running in Docker Compose, host paths such as `C:\\...` are not visible inside the container; use `/workspace` for this project or `/scan-roots/<repo>` for repositories mounted through `SKILL_ISSUE_SCAN_ROOT`.");
    }
    if !root.is_dir() {
        bail!("scan path `{source}` is not a directory");
    }

    Ok(PreparedScanTarget {
        source_label: source.to_owned(),
        root,
        temp_root: None,
    })
}

fn parse_github_repo(source: &str) -> Option<GitHubRepoRef> {
    let source = source.trim().trim_end_matches('/');
    let path = source
        .strip_prefix("https://")
        .or_else(|| source.strip_prefix("http://"))
        .unwrap_or(source)
        .strip_prefix("www.")
        .unwrap_or_else(|| {
            source
                .strip_prefix("https://")
                .or_else(|| source.strip_prefix("http://"))
                .unwrap_or(source)
        });

    let path = if let Some(path) = path.strip_prefix("github.com/") {
        path
    } else if let Some(path) = source.strip_prefix("git@github.com:") {
        path
    } else {
        return None;
    };

    let mut parts = path.split(['/', '?', '#']).filter(|part| !part.is_empty());
    let owner = parts.next()?.to_owned();
    let repo = parts.next()?.trim_end_matches(".git").to_owned();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }

    let label = format!("https://github.com/{owner}/{repo}");
    Some(GitHubRepoRef {
        owner,
        repo,
        clone_url: format!("{label}.git"),
        label,
    })
}

fn clone_github_repo(repo: GitHubRepoRef) -> anyhow::Result<PreparedScanTarget> {
    let temp_root = env::temp_dir().join(format!("skill-issue-scan-{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_root)
        .with_context(|| format!("failed creating scan workspace {}", temp_root.display()))?;
    let checkout = temp_root.join(format!(
        "{}-{}",
        sanitize_path_segment(&repo.owner),
        sanitize_path_segment(&repo.repo)
    ));

    let output = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--single-branch")
        .arg(&repo.clone_url)
        .arg(&checkout)
        .output()
        .with_context(|| "failed to start `git clone`; install git in the Skill Issue runtime")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        let _ = fs::remove_dir_all(&temp_root);
        bail!("failed cloning {}: {}", repo.label, detail);
    }

    Ok(PreparedScanTarget {
        source_label: repo.label,
        root: checkout,
        temp_root: Some(temp_root),
    })
}

fn sanitize_path_segment(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn looks_like_url(source: &str) -> bool {
    source.contains("://") || source.starts_with("git@")
}

async fn persist_scan_if_available(
    state: &AppState,
    actor: &str,
    scan: &ScanRun,
) -> anyhow::Result<Option<Uuid>> {
    let Some(pool) = &state.db else {
        return Ok(None);
    };
    let scan_id = store_local_scan(
        pool,
        LocalScanRecord {
            actor,
            source_label: &scan.source_label,
            assets: &scan.assets,
            findings: &scan.findings,
            mcp_snapshots: &scan.mcp_snapshots,
            policy_report: &scan.policy,
            provenance: &scan.provenance,
        },
    )
    .await?;
    Ok(Some(scan_id))
}

fn trusted_actor(headers: &HeaderMap) -> String {
    for header in [
        "x-skill-issue-actor",
        "x-auth-request-user",
        "x-forwarded-user",
    ] {
        if let Some(value) = headers.get(header).and_then(|value| value.to_str().ok()) {
            if !value.trim().is_empty() {
                return value.trim().to_owned();
            }
        }
    }
    "unknown".to_owned()
}

fn error_response(error: anyhow::Error) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Html(views::error_panel(&format!("{error:#}")).into_string()),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_public_github_urls() {
        let repo = parse_github_repo("https://github.com/octocat/Hello-World").unwrap();
        assert_eq!(repo.owner, "octocat");
        assert_eq!(repo.repo, "Hello-World");
        assert_eq!(repo.clone_url, "https://github.com/octocat/Hello-World.git");
    }

    #[test]
    fn parses_github_tree_urls_as_repo_root() {
        let repo = parse_github_repo("https://github.com/owner/repo/tree/main/path").unwrap();
        assert_eq!(repo.label, "https://github.com/owner/repo");
        assert_eq!(repo.clone_url, "https://github.com/owner/repo.git");
    }
}
