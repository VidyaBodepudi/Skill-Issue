use maud::{html, Markup, DOCTYPE};
use skill_issue_core::{Asset, Finding, ScanSummary, Severity};
use skill_issue_db::{StoredProvenance, StoredScan, StoredScanOverview};
use skill_issue_policy::PolicyAction;

pub fn layout(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                style { (styles()) }
            }
            body {
                header class="topbar" {
                    div class="brand" { "Skill Issue" }
                    nav { a href="/scans" { "Scans" } a href="/healthz" { "Health" } }
                }
                main class="shell" { (body) }
            }
        }
    }
}

pub fn dashboard(database_connected: bool, recent_scans: &[StoredScanOverview]) -> Markup {
    html! {
        section class="panel" {
            div class="panel-heading" {
                h1 { "Agent Asset Governance" }
                span class=(if database_connected { "pill ok" } else { "pill warn" }) {
                    @if database_connected { "Postgres connected" } @else { "Ephemeral mode" }
                }
            }
            p class="muted" { "Scan a mounted repository path or public GitHub URL. Docker Compose exposes this workspace at /workspace and the configured scan root at /scan-roots." }
            form method="post" action="/scans/local" class="scan-form" {
                label for="path" { "Repository source" }
                input id="path" name="path" value="/workspace" placeholder="/scan-roots/repo or https://github.com/owner/repo";
                div class="actions" {
                    button type="submit" name="format" value="html" { "Scan" }
                    button type="submit" formaction="/jobs/local" { "Queue" }
                    button type="submit" name="format" value="json" { "JSON" }
                    button type="submit" name="format" value="sarif" { "SARIF" }
                }
            }
        }
        @if database_connected {
            section class="panel" {
                div class="panel-heading" {
                    h2 { "Recent scans" }
                    a href="/scans" { "View all" }
                }
                (scan_table(recent_scans))
            }
        }
    }
}

pub fn scan_history(scans: &[StoredScanOverview]) -> Markup {
    html! {
        section class="panel" {
            div class="panel-heading" {
                h1 { "Scan History" }
                a href="/" { "New scan" }
            }
            (scan_table(scans))
        }
    }
}

pub fn stored_scan(scan: &StoredScan) -> Markup {
    let summary = ScanSummary::from_findings(scan.assets.len(), &scan.findings);
    layout(
        "Scan Results",
        html! {
            section class="panel" {
                div class="panel-heading" {
                    h1 { "Scan Results" }
                    span class="pill" { (&scan.source_label) }
                }
                div class="stats" {
                    (stat("Assets", &summary.asset_count.to_string()))
                    (stat("Findings", &summary.finding_count.to_string()))
                    (stat("Highest", summary.highest_severity.map(|severity| severity.to_string()).as_deref().unwrap_or("none")))
                    (stat("Risk", scan.risk_score.map(|score| score.to_string()).as_deref().unwrap_or("none")))
                    (stat("Provenance", scan.provenance.as_ref().map(|provenance| provenance.score.to_string()).as_deref().unwrap_or("none")))
                    (stat("Policy", scan.policy_decisions.first().map(|decision| decision.action.to_string()).as_deref().unwrap_or("allow")))
                }
                div class="meta-row" {
                    span { "Scan " code { (scan.id.to_string()) } }
                    span { "Status " strong { (&scan.status) } }
                    @if let Some(policy_version) = &scan.policy_version {
                        span { "Policy " code { (policy_version) } }
                    }
                    span { "Created " time { (scan.created_at.to_rfc3339()) } }
                    @if let Some(completed_at) = scan.completed_at {
                        span { "Completed " time { (completed_at.to_rfc3339()) } }
                    }
                }
                div class="actions export-actions" {
                    a class="button-link" href=(format!("/scans/{}/json", scan.id)) { "JSON" }
                    @if scan.provenance.is_some() {
                        a class="button-link" href=(format!("/scans/{}/provenance", scan.id)) { "Provenance" }
                    }
                    a class="button-link" href=(format!("/scans/{}/sarif", scan.id)) { "SARIF" }
                }
            }
            @if let Some(provenance) = &scan.provenance {
                (provenance_panel(provenance))
            }
            @if !scan.policy_decisions.is_empty() {
                section class="panel" {
                    h2 { "Policy decisions" }
                    table {
                        thead { tr { th { "Action" } th { "Policy" } th { "Subject" } th { "Decision" } } }
                        tbody {
                            @for decision in &scan.policy_decisions {
                                tr {
                                    td { span class=(policy_class(decision.action)) { (decision.action.to_string()) } }
                                    td code { (&decision.policy_id) }
                                    td {
                                        code { (&decision.subject_key) }
                                        @if let Some(asset_path) = &decision.asset_path {
                                            p class="muted" { (asset_path) }
                                        }
                                    }
                                    td {
                                        strong { (&decision.title) }
                                        p class="muted" { (&decision.description) }
                                        @if !decision.evidence.is_empty() {
                                            code class="evidence" { (&decision.evidence) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if !scan.drift_events.is_empty() {
                section class="panel" {
                    h2 { "MCP drift" }
                    table {
                        thead { tr { th { "Server" } th { "Asset" } th { "Change" } th { "Hash" } } }
                        tbody {
                            @for event in &scan.drift_events {
                                tr {
                                    td code { (&event.server_name) }
                                    td code { (&event.asset_path) }
                                    td {
                                        strong { (&event.drift_kind) }
                                        p class="muted" { (&event.description) }
                                    }
                                    td code { (&event.current_hash[..12.min(event.current_hash.len())]) }
                                }
                            }
                        }
                    }
                }
            }
            (scan_body(&scan.assets, &scan.findings))
        },
    )
}

pub fn queued_job(task_id: &str) -> Markup {
    layout(
        "Queued Scan",
        html! {
            section class="panel" {
                div class="panel-heading" {
                    h1 { "Scan queued" }
                    span class="pill ok" { "apalis" }
                }
                p class="muted" { "The job was written to the PostgreSQL-backed queue." }
                p { "Task " code { (task_id) } }
                a href="/" { "Back" }
            }
        },
    )
}

pub fn scan_results(
    path: &str,
    summary: &ScanSummary,
    assets: &[Asset],
    findings: &[Finding],
) -> Markup {
    layout(
        "Scan Results",
        html! {
            section class="panel" {
                div class="panel-heading" {
                    h1 { "Scan Results" }
                    span class="pill" { (path) }
                }
                div class="stats" {
                    (stat("Assets", &summary.asset_count.to_string()))
                    (stat("Findings", &summary.finding_count.to_string()))
                    (stat("Highest", summary.highest_severity.map(|severity| severity.to_string()).as_deref().unwrap_or("none")))
                }
            }
            (scan_body(assets, findings))
        },
    )
}

fn scan_table(scans: &[StoredScanOverview]) -> Markup {
    html! {
        @if scans.is_empty() {
            p class="muted" { "No persisted scans yet." }
        } @else {
            table {
                thead { tr { th { "Source" } th { "Status" } th { "Policy" } th { "Risk" } th { "Provenance" } th { "Assets" } th { "Findings" } th { "Created" } } }
                tbody {
                    @for scan in scans {
                        tr {
                            td { a href=(format!("/scans/{}", scan.id)) { (&scan.source_label) } }
                            td { (&scan.status) }
                            td {
                                @if let Some(action) = scan.highest_policy_action {
                                    span class=(policy_class(action)) { (action.to_string()) }
                                } @else {
                                    span class="policy allow" { "allow" }
                                }
                            }
                            td { (scan.risk_score.map(|score| score.to_string()).unwrap_or_else(|| "-".to_owned())) }
                            td { (scan.provenance_score.map(|score| score.to_string()).unwrap_or_else(|| "-".to_owned())) }
                            td { (scan.asset_count) }
                            td { (scan.finding_count) }
                            td { time { (scan.created_at.to_rfc3339()) } }
                        }
                    }
                }
            }
        }
    }
}

fn provenance_panel(provenance: &StoredProvenance) -> Markup {
    let checks = provenance
        .report
        .get("score")
        .and_then(|score| score.get("checks"))
        .and_then(serde_json::Value::as_array);

    html! {
        section class="panel" {
            div class="panel-heading" {
                h2 { "Provenance" }
                span class=(provenance_score_class(provenance.score)) { (provenance.score) }
            }
            div class="stats" {
                (stat("Approval", if provenance.production_approval { "candidate" } else { "blocked" }))
                (stat("Source", provenance.source_ref.as_deref().unwrap_or("unknown")))
                (stat("Commit", provenance.source_commit.as_deref().map(short_value).unwrap_or("unknown")))
                (stat("State", if provenance.source_dirty { "dirty" } else { "clean" }))
            }
            div class="meta-row" {
                span { "Schema " code { (&provenance.schema_version) } }
                @if let Some(source_url) = &provenance.source_url {
                    span { "Remote " code { (source_url) } }
                }
                span { "Content " code { (short_value(&provenance.content_hash)) } }
                @if let Some(lockfile_hash) = &provenance.lockfile_hash {
                    span { "Lockfiles " code { (short_value(lockfile_hash)) } }
                }
            }
            @if let Some(checks) = checks {
                table class="evidence-table" {
                    thead { tr { th { "Check" } th { "Status" } th { "Points" } th { "Evidence" } } }
                    tbody {
                        @for check in checks {
                            @let id = check.get("id").and_then(serde_json::Value::as_str).unwrap_or("unknown");
                            @let passed = check.get("passed").and_then(serde_json::Value::as_bool).unwrap_or(false);
                            @let status = check.get("status").and_then(serde_json::Value::as_str).unwrap_or(if passed { "passed" } else { "failed" });
                            @let points = check.get("points").and_then(serde_json::Value::as_u64).unwrap_or(0);
                            @let max_points = check.get("max_points").and_then(serde_json::Value::as_u64).unwrap_or(0);
                            @let message = check.get("message").and_then(serde_json::Value::as_str).unwrap_or("");
                            tr {
                                td code { (id) }
                                td { span class=(evidence_status_class(status, passed)) { (status.replace('_', " ")) } }
                                td { (format!("{points}/{max_points}")) }
                                td { (message) }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn scan_body(assets: &[Asset], findings: &[Finding]) -> Markup {
    html! {
        section class="grid" {
            div class="panel" {
                h2 { "Findings" }
                @if findings.is_empty() {
                    p class="muted" { "No findings from the starter rules." }
                } @else {
                    table {
                        thead { tr { th { "Severity" } th { "Rule" } th { "Asset" } th { "Finding" } } }
                        tbody {
                            @for finding in findings {
                                tr {
                                    td { span class=(severity_class(finding.severity)) { (finding.severity.to_string()) } }
                                    td code { (&finding.rule_id) }
                                    td code { (&finding.asset_path) }
                                    td {
                                        strong { (&finding.title) }
                                        p class="muted" { (&finding.description) }
                                        code class="evidence" { (&finding.evidence) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div class="panel" {
                h2 { "Inventory" }
                table {
                    thead { tr { th { "Kind" } th { "Path" } th { "Fingerprint" } } }
                    tbody {
                        @for asset in assets {
                            tr {
                                td { (asset.kind.to_string()) }
                                td code { (&asset.path) }
                                td code { (&asset.fingerprint[..12.min(asset.fingerprint.len())]) }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn error_panel(message: &str) -> Markup {
    layout(
        "Scan Error",
        html! {
            section class="panel error" {
                h1 { "Scan failed" }
                pre { (message) }
                a href="/" { "Back" }
            }
        },
    )
}

fn stat(label: &str, value: &str) -> Markup {
    html! {
        div class="stat" { span { (label) } strong { (value) } }
    }
}

fn severity_class(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "severity critical",
        Severity::High => "severity high",
        Severity::Medium => "severity medium",
        Severity::Low => "severity low",
        Severity::Info => "severity info",
    }
}

fn policy_class(action: PolicyAction) -> &'static str {
    match action {
        PolicyAction::Block => "policy block",
        PolicyAction::Review => "policy review",
        PolicyAction::Warn => "policy warn",
        PolicyAction::Allow => "policy allow",
    }
}

fn provenance_score_class(score: i32) -> &'static str {
    if score >= 80 {
        "provenance-score strong"
    } else if score >= 55 {
        "provenance-score review"
    } else {
        "provenance-score weak"
    }
}

fn evidence_status_class(status: &str, passed: bool) -> &'static str {
    match status {
        "passed" | "not_applicable" => "policy allow",
        "failed" if !passed => "policy block",
        _ => "policy warn",
    }
}

fn short_value(value: &str) -> &str {
    value.get(0..12).unwrap_or(value)
}

fn styles() -> &'static str {
    r#"
        :root { color-scheme: light; --bg: #f6f7f9; --panel: #ffffff; --text: #1b1f24; --muted: #667085; --line: #d8dee6; --accent: #0f766e; --danger: #b42318; --warn: #b54708; }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }
        .topbar { height: 56px; display: flex; align-items: center; justify-content: space-between; padding: 0 24px; background: #111827; color: #fff; }
        .brand { font-weight: 700; }
        .topbar nav { display: flex; gap: 14px; }
        .topbar a { color: #d1fae5; text-decoration: none; }
        .shell { max-width: 1180px; margin: 24px auto; padding: 0 16px; }
        .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
        .panel-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
        h1, h2 { margin: 0 0 12px; line-height: 1.2; }
        h1 { font-size: 26px; }
        h2 { font-size: 18px; }
        .muted { color: var(--muted); margin: 6px 0; }
        .pill { display: inline-flex; align-items: center; border: 1px solid var(--line); border-radius: 999px; padding: 4px 10px; color: var(--muted); font-size: 13px; }
        .pill.ok { color: #047857; border-color: #a7f3d0; background: #ecfdf5; }
        .pill.warn { color: #92400e; border-color: #fde68a; background: #fffbeb; }
        .scan-form { display: grid; gap: 10px; max-width: 640px; margin-top: 16px; }
        input { height: 40px; border: 1px solid var(--line); border-radius: 6px; padding: 0 12px; font: inherit; }
        button, .button-link { border: 0; border-radius: 6px; background: var(--accent); color: #fff; min-height: 38px; padding: 8px 14px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; }
        .actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .export-actions { margin-top: 14px; }
        .meta-row { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 14px; color: var(--muted); font-size: 13px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
        .stat { border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
        .stat span { display: block; color: var(--muted); font-size: 13px; }
        .stat strong { display: block; font-size: 22px; margin-top: 4px; }
        .grid { display: grid; grid-template-columns: 1.4fr 1fr; gap: 16px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }
        code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
        .evidence { display: block; margin-top: 8px; color: #475467; }
        .severity { display: inline-flex; border-radius: 999px; padding: 3px 8px; font-size: 12px; font-weight: 700; }
        .policy { display: inline-flex; border-radius: 999px; padding: 3px 8px; font-size: 12px; font-weight: 700; }
        .provenance-score { display: inline-flex; border-radius: 999px; padding: 4px 10px; font-size: 13px; font-weight: 800; }
        .provenance-score.strong { color: #047857; background: #ecfdf5; border: 1px solid #a7f3d0; }
        .provenance-score.review { color: #92400e; background: #fffbeb; border: 1px solid #fde68a; }
        .provenance-score.weak { color: #fff; background: var(--danger); }
        .evidence-table { margin-top: 14px; }
        .critical, .high { color: #fff; background: var(--danger); }
        .medium { color: #fff; background: var(--warn); }
        .low, .info { color: #344054; background: #eaecf0; }
        .block { color: #fff; background: var(--danger); }
        .review { color: #fff; background: var(--warn); }
        .warn { color: #92400e; background: #fffbeb; border: 1px solid #fde68a; }
        .allow { color: #047857; background: #ecfdf5; border: 1px solid #a7f3d0; }
        .error { border-color: #fda29b; }
        pre { white-space: pre-wrap; }
        @media (max-width: 820px) { .grid, .stats { grid-template-columns: 1fr; } .panel-heading { align-items: flex-start; flex-direction: column; } }
    "#
}
