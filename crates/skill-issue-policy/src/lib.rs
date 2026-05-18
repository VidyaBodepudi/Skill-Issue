use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use skill_issue_core::{Asset, AssetKind, Finding, McpServerSnapshot, Severity};
use skill_issue_provenance::ProvenanceReport;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

pub const BUILTIN_POLICY_VERSION: &str = "builtin/0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Warn,
    Review,
    Block,
}

impl fmt::Display for PolicyAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Review => "review",
            Self::Block => "block",
        };
        formatter.write_str(label)
    }
}

impl FromStr for PolicyAction {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "allow" => Ok(Self::Allow),
            "warn" => Ok(Self::Warn),
            "review" => Ok(Self::Review),
            "block" => Ok(Self::Block),
            other => Err(format!("unknown policy action `{other}`")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyScanMode {
    Developer,
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub id: Uuid,
    pub policy_id: String,
    pub action: PolicyAction,
    pub title: String,
    pub description: String,
    pub subject_type: String,
    pub subject_key: String,
    pub finding_id: Option<Uuid>,
    pub asset_path: Option<String>,
    pub evidence: String,
    pub created_at: DateTime<Utc>,
}

impl PolicyDecision {
    fn finding(
        finding: &Finding,
        policy_id: &str,
        action: PolicyAction,
        title: &str,
        description: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            policy_id: policy_id.to_owned(),
            action,
            title: title.to_owned(),
            description: description.to_owned(),
            subject_type: "finding".to_owned(),
            subject_key: finding.rule_id.clone(),
            finding_id: Some(finding.id),
            asset_path: Some(finding.asset_path.clone()),
            evidence: finding.evidence.clone(),
            created_at: Utc::now(),
        }
    }

    fn asset(
        asset: &Asset,
        policy_id: &str,
        action: PolicyAction,
        title: &str,
        description: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            policy_id: policy_id.to_owned(),
            action,
            title: title.to_owned(),
            description: description.to_owned(),
            subject_type: "asset".to_owned(),
            subject_key: asset.kind.to_string(),
            finding_id: None,
            asset_path: Some(asset.path.clone()),
            evidence: asset.path.clone(),
            created_at: Utc::now(),
        }
    }

    fn mcp_snapshot(
        snapshot: &McpServerSnapshot,
        policy_id: &str,
        action: PolicyAction,
        title: &str,
        description: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            policy_id: policy_id.to_owned(),
            action,
            title: title.to_owned(),
            description: description.to_owned(),
            subject_type: "mcp_server".to_owned(),
            subject_key: snapshot.server_name.clone(),
            finding_id: None,
            asset_path: Some(snapshot.asset_path.clone()),
            evidence: format!("env_keys={}", snapshot.env_keys.join(",")),
            created_at: Utc::now(),
        }
    }

    fn provenance(
        policy_id: &str,
        action: PolicyAction,
        title: &str,
        description: &str,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            policy_id: policy_id.to_owned(),
            action,
            title: title.to_owned(),
            description: description.to_owned(),
            subject_type: "provenance".to_owned(),
            subject_key: "production_approval".to_owned(),
            finding_id: None,
            asset_path: None,
            evidence: evidence.into(),
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReport {
    pub policy_version: String,
    pub highest_action: PolicyAction,
    pub risk_score: u8,
    pub decisions: Vec<PolicyDecision>,
}

pub fn evaluate_builtin_policy(
    assets: &[Asset],
    findings: &[Finding],
    mcp_snapshots: &[McpServerSnapshot],
) -> PolicyReport {
    let mut decisions = Vec::new();

    for finding in findings {
        if matches!(
            finding.rule_id.as_str(),
            "SI-REMOTE-EXEC" | "SI-MCP-RUNTIME-DOWNLOAD"
        ) || finding
            .tags
            .iter()
            .any(|tag| tag == "remote_execution" || tag == "runtime_resolution")
        {
            decisions.push(PolicyDecision::finding(
                finding,
                "builtin.block-runtime-code-fetch",
                PolicyAction::Block,
                "Runtime-fetched execution is blocked",
                "Remote code fetched at scan or tool startup time must be pinned, reviewed, and backed by provenance before approval.",
            ));
            continue;
        }

        if finding.rule_id == "SI-SECRET-ADJACENT"
            || finding.tags.iter().any(|tag| tag == "credential_access")
        {
            decisions.push(PolicyDecision::finding(
                finding,
                "builtin.review-credential-adjacent-access",
                PolicyAction::Review,
                "Credential-adjacent behavior requires review",
                "Agent assets that read environment variables, credential files, or private key paths need owner approval and scope justification.",
            ));
            continue;
        }

        if matches!(
            finding.rule_id.as_str(),
            "SI-DYNAMIC-EXECUTION" | "SI-DESTRUCTIVE-FS"
        ) {
            decisions.push(PolicyDecision::finding(
                finding,
                "builtin.review-dynamic-or-destructive-execution",
                PolicyAction::Review,
                "Dynamic or destructive execution requires review",
                "Execution sinks and broad destructive filesystem operations need explicit path constraints and reviewer approval.",
            ));
            continue;
        }

        if finding.rule_id == "SI-MCP-INVALID-JSON" {
            decisions.push(PolicyDecision::finding(
                finding,
                "builtin.review-unparseable-agent-config",
                PolicyAction::Review,
                "Unparseable agent configuration requires review",
                "Invalid MCP JSON prevents reliable inventory, drift tracking, and policy evaluation.",
            ));
            continue;
        }

        if finding.severity >= Severity::High {
            decisions.push(PolicyDecision::finding(
                finding,
                "builtin.review-high-severity-findings",
                PolicyAction::Review,
                "High severity finding requires review",
                "High severity scanner findings need a reviewer decision before the asset is approved for production use.",
            ));
        }
    }

    for asset in assets
        .iter()
        .filter(|asset| asset.kind == AssetKind::GitHook)
    {
        decisions.push(PolicyDecision::asset(
            asset,
            "builtin.review-git-hooks",
            PolicyAction::Review,
            "Git hook requires review",
            "Git hooks are hidden local execution surfaces and should be approved by repository owners before use.",
        ));
    }

    for snapshot in mcp_snapshots
        .iter()
        .filter(|snapshot| !snapshot.env_keys.is_empty())
    {
        decisions.push(PolicyDecision::mcp_snapshot(
            snapshot,
            "builtin.review-mcp-environment-access",
            PolicyAction::Review,
            "MCP environment access requires review",
            "MCP servers that receive environment variables may gain credential access and should have explicit owner approval.",
        ));
    }

    build_policy_report(findings, decisions)
}

pub fn evaluate_builtin_policy_with_provenance(
    assets: &[Asset],
    findings: &[Finding],
    mcp_snapshots: &[McpServerSnapshot],
    provenance: Option<&ProvenanceReport>,
    mode: PolicyScanMode,
) -> PolicyReport {
    let mut report = evaluate_builtin_policy(assets, findings, mcp_snapshots);
    add_provenance_decision(&mut report.decisions, provenance, mode);
    build_policy_report(findings, report.decisions)
}

fn add_provenance_decision(
    decisions: &mut Vec<PolicyDecision>,
    provenance: Option<&ProvenanceReport>,
    mode: PolicyScanMode,
) {
    match (mode, provenance) {
        (PolicyScanMode::Developer, Some(provenance))
            if !provenance.approval.production_approval =>
        {
            decisions.push(PolicyDecision::provenance(
                "builtin.warn-developer-scan-not-production-approved",
                PolicyAction::Warn,
                "Developer scan is not production approval",
                "This scan is useful for local feedback, but its provenance does not meet the clean Git evidence bar required for production approval.",
                provenance
                    .approval
                    .reason
                    .clone()
                    .unwrap_or_else(|| "production approval unavailable".to_owned()),
            ));
        }
        (PolicyScanMode::Production, Some(provenance))
            if !provenance.approval.production_approval =>
        {
            decisions.push(PolicyDecision::provenance(
                "builtin.block-nonproduction-provenance",
                PolicyAction::Block,
                "Production scan requires clean provenance",
                "Production approval scans require Git metadata, a resolvable HEAD commit, and a clean working tree.",
                provenance
                    .approval
                    .reason
                    .clone()
                    .unwrap_or_else(|| "production approval unavailable".to_owned()),
            ));
        }
        (PolicyScanMode::Production, None) => {
            decisions.push(PolicyDecision::provenance(
                "builtin.block-missing-provenance",
                PolicyAction::Block,
                "Production scan requires provenance",
                "Production approval scans require a provenance report with source, scanner, policy, model-pack, asset, lockfile, and MCP command evidence.",
                "provenance report missing",
            ));
        }
        _ => {}
    }
}

fn build_policy_report(findings: &[Finding], mut decisions: Vec<PolicyDecision>) -> PolicyReport {
    decisions.sort_by(|left, right| {
        right
            .action
            .cmp(&left.action)
            .then(left.policy_id.cmp(&right.policy_id))
            .then(left.subject_key.cmp(&right.subject_key))
    });
    let highest_action = decisions
        .iter()
        .map(|decision| decision.action)
        .max()
        .unwrap_or(PolicyAction::Allow);
    let risk_score = score_risk(findings, &decisions);

    PolicyReport {
        policy_version: BUILTIN_POLICY_VERSION.to_owned(),
        highest_action,
        risk_score,
        decisions,
    }
}

fn score_risk(findings: &[Finding], decisions: &[PolicyDecision]) -> u8 {
    let finding_score: u16 = findings
        .iter()
        .map(|finding| match finding.severity {
            Severity::Info => 2,
            Severity::Low => 5,
            Severity::Medium => 12,
            Severity::High => 25,
            Severity::Critical => 40,
        })
        .sum();
    let policy_score: u16 = decisions
        .iter()
        .map(|decision| match decision.action {
            PolicyAction::Allow => 0,
            PolicyAction::Warn => 5,
            PolicyAction::Review => 15,
            PolicyAction::Block => 35,
        })
        .sum();

    finding_score.saturating_add(policy_score).min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_runtime_download_findings() {
        let finding = Finding::new(
            "mcp.json",
            "SI-MCP-RUNTIME-DOWNLOAD",
            Severity::High,
            "runtime download",
            "downloads code at runtime",
            "npx package",
            vec!["mcp".into(), "runtime_resolution".into()],
        );

        let report = evaluate_builtin_policy(&[], &[finding], &[]);

        assert_eq!(report.highest_action, PolicyAction::Block);
        assert_eq!(report.decisions.len(), 1);
        assert_eq!(
            report.decisions[0].policy_id,
            "builtin.block-runtime-code-fetch"
        );
        assert!(report.risk_score >= 50);
    }

    #[test]
    fn reviews_mcp_environment_access() {
        let snapshot = McpServerSnapshot {
            asset_path: "mcp.json".into(),
            server_name: "internal".into(),
            command: Some("server".into()),
            args: vec![],
            env_keys: vec!["API_TOKEN".into()],
            command_hash: "abc".into(),
            tool_schema_hash: None,
        };

        let report = evaluate_builtin_policy(&[], &[], &[snapshot]);

        assert_eq!(report.highest_action, PolicyAction::Review);
        assert_eq!(
            report.decisions[0].policy_id,
            "builtin.review-mcp-environment-access"
        );
    }

    #[test]
    fn warns_when_developer_scan_lacks_production_provenance() {
        let provenance = skill_issue_provenance::build_provenance_report(
            std::env::temp_dir(),
            &[],
            &[],
            "0.1.0",
            BUILTIN_POLICY_VERSION,
            skill_issue_provenance::DEFAULT_MODEL_PACK_VERSION,
        );

        let report = evaluate_builtin_policy_with_provenance(
            &[],
            &[],
            &[],
            Some(&provenance),
            PolicyScanMode::Developer,
        );

        assert_eq!(report.highest_action, PolicyAction::Warn);
        assert_eq!(
            report.decisions[0].policy_id,
            "builtin.warn-developer-scan-not-production-approved"
        );
    }

    #[test]
    fn blocks_when_production_scan_lacks_clean_provenance() {
        let provenance = skill_issue_provenance::build_provenance_report(
            std::env::temp_dir(),
            &[],
            &[],
            "0.1.0",
            BUILTIN_POLICY_VERSION,
            skill_issue_provenance::DEFAULT_MODEL_PACK_VERSION,
        );

        let report = evaluate_builtin_policy_with_provenance(
            &[],
            &[],
            &[],
            Some(&provenance),
            PolicyScanMode::Production,
        );

        assert_eq!(report.highest_action, PolicyAction::Block);
        assert_eq!(
            report.decisions[0].policy_id,
            "builtin.block-nonproduction-provenance"
        );
    }
}
