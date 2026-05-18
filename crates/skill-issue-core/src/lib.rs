use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    AgentConfig,
    McpConfig,
    Script,
    Workflow,
    GitHook,
    DependencyManifest,
    ContainerDefinition,
    BuildFile,
    Unknown,
}

impl fmt::Display for AssetKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::AgentConfig => "agent_config",
            Self::McpConfig => "mcp_config",
            Self::Script => "script",
            Self::Workflow => "workflow",
            Self::GitHook => "git_hook",
            Self::DependencyManifest => "dependency_manifest",
            Self::ContainerDefinition => "container_definition",
            Self::BuildFile => "build_file",
            Self::Unknown => "unknown",
        };
        formatter.write_str(label)
    }
}

impl FromStr for AssetKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agent_config" => Ok(Self::AgentConfig),
            "mcp_config" => Ok(Self::McpConfig),
            "script" => Ok(Self::Script),
            "workflow" => Ok(Self::Workflow),
            "git_hook" => Ok(Self::GitHook),
            "dependency_manifest" => Ok(Self::DependencyManifest),
            "container_definition" => Ok(Self::ContainerDefinition),
            "build_file" => Ok(Self::BuildFile),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!("unknown asset kind `{other}`")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub path: String,
    pub kind: AssetKind,
    pub fingerprint: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        formatter.write_str(label)
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub asset_path: String,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl Finding {
    pub fn new(
        asset_path: impl Into<String>,
        rule_id: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        evidence: impl Into<String>,
        tags: Vec<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            asset_path: asset_path.into(),
            rule_id: rule_id.into(),
            severity,
            title: title.into(),
            description: description.into(),
            evidence: evidence.into(),
            tags,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scanned_at: DateTime<Utc>,
    pub asset_count: usize,
    pub finding_count: usize,
    pub highest_severity: Option<Severity>,
}

impl ScanSummary {
    pub fn from_findings(asset_count: usize, findings: &[Finding]) -> Self {
        Self {
            scanned_at: Utc::now(),
            asset_count,
            finding_count: findings.len(),
            highest_severity: findings.iter().map(|finding| finding.severity).max(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanJob {
    LocalScan { path: String, actor: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerSnapshot {
    pub asset_path: String,
    pub server_name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env_keys: Vec<String>,
    pub command_hash: String,
    pub tool_schema_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpDriftEvent {
    pub id: Uuid,
    pub asset_path: String,
    pub server_name: String,
    pub drift_kind: String,
    pub previous_hash: String,
    pub current_hash: String,
    pub description: String,
}
