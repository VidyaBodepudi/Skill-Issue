use anyhow::Result;
use skill_issue_analyzers::analyze_assets;
use skill_issue_core::{Asset, Finding, McpServerSnapshot};
use skill_issue_inventory::{collect_mcp_snapshots, discover_path};
use skill_issue_judges::{
    evaluate_deterministic_preview_panel, load_model_pack, JudgePanelReport, JudgeSnippet,
};
use skill_issue_policy::{
    evaluate_builtin_policy_with_provenance, PolicyReport, PolicyScanMode, BUILTIN_POLICY_VERSION,
};
use skill_issue_provenance::{
    build_provenance_report, ProvenanceReport, DEFAULT_MODEL_PACK_VERSION,
};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum JudgeMode {
    Disabled,
    DeterministicPreview { model_pack_path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub source_label: Option<String>,
    pub policy_mode: PolicyScanMode,
    pub judge_mode: JudgeMode,
    pub scanner_version: String,
    pub model_pack_version: String,
}

impl ScanOptions {
    pub fn new(policy_mode: PolicyScanMode, scanner_version: impl Into<String>) -> Self {
        Self {
            source_label: None,
            policy_mode,
            judge_mode: JudgeMode::Disabled,
            scanner_version: scanner_version.into(),
            model_pack_version: DEFAULT_MODEL_PACK_VERSION.to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct ScanRun {
    pub source_label: String,
    pub assets: Vec<Asset>,
    pub findings: Vec<Finding>,
    pub mcp_snapshots: Vec<McpServerSnapshot>,
    pub policy: PolicyReport,
    pub provenance: ProvenanceReport,
    pub judge_panel: Option<JudgePanelReport>,
}

pub fn run_scan(root: impl AsRef<Path>, options: ScanOptions) -> Result<ScanRun> {
    let root = root.as_ref();
    let source_label = options
        .source_label
        .unwrap_or_else(|| default_source_label(root));
    let assets = discover_path(root)?;
    let findings = analyze_assets(root, &assets)?;
    let mcp_snapshots = collect_mcp_snapshots(root, &assets)?;
    let provenance = build_provenance_report(
        root,
        &assets,
        &mcp_snapshots,
        options.scanner_version,
        BUILTIN_POLICY_VERSION,
        options.model_pack_version,
    );
    let policy = evaluate_builtin_policy_with_provenance(
        &assets,
        &findings,
        &mcp_snapshots,
        Some(&provenance),
        options.policy_mode,
    );
    let judge_panel = match options.judge_mode {
        JudgeMode::Disabled => None,
        JudgeMode::DeterministicPreview { model_pack_path } => {
            let pack = load_model_pack(model_pack_path)?;
            let snippets = build_judge_snippets(root, &assets, &findings)?;
            Some(evaluate_deterministic_preview_panel(&pack, &snippets))
        }
    };

    Ok(ScanRun {
        source_label,
        assets,
        findings,
        mcp_snapshots,
        policy,
        provenance,
        judge_panel,
    })
}

fn build_judge_snippets(
    root: &Path,
    assets: &[Asset],
    findings: &[Finding],
) -> Result<Vec<JudgeSnippet>> {
    let mut snippets = Vec::new();

    for asset in assets {
        let path = root.join(&asset.path);
        let text = fs::read_to_string(&path).unwrap_or_default();
        snippets.push(JudgeSnippet {
            id: format!("asset:{}", asset.path),
            asset_path: Some(asset.path.clone()),
            text: truncate_for_judges(&text),
            tags: vec![asset.kind.to_string()],
        });
    }

    for finding in findings {
        snippets.push(JudgeSnippet {
            id: format!("finding:{}", finding.id),
            asset_path: Some(finding.asset_path.clone()),
            text: truncate_for_judges(&format!(
                "{}\n{}\n{}\ntags={}",
                finding.title,
                finding.description,
                finding.evidence,
                finding.tags.join(",")
            )),
            tags: finding.tags.clone(),
        });
    }

    Ok(snippets)
}

fn truncate_for_judges(text: &str) -> String {
    const MAX_CHARS: usize = 4096;
    if text.len() <= MAX_CHARS {
        return text.to_owned();
    }
    text.chars().take(MAX_CHARS).collect()
}

fn default_source_label(root: &Path) -> String {
    root.canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judge_text_is_truncated_for_runtime() {
        let text = "a".repeat(5000);
        assert_eq!(truncate_for_judges(&text).len(), 4096);
    }
}
