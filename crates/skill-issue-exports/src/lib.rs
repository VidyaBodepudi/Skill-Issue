use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use skill_issue_core::{Asset, Finding, McpServerSnapshot, ScanSummary};
use skill_issue_judges::JudgePanelReport;
use skill_issue_policy::PolicyReport;
use skill_issue_provenance::ProvenanceReport;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct ScanExport<'a> {
    pub summary: ScanSummary,
    pub assets: &'a [Asset],
    pub findings: &'a [Finding],
}

#[derive(Debug, Serialize)]
pub struct FullScanExport<'a> {
    pub source: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<&'a str>,
    pub summary: ScanSummary,
    pub assets: &'a [Asset],
    pub findings: &'a [Finding],
    pub mcp_snapshots: &'a [McpServerSnapshot],
    pub policy: &'a PolicyReport,
    pub provenance: &'a ProvenanceReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge_panel: Option<&'a JudgePanelReport>,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanJsonInput<'a> {
    pub source: &'a str,
    pub mode: Option<&'a str>,
    pub assets: &'a [Asset],
    pub findings: &'a [Finding],
    pub mcp_snapshots: &'a [McpServerSnapshot],
    pub policy: &'a PolicyReport,
    pub provenance: &'a ProvenanceReport,
    pub judge_panel: Option<&'a JudgePanelReport>,
}

pub fn to_json(assets: &[Asset], findings: &[Finding]) -> Result<String> {
    let export = ScanExport {
        summary: ScanSummary::from_findings(assets.len(), findings),
        assets,
        findings,
    };
    Ok(serde_json::to_string_pretty(&export)?)
}

pub fn to_scan_json(input: ScanJsonInput<'_>) -> Result<String> {
    let export = FullScanExport {
        source: input.source,
        mode: input.mode,
        summary: ScanSummary::from_findings(input.assets.len(), input.findings),
        assets: input.assets,
        findings: input.findings,
        mcp_snapshots: input.mcp_snapshots,
        policy: input.policy,
        provenance: input.provenance,
        judge_panel: input.judge_panel,
    };
    Ok(serde_json::to_string_pretty(&export)?)
}

pub fn to_sarif(findings: &[Finding]) -> Result<String> {
    let rule_indices = sarif_rule_indices(findings);
    let rules = sarif_rules(findings);
    let results = findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": finding.rule_id,
                "ruleIndex": rule_indices.get(&finding.rule_id).copied().unwrap_or_default(),
                "level": sarif_level(&finding.severity),
                "message": { "text": finding.title },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": finding.asset_path }
                    }
                }],
                "properties": {
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "tags": finding.tags,
                    "severity": finding.severity.to_string()
                }
            })
        })
        .collect::<Vec<_>>();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Skill Issue",
                    "informationUri": "https://github.com/skill-issue/skill-issue",
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn sarif_rule_indices(findings: &[Finding]) -> BTreeMap<String, usize> {
    findings
        .iter()
        .map(|finding| finding.rule_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, rule_id)| (rule_id, index))
        .collect()
}

fn sarif_rules(findings: &[Finding]) -> Vec<serde_json::Value> {
    let mut by_rule = BTreeMap::<String, &Finding>::new();
    for finding in findings {
        by_rule.entry(finding.rule_id.clone()).or_insert(finding);
    }

    by_rule
        .into_values()
        .map(|finding| {
            json!({
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": { "text": finding.title },
                "fullDescription": { "text": finding.description },
                "defaultConfiguration": { "level": sarif_level(&finding.severity) },
                "properties": {
                    "tags": finding.tags,
                    "severity": finding.severity.to_string()
                }
            })
        })
        .collect()
}

fn sarif_level(severity: &skill_issue_core::Severity) -> &'static str {
    match severity {
        skill_issue_core::Severity::Critical | skill_issue_core::Severity::High => "error",
        skill_issue_core::Severity::Medium => "warning",
        skill_issue_core::Severity::Low | skill_issue_core::Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_issue_core::{Finding, Severity};

    #[test]
    fn sarif_exports_rule_metadata() -> Result<()> {
        let finding = Finding::new(
            "mcp.json",
            "SI-MCP-RUNTIME-DOWNLOAD",
            Severity::High,
            "Runtime download",
            "Downloads code at runtime",
            "npx package",
            vec!["mcp".to_owned(), "runtime_resolution".to_owned()],
        );

        let sarif: serde_json::Value = serde_json::from_str(&to_sarif(&[finding])?)?;
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "SI-MCP-RUNTIME-DOWNLOAD");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleIndex"], 0);
        Ok(())
    }
}
