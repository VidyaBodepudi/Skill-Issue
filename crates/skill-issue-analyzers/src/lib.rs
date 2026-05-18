use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;
use skill_issue_audit::evidence_snippet;
use skill_issue_core::{Asset, AssetKind, Finding, Severity};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

pub fn analyze_assets(root: impl AsRef<Path>, assets: &[Asset]) -> Result<Vec<Finding>> {
    let root = root.as_ref();
    let mut findings = Vec::new();

    for asset in assets {
        let path = root.join(&asset.path);
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed reading {}", path.display()))?;

        findings.extend(analyze_text_asset(asset, &content));

        if asset.kind == AssetKind::McpConfig {
            findings.extend(analyze_mcp_config(asset, &content));
        }
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.asset_path.cmp(&right.asset_path))
    });
    Ok(findings)
}

fn analyze_text_asset(asset: &Asset, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lower = content.to_lowercase();

    if remote_exec_regex().is_match(content) {
        findings.push(Finding::new(
            &asset.path,
            "SI-REMOTE-EXEC",
            Severity::High,
            "Remote download piped to interpreter",
            "The asset appears to download remote content and execute it directly. This is difficult to provenance and can become a rug-pull path.",
            evidence_snippet(content, "curl", 120),
            vec!["supply_chain".into(), "remote_execution".into()],
        ));
    }

    for needle in [
        "id_rsa",
        ".env",
        "aws_secret_access_key",
        "openai_api_key",
        "process.env",
        "os.environ",
    ] {
        if lower.contains(needle) {
            findings.push(Finding::new(
                &asset.path,
                "SI-SECRET-ADJACENT",
                Severity::Medium,
                "Secret-adjacent access pattern",
                "The asset references credentials, environment variables, private keys, or env files. Review whether this access is necessary and constrained.",
                evidence_snippet(content, needle, 120),
                vec!["credential_access".into(), "redacted".into()],
            ));
            break;
        }
    }

    if asset.kind == AssetKind::Script
        && (lower.contains("shell=true") || lower.contains("eval(") || lower.contains("exec("))
    {
        findings.push(Finding::new(
            &asset.path,
            "SI-DYNAMIC-EXECUTION",
            Severity::Medium,
            "Dynamic execution sink",
            "The script contains dynamic execution primitives. Cross-file taint tracking will later determine whether untrusted input can reach this sink.",
            evidence_snippet(content, "exec", 120),
            vec!["execution".into(), "taint_sink".into()],
        ));
    }

    if lower.contains("rm -rf") || lower.contains("remove-item -recurse") {
        findings.push(Finding::new(
            &asset.path,
            "SI-DESTRUCTIVE-FS",
            Severity::Medium,
            "Destructive filesystem operation",
            "The asset contains a broad destructive filesystem operation. Review path constraints and user confirmation behavior.",
            evidence_snippet(content, "rm -rf", 120),
            vec!["impact".into(), "filesystem".into()],
        ));
    }

    findings
}

fn analyze_mcp_config(asset: &Asset, content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        findings.push(Finding::new(
            &asset.path,
            "SI-MCP-INVALID-JSON",
            Severity::Medium,
            "MCP configuration is not valid JSON",
            "The MCP config could not be parsed as JSON, preventing reliable inventory and drift analysis.",
            evidence_snippet(content, "mcp", 120),
            vec!["mcp".into(), "inventory".into()],
        ));
        return findings;
    };

    let Some(servers) = json.get("mcpServers").and_then(Value::as_object) else {
        return findings;
    };

    for (server_name, server_config) in servers {
        let command = server_config
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let args = server_config
            .get("args")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let command_line = format!("{command} {args}").trim().to_owned();
        let lowered = command_line.to_lowercase();

        if lowered.contains("npx")
            || lowered.contains("uvx")
            || lowered.contains("curl")
            || lowered.contains("wget")
        {
            findings.push(Finding::new(
                &asset.path,
                "SI-MCP-RUNTIME-DOWNLOAD",
                Severity::High,
                format!("MCP server `{server_name}` executes runtime-fetched code"),
                "The MCP server command appears to execute code resolved at runtime. Pin versions and require provenance before approval.",
                command_line,
                vec!["mcp".into(), "supply_chain".into(), "runtime_resolution".into()],
            ));
        }
    }

    findings
}

fn remote_exec_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?is)(curl|wget|irm|iwr)[^\n|;]*(\||;)[^\n]*(sh|bash|python|pwsh|powershell)")
            .expect("valid remote exec regex")
    })
}
