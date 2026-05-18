use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use skill_issue_core::{Asset, AssetKind, McpServerSnapshot};
use std::fs;
use std::path::{Component, Path};
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};

pub fn discover_path(root: impl AsRef<Path>) -> Result<Vec<Asset>> {
    let root = root.as_ref();
    let mut assets = Vec::new();

    if !root.exists() {
        bail!("scan path not found: {}", root.display());
    }
    if !root.is_dir() {
        bail!("scan path is not a directory: {}", root.display());
    }

    for entry in WalkDir::new(root).into_iter().filter_entry(should_descend) {
        let entry = entry.with_context(|| format!("failed walking {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }

        let relative_path = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        let kind = classify_path(&relative_path);
        if kind == AssetKind::Unknown {
            continue;
        }

        let content = fs::read(entry.path())
            .with_context(|| format!("failed reading {}", entry.path().display()))?;
        let fingerprint = hex_sha256(&content);

        assets.push(Asset {
            id: Uuid::new_v4(),
            path: relative_path,
            kind,
            fingerprint,
            size_bytes: content.len() as u64,
        });
    }

    assets.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(assets)
}

pub fn collect_mcp_snapshots(
    root: impl AsRef<Path>,
    assets: &[Asset],
) -> Result<Vec<McpServerSnapshot>> {
    let root = root.as_ref();
    let mut snapshots = Vec::new();

    for asset in assets
        .iter()
        .filter(|asset| asset.kind == AssetKind::McpConfig)
    {
        let path = root.join(&asset.path);
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed reading MCP config {}", path.display()))?;
        let json: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("failed parsing MCP config {}", path.display()))?;
        let Some(servers) = json
            .get("mcpServers")
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };

        for (server_name, config) in servers {
            let command = config
                .get("command")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            let args = config
                .get("args")
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let env_keys = config
                .get("env")
                .and_then(serde_json::Value::as_object)
                .map(|env| env.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let command_hash = hash_mcp_declaration(command.as_deref(), &args, &env_keys);
            let tool_schema_hash = hash_mcp_tool_schema(config);

            snapshots.push(McpServerSnapshot {
                asset_path: asset.path.clone(),
                server_name: server_name.clone(),
                command,
                args,
                env_keys,
                command_hash,
                tool_schema_hash,
            });
        }
    }

    Ok(snapshots)
}

pub fn classify_path(relative_path: &str) -> AssetKind {
    let path = relative_path.replace('\\', "/");
    let lower = path.to_lowercase();
    let filename = lower.rsplit('/').next().unwrap_or(&lower);

    if lower == "skill.md"
        || lower.ends_with("/skill.md")
        || filename == ".agent.md"
        || filename == ".instructions.md"
        || filename == "copilot-instructions.md"
        || lower.starts_with(".cursor/rules/")
        || lower.contains("/.cursor/rules/")
        || lower.starts_with(".claude/commands/")
        || lower.contains("/.claude/commands/")
    {
        return AssetKind::AgentConfig;
    }

    if filename == "mcp.json" || lower.ends_with("/mcp.json") {
        return AssetKind::McpConfig;
    }

    if (lower.starts_with(".github/workflows/") || lower.contains("/.github/workflows/"))
        && (filename.ends_with(".yml") || filename.ends_with(".yaml"))
    {
        return AssetKind::Workflow;
    }

    if lower.contains("/.git/hooks/") {
        return AssetKind::GitHook;
    }

    if matches!(
        filename,
        "package.json"
            | "requirements.txt"
            | "pyproject.toml"
            | "cargo.toml"
            | "cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "poetry.lock"
            | "uv.lock"
            | "gemfile.lock"
            | "composer.lock"
            | "go.sum"
    ) || filename.ends_with("lock")
        || filename.ends_with(".lock")
    {
        return AssetKind::DependencyManifest;
    }

    if filename == "dockerfile" || filename.ends_with(".dockerfile") {
        return AssetKind::ContainerDefinition;
    }

    if matches!(filename, "makefile" | "justfile") {
        return AssetKind::BuildFile;
    }

    if filename.ends_with(".py")
        || filename.ends_with(".js")
        || filename.ends_with(".ts")
        || filename.ends_with(".sh")
        || filename.ends_with(".bash")
        || filename.ends_with(".ps1")
    {
        return AssetKind::Script;
    }

    AssetKind::Unknown
}

fn should_descend(entry: &DirEntry) -> bool {
    let path = entry.path();
    if path.components().any(|component| matches!(component, Component::Normal(name) if name == "target" || name == "node_modules")) {
        return false;
    }

    if path
        .components()
        .any(|component| matches!(component, Component::Normal(name) if name == ".git"))
    {
        let normalized = path.to_string_lossy().replace('\\', "/");
        return normalized.contains("/.git/hooks")
            || normalized.ends_with("/.git")
            || normalized.ends_with("/.git/hooks");
    }

    true
}

fn hex_sha256(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_mcp_declaration(command: Option<&str>, args: &[String], env_keys: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(command.unwrap_or_default().as_bytes());
    for arg in args {
        hasher.update(b"\0arg\0");
        hasher.update(arg.as_bytes());
    }
    for env_key in env_keys {
        hasher.update(b"\0env\0");
        hasher.update(env_key.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_mcp_tool_schema(config: &serde_json::Value) -> Option<String> {
    let schema = config
        .get("tools")
        .or_else(|| config.get("toolSchemas"))
        .or_else(|| config.get("tool_schema"))
        .or_else(|| config.get("inputSchema"))?;
    let encoded = serde_json::to_vec(schema).ok()?;
    Some(hex_sha256(&encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_agent_files() {
        assert_eq!(classify_path("SKILL.md"), AssetKind::AgentConfig);
        assert_eq!(
            classify_path(".cursor/rules/review.md"),
            AssetKind::AgentConfig
        );
        assert_eq!(classify_path("config/mcp.json"), AssetKind::McpConfig);
        assert_eq!(
            classify_path("frontend/package-lock.json"),
            AssetKind::DependencyManifest
        );
        assert_eq!(
            classify_path("frontend/pnpm-lock.yaml"),
            AssetKind::DependencyManifest
        );
        assert_eq!(
            classify_path(".github/workflows/scan.yml"),
            AssetKind::Workflow
        );
    }

    #[test]
    fn snapshots_mcp_servers() -> Result<()> {
        let root = std::env::temp_dir().join(format!("skill-issue-inventory-{}", Uuid::new_v4()));
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("mcp.json"),
            r#"{
                "mcpServers": {
                    "internal": {
                        "command": "node",
                        "args": ["server.js"],
                        "env": { "API_TOKEN": "${API_TOKEN}" },
                        "tools": [{"name": "search", "inputSchema": {"type": "object"}}]
                    }
                }
            }"#,
        )?;

        let assets = discover_path(&root)?;
        let snapshots = collect_mcp_snapshots(&root, &assets)?;
        let _ = fs::remove_dir_all(&root);

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].server_name, "internal");
        assert_eq!(snapshots[0].env_keys, vec!["API_TOKEN"]);
        assert!(!snapshots[0].command_hash.is_empty());
        assert!(snapshots[0].tool_schema_hash.is_some());
        Ok(())
    }
}
