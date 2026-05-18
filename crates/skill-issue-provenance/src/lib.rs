use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use skill_issue_core::{Asset, AssetKind, McpServerSnapshot};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

pub const PROVENANCE_SCHEMA_VERSION: &str = "skill-issue.provenance/v1";
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_PROVENANCE_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
pub const DEFAULT_MODEL_PACK_VERSION: &str = "skill-issue-default-pack/0.1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceReport {
    pub schema_version: String,
    pub generated_at: DateTime<Utc>,
    pub statement: InTotoStatement,
    pub source: SourceProvenance,
    pub scanner: ScannerProvenance,
    pub approval: ApprovalProvenance,
    pub content: ContentProvenance,
    pub assets: Vec<AssetProvenance>,
    pub lockfiles: Vec<LockfileProvenance>,
    pub mcp_commands: Vec<McpCommandProvenance>,
    pub signatures: Vec<SignatureVerification>,
    pub score: ProvenanceScore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: SlsaProvenancePredicate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InTotoSubject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaProvenancePredicate {
    pub build_definition: SlsaBuildDefinition,
    pub run_details: SlsaRunDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaBuildDefinition {
    pub build_type: String,
    pub external_parameters: SlsaExternalParameters,
    pub resolved_dependencies: Vec<ProvenanceMaterial>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaExternalParameters {
    pub source_root: String,
    pub source_url: Option<String>,
    pub source_ref: Option<String>,
    pub source_commit: Option<String>,
    pub policy_version: String,
    pub model_pack_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaRunDetails {
    pub builder: SlsaBuilder,
    pub metadata: SlsaRunMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlsaBuilder {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaRunMetadata {
    pub invocation_id: String,
    pub started_on: DateTime<Utc>,
    pub finished_on: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceMaterial {
    pub uri: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceProvenance {
    pub root: String,
    pub git: Option<GitProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitProvenance {
    pub repository_root: Option<String>,
    pub remote_url: Option<String>,
    pub branch: Option<String>,
    pub head_commit: Option<String>,
    pub dirty: bool,
    pub status: GitStatusSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitStatusSummary {
    pub total_entries: usize,
    pub modified: usize,
    pub deleted: usize,
    pub renamed: usize,
    pub untracked: usize,
    pub other: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerProvenance {
    pub name: String,
    pub version: String,
    pub policy_version: String,
    pub model_pack_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalProvenance {
    pub developer_feedback: bool,
    pub production_approval: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentProvenance {
    pub asset_count: usize,
    pub content_digest_sha256: String,
    pub lockfile_digest_sha256: Option<String>,
    pub mcp_declaration_digest_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetProvenance {
    pub path: String,
    pub kind: AssetKind,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfileProvenance {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCommandProvenance {
    pub asset_path: String,
    pub server_name: String,
    pub command_hash: String,
    pub tool_schema_hash: Option<String>,
    pub env_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureVerification {
    pub verifier: String,
    pub status: SignatureVerificationStatus,
    pub subject: String,
    pub signature_path: Option<String>,
    pub certificate_path: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureVerificationStatus {
    MissingSignature,
    VerifierUnavailable,
    NeedsConfiguration,
    Verified,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceScore {
    pub value: u8,
    pub level: ProvenanceScoreLevel,
    pub checks: Vec<ProvenanceCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceScoreLevel {
    Strong,
    Review,
    Weak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceCheck {
    pub id: String,
    pub status: ProvenanceCheckStatus,
    pub passed: bool,
    pub points: u8,
    pub max_points: u8,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceCheckStatus {
    Passed,
    Partial,
    Failed,
    NotApplicable,
}

pub fn build_provenance_report(
    root: impl AsRef<Path>,
    assets: &[Asset],
    mcp_snapshots: &[McpServerSnapshot],
    scanner_version: impl Into<String>,
    policy_version: impl Into<String>,
    model_pack_version: impl Into<String>,
) -> ProvenanceReport {
    let root = root.as_ref();
    let generated_at = Utc::now();
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let git = collect_git_metadata(&canonical_root);
    let approval = approval_from_git(git.as_ref());
    let scanner = ScannerProvenance {
        name: "skill-issue".to_owned(),
        version: scanner_version.into(),
        policy_version: policy_version.into(),
        model_pack_version: model_pack_version.into(),
    };
    let source = SourceProvenance {
        root: canonical_root.display().to_string(),
        git,
    };
    let asset_provenance = assets.iter().map(AssetProvenance::from).collect::<Vec<_>>();
    let lockfiles = assets
        .iter()
        .filter(|asset| is_lockfile(&asset.path))
        .map(LockfileProvenance::from)
        .collect::<Vec<_>>();
    let mcp_commands = mcp_snapshots
        .iter()
        .map(McpCommandProvenance::from)
        .collect::<Vec<_>>();
    let content = ContentProvenance {
        asset_count: asset_provenance.len(),
        content_digest_sha256: content_digest(&asset_provenance),
        lockfile_digest_sha256: aggregate_lockfile_digest(&lockfiles),
        mcp_declaration_digest_sha256: aggregate_mcp_digest(&mcp_commands),
    };
    let signatures = vec![collect_cosign_verification(&canonical_root)];
    let statement = build_statement(
        &source,
        &scanner,
        &content,
        &lockfiles,
        &mcp_commands,
        &generated_at,
    );
    let score = score_provenance(&source, &content, &lockfiles, &mcp_commands, &signatures);

    ProvenanceReport {
        schema_version: PROVENANCE_SCHEMA_VERSION.to_owned(),
        generated_at,
        statement,
        source,
        scanner,
        approval,
        content,
        assets: asset_provenance,
        lockfiles,
        mcp_commands,
        signatures,
        score,
    }
}

fn build_statement(
    source: &SourceProvenance,
    scanner: &ScannerProvenance,
    content: &ContentProvenance,
    lockfiles: &[LockfileProvenance],
    mcp_commands: &[McpCommandProvenance],
    generated_at: &DateTime<Utc>,
) -> InTotoStatement {
    let mut subject_digest = BTreeMap::new();
    subject_digest.insert("sha256".to_owned(), content.content_digest_sha256.clone());

    InTotoStatement {
        statement_type: IN_TOTO_STATEMENT_TYPE.to_owned(),
        subject: vec![InTotoSubject {
            name: source.root.clone(),
            digest: subject_digest,
        }],
        predicate_type: SLSA_PROVENANCE_PREDICATE_TYPE.to_owned(),
        predicate: SlsaProvenancePredicate {
            build_definition: SlsaBuildDefinition {
                build_type: "https://skill-issue.dev/provenance/local-scan/v1".to_owned(),
                external_parameters: SlsaExternalParameters {
                    source_root: source.root.clone(),
                    source_url: source.git.as_ref().and_then(|git| git.remote_url.clone()),
                    source_ref: source.git.as_ref().and_then(|git| git.branch.clone()),
                    source_commit: source.git.as_ref().and_then(|git| git.head_commit.clone()),
                    policy_version: scanner.policy_version.clone(),
                    model_pack_version: scanner.model_pack_version.clone(),
                },
                resolved_dependencies: provenance_materials(source, lockfiles, mcp_commands),
            },
            run_details: SlsaRunDetails {
                builder: SlsaBuilder {
                    id: format!("{}@{}", scanner.name, scanner.version),
                },
                metadata: SlsaRunMetadata {
                    invocation_id: format!(
                        "skill-issue:{}:{}",
                        scanner.version, content.content_digest_sha256
                    ),
                    started_on: generated_at.to_owned(),
                    finished_on: generated_at.to_owned(),
                },
            },
        },
    }
}

fn provenance_materials(
    source: &SourceProvenance,
    lockfiles: &[LockfileProvenance],
    mcp_commands: &[McpCommandProvenance],
) -> Vec<ProvenanceMaterial> {
    let mut materials = Vec::new();

    if let Some(git) = &source.git {
        if let Some(remote_url) = &git.remote_url {
            let mut digest = BTreeMap::new();
            if let Some(commit) = &git.head_commit {
                digest.insert("gitCommit".to_owned(), commit.clone());
            }
            materials.push(ProvenanceMaterial {
                uri: format!("git+{remote_url}"),
                digest,
            });
        }
    }

    for lockfile in lockfiles {
        let mut digest = BTreeMap::new();
        digest.insert("sha256".to_owned(), lockfile.sha256.clone());
        materials.push(ProvenanceMaterial {
            uri: format!("file://{}", lockfile.path),
            digest,
        });
    }

    for command in mcp_commands {
        let mut digest = BTreeMap::new();
        digest.insert("commandSha256".to_owned(), command.command_hash.clone());
        if let Some(schema_hash) = &command.tool_schema_hash {
            digest.insert("toolSchemaSha256".to_owned(), schema_hash.clone());
        }
        materials.push(ProvenanceMaterial {
            uri: format!("mcp://{}/{}", command.asset_path, command.server_name),
            digest,
        });
    }

    materials
}

fn collect_git_metadata(root: &Path) -> Option<GitProvenance> {
    let inside_work_tree = git_stdout(root, &["rev-parse", "--is-inside-work-tree"])?;
    if inside_work_tree.trim() != "true" {
        return None;
    }

    let status_text = git_stdout(root, &["status", "--porcelain=v1"]).unwrap_or_default();
    let status = summarize_status(&status_text);
    let branch = git_stdout(root, &["branch", "--show-current"])
        .filter(|value| !value.is_empty())
        .or_else(|| {
            git_stdout(root, &["rev-parse", "--abbrev-ref", "HEAD"])
                .filter(|value| !value.is_empty() && value != "HEAD")
        });

    Some(GitProvenance {
        repository_root: git_stdout(root, &["rev-parse", "--show-toplevel"])
            .filter(|value| !value.is_empty()),
        remote_url: git_stdout(root, &["remote", "get-url", "origin"])
            .filter(|value| !value.is_empty()),
        branch,
        head_commit: git_stdout(root, &["rev-parse", "HEAD"]).filter(|value| !value.is_empty()),
        dirty: status.total_entries > 0,
        status,
    })
}

fn git_stdout(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn summarize_status(status_text: &str) -> GitStatusSummary {
    let mut summary = GitStatusSummary::default();

    for line in status_text.lines().filter(|line| !line.trim().is_empty()) {
        summary.total_entries += 1;
        if line.starts_with("??") {
            summary.untracked += 1;
            continue;
        }

        let status = line.get(0..2).unwrap_or(line);
        if status.contains('R') {
            summary.renamed += 1;
        } else if status.contains('D') {
            summary.deleted += 1;
        } else if status.contains('M') {
            summary.modified += 1;
        } else {
            summary.other += 1;
        }
    }

    summary
}

fn approval_from_git(git: Option<&GitProvenance>) -> ApprovalProvenance {
    let reason = match git {
        None => Some("git metadata unavailable".to_owned()),
        Some(git) if git.head_commit.is_none() => Some("git HEAD commit unavailable".to_owned()),
        Some(git) if git.dirty => Some("working tree has uncommitted changes".to_owned()),
        Some(_) => None,
    };

    ApprovalProvenance {
        developer_feedback: true,
        production_approval: reason.is_none(),
        reason,
    }
}

fn collect_cosign_verification(root: &Path) -> SignatureVerification {
    let manifest = root.join("PROVENANCE.json");
    let signature = root.join("PROVENANCE.json.sig");
    let certificate = root.join("PROVENANCE.json.pem");
    let subject = manifest.display().to_string();

    if !manifest.is_file() || !signature.is_file() || !certificate.is_file() {
        return SignatureVerification {
            verifier: "cosign".to_owned(),
            status: SignatureVerificationStatus::MissingSignature,
            subject,
            signature_path: signature.is_file().then(|| signature.display().to_string()),
            certificate_path: certificate
                .is_file()
                .then(|| certificate.display().to_string()),
            message:
                "PROVENANCE.json, PROVENANCE.json.sig, and PROVENANCE.json.pem were not all present"
                    .to_owned(),
        };
    }

    if Command::new("cosign").arg("version").output().is_err() {
        return SignatureVerification {
            verifier: "cosign".to_owned(),
            status: SignatureVerificationStatus::VerifierUnavailable,
            subject,
            signature_path: Some(signature.display().to_string()),
            certificate_path: Some(certificate.display().to_string()),
            message: "cosign was not available on PATH".to_owned(),
        };
    }

    let Ok(identity) = std::env::var("SKILL_ISSUE_COSIGN_IDENTITY") else {
        return SignatureVerification {
            verifier: "cosign".to_owned(),
            status: SignatureVerificationStatus::NeedsConfiguration,
            subject,
            signature_path: Some(signature.display().to_string()),
            certificate_path: Some(certificate.display().to_string()),
            message: "set SKILL_ISSUE_COSIGN_IDENTITY and SKILL_ISSUE_COSIGN_ISSUER to verify keyless signatures".to_owned(),
        };
    };
    let Ok(issuer) = std::env::var("SKILL_ISSUE_COSIGN_ISSUER") else {
        return SignatureVerification {
            verifier: "cosign".to_owned(),
            status: SignatureVerificationStatus::NeedsConfiguration,
            subject,
            signature_path: Some(signature.display().to_string()),
            certificate_path: Some(certificate.display().to_string()),
            message: "set SKILL_ISSUE_COSIGN_ISSUER to verify keyless signatures".to_owned(),
        };
    };

    let output = Command::new("cosign")
        .arg("verify-blob")
        .arg("--certificate")
        .arg(&certificate)
        .arg("--signature")
        .arg(&signature)
        .arg("--certificate-identity")
        .arg(identity)
        .arg("--certificate-oidc-issuer")
        .arg(issuer)
        .arg(&manifest)
        .output();

    match output {
        Ok(output) if output.status.success() => SignatureVerification {
            verifier: "cosign".to_owned(),
            status: SignatureVerificationStatus::Verified,
            subject,
            signature_path: Some(signature.display().to_string()),
            certificate_path: Some(certificate.display().to_string()),
            message: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        },
        Ok(output) => SignatureVerification {
            verifier: "cosign".to_owned(),
            status: SignatureVerificationStatus::Failed,
            subject,
            signature_path: Some(signature.display().to_string()),
            certificate_path: Some(certificate.display().to_string()),
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        },
        Err(error) => SignatureVerification {
            verifier: "cosign".to_owned(),
            status: SignatureVerificationStatus::Failed,
            subject,
            signature_path: Some(signature.display().to_string()),
            certificate_path: Some(certificate.display().to_string()),
            message: error.to_string(),
        },
    }
}

fn score_provenance(
    source: &SourceProvenance,
    content: &ContentProvenance,
    lockfiles: &[LockfileProvenance],
    mcp_commands: &[McpCommandProvenance],
    signatures: &[SignatureVerification],
) -> ProvenanceScore {
    let mut checks = Vec::new();

    let git_available = source.git.is_some();
    checks.push(check(
        "source.git_metadata",
        git_available,
        10,
        if git_available {
            "Git metadata was collected"
        } else {
            "Git metadata was unavailable"
        },
    ));

    let head_available = source
        .git
        .as_ref()
        .and_then(|git| git.head_commit.as_ref())
        .is_some();
    checks.push(check(
        "source.head_commit",
        head_available,
        10,
        if head_available {
            "Git HEAD commit was resolved"
        } else {
            "Git HEAD commit was not resolved"
        },
    ));

    let clean = source.git.as_ref().is_some_and(|git| !git.dirty);
    checks.push(check(
        "source.clean_worktree",
        clean,
        10,
        if clean {
            "Working tree was clean"
        } else {
            "Working tree was dirty or unavailable"
        },
    ));

    checks.push(check(
        "content.aggregate_hash",
        !content.content_digest_sha256.is_empty(),
        15,
        "Aggregate content digest was generated",
    ));

    checks.push(check(
        "content.asset_hashes",
        content.asset_count > 0,
        10,
        if content.asset_count > 0 {
            "Asset hashes were captured"
        } else {
            "No agent assets were discovered to hash"
        },
    ));

    let lockfile_points = if lockfiles.is_empty() { 7 } else { 15 };
    checks.push(ProvenanceCheck {
        id: "dependencies.lockfiles".to_owned(),
        status: if lockfiles.is_empty() {
            ProvenanceCheckStatus::Partial
        } else {
            ProvenanceCheckStatus::Passed
        },
        passed: !lockfiles.is_empty(),
        points: lockfile_points,
        max_points: 15,
        message: if lockfiles.is_empty() {
            "No lockfiles were discovered; dependency evidence is partial".to_owned()
        } else {
            "Dependency lockfile hashes were captured".to_owned()
        },
    });

    checks.push(ProvenanceCheck {
        id: "mcp.declarations".to_owned(),
        status: if mcp_commands.is_empty() {
            ProvenanceCheckStatus::NotApplicable
        } else {
            ProvenanceCheckStatus::Passed
        },
        passed: true,
        points: 10,
        max_points: 10,
        message: if mcp_commands.is_empty() {
            "No MCP server declarations were discovered".to_owned()
        } else {
            "MCP command and tool-schema declaration hashes were captured".to_owned()
        },
    });

    let signature_verified = signatures
        .iter()
        .any(|signature| signature.status == SignatureVerificationStatus::Verified);
    let signature_status = if signature_verified {
        ProvenanceCheckStatus::Passed
    } else if signatures
        .iter()
        .any(|signature| signature.status == SignatureVerificationStatus::Failed)
    {
        ProvenanceCheckStatus::Failed
    } else {
        ProvenanceCheckStatus::Partial
    };
    checks.push(status_check(
        "signature.cosign",
        signature_status,
        if signature_verified { 20 } else { 0 },
        20,
        if signature_verified {
            "Cosign signature verification passed"
        } else {
            "Cosign signature verification did not pass or was not configured"
        },
    ));

    let value = checks.iter().map(|check| check.points).sum::<u8>().min(100);
    let level = if value >= 80 {
        ProvenanceScoreLevel::Strong
    } else if value >= 55 {
        ProvenanceScoreLevel::Review
    } else {
        ProvenanceScoreLevel::Weak
    };

    ProvenanceScore {
        value,
        level,
        checks,
    }
}

fn check(id: &str, passed: bool, max_points: u8, message: &str) -> ProvenanceCheck {
    status_check(
        id,
        if passed {
            ProvenanceCheckStatus::Passed
        } else {
            ProvenanceCheckStatus::Failed
        },
        if passed { max_points } else { 0 },
        max_points,
        message,
    )
}

fn status_check(
    id: &str,
    status: ProvenanceCheckStatus,
    points: u8,
    max_points: u8,
    message: &str,
) -> ProvenanceCheck {
    ProvenanceCheck {
        id: id.to_owned(),
        status,
        passed: matches!(
            status,
            ProvenanceCheckStatus::Passed | ProvenanceCheckStatus::NotApplicable
        ),
        points,
        max_points,
        message: message.to_owned(),
    }
}

fn is_lockfile(path: &str) -> bool {
    let filename = path
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .to_lowercase();

    matches!(
        filename.as_str(),
        "cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "poetry.lock"
            | "uv.lock"
            | "gemfile.lock"
            | "composer.lock"
            | "go.sum"
    ) || filename.ends_with(".lock")
        || filename.ends_with("lock")
}

impl From<&Asset> for AssetProvenance {
    fn from(asset: &Asset) -> Self {
        Self {
            path: asset.path.clone(),
            kind: asset.kind,
            sha256: asset.fingerprint.clone(),
            size_bytes: asset.size_bytes,
        }
    }
}

impl From<&Asset> for LockfileProvenance {
    fn from(asset: &Asset) -> Self {
        Self {
            path: asset.path.clone(),
            sha256: asset.fingerprint.clone(),
            size_bytes: asset.size_bytes,
        }
    }
}

impl From<&McpServerSnapshot> for McpCommandProvenance {
    fn from(snapshot: &McpServerSnapshot) -> Self {
        Self {
            asset_path: snapshot.asset_path.clone(),
            server_name: snapshot.server_name.clone(),
            command_hash: snapshot.command_hash.clone(),
            tool_schema_hash: snapshot.tool_schema_hash.clone(),
            env_keys: snapshot.env_keys.clone(),
        }
    }
}

fn content_digest(assets: &[AssetProvenance]) -> String {
    let mut sorted = assets.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.path.cmp(&right.path));

    let mut hasher = Sha256::new();
    for asset in sorted {
        hasher.update(asset.path.as_bytes());
        hasher.update(b"\0kind\0");
        hasher.update(asset.kind.to_string().as_bytes());
        hasher.update(b"\0sha256\0");
        hasher.update(asset.sha256.as_bytes());
        hasher.update(b"\0size\0");
        hasher.update(asset.size_bytes.to_string().as_bytes());
    }
    hex_sha256(hasher)
}

fn aggregate_lockfile_digest(lockfiles: &[LockfileProvenance]) -> Option<String> {
    if lockfiles.is_empty() {
        return None;
    }
    let mut sorted = lockfiles.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.path.cmp(&right.path));

    let mut hasher = Sha256::new();
    for lockfile in sorted {
        hasher.update(lockfile.path.as_bytes());
        hasher.update(b"\0sha256\0");
        hasher.update(lockfile.sha256.as_bytes());
        hasher.update(b"\0size\0");
        hasher.update(lockfile.size_bytes.to_string().as_bytes());
    }
    Some(hex_sha256(hasher))
}

fn aggregate_mcp_digest(commands: &[McpCommandProvenance]) -> Option<String> {
    if commands.is_empty() {
        return None;
    }
    let mut sorted = commands.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        left.asset_path
            .cmp(&right.asset_path)
            .then(left.server_name.cmp(&right.server_name))
    });

    let mut hasher = Sha256::new();
    for command in sorted {
        hasher.update(command.asset_path.as_bytes());
        hasher.update(b"\0server\0");
        hasher.update(command.server_name.as_bytes());
        hasher.update(b"\0command\0");
        hasher.update(command.command_hash.as_bytes());
        if let Some(schema_hash) = &command.tool_schema_hash {
            hasher.update(b"\0schema\0");
            hasher.update(schema_hash.as_bytes());
        }
    }
    Some(hex_sha256(hasher))
}

fn hex_sha256(hasher: Sha256) -> String {
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_issue_core::AssetKind;
    use uuid::Uuid;

    #[test]
    fn blocks_production_approval_without_git_metadata() {
        let report = build_provenance_report(
            std::env::temp_dir(),
            &[],
            &[],
            "0.1.0",
            "builtin/0.1.0",
            DEFAULT_MODEL_PACK_VERSION,
        );

        assert!(report.approval.developer_feedback);
        assert!(!report.approval.production_approval);
        assert_eq!(
            report.approval.reason.as_deref(),
            Some("git metadata unavailable")
        );
    }

    #[test]
    fn extracts_lockfile_hashes_from_assets() {
        let asset = Asset {
            id: Uuid::new_v4(),
            path: "frontend/package-lock.json".to_owned(),
            kind: AssetKind::DependencyManifest,
            fingerprint: "abc123".to_owned(),
            size_bytes: 42,
        };

        let report = build_provenance_report(
            std::env::temp_dir(),
            &[asset],
            &[],
            "0.1.0",
            "builtin/0.1.0",
            DEFAULT_MODEL_PACK_VERSION,
        );

        assert_eq!(report.lockfiles.len(), 1);
        assert_eq!(report.lockfiles[0].path, "frontend/package-lock.json");
        assert_eq!(report.lockfiles[0].sha256, "abc123");
        assert!(report.content.lockfile_digest_sha256.is_some());
    }

    #[test]
    fn emits_in_toto_statement_and_score() {
        let asset = Asset {
            id: Uuid::new_v4(),
            path: "SKILL.md".to_owned(),
            kind: AssetKind::AgentConfig,
            fingerprint: "abc123".to_owned(),
            size_bytes: 42,
        };

        let report = build_provenance_report(
            std::env::temp_dir(),
            &[asset],
            &[],
            "0.1.0",
            "builtin/0.1.0",
            DEFAULT_MODEL_PACK_VERSION,
        );

        assert_eq!(report.statement.statement_type, IN_TOTO_STATEMENT_TYPE);
        assert_eq!(
            report.generated_at,
            report.statement.predicate.run_details.metadata.started_on
        );
        assert_eq!(
            report.statement.predicate_type,
            SLSA_PROVENANCE_PREDICATE_TYPE
        );
        assert!(!report.content.content_digest_sha256.is_empty());
        assert!(report.score.value <= 100);
        assert!(report
            .score
            .checks
            .iter()
            .any(|check| check.id == "signature.cosign"));
    }

    #[test]
    fn score_marks_partial_and_not_applicable_evidence() {
        let report = build_provenance_report(
            std::env::temp_dir(),
            &[],
            &[],
            "0.1.0",
            "builtin/0.1.0",
            DEFAULT_MODEL_PACK_VERSION,
        );

        let lockfile_check = report
            .score
            .checks
            .iter()
            .find(|check| check.id == "dependencies.lockfiles")
            .unwrap();
        assert_eq!(lockfile_check.status, ProvenanceCheckStatus::Partial);
        assert!(!lockfile_check.passed);
        assert_eq!(lockfile_check.points, 7);

        let mcp_check = report
            .score
            .checks
            .iter()
            .find(|check| check.id == "mcp.declarations")
            .unwrap();
        assert_eq!(mcp_check.status, ProvenanceCheckStatus::NotApplicable);
        assert!(mcp_check.passed);
    }

    #[test]
    fn summarizes_porcelain_status_without_paths() {
        let summary =
            summarize_status(" M src/lib.rs\n?? scratch.txt\nR  old -> new\n D gone.rs\n");

        assert_eq!(summary.total_entries, 4);
        assert_eq!(summary.modified, 1);
        assert_eq!(summary.untracked, 1);
        assert_eq!(summary.renamed, 1);
        assert_eq!(summary.deleted, 1);
    }
}
