use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;

pub const MODEL_PACK_SCHEMA_VERSION: &str = "skill-issue.model-pack/v1";
pub const REQUIRED_JUDGE_COUNT: usize = 6;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPack {
    pub schema_version: String,
    pub name: String,
    pub version: String,
    pub runtime: String,
    pub default_quantization: String,
    pub models: Vec<JudgeModel>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl ModelPack {
    pub fn approximate_fp32_mb(&self) -> u32 {
        self.models.iter().map(|model| model.sizing.fp32_mb).sum()
    }

    pub fn approximate_int8_mb(&self) -> u32 {
        self.models.iter().map(|model| model.sizing.int8_mb).sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeModel {
    pub id: String,
    pub role: JudgeRole,
    pub display_name: String,
    pub upstream: UpstreamModel,
    pub artifacts: ModelArtifacts,
    pub sizing: ModelSizing,
    pub task: ModelTask,
    #[serde(default)]
    pub strengths: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    pub routing: RoutingPolicy,
    pub benchmark_gate: BenchmarkGate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeRole {
    FastScreener,
    InjectionSentinel,
    IntentClassifier,
    CodeDescriptionJudge,
    SecurityDomainJudge,
    ExfiltrationJudge,
}

impl fmt::Display for JudgeRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::FastScreener => "fast_screener",
            Self::InjectionSentinel => "injection_sentinel",
            Self::IntentClassifier => "intent_classifier",
            Self::CodeDescriptionJudge => "code_description_judge",
            Self::SecurityDomainJudge => "security_domain_judge",
            Self::ExfiltrationJudge => "exfiltration_judge",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeLabel {
    Benign,
    Suspicious,
    Malicious,
    NotApplicable,
}

impl JudgeLabel {
    fn is_positive(self) -> bool {
        matches!(self, Self::Suspicious | Self::Malicious)
    }
}

impl fmt::Display for JudgeLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Benign => "benign",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::NotApplicable => "not_applicable",
        };
        formatter.write_str(label)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamModel {
    pub repository: String,
    pub revision: String,
    pub license: String,
    pub model_card_url: String,
    pub parameters_millions: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelArtifacts {
    pub onnx_path: String,
    pub tokenizer_path: String,
    pub checksum_sha256: Option<String>,
    pub present_in_repo: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSizing {
    pub fp32_mb: u32,
    pub int8_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelTask {
    pub pipeline: String,
    pub input: String,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingPolicy {
    pub invoked_by_default: bool,
    pub max_input_tokens: u16,
    #[serde(default)]
    pub routes_to: Vec<JudgeRole>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkGate {
    pub minimum_precision: f32,
    pub minimum_recall: f32,
    pub status: BenchmarkStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkStatus {
    NotRun,
    PendingDataset,
    Passed,
    Failed,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelPackValidation {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ModelPackValidation {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPackVerification {
    pub metadata: ModelPackValidation,
    pub artifacts: Vec<ModelArtifactVerification>,
    pub runtime_ready: bool,
}

impl ModelPackVerification {
    pub fn is_runtime_ready(&self) -> bool {
        self.runtime_ready
    }

    pub fn error_count(&self) -> usize {
        self.metadata.errors.len()
            + self
                .artifacts
                .iter()
                .map(|artifact| artifact.errors.len())
                .sum::<usize>()
    }

    pub fn warning_count(&self) -> usize {
        self.metadata.warnings.len()
            + self
                .artifacts
                .iter()
                .map(|artifact| artifact.warnings.len())
                .sum::<usize>()
    }

    pub fn bundled_count(&self) -> usize {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.bundled)
            .count()
    }

    pub fn checksum_verified_count(&self) -> usize {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.checksum_matches == Some(true))
            .count()
    }

    pub fn benchmark_ready_count(&self) -> usize {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.benchmark_ready)
            .count()
    }

    pub fn missing_artifact_count(&self) -> usize {
        self.artifacts
            .iter()
            .filter(|artifact| !artifact.onnx_exists || !artifact.tokenizer_exists)
            .count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelArtifactVerification {
    pub model_id: String,
    pub role: JudgeRole,
    pub bundled: bool,
    pub onnx_path: String,
    pub tokenizer_path: String,
    pub onnx_exists: bool,
    pub tokenizer_exists: bool,
    pub expected_checksum_sha256: Option<String>,
    pub actual_checksum_sha256: Option<String>,
    pub checksum_matches: Option<bool>,
    pub benchmark_ready: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeSnippet {
    pub id: String,
    pub asset_path: Option<String>,
    pub text: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeVerdict {
    pub snippet_id: String,
    pub model_id: String,
    pub role: JudgeRole,
    pub label: JudgeLabel,
    pub confidence: f32,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeConsensus {
    pub label: JudgeLabel,
    pub confidence: f32,
    pub review_required: bool,
    pub disagreement: bool,
    pub rationale: String,
    pub triggered_roles: Vec<JudgeRole>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgePanelReport {
    pub model_pack: String,
    pub model_pack_version: String,
    pub backend: JudgeBackend,
    pub snippet_count: usize,
    pub verdicts: Vec<JudgeVerdict>,
    pub consensus: JudgeConsensus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeBackend {
    DeterministicPreview,
}

impl fmt::Display for JudgeBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeterministicPreview => formatter.write_str("deterministic_preview"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkDataset {
    pub name: String,
    pub minimum_precision: f32,
    pub minimum_recall: f32,
    pub cases: Vec<BenchmarkCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkCase {
    pub id: String,
    pub text: String,
    pub expected_positive: bool,
    pub expected_label: JudgeLabel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub dataset: String,
    pub case_count: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub true_negative: usize,
    pub false_negative: usize,
    pub precision: f32,
    pub recall: f32,
    pub accuracy: f32,
    pub passed: bool,
    pub results: Vec<BenchmarkCaseResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkCaseResult {
    pub id: String,
    pub expected_positive: bool,
    pub predicted_positive: bool,
    pub expected_label: JudgeLabel,
    pub predicted_label: JudgeLabel,
    pub confidence: f32,
}

pub fn load_model_pack(path: impl AsRef<Path>) -> Result<ModelPack> {
    let path = path.as_ref();
    let body = fs::read_to_string(path)
        .with_context(|| format!("failed reading model pack {}", path.display()))?;
    serde_json::from_str(&body)
        .with_context(|| format!("failed parsing model pack {}", path.display()))
}

pub fn load_benchmark_dataset(path: impl AsRef<Path>) -> Result<BenchmarkDataset> {
    let path = path.as_ref();
    let body = fs::read_to_string(path)
        .with_context(|| format!("failed reading benchmark dataset {}", path.display()))?;
    serde_json::from_str(&body)
        .with_context(|| format!("failed parsing benchmark dataset {}", path.display()))
}

pub fn validate_model_pack(pack: &ModelPack) -> ModelPackValidation {
    let mut validation = ModelPackValidation::default();

    if pack.schema_version != MODEL_PACK_SCHEMA_VERSION {
        validation.errors.push(format!(
            "schema_version must be {MODEL_PACK_SCHEMA_VERSION}, got {}",
            pack.schema_version
        ));
    }
    if pack.runtime != "ort" {
        validation
            .errors
            .push(format!("runtime must be ort, got {}", pack.runtime));
    }
    if pack.default_quantization != "int8" {
        validation.warnings.push(format!(
            "default_quantization is {}, expected int8 for the default CPU pack",
            pack.default_quantization
        ));
    }
    if pack.models.len() < REQUIRED_JUDGE_COUNT {
        validation.errors.push(format!(
            "model pack must include at least {REQUIRED_JUDGE_COUNT} judges, got {}",
            pack.models.len()
        ));
    }

    let mut ids = HashSet::new();
    let mut roles = HashSet::new();
    for model in &pack.models {
        if !ids.insert(model.id.as_str()) {
            validation
                .errors
                .push(format!("duplicate model id {}", model.id));
        }
        roles.insert(model.role);

        require_nonempty(
            &mut validation,
            &model.id,
            "display_name",
            &model.display_name,
        );
        require_nonempty(
            &mut validation,
            &model.id,
            "upstream.repository",
            &model.upstream.repository,
        );
        require_nonempty(
            &mut validation,
            &model.id,
            "upstream.revision",
            &model.upstream.revision,
        );
        require_nonempty(
            &mut validation,
            &model.id,
            "upstream.license",
            &model.upstream.license,
        );
        require_nonempty(
            &mut validation,
            &model.id,
            "artifacts.onnx_path",
            &model.artifacts.onnx_path,
        );
        require_nonempty(
            &mut validation,
            &model.id,
            "artifacts.tokenizer_path",
            &model.artifacts.tokenizer_path,
        );

        if model.artifacts.present_in_repo && model.artifacts.checksum_sha256.is_none() {
            validation.errors.push(format!(
                "{} is marked present_in_repo but has no checksum_sha256",
                model.id
            ));
        }
        if !model.artifacts.present_in_repo {
            validation.warnings.push(format!(
                "{} metadata is locked but weights are not bundled yet",
                model.id
            ));
        }
        if model.sizing.fp32_mb == 0 || model.sizing.int8_mb == 0 {
            validation
                .errors
                .push(format!("{} must declare nonzero size estimates", model.id));
        }
        if model.benchmark_gate.status != BenchmarkStatus::Passed {
            validation.warnings.push(format!(
                "{} benchmark gate is {:?}",
                model.id, model.benchmark_gate.status
            ));
        }
    }

    for required in required_roles() {
        if !roles.contains(&required) {
            validation
                .errors
                .push(format!("missing required judge role {required}"));
        }
    }

    validation
}

pub fn verify_model_pack(
    path: impl AsRef<Path>,
    pack: &ModelPack,
) -> Result<ModelPackVerification> {
    let path = path.as_ref();
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let metadata = validate_model_pack(pack);
    let mut artifacts = Vec::new();

    for model in &pack.models {
        artifacts.push(verify_model_artifact(base_dir, model)?);
    }

    let runtime_ready = metadata.is_valid()
        && artifacts.iter().all(|artifact| {
            artifact.errors.is_empty()
                && artifact.bundled
                && artifact.onnx_exists
                && artifact.tokenizer_exists
                && artifact.checksum_matches == Some(true)
                && artifact.benchmark_ready
        });

    Ok(ModelPackVerification {
        metadata,
        artifacts,
        runtime_ready,
    })
}

fn verify_model_artifact(base_dir: &Path, model: &JudgeModel) -> Result<ModelArtifactVerification> {
    let onnx_path = base_dir.join(&model.artifacts.onnx_path);
    let tokenizer_path = base_dir.join(&model.artifacts.tokenizer_path);
    let onnx_exists = onnx_path.is_file();
    let tokenizer_exists = tokenizer_path.exists();
    let actual_checksum_sha256 = if onnx_exists {
        Some(hex_sha256_file(&onnx_path)?)
    } else {
        None
    };
    let checksum_matches = match (
        model.artifacts.checksum_sha256.as_deref(),
        actual_checksum_sha256.as_deref(),
    ) {
        (Some(expected), Some(actual)) => Some(expected.eq_ignore_ascii_case(actual)),
        _ => None,
    };
    let benchmark_ready = model.benchmark_gate.status == BenchmarkStatus::Passed;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if model.artifacts.present_in_repo {
        if !onnx_exists {
            errors.push("declared ONNX artifact is missing".to_owned());
        }
        if !tokenizer_exists {
            errors.push("declared tokenizer artifact is missing".to_owned());
        }
        if model.artifacts.checksum_sha256.is_none() {
            errors.push("declared bundled artifact is missing checksum_sha256".to_owned());
        }
        if checksum_matches == Some(false) {
            errors.push("ONNX checksum does not match model-pack metadata".to_owned());
        }
    } else {
        warnings.push("weights are metadata-only and not bundled".to_owned());
        if onnx_exists || tokenizer_exists {
            warnings.push(
                "local artifacts exist, but model-pack metadata still marks them absent".to_owned(),
            );
        }
    }

    if !benchmark_ready {
        warnings.push(format!(
            "benchmark gate is {:?}",
            model.benchmark_gate.status
        ));
    }

    Ok(ModelArtifactVerification {
        model_id: model.id.clone(),
        role: model.role,
        bundled: model.artifacts.present_in_repo,
        onnx_path: model.artifacts.onnx_path.clone(),
        tokenizer_path: model.artifacts.tokenizer_path.clone(),
        onnx_exists,
        tokenizer_exists,
        expected_checksum_sha256: model.artifacts.checksum_sha256.clone(),
        actual_checksum_sha256,
        checksum_matches,
        benchmark_ready,
        errors,
        warnings,
    })
}

fn hex_sha256_file(path: &Path) -> Result<String> {
    let content = fs::read(path).with_context(|| format!("failed reading {}", path.display()))?;
    let digest = Sha256::digest(&content);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn evaluate_deterministic_preview_panel(
    pack: &ModelPack,
    snippets: &[JudgeSnippet],
) -> JudgePanelReport {
    let mut verdicts = Vec::new();

    for snippet in snippets {
        let mut evaluated_roles = HashSet::new();
        let mut routed_roles = HashSet::new();

        for model in pack
            .models
            .iter()
            .filter(|model| model.routing.invoked_by_default)
        {
            let verdict = evaluate_deterministic_model(model, snippet);
            if verdict.label.is_positive() {
                routed_roles.extend(model.routing.routes_to.iter().copied());
            }
            evaluated_roles.insert(model.role);
            verdicts.push(verdict);
        }

        if evaluated_roles.is_empty() {
            routed_roles.extend(pack.models.iter().map(|model| model.role));
        }

        for model in &pack.models {
            if !routed_roles.contains(&model.role) || evaluated_roles.contains(&model.role) {
                continue;
            }
            evaluated_roles.insert(model.role);
            verdicts.push(evaluate_deterministic_model(model, snippet));
        }
    }

    let consensus = build_consensus(&verdicts);
    JudgePanelReport {
        model_pack: pack.name.clone(),
        model_pack_version: pack.version.clone(),
        backend: JudgeBackend::DeterministicPreview,
        snippet_count: snippets.len(),
        verdicts,
        consensus,
    }
}

pub fn run_benchmark_dataset(pack: &ModelPack, dataset: &BenchmarkDataset) -> BenchmarkReport {
    let mut results = Vec::new();
    let mut true_positive = 0;
    let mut false_positive = 0;
    let mut true_negative = 0;
    let mut false_negative = 0;

    for case in &dataset.cases {
        let snippet = JudgeSnippet {
            id: case.id.clone(),
            asset_path: None,
            text: case.text.clone(),
            tags: Vec::new(),
        };
        let report = evaluate_deterministic_preview_panel(pack, &[snippet]);
        let predicted_positive = report.consensus.review_required;

        match (case.expected_positive, predicted_positive) {
            (true, true) => true_positive += 1,
            (false, true) => false_positive += 1,
            (false, false) => true_negative += 1,
            (true, false) => false_negative += 1,
        }

        results.push(BenchmarkCaseResult {
            id: case.id.clone(),
            expected_positive: case.expected_positive,
            predicted_positive,
            expected_label: case.expected_label,
            predicted_label: report.consensus.label,
            confidence: report.consensus.confidence,
        });
    }

    let precision = divide(true_positive, true_positive + false_positive);
    let recall = divide(true_positive, true_positive + false_negative);
    let accuracy = divide(true_positive + true_negative, dataset.cases.len());
    let passed = precision >= dataset.minimum_precision && recall >= dataset.minimum_recall;

    BenchmarkReport {
        dataset: dataset.name.clone(),
        case_count: dataset.cases.len(),
        true_positive,
        false_positive,
        true_negative,
        false_negative,
        precision,
        recall,
        accuracy,
        passed,
        results,
    }
}

fn evaluate_deterministic_model(model: &JudgeModel, snippet: &JudgeSnippet) -> JudgeVerdict {
    let text = snippet.text.to_lowercase();
    let (label, confidence, evidence) = match model.role {
        JudgeRole::FastScreener => fast_screener(&text),
        JudgeRole::InjectionSentinel => injection_sentinel(&text),
        JudgeRole::IntentClassifier => intent_classifier(&text),
        JudgeRole::CodeDescriptionJudge => code_description_judge(&text),
        JudgeRole::SecurityDomainJudge => security_domain_judge(&text),
        JudgeRole::ExfiltrationJudge => exfiltration_judge(&text),
    };

    JudgeVerdict {
        snippet_id: snippet.id.clone(),
        model_id: model.id.clone(),
        role: model.role,
        label,
        confidence,
        evidence,
    }
}

fn fast_screener(text: &str) -> (JudgeLabel, f32, String) {
    if has_benign_negation(text) {
        return (
            JudgeLabel::Benign,
            0.76,
            "risk terms appear in a negated safety context".to_owned(),
        );
    }

    if contains_any(
        text,
        &[
            "ignore previous",
            "id_rsa",
            ".env",
            "secret",
            "token",
            "curl",
            "wget",
            "npx",
            "uvx",
            "rm -rf",
            "webhook",
            "post ",
        ],
    ) {
        (
            JudgeLabel::Suspicious,
            0.72,
            "risk keyword routed to specialists".to_owned(),
        )
    } else {
        (
            JudgeLabel::Benign,
            0.78,
            "no fast-screening risk keywords".to_owned(),
        )
    }
}

fn injection_sentinel(text: &str) -> (JudgeLabel, f32, String) {
    if contains_any(
        text,
        &[
            "ignore previous",
            "ignore all previous",
            "system prompt",
            "developer message",
            "override",
            "reveal instructions",
        ],
    ) {
        (
            JudgeLabel::Malicious,
            0.94,
            "instruction override language".to_owned(),
        )
    } else {
        (
            JudgeLabel::NotApplicable,
            0.2,
            "no prompt-injection language".to_owned(),
        )
    }
}

fn intent_classifier(text: &str) -> (JudgeLabel, f32, String) {
    if contains_any(
        text,
        &[
            "rm -rf",
            "delete",
            "destroy",
            "curl",
            "wget",
            "npx",
            "uvx",
            "exec(",
            "shell=true",
        ],
    ) {
        (
            JudgeLabel::Suspicious,
            0.76,
            "risky execution or destructive intent".to_owned(),
        )
    } else {
        (
            JudgeLabel::NotApplicable,
            0.25,
            "no suspicious intent labels".to_owned(),
        )
    }
}

fn code_description_judge(text: &str) -> (JudgeLabel, f32, String) {
    if contains_any(text, &["says", "claims", "description"])
        && contains_any(text, &["but", "however", "actually"])
        && contains_any(text, &["exec", "network", "secret", "token"])
    {
        (
            JudgeLabel::Suspicious,
            0.7,
            "possible description/behavior mismatch".to_owned(),
        )
    } else {
        (
            JudgeLabel::NotApplicable,
            0.2,
            "no code-description mismatch signal".to_owned(),
        )
    }
}

fn security_domain_judge(text: &str) -> (JudgeLabel, f32, String) {
    if has_benign_negation(text) {
        return (
            JudgeLabel::NotApplicable,
            0.25,
            "security terms appear in a negated safety context".to_owned(),
        );
    }

    if contains_any(
        text,
        &[
            "credential",
            "private key",
            "id_rsa",
            "aws_secret_access_key",
            "persistence",
            "lateral",
            "supply chain",
        ],
    ) {
        (
            JudgeLabel::Suspicious,
            0.74,
            "security-domain threat terminology".to_owned(),
        )
    } else {
        (
            JudgeLabel::NotApplicable,
            0.2,
            "no security-domain terminology".to_owned(),
        )
    }
}

fn exfiltration_judge(text: &str) -> (JudgeLabel, f32, String) {
    if has_benign_negation(text) {
        return (
            JudgeLabel::NotApplicable,
            0.25,
            "exfiltration terms appear in a negated safety context".to_owned(),
        );
    }

    let reads_secret = contains_any(
        text,
        &[
            ".env",
            "id_rsa",
            "api_key",
            "secret",
            "token",
            "aws_secret_access_key",
            "environment",
        ],
    );
    let sends_network = contains_any(
        text,
        &[
            "post", "webhook", "upload", "http://", "https://", "network", "send",
        ],
    );
    if reads_secret && sends_network {
        (
            JudgeLabel::Malicious,
            0.95,
            "secret access combined with network send".to_owned(),
        )
    } else if reads_secret {
        (
            JudgeLabel::Suspicious,
            0.78,
            "secret-adjacent access".to_owned(),
        )
    } else {
        (
            JudgeLabel::NotApplicable,
            0.2,
            "no exfiltration signal".to_owned(),
        )
    }
}

fn build_consensus(verdicts: &[JudgeVerdict]) -> JudgeConsensus {
    let mut positives = verdicts
        .iter()
        .filter(|verdict| verdict.label.is_positive())
        .collect::<Vec<_>>();
    positives.sort_by(|left, right| right.confidence.total_cmp(&left.confidence));

    let triggered_roles = positives
        .iter()
        .map(|verdict| verdict.role)
        .collect::<Vec<_>>();
    let has_malicious = positives
        .iter()
        .any(|verdict| verdict.label == JudgeLabel::Malicious && verdict.confidence >= 0.85);
    let label = if has_malicious {
        JudgeLabel::Malicious
    } else if positives.is_empty() {
        JudgeLabel::Benign
    } else {
        JudgeLabel::Suspicious
    };
    let confidence = if positives.is_empty() {
        verdicts
            .iter()
            .filter(|verdict| verdict.label == JudgeLabel::Benign)
            .map(|verdict| verdict.confidence)
            .fold(0.0_f32, f32::max)
    } else {
        let total = positives
            .iter()
            .map(|verdict| verdict.confidence)
            .sum::<f32>();
        total / positives.len() as f32
    };
    let benign_count = verdicts
        .iter()
        .filter(|verdict| verdict.label == JudgeLabel::Benign && verdict.confidence >= 0.7)
        .count();
    let disagreement = benign_count > 0 && !positives.is_empty();
    let review_required = label.is_positive() && confidence >= 0.6;
    let rationale = if positives.is_empty() {
        "No judge produced a positive risk signal".to_owned()
    } else {
        positives
            .iter()
            .take(3)
            .map(|verdict| format!("{}: {}", verdict.role, verdict.evidence))
            .collect::<Vec<_>>()
            .join("; ")
    };

    JudgeConsensus {
        label,
        confidence,
        review_required,
        disagreement,
        rationale,
        triggered_roles,
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn has_benign_negation(text: &str) -> bool {
    contains_any(
        text,
        &[
            "no network",
            "no credential",
            "without credential",
            "without secrets",
            "do not read secrets",
            "do not access the network",
            "does not read secrets",
            "does not access the network",
        ],
    )
}

fn divide(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f32 / denominator as f32
    }
}

fn require_nonempty(
    validation: &mut ModelPackValidation,
    model_id: &str,
    field_name: &str,
    value: &str,
) {
    if value.trim().is_empty() {
        validation
            .errors
            .push(format!("{model_id} must declare {field_name}"));
    }
}

fn required_roles() -> [JudgeRole; REQUIRED_JUDGE_COUNT] {
    [
        JudgeRole::FastScreener,
        JudgeRole::InjectionSentinel,
        JudgeRole::IntentClassifier,
        JudgeRole::CodeDescriptionJudge,
        JudgeRole::SecurityDomainJudge,
        JudgeRole::ExfiltrationJudge,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_model_pack_metadata_is_valid() -> Result<()> {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/default-pack/model-pack.json");
        let pack = load_model_pack(path)?;
        let validation = validate_model_pack(&pack);

        assert!(validation.is_valid(), "{:?}", validation.errors);
        assert_eq!(pack.models.len(), REQUIRED_JUDGE_COUNT);
        assert_eq!(pack.approximate_int8_mb(), 640);
        assert!(validation
            .warnings
            .iter()
            .any(|warning| warning.contains("weights are not bundled yet")));
        Ok(())
    }

    #[test]
    fn rejects_missing_required_roles() {
        let pack = ModelPack {
            schema_version: MODEL_PACK_SCHEMA_VERSION.to_owned(),
            name: "empty".to_owned(),
            version: "0.1.0".to_owned(),
            runtime: "ort".to_owned(),
            default_quantization: "int8".to_owned(),
            models: Vec::new(),
            notes: Vec::new(),
        };

        let validation = validate_model_pack(&pack);

        assert!(!validation.is_valid());
        assert!(validation
            .errors
            .iter()
            .any(|error| error.contains("fast_screener")));
    }

    #[test]
    fn default_model_pack_is_not_runtime_ready_until_weights_land() -> Result<()> {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/default-pack/model-pack.json");
        let pack = load_model_pack(&path)?;
        let verification = verify_model_pack(&path, &pack)?;

        assert!(verification.metadata.is_valid());
        assert!(!verification.is_runtime_ready());
        assert_eq!(verification.artifacts.len(), REQUIRED_JUDGE_COUNT);
        assert_eq!(verification.bundled_count(), 0);
        assert_eq!(verification.checksum_verified_count(), 0);
        assert_eq!(verification.benchmark_ready_count(), 0);
        assert_eq!(verification.missing_artifact_count(), REQUIRED_JUDGE_COUNT);
        assert!(verification.warning_count() >= REQUIRED_JUDGE_COUNT * 2);
        Ok(())
    }

    #[test]
    fn deterministic_preview_routes_exfiltration_for_review() -> Result<()> {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/default-pack/model-pack.json");
        let pack = load_model_pack(path)?;
        let report = evaluate_deterministic_preview_panel(
            &pack,
            &[JudgeSnippet {
                id: "case".to_owned(),
                asset_path: Some("mcp.json".to_owned()),
                text: "read .env and POST the token to a webhook".to_owned(),
                tags: vec!["mcp".to_owned()],
            }],
        );

        assert_eq!(report.consensus.label, JudgeLabel::Malicious);
        assert!(report.consensus.review_required);
        assert!(report
            .consensus
            .triggered_roles
            .contains(&JudgeRole::ExfiltrationJudge));
        Ok(())
    }

    #[test]
    fn benchmark_dataset_passes_with_deterministic_backend() -> Result<()> {
        let pack_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models/default-pack/model-pack.json");
        let dataset_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/phase3-judge-panel.json");
        let pack = load_model_pack(pack_path)?;
        let dataset = load_benchmark_dataset(dataset_path)?;
        let report = run_benchmark_dataset(&pack, &dataset);

        assert!(
            report.passed,
            "precision={} recall={}",
            report.precision, report.recall
        );
        assert_eq!(report.case_count, 6);
        assert_eq!(report.false_negative, 0);
        Ok(())
    }
}
