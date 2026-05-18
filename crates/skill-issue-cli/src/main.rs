use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use skill_issue_core::ScanSummary;
use skill_issue_exports::{to_sarif, to_scan_json, ScanJsonInput};
use skill_issue_judges::{
    load_benchmark_dataset, load_model_pack, run_benchmark_dataset, validate_model_pack,
    verify_model_pack, BenchmarkReport, ModelPack, ModelPackValidation, ModelPackVerification,
};
use skill_issue_policy::{PolicyAction, PolicyScanMode};
use skill_issue_provenance::ProvenanceReport;
use skill_issue_scanner::{run_scan, JudgeMode, ScanOptions, ScanRun};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(name = "skill-issue")]
#[command(
    version,
    about = "Scan locally cloned repositories for agentic AI security risks"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Scan(ScanArgs),
    Models(ModelsArgs),
}

#[derive(Debug, Args)]
struct ModelsArgs {
    #[command(subcommand)]
    command: ModelsCommand,
}

#[derive(Debug, Subcommand)]
enum ModelsCommand {
    Benchmark(ModelBenchmarkArgs),
    Inspect(ModelInspectArgs),
    Verify(ModelVerifyArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[arg(long, value_enum, default_value_t = ScanMode::Developer)]
    mode: ScanMode,

    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,

    #[arg(long)]
    provenance_out: Option<PathBuf>,

    #[arg(
        long,
        help = "Run the deterministic judge preview; ONNX artifacts are not required"
    )]
    judges: bool,

    #[arg(long, default_value = "models/default-pack/model-pack.json")]
    model_pack: PathBuf,
}

#[derive(Debug, Args)]
struct ModelBenchmarkArgs {
    #[arg(default_value = "benchmarks/phase3-judge-panel.json")]
    dataset: PathBuf,

    #[arg(long, default_value = "models/default-pack/model-pack.json")]
    model_pack: PathBuf,

    #[arg(short, long, value_enum, default_value_t = ModelInspectFormat::Text)]
    format: ModelInspectFormat,
}

#[derive(Debug, Args)]
struct ModelInspectArgs {
    #[arg(default_value = "models/default-pack/model-pack.json")]
    path: PathBuf,

    #[arg(short, long, value_enum, default_value_t = ModelInspectFormat::Text)]
    format: ModelInspectFormat,
}

#[derive(Debug, Args)]
struct ModelVerifyArgs {
    #[arg(default_value = "models/default-pack/model-pack.json")]
    path: PathBuf,

    #[arg(short, long, value_enum, default_value_t = ModelInspectFormat::Text)]
    format: ModelInspectFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModelInspectFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum ScanMode {
    Developer,
    Production,
}

impl fmt::Display for ScanMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Developer => formatter.write_str("developer"),
            Self::Production => formatter.write_str("production"),
        }
    }
}

impl From<ScanMode> for PolicyScanMode {
    fn from(mode: ScanMode) -> Self {
        match mode {
            ScanMode::Developer => Self::Developer,
            ScanMode::Production => Self::Production,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum FailOn {
    Never,
    Warn,
    Review,
    Block,
}

#[derive(Debug, Serialize)]
struct ModelPackInspection<'a> {
    path: String,
    pack: &'a ModelPack,
    validation: &'a ModelPackValidation,
}

#[derive(Debug, Serialize)]
struct ModelPackVerificationExport<'a> {
    path: String,
    pack: &'a ModelPack,
    verification: &'a ModelPackVerification,
}

#[derive(Debug, Serialize)]
struct ModelBenchmarkExport<'a> {
    dataset_path: String,
    model_pack_path: String,
    report: &'a BenchmarkReport,
}

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => scan(args),
        Commands::Models(args) => models(args),
    }
}

fn models(args: ModelsArgs) -> Result<ExitCode> {
    match args.command {
        ModelsCommand::Benchmark(args) => benchmark_model_pack(args),
        ModelsCommand::Inspect(args) => inspect_model_pack(args),
        ModelsCommand::Verify(args) => verify_model_pack_command(args),
    }
}

fn benchmark_model_pack(args: ModelBenchmarkArgs) -> Result<ExitCode> {
    let pack = load_model_pack(&args.model_pack)?;
    let dataset = load_benchmark_dataset(&args.dataset)?;
    let report = run_benchmark_dataset(&pack, &dataset);

    match args.format {
        ModelInspectFormat::Text => print_benchmark_text(&args.dataset, &args.model_pack, &report),
        ModelInspectFormat::Json => print_benchmark_json(&args.dataset, &args.model_pack, &report)?,
    }

    if report.passed {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn inspect_model_pack(args: ModelInspectArgs) -> Result<ExitCode> {
    let pack = load_model_pack(&args.path)?;
    let validation = validate_model_pack(&pack);

    match args.format {
        ModelInspectFormat::Text => print_model_pack_text(&args.path, &pack, &validation),
        ModelInspectFormat::Json => print_model_pack_json(&args.path, &pack, &validation)?,
    }

    if validation.is_valid() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn verify_model_pack_command(args: ModelVerifyArgs) -> Result<ExitCode> {
    let pack = load_model_pack(&args.path)?;
    let verification = verify_model_pack(&args.path, &pack)?;

    match args.format {
        ModelInspectFormat::Text => {
            print_model_pack_verification_text(&args.path, &pack, &verification)
        }
        ModelInspectFormat::Json => {
            print_model_pack_verification_json(&args.path, &pack, &verification)?
        }
    }

    if verification.is_runtime_ready() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn scan(args: ScanArgs) -> Result<ExitCode> {
    let mode = args.mode;
    let result = run_scan(
        &args.path,
        scan_options(mode, args.judges, &args.model_pack),
    )?;

    match args.format {
        OutputFormat::Text => print_text_report(&result, mode),
        OutputFormat::Json => print_json_report(&result, mode)?,
        OutputFormat::Sarif => println!("{}", to_sarif(&result.findings)?),
    }

    if let Some(path) = &args.provenance_out {
        write_provenance_report(path, &result.provenance)?;
    }

    if should_fail(
        result.policy.highest_action,
        effective_fail_on(mode, args.fail_on),
    ) {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn scan_options(mode: ScanMode, run_judges: bool, model_pack_path: &Path) -> ScanOptions {
    let mut options = ScanOptions::new(mode.into(), env!("CARGO_PKG_VERSION"));
    if run_judges {
        options.judge_mode = JudgeMode::DeterministicPreview {
            model_pack_path: model_pack_path.to_path_buf(),
        };
    }
    options
}

fn print_text_report(result: &ScanRun, mode: ScanMode) {
    let summary = ScanSummary::from_findings(result.assets.len(), &result.findings);
    println!("Skill Issue scan");
    println!("Source: {}", result.source_label);
    println!("Mode: {}", mode);
    println!("Assets: {}", summary.asset_count);
    println!("Findings: {}", summary.finding_count);
    println!(
        "Policy: {} risk={} decisions={}",
        result.policy.highest_action,
        result.policy.risk_score,
        result.policy.decisions.len()
    );
    println!(
        "Provenance: score={} level={:?}",
        result.provenance.score.value, result.provenance.score.level
    );
    match &result.provenance.source.git {
        Some(git) => {
            let branch = git.branch.as_deref().unwrap_or("detached");
            let commit = git
                .head_commit
                .as_deref()
                .map(short_commit)
                .unwrap_or("unknown");
            let state = if git.dirty { "dirty" } else { "clean" };
            println!("Git: {branch}@{commit} ({state})");
        }
        None => println!("Git: unavailable"),
    }
    if result.provenance.approval.production_approval {
        println!("Production approval: candidate");
    } else if let Some(reason) = &result.provenance.approval.reason {
        println!("Production approval: blocked ({reason})");
    }
    if let Some(judge_panel) = &result.judge_panel {
        println!(
            "Judges: {} snippets backend={} consensus={} confidence={:.2} review_required={}",
            judge_panel.snippet_count,
            judge_panel.backend,
            judge_panel.consensus.label,
            judge_panel.consensus.confidence,
            judge_panel.consensus.review_required
        );
    }

    if result.assets.is_empty() {
        println!();
        println!("No agent assets found.");
        return;
    }

    if result.findings.is_empty() {
        println!();
        println!("No findings.");
    } else {
        println!();
        println!("Findings:");
        for finding in &result.findings {
            println!(
                "[{}] {} - {}",
                finding.severity, finding.rule_id, finding.title
            );
            println!("  Asset: {}", finding.asset_path);
            if !finding.evidence.trim().is_empty() {
                println!("  Evidence: {}", finding.evidence.trim());
            }
        }
    }

    if !result.policy.decisions.is_empty() {
        println!();
        println!("Policy decisions:");
        for decision in &result.policy.decisions {
            println!(
                "[{}] {} - {}",
                decision.action, decision.policy_id, decision.title
            );
            if let Some(asset_path) = &decision.asset_path {
                println!("  Asset: {asset_path}");
            }
        }
    }
}

fn print_json_report(result: &ScanRun, mode: ScanMode) -> Result<()> {
    let mode_label = mode.to_string();
    println!(
        "{}",
        to_scan_json(ScanJsonInput {
            source: &result.source_label,
            mode: Some(&mode_label),
            assets: &result.assets,
            findings: &result.findings,
            mcp_snapshots: &result.mcp_snapshots,
            policy: &result.policy,
            provenance: &result.provenance,
            judge_panel: result.judge_panel.as_ref(),
        })?
    );
    Ok(())
}

fn print_model_pack_text(path: &Path, pack: &ModelPack, validation: &ModelPackValidation) {
    println!("Skill Issue model pack");
    println!("Path: {}", path.display());
    println!("Name: {} {}", pack.name, pack.version);
    println!(
        "Runtime: {} default_quantization={}",
        pack.runtime, pack.default_quantization
    );
    println!("Judges: {}", pack.models.len());
    println!(
        "Approx size: {} MB INT8 / {} MB FP32",
        pack.approximate_int8_mb(),
        pack.approximate_fp32_mb()
    );
    println!(
        "Validation: {} ({} warnings)",
        if validation.is_valid() {
            "ok"
        } else {
            "failed"
        },
        validation.warnings.len()
    );

    if !validation.errors.is_empty() {
        println!();
        println!("Errors:");
        for error in &validation.errors {
            println!("- {error}");
        }
    }

    if !validation.warnings.is_empty() {
        println!();
        println!("Warnings:");
        for warning in &validation.warnings {
            println!("- {warning}");
        }
    }

    println!();
    println!("Judges:");
    for model in &pack.models {
        println!(
            "[{}] {} - {}",
            model.role, model.display_name, model.upstream.repository
        );
        println!(
            "  license={} revision={} int8~{}MB fp32~{}MB benchmark={:?}",
            model.upstream.license,
            model.upstream.revision,
            model.sizing.int8_mb,
            model.sizing.fp32_mb,
            model.benchmark_gate.status
        );
        if !model.strengths.is_empty() {
            println!("  excels: {}", model.strengths.join("; "));
        }
    }
}

fn print_model_pack_json(
    path: &Path,
    pack: &ModelPack,
    validation: &ModelPackValidation,
) -> Result<()> {
    let inspection = ModelPackInspection {
        path: path.display().to_string(),
        pack,
        validation,
    };
    println!("{}", serde_json::to_string_pretty(&inspection)?);
    Ok(())
}

fn print_benchmark_text(dataset_path: &Path, model_pack_path: &Path, report: &BenchmarkReport) {
    println!("Skill Issue judge benchmark");
    println!("Dataset: {}", dataset_path.display());
    println!("Model pack: {}", model_pack_path.display());
    println!("Cases: {}", report.case_count);
    println!(
        "Precision: {:.3} Recall: {:.3} Accuracy: {:.3}",
        report.precision, report.recall, report.accuracy
    );
    println!(
        "Confusion: tp={} fp={} tn={} fn={}",
        report.true_positive, report.false_positive, report.true_negative, report.false_negative
    );
    println!("Passed: {}", report.passed);

    println!();
    println!("Cases:");
    for result in &report.results {
        println!(
            "{} expected={} predicted={} confidence={:.2}",
            result.id, result.expected_label, result.predicted_label, result.confidence
        );
    }
}

fn print_benchmark_json(
    dataset_path: &Path,
    model_pack_path: &Path,
    report: &BenchmarkReport,
) -> Result<()> {
    let export = ModelBenchmarkExport {
        dataset_path: dataset_path.display().to_string(),
        model_pack_path: model_pack_path.display().to_string(),
        report,
    };
    println!("{}", serde_json::to_string_pretty(&export)?);
    Ok(())
}

fn print_model_pack_verification_text(
    path: &Path,
    pack: &ModelPack,
    verification: &ModelPackVerification,
) {
    println!("Skill Issue model pack verification");
    println!("Path: {}", path.display());
    println!("Name: {} {}", pack.name, pack.version);
    println!(
        "Runtime ready: {}",
        if verification.is_runtime_ready() {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "Metadata: {} errors, {} warnings",
        verification.metadata.errors.len(),
        verification.metadata.warnings.len()
    );
    println!(
        "Artifacts: bundled={}/{} missing={} checksum_verified={} benchmark_ready={}",
        verification.bundled_count(),
        verification.artifacts.len(),
        verification.missing_artifact_count(),
        verification.checksum_verified_count(),
        verification.benchmark_ready_count()
    );
    println!(
        "Totals: errors={} warnings={}",
        verification.error_count(),
        verification.warning_count()
    );

    if !verification.metadata.errors.is_empty() {
        println!();
        println!("Metadata errors:");
        for error in &verification.metadata.errors {
            println!("- {error}");
        }
    }

    println!();
    println!("Judges:");
    for artifact in &verification.artifacts {
        println!(
            "[{}] {} bundled={} onnx={} tokenizer={} checksum={} benchmark={}",
            artifact.role,
            artifact.model_id,
            artifact.bundled,
            artifact.onnx_exists,
            artifact.tokenizer_exists,
            artifact
                .checksum_matches
                .map(|matches| if matches { "ok" } else { "mismatch" })
                .unwrap_or("missing"),
            artifact.benchmark_ready
        );
        for error in &artifact.errors {
            println!("  error: {error}");
        }
        for warning in &artifact.warnings {
            println!("  warning: {warning}");
        }
    }
}

fn print_model_pack_verification_json(
    path: &Path,
    pack: &ModelPack,
    verification: &ModelPackVerification,
) -> Result<()> {
    let export = ModelPackVerificationExport {
        path: path.display().to_string(),
        pack,
        verification,
    };
    println!("{}", serde_json::to_string_pretty(&export)?);
    Ok(())
}

fn write_provenance_report(path: &Path, provenance: &ProvenanceReport) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(provenance)?;
    fs::write(path, body).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

fn short_commit(commit: &str) -> &str {
    commit.get(0..12).unwrap_or(commit)
}

fn effective_fail_on(mode: ScanMode, requested: Option<FailOn>) -> FailOn {
    requested.unwrap_or(match mode {
        ScanMode::Developer => FailOn::Never,
        ScanMode::Production => FailOn::Block,
    })
}

fn should_fail(action: PolicyAction, fail_on: FailOn) -> bool {
    match fail_on {
        FailOn::Never => false,
        FailOn::Warn => action >= PolicyAction::Warn,
        FailOn::Review => action >= PolicyAction::Review,
        FailOn::Block => action >= PolicyAction::Block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_thresholds_are_ordered_by_policy_action() {
        assert!(!should_fail(PolicyAction::Allow, FailOn::Warn));
        assert!(should_fail(PolicyAction::Warn, FailOn::Warn));
        assert!(should_fail(PolicyAction::Review, FailOn::Warn));
        assert!(!should_fail(PolicyAction::Review, FailOn::Block));
        assert!(should_fail(PolicyAction::Block, FailOn::Block));
        assert!(!should_fail(PolicyAction::Block, FailOn::Never));
    }

    #[test]
    fn short_commit_handles_short_values() {
        assert_eq!(short_commit("abcdef"), "abcdef");
        assert_eq!(short_commit("abcdef1234567890"), "abcdef123456");
    }

    #[test]
    fn production_mode_defaults_to_block_failure() {
        assert_eq!(effective_fail_on(ScanMode::Developer, None), FailOn::Never);
        assert_eq!(effective_fail_on(ScanMode::Production, None), FailOn::Block);
        assert_eq!(
            effective_fail_on(ScanMode::Production, Some(FailOn::Never)),
            FailOn::Never
        );
    }

    #[test]
    fn default_model_pack_path_is_stable() {
        let args = ModelInspectArgs {
            path: PathBuf::from("models/default-pack/model-pack.json"),
            format: ModelInspectFormat::Text,
        };

        assert_eq!(
            args.path,
            PathBuf::from("models/default-pack/model-pack.json")
        );
    }
}
