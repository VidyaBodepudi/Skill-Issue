# Plan: Skill Issue — Agentic AI Security Governance (v4)

## TL;DR
Build Skill Issue as a self-hosted, Rust-first governance and evidence platform for org-wide AI agent security. The strongest wedge is not “one more malicious skill scanner”; Cisco already owns deep static skill scanning and Snyk owns local agent/MCP discovery. Skill Issue should own the private system of record: inventory, provenance, drift, MCP tool snapshots, policy decisions, SARIF exports, baselines, exceptions, reviewer workflow, and audit evidence across all agent assets in a company’s Git org.

Runtime goal: no Python or Node production services. Rust service with Axum + Maud + HTMX, PostgreSQL + sqlx, apalis on PostgreSQL, ONNX inference via `ort`, tree-sitter static analysis, Git provider APIs, and optional lab-mode dynamic analysis later. Model training can use Python outside the runtime; exported ONNX weights are bundled as versioned model packs.

## Current Technical Verdict

**Sound with corrections:** The Rust web/data/scanning architecture is feasible and lean. The biggest correction is to make dynamic behavioral observability optional lab mode, not MVP default. The MVP should be offline/static/governance-first.

**Main incongruencies fixed:**
- FastAPI/Next.js/Zitadel references removed.
- Ferron changed from core dependency to optional appliance ingress profile.
- Redis and MinIO excluded from MVP.
- “Pure Rust” clarified as no Python/Node production services, with explicit native dependencies (`ort`, ONNX Runtime) and a preference for Rust-native crates where practical.
- Behavioral tracing moved behind a Linux-only, opt-in lab worker threat model.
- Governance features added: inventory, policy-as-code, baselines, exceptions, audit logs, MCP snapshots/schema diffs, SARIF, model cards, SBOM/VEX/ML-BOM, OpenTelemetry.

**Current implementation sequence:**
1. Bring v0.1 core to final form first: local/server scanning, built-in policy, provenance, PostgreSQL persistence, audit trail, canonical JSON exports, and SARIF exports.
2. Complete the real ONNX/tokenizer SLM judge panel after the v0.1 core is stable. The deterministic judge preview can continue to ship as non-blocking evidence during this track.
3. Add the optional dynamic lab only after the static/provenance platform and real model runtime are solid.
4. Treat Phase 6 as expansion after Skill Issue is a usable v0.1 product with its core evidence system in place.

## Architecture

### Pillar 0: Minimal Self-Hosted Platform

**Deployment model:** Self-hosted Docker Compose first; Helm/Kubernetes later. Default deployment assumes the customer brings an internal network boundary, VPN, or existing ingress.

**Core services:**
- `skill-issue-server`: single Rust binary for UI, API, scanner orchestration, and jobs.
- `postgres`: system of record and apalis job backend.
- Optional `ferron`: Rust-native reverse proxy profile for appliance-style deployments that want bundled TLS.

**Runtime stack:**
- Web: Axum 0.8, Tower middleware, SSE for live scan updates.
- UI: Maud 0.27 + HTMX, server-rendered dashboard, no JS framework.
- Database: PostgreSQL via sqlx 0.8, compile-time checked queries, JSONB for structured findings and judge evidence.
- Jobs: apalis 0.7 with PostgreSQL backend only for MVP.
- Git: prefer `gix` for Rust-native repository access; use `octocrab` for GitHub API, `gitlab` crate for GitLab, and `reqwest` for Bitbucket.
- Static parsing: tree-sitter 0.26 with Python, JavaScript, TypeScript, Bash, YAML, JSON, TOML grammars.
- ML inference: `ort` 2.0 with bundled ONNX Runtime and CPU-only default execution provider.
- Policy: Rego via `regorus` or a small built-in policy DSL for MVP, with Rego favored once policy complexity grows.
- Observability: OpenTelemetry Rust for traces, metrics, and structured logs.

**Authentication boundary:**
No bundled identity provider in v1. The app must default to internal-only deployment and support BYO reverse-proxy auth through trusted headers. Audit events should still be captured from trusted actor headers when present, otherwise recorded as `system` or `unknown`. Full OIDC/SAML/RBAC can land later without changing the core data model.

### Pillar 1: Org-Wide Inventory and Discovery

Skill Issue should maintain a durable inventory of agent assets across connected Git organizations.

**Assets to inventory:**
- Repositories, default branches, relevant refs, owners, teams, last scan status.
- Agent configs: `SKILL.md`, `.cursor/rules`, `.claude/commands`, `.agent.md`, `.instructions.md`, `copilot-instructions.md`, `mcp.json`.
- MCP servers, tools, tool descriptions, input schemas, output schemas, annotations, transport type, command declarations.
- Code-adjacent execution files: Python utilities, JS/TS scripts, Bash scripts, Makefiles, Dockerfiles, GitHub Actions, Git hooks found in repo content.
- Dependency manifests: `package.json`, lockfiles, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, Docker image references.

**Core outputs:**
- Stable asset fingerprints.
- Repo-level and org-level risk posture.
- Asset history across scans.
- Ownership and review status.

### Pillar 2: Static Analysis and Cross-File Validation

Keep the MVP static/offline by default. Do not execute untrusted MCP servers or skills in the baseline path.

**Analyzers:**
- Cross-file taint tracker using tree-sitter ASTs and conservative source/sink rules.
- Git hook and workflow inspector for hidden execution surfaces.
- Dependency risk analyzer for unpinned downloads, remote install scripts, suspicious package names, unverifiable external dependencies, and lockfile drift.
- MCP tool snapshotter and schema diff engine.
- Description/behavior mismatch detector using SLM judges and code/text embeddings.
- Secret-adjacent pattern detector with aggressive redaction before persistence.

**MCP-specific checks:**
- Tool description changed without version/ref change.
- Tool schema added sensitive parameters or broader outputs.
- Tool references another server’s tool or attempts tool shadowing.
- New network/file/destructive capability appears in text, schema, scripts, or workflows.
- Stdio command changed or now downloads code at runtime.

### Pillar 3: SLM Judge Panel

Use local SLMs as fast, cheap, deterministic semantic triage. This is a cost and privacy advantage over cloud-only semantic analysis.

**Default model pack:**
Ship at least five independent local judges. The MVP target is six, with specialist models only invoked on relevant snippets so CPU scans stay practical. Size estimates are for exported ONNX packages; the default runtime should prefer INT8 quantized weights when benchmark quality stays acceptable, while model cards retain the FP32 source metadata.

| Judge | Candidate model | Approx size | What it does / excels at |
| --- | --- | ---: | --- |
| Fast Screener | `sentence-transformers/all-MiniLM-L6-v2` | ~90 MB FP32 / ~25 MB INT8 | Fast semantic embeddings for cheap triage, duplicate grouping, finding clustering, and routing assets to specialist judges. |
| Injection Sentinel | `ProtectAI/deberta-v3-base-prompt-injection-v2` | ~740 MB FP32 / ~190 MB INT8 | Prompt injection and instruction-override detection in natural-language tool descriptions, prompts, rules, and agent instructions. |
| Intent Classifier | `MoritzLaurer/deberta-v3-base-zeroshot-v1.1-all-33` | ~740 MB FP32 / ~190 MB INT8 | Zero-shot classification of intent labels such as benign automation, credential access, destructive action, network exfiltration, and policy bypass. |
| Code-Description Judge | `microsoft/unixcoder-base` | ~500 MB FP32 / ~125 MB INT8 | Code/text alignment for detecting mismatch between what an MCP tool or skill says it does and what adjacent scripts or commands appear to do. |
| Security Domain Judge | `jackaduma/SecBERT` | ~340 MB FP32 / ~85 MB INT8 | Cybersecurity vocabulary and threat-category understanding for mapping findings to credential theft, persistence, lateral movement, supply chain, and impact taxonomies. |
| Exfiltration Judge | `skill-issue/exfiltration-minilm-l6` custom fine-tune | ~90 MB FP32 / ~25 MB INT8 target | Project-owned classifier for environment reads, private file harvesting, token/key patterns, archive creation, and network-send combinations. |

Model-pack v1 should treat `all-MiniLM-L6-v2`, `ProtectAI/deberta-v3-base-prompt-injection-v2`, `MoritzLaurer/deberta-v3-base-zeroshot-v1.1-all-33`, `microsoft/unixcoder-base`, and `jackaduma/SecBERT` as public upstream candidates. The exfiltration judge is a Skill Issue fine-tune trained from curated benign/malicious examples because this category is too product-specific to outsource completely to a generic classifier.

**Packaging discipline:**
- Bundle a small default ONNX model pack in the Docker image.
- Include checksums, model cards, training dataset references, license metadata, and expected input/output schemas.
- Publish model packs to Hugging Face separately, but do not require runtime downloads.
- Larger or experimental models become optional image layers or mounted model packs.
- Record exact file size, parameter count, quantization mode, tokenizer files, license, upstream revision, and benchmark scores in `models/default-pack/model-pack.json`.

**Consensus:**
- Fast screener routes to specialist judges.
- Specialist verdicts are confidence-weighted.
- High-disagreement results are marked for review or optional LLM tiebreaking.
- Store judge verdicts and evidence snippets, not raw full prompts or traces by default.
- No single model should block an asset by itself until its category-specific benchmark passes a minimum precision gate; static findings and policy rules remain the deterministic source of hard blocks.

### Pillar 4: Provenance and Drift

Provenance is a first-class differentiator.

**Checks:**
- `PROVENANCE.json` or compatible manifest with source URL, commit/ref, content hashes, dependency lock hashes, signer/build identity, scanner version, policy version, timestamp.
- Sigstore/cosign verification where available.
- SLSA/in-toto-compatible attestations where available.
- Rug-pull detection through content hash and tool/schema/description diffs.
- Publisher/source reputation signals: repo age, maintainer activity, signed commits/tags, release cadence, dependency pinning.

**Evidence store:**
- Every finding links to scan ID, asset ID, policy version, scanner version, model pack version, evidence snippet, and reviewer state.
- Raw artifacts are disabled by default; if enabled, store locally with TTL, size caps, redaction, and content-addressed paths.

**Phase 4 provenance foundation:**
- Emit a provenance report for every CLI scan, either embedded in JSON output or written through `--provenance-out`.
- Capture repository root, remote URL, current branch, HEAD commit, dirty working tree status, scanner version, policy version, model-pack version, aggregate content hash, asset hashes, MCP command/tool-schema hashes, and dependency lockfile hashes.
- Store scan-level provenance reports in PostgreSQL for server-backed scans and expose score/evidence in the scan UI and `/scans/{id}/provenance` JSON.
- Treat unsigned or dirty local scans as usable for developer feedback but not production approval.
- Record Sigstore/cosign verification status when artifacts and verifier configuration are available.
- Preserve evidence nuance with passed, partial, failed, and not-applicable check statuses; use the score as evidence while keeping production gating in policy.

### Pillar 5: Policy, Workflow, and Exports

This is the governance layer competitors do not fully provide in a self-hosted, vendor-neutral form.

**Policy-as-code:**
- Admission policies such as: block unpinned remote downloads, require review for finance/destructive tools, deny new stdio MCP servers without approval, warn on workspace-read plus network-send combinations, require provenance for production-approved assets.
- Policy versioning and evaluation history.

**Workflow:**
- Baselines for existing accepted risk.
- Suppressions/exceptions with owner, reason, expiry, and linked finding IDs.
- Reviewer queue for high-risk changes.
- Severity normalization and risk scoring across scanner, policy, provenance, and SLM signals.
- Audit log for scans, exports, policy changes, exceptions, and finding status changes.

**Exports:**
- JSON for automation.
- SARIF 2.1.0 for GitHub Code Scanning and compatible systems.
- Model-card-style report for each SLM model pack.
- SBOM/VEX/ML-BOM-style exports via CycloneDX-compatible formats.
- OpenTelemetry metrics/logs/traces for SIEM/observability integration.

### Pillar 6: Optional Dynamic Lab Mode

Dynamic analysis is valuable and strategically important, but too risky for the default v0.1 scan path. The MVP should remain static/provenance-first while Phase 5 is designed as a separate opt-in lab track.

**Scope:**
- Linux-only lab workers in a separate `skill-issue-lab` binary/crate.
- Explicit opt-in per run or policy rule; no default CLI/server execution.
- Static scan, provenance, and policy gate must run before execution.
- Server acts as control plane; lab worker runs isolated jobs and returns redacted evidence.
- No raw body capture by default.

**Safety requirements:**
- Rootless Docker/Podman where possible.
- No Docker socket inside analyzed containers.
- Drop all capabilities by default.
- Read-only filesystem except controlled input/output volumes.
- CPU, memory, process, and wall-clock limits.
- Default-deny egress with allowlist profiles.
- Signed/pinned worker images.
- Redaction before persistence.
- Canary credentials and honeypot files only in lab contexts.

**v0.1 boundary:**
- No dynamic execution in v0.1 default builds.
- Reserve evidence/schema concepts and policy language only.
- Treat dynamic lab as v0.2+ or explicitly experimental until the threat model, worker isolation, and cleanup tests pass.

**Future improvements:**
- Rust-native HTTP proxy instead of Python `mitmproxy`.
- gVisor or Firecracker for higher isolation.
- eBPF-based monitoring for Linux worker fleets.
- Endpoint/MDM fleet mode only after the lab worker threat model is mature.

### Pillar 7: Ground Truth Dataset

Build the dataset before competitors do.

**Sources:**
- Invariant Labs tool poisoning, WhatsApp MCP, GitHub MCP cases.
- Greshake et al. indirect prompt injection.
- InjecAgent benchmark.
- MITRE ATLAS case studies and techniques.
- OWASP Top 10 for LLM Applications 2025.
- Snyk skills ecosystem reports.
- Synthetic malicious and benign skill/MCP examples generated by red-team workflows.

**Taxonomy:**
- Credential theft and data exfiltration.
- Resource exhaustion and denial-of-wallet.
- Prompt injection and instruction override.
- Supply chain compromise and rug pull.
- Lateral movement across agent configs and tools.
- RAG/tool/context poisoning.
- Covert channels and indirect exfiltration.
- Accuracy and reliability degradation.

## Steps

### Phase 0: Research and Dataset Foundation
1. Compile public attack research and map it to a Skill Issue taxonomy.
2. Build labeled benign/malicious examples for skills, MCP tools, configs, and utility scripts.
3. Define evaluation metrics: precision, recall, false-positive rate by category, time-to-scan, and storage footprint.

### Phase 1: Minimal Governance MVP
4. Create Rust workspace and single Axum/Maud/HTMX server binary.
5. Add PostgreSQL schema with sqlx migrations for orgs, repos, assets, scans, findings, policies, exceptions, audit events, model packs, and provenance records.
6. Add apalis PostgreSQL job queue for repo sync and scan jobs.
7. Implement GitHub App connector first; add GitLab and Bitbucket later.
8. Implement asset inventory and file discovery.
9. Implement MCP snapshotting and schema/description diffing.
10. Implement canonical full-scan JSON exports and SARIF 2.1.0 exports with rule metadata.
11. Implement audit logging and trusted-header actor capture for BYO auth deployments.

### Phase 2: Static Analysis and Policy
12. Implement tree-sitter static analyzers for Python, JS/TS, Bash, YAML/JSON/TOML.
13. Implement git hook, workflow, dependency, remote-download, and secret-adjacent detectors.
14. Implement policy-as-code with a minimal built-in policy engine first; evaluate `regorus` when policies need Rego compatibility.
15. Add baselines, exceptions, reviewer state, and risk scoring.

### Phase 2.5: CLI Provenance Foundation (complete)
- Add CLI provenance output before the full server-backed provenance system.
- Capture Git source/ref/dirty-state metadata, scanner version, policy version, model-pack version, asset hashes, lockfile hashes, and MCP command hashes.
- Add `--mode developer|production` and provenance-aware policy decisions that distinguish developer feedback scans from production-approval scans.

### Phase 3: SLM Judge Panel (code complete, artifact blocked)
16. Lock the default six-judge model pack listed in Pillar 3 and verify licenses, upstream revisions, tokenizer compatibility, and ONNX export paths. Metadata validation is implemented through `skill-issue models inspect`, and public upstream model revisions are pinned to exact Hugging Face commit SHAs. The custom exfiltration judge remains pinned to the future `dataset-freeze-0.1.0` revision until training data exists.
17. Export and quantize model weights, then generate `model-pack.json` with checksums, exact sizes, licenses, model cards, input/output schemas, and benchmark metadata. Runtime readiness verification is implemented through `skill-issue models verify`; actual ONNX exports, tokenizer bundles, checksums, and passing benchmark gates remain external artifact work.
18. Implement the `ort` inference service in Rust with batched CPU inference, per-model timeouts, and redacted evidence windows. The Rust judge API, artifact verification, and deterministic preview backend are implemented; the actual `ort` backend is intentionally gated until ONNX artifacts are bundled.
19. Implement screener routing, specialist judges, confidence-weighted consensus, and disagreement escalation. Deterministic preview routing and consensus are implemented and available through `skill-issue scan --judges`.
20. Train the custom exfiltration judge, add optional LLM tiebreaker hook disabled by default, and publish model-pack benchmark reports and drift tests. A Phase 3 benchmark dataset and runner are implemented through `skill-issue models benchmark`; custom model training and optional LLM tiebreaking remain future artifact/model work.

### Phase 4: Provenance (complete)
21. Draft `PROVENANCE.json` spec compatible with SLSA/in-toto concepts. Implemented in `docs/PROVENANCE.md`, `docs/PHASE4_PROVENANCE_DESIGN.md`, and the `statement` field of scan provenance reports.
22. Implement content-hash tracking, tool-schema drift, source/ref tracking, and lockfile tracking. Implemented through aggregate content/lockfile/MCP digests, MCP tool-schema hashes, and scan-level persistence.
23. Add Sigstore/cosign verification where available. Implemented as optional verification for `PROVENANCE.json` signatures when cosign artifacts and verifier identity/issuer settings are present.
24. Add provenance score and evidence report. Implemented as a 100-point score with persisted evidence checks and server UI/JSON exposure.

### Phase 5: Optional Dynamic Lab (planned after v0.1 core and ONNX/tokenizer runtime)
25. Draft the dynamic lab threat model and design. Planned in `docs/PHASE5_DYNAMIC_LAB_DESIGN.md`; implementation remains gated behind an explicit experimental worker path.
26. Define lab job, sandbox profile, observation, canary, and artifact-retention schemas without executing untrusted code in the default product.
27. Create a separate Linux `skill-issue-lab` worker profile with rootless runtime, strict limits, no Docker socket exposure, no host write mounts, and default-deny egress.
28. Add canary/honeypot generation for lab runs only, with redaction and audit events before persistence.
29. Add controlled MCP/script behavior probes gated by policy and compare observed behavior against static intent and historical baseline.
30. Evaluate gVisor/Firecracker and eBPF observation after Docker/Podman lab mode is stable.

### Phase 6: Expansion
31. Add GitLab and Bitbucket connectors.
32. Add Helm chart.
33. Add CycloneDX SBOM/VEX/ML-BOM exports.
34. Add OpenTelemetry dashboards and SIEM integrations.
35. Add auth/RBAC provider integration.
36. Build separate CLI repository that can run local developer scans and report to the server.

## Relevant Files

- `Cargo.toml` — workspace root.
- `docker-compose.yml` — minimal app + postgres deployment.
- `deploy/ferron/ferron.kdl` — optional Ferron appliance ingress profile.
- `Dockerfile` — Rust binary plus default model-pack metadata; ONNX weights are added once artifacts land.
- `crates/skill-issue-server/` — Axum server, Maud views, routes, jobs.
- `crates/skill-issue-scanner/` — shared scan orchestration for CLI and server flows.
- `crates/skill-issue-db/` — sqlx models, migrations, query helpers.
- `crates/skill-issue-connectors/` — webhook signature verification; Git provider connectors land in Phase 6.
- `crates/skill-issue-inventory/` — asset discovery, fingerprinting, MCP snapshots.
- `crates/skill-issue-analyzers/` — tree-sitter static analyzers and rule engine.
- `crates/skill-issue-policy/` — policy evaluation, baselines, exceptions.
- `crates/skill-issue-judges/` — model-pack metadata, artifact verification, deterministic judge preview, consensus.
- `crates/skill-issue-provenance/` — provenance manifest, signatures, drift.
- `crates/skill-issue-exports/` — canonical full-scan JSON, SARIF, CycloneDX-style exports.
- `crates/skill-issue-audit/` — audit events and redaction utilities.
- `crates/skill-issue-lab/` — planned optional dynamic lab worker crate; not part of the default v0.1 runtime.
- `models/default-pack/` — bundled model-pack metadata; ONNX weights and tokenizer artifacts land with the real SLM runtime track.
- `training/` — non-runtime Python fine-tuning/export scripts.
- `datasets/` — curated training and benchmark data.
- `benchmarks/` — scanner and judge evaluation harness.
- `tests/fixtures/` — benign and malicious sample assets.
- `helm/` — future enterprise deployment.

## Verification

1. Unit-test each analyzer against benign and malicious fixtures.
2. Validate SARIF output against GitHub Code Scanning requirements.
3. Validate MCP snapshot diffs: unchanged, renamed, schema-expanded, description-poisoned, and command-changed cases.
4. Test policy decisions and exception expiry behavior.
5. Test redaction before storage for findings, traces, model inputs, and exports.
6. Benchmark SLM judge precision/recall/F1 by category and model-pack version.
7. Benchmark scan time and storage footprint on small, medium, and large org fixtures.
8. Test audit log coverage for scan creation, exports, policy changes, and exception changes.
9. Compare findings against Cisco Skill Scanner and Snyk Agent Scan where applicable; Skill Issue should match relevant known issues and add inventory/provenance/drift/governance findings.
10. For lab mode only: test container limits, no Docker socket exposure, default-deny egress, no host mounts, and artifact TTL cleanup.

## Risk Analysis: Why This Might Not Be A Good Idea

1. **Cisco and Snyk can move into this space.** Cisco already has strong scanning primitives; Snyk already has agent/MCP discovery and enterprise distribution. They could add provenance or governance faster than expected.
2. **Detection quality is hard.** SLM judges can reduce cost but do not solve ambiguity, false positives, or novel attacks. Bad precision would make the product noisy.
3. **Self-hosted SaaS adds operational burden.** Even a small Postgres-backed Rust app needs deployment, backups, upgrades, TLS/ingress, and support.
4. **Org-wide source visibility makes the tool sensitive.** Without careful auth boundaries, redaction, retention, and audit logs, the scanner becomes a high-value internal target.
5. **Dynamic analysis is dangerous.** Starting MCP servers or skills can execute arbitrary commands. Lab mode needs an explicit threat model and strong containment.
6. **The ecosystem may fragment.** Agent assets are not standardized across Cursor, Claude, Codex, MCP, VS Code, GitHub, and future platforms.
7. **Model licensing and packaging can get messy.** Bundled weights need clear licenses, model cards, checksums, and upgrade paths.
8. **Open dataset work is dual-use.** Publishing malicious examples requires responsible framing, labels, and safeguards.
9. **Monetization is not immediate.** Apache 2.0 builds trust, but fully open source means revenue would depend on services, hosted enterprise, support, or later add-ons.

## Validation: Why This Is Still A Good Idea

1. **The wedge is durable governance, not scanner novelty.** Existing tools find issues; Skill Issue can become the private evidence system that tracks what exists, what changed, who accepted it, and why it is allowed.
2. **Self-hosted privacy matters.** Agent configs, tool descriptions, prompts, and source files can reveal internal business logic. Many companies will prefer local analysis over third-party APIs.
3. **Provenance and drift are real gaps.** Tool/schema/description changes, rug pulls, and source/ref drift are not solved by point-in-time scanning.
4. **MCP gives structured leverage.** Tool descriptions, schemas, annotations, and list-change notifications make snapshotting and diffing technically feasible.
5. **Rust plus Postgres keeps footprint low.** One app binary and one database can cover UI, API, jobs, static scanning, exports, and model inference.
6. **Local SLM judges are a strong cost advantage.** CPU inference avoids per-scan API costs and supports private deployments.
7. **Policy workflows are what security teams need.** Baselines, exceptions, SARIF, audit logs, and reviewer queues make findings operationally useful.
8. **Ground truth has standalone value.** The dataset, taxonomy, benchmarks, and model cards can establish credibility even before advanced dynamic analysis lands.

## Future Features Missing From Cisco/Snyk Worth Adding

1. Vendor-neutral, self-hosted org-wide inventory of skills, MCP servers, tools, prompts, configs, schemas, and provenance.
2. MCP tool snapshotting, schema diffing, and description drift detection.
3. Provenance manifest and signature verification for agent assets.
4. Policy-as-code admission control for agent assets.
5. Reviewer workflow with baselines, suppressions, exception expiry, and owners.
6. SARIF for MCP/tool/governance findings, not only code findings.
7. CycloneDX SBOM/VEX/ML-BOM and model-card exports.
8. OpenTelemetry-native metrics, traces, and audit events.
9. Egress intent classification and optional future enforcement profiles.
10. Secret canaries and honeypot files for lab-only dynamic analysis.
11. SLM judge panel with local model packs, reproducible model metadata, and benchmark reports.
12. Separate developer CLI that can scan locally and optionally report to the central server.
