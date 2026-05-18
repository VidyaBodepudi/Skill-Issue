# Skill Issue

Skill Issue scans locally cloned repositories for agentic AI security governance risks: agent config files, MCP declarations, scripts, workflows, dependency manifests, and hidden execution surfaces.

## CLI MVP

Run a local scan from the repository root:

```powershell
cargo run -p skill-issue-cli -- scan .
```

Developer mode is the default. It is meant for local feedback and does not fail unless the scan itself fails or `--fail-on` is set.

Emit machine-readable JSON:

```powershell
cargo run -p skill-issue-cli -- scan . --format json
```

JSON output is the canonical v0.1 scan envelope: source, mode, summary, assets, findings, MCP snapshots, policy report, provenance report, and optional deterministic judge-panel preview. The provenance report includes Git metadata, scanner version, policy version, model-pack version, asset hashes, lockfile hashes, MCP command and tool-schema hashes, optional cosign status, and an explainable provenance score.

Run the deterministic Phase 3 judge preview during a scan:

```powershell
cargo run -p skill-issue-cli -- scan . --judges --format json
```

The judge preview uses deterministic preview logic for routing, consensus, and benchmarkable behavior while ONNX artifacts are being prepared. It is not live ONNX inference.

Emit SARIF for code-scanning systems:

```powershell
cargo run -p skill-issue-cli -- scan . --format sarif
```

SARIF output includes stable rule metadata and result rule indexes for GitHub Code Scanning and compatible systems.

Fail CI when built-in policy reaches a threshold:

```powershell
cargo run -p skill-issue-cli -- scan . --format sarif --fail-on block
```

Supported `--fail-on` values are `never`, `warn`, `review`, and `block`. The default is `never`, so exploratory local scans only fail when the scan itself fails.

Run a production-approval scan:

```powershell
cargo run -p skill-issue-cli -- scan . --mode production
```

Production mode adds blocking policy decisions when provenance is missing, Git HEAD cannot be resolved, or the working tree is dirty. If `--fail-on` is omitted, production mode defaults to `block`; pass `--fail-on never` only when you want a report without a gating exit code.

Write provenance to a standalone file while keeping the normal scan output on stdout:

```powershell
cargo run -p skill-issue-cli -- scan . --provenance-out .skill-issue/provenance.json
```

Dirty or non-Git scans are still allowed for developer feedback, but their provenance marks them as blocked for production approval.

The Phase 4 provenance contract is documented in [docs/PROVENANCE.md](docs/PROVENANCE.md), with the implementation shape in [docs/PHASE4_PROVENANCE_DESIGN.md](docs/PHASE4_PROVENANCE_DESIGN.md). Server-backed scans persist scan assets, findings, MCP snapshots, policy decisions, drift events, and the full provenance report. Stored scans expose `/scans/{id}/json`, `/scans/{id}/sarif`, and `/scans/{id}/provenance` for automation. If `cosign` verification artifacts are present at the scan root, set `SKILL_ISSUE_COSIGN_IDENTITY` and `SKILL_ISSUE_COSIGN_ISSUER` to verify them during the scan.

Dynamic lab execution is intentionally not part of the default v0.1 scan path. The Phase 5 plan is documented in [docs/PHASE5_DYNAMIC_LAB_DESIGN.md](docs/PHASE5_DYNAMIC_LAB_DESIGN.md): lab mode should be Linux-only, opt-in, isolated in a separate worker, and gated by static scan and policy evidence before any untrusted code runs.

Inspect the default Phase 3 judge model pack metadata:

```powershell
cargo run -p skill-issue-cli -- models inspect
```

Emit the model-pack inspection as JSON:

```powershell
cargo run -p skill-issue-cli -- models inspect --format json
```

The default pack is metadata-only until ONNX exports, checksums, and benchmark gates are complete.

Verify whether a model pack is runtime-ready:

```powershell
cargo run -p skill-issue-cli -- models verify
```

`models verify` exits nonzero until bundled ONNX artifacts, tokenizer files, checksums, and benchmark gates are all ready. This is expected for the current metadata-only Phase 3 pack.

Run the Phase 3 judge benchmark dataset:

```powershell
cargo run -p skill-issue-cli -- models benchmark
```

Emit benchmark results as JSON:

```powershell
cargo run -p skill-issue-cli -- models benchmark --format json
```