# Phase 4 Provenance Design

Phase 4 makes provenance a scan-level evidence contract shared by the CLI, server, policy engine, exports, and future reviewer workflow. It deliberately keeps SLM inference non-blocking: model-panel readiness can improve semantic triage later, while provenance remains deterministic and available for every scan.

## Shape

The durable Phase 4 shape has five layers:

1. Report contract: `ProvenanceReport` is the canonical Rust and JSON shape. It carries source, scanner, approval, content, asset, lockfile, MCP declaration, signature, and score evidence.
2. Interop envelope: `statement` embeds an in-toto Statement v1 envelope with SLSA provenance v1 predicate type. This is an evidence carrier, not a claim that local scans are reproducible hosted builds.
3. Persistence summary: `scan_provenance_records` stores one report per scan plus queryable summary columns for score, production approval, source commit/ref, dirty state, content hash, and lockfile hash.
4. Drift surface: MCP command hashes and tool-schema hashes are stored with snapshots so future scans can produce command and schema drift events.
5. Presentation/API: scan pages show provenance score, source/ref state, content hashes, and evidence checks; `/scans/{id}/provenance` returns the persisted report JSON.

## Evidence Statuses

Each score check includes both `status` and `passed`:

- `passed`: evidence is present and satisfies the check.
- `partial`: evidence is useful but incomplete, such as missing lockfiles or unconfigured signatures.
- `failed`: evidence was expected and failed, such as an invalid cosign verification.
- `not_applicable`: the check does not apply to this scan, such as no MCP declarations discovered.

`passed` remains for simple consumers. `status` is the preferred field for UI, reviewer workflow, and future policy language because it preserves partial and not-applicable states.

## Score Boundaries

The score is governance evidence, not the production gate by itself. Production policy still evaluates explicit approval facts such as Git metadata, clean working tree, and source commit availability. Signature verification improves the score when available, but missing signatures do not block developer scans.

Current score bands:

- `strong`: 80-100
- `review`: 55-79
- `weak`: 0-54

## Flow

1. Inventory discovers agent assets and MCP declarations.
2. Provenance builds aggregate content, lockfile, and MCP declaration hashes.
3. Git metadata determines production-approval eligibility.
4. Optional cosign verification records signature status when `PROVENANCE.json` artifacts and verifier settings are available.
5. Policy consumes provenance and emits warn/review/block decisions.
6. Server persistence stores scan facts, drift facts, policy decisions, and the full provenance report in one transaction.

## Deferred Work

The Phase 4 foundation intentionally defers source reputation, signed commit/tag verification, release cadence, dependency publisher reputation, reviewer-state retention, and raw artifact storage. Those belong in later governance/workflow phases and can build on the scan-level report without changing the core contract.