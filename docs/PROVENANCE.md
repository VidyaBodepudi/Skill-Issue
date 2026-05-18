# PROVENANCE.json

Skill Issue emits a provenance report for every scan using schema `skill-issue.provenance/v1`. The report is designed to be directly useful as Skill Issue evidence while carrying an in-toto/SLSA-shaped statement for interoperability.

## Top-Level Fields

- `schema_version`: Skill Issue provenance schema version.
- `generated_at`: UTC timestamp for report generation.
- `statement`: in-toto Statement v1 envelope with SLSA provenance v1 predicate type.
- `source`: repository root plus Git remote, branch, HEAD commit, and dirty-state metadata when Git is available.
- `scanner`: scanner, policy, and model-pack versions used for the scan.
- `approval`: production approval candidate flag and reason.
- `content`: aggregate asset digest, lockfile digest, and MCP declaration digest.
- `assets`: per-asset path, kind, size, and SHA-256 fingerprint.
- `lockfiles`: dependency lockfile hashes included as resolved materials.
- `mcp_commands`: MCP command declaration hashes plus tool-schema hashes when configs expose tool schema metadata.
- `signatures`: optional Sigstore/cosign verification status for `PROVENANCE.json`.
- `score`: 100-point provenance score with check-by-check evidence. Each check includes a `status`, legacy `passed` boolean, point value, maximum point value, and message.

## SLSA/In-Toto Compatibility

The `statement` field uses `_type = https://in-toto.io/Statement/v1` and `predicateType = https://slsa.dev/provenance/v1`. Its `subject` digest is the aggregate scan content hash. Its predicate records the Skill Issue local scan builder, source parameters, scanner/policy/model-pack versions, Git material when available, dependency lockfile materials, and MCP declaration materials.

Skill Issue does not claim a hosted build service or reproducible build guarantee for local developer scans. The SLSA-shaped fields are evidence-carriers for governance and later attestation exchange.

## Cosign Verification

If `PROVENANCE.json`, `PROVENANCE.json.sig`, and `PROVENANCE.json.pem` exist at the scan root, Skill Issue attempts cosign verification when `cosign` is available and both environment variables are set:

- `SKILL_ISSUE_COSIGN_IDENTITY`
- `SKILL_ISSUE_COSIGN_ISSUER`

Without those files or settings, the report records the missing or unconfigured status and the scan continues. Cosign verification contributes to the provenance score only when it succeeds.

## Score Bands

- `strong`: 80-100
- `review`: 55-79
- `weak`: 0-54

The score is evidence, not policy by itself. Production policy still requires clean source provenance; signatures improve assurance but do not block local development scans.

Check statuses are:

- `passed`: evidence is present and satisfies the check.
- `partial`: evidence is useful but incomplete.
- `failed`: evidence was expected and failed.
- `not_applicable`: the check does not apply to this scan.

The broader Phase 4 shape is captured in [PHASE4_PROVENANCE_DESIGN.md](PHASE4_PROVENANCE_DESIGN.md).