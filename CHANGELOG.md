# Changelog

## v1.5a — Stabilization Release (2026-04-25)

v1.5a is a post-review stabilization release following the v1.5 security hardening milestone.
It introduces no new functional scope or authority and does not modify the threat model,
privilege profile, or guardrail logic documented in `docs/threat-model-v1.5.md`.
The release exists solely to add security documentation artifacts (security posture summary,
red-team scenario analysis, refined SECURITY.md) after initial audit review.

**No code changes. No new threat surface. Existing risk acceptance remains valid.**

## v1.5 — Security Hardening Release (2026-04-25)

### Evidence Sealing (tamper-evidence)
- **Hash-chain sealing added to `Evidence.psm1`** — every NDJSON event includes
  `PrevHash` and `EventHash`. Any edit, deletion, or reorder of events breaks the chain.
- **`evidence.manifest.json` written at end of every run** — contains `FinalEventHash`,
  `RunId`, `CorrelationId`, `OperatorUPN`, `TicketId`, and event count as integrity anchor.
- **`SealEvidence` context flag** — default `$true`. Use `-NoSeal` for dev/test only.
- **`Get-DecomSha256Hex`** and **`Seal-DecomEvidenceEvent`** exported from Evidence.psm1.

### Operator Identity (repudiation resistance)
- **`OperatorUPN` and `OperatorObjectId` added to every evidence event** — resolved from
  `Get-MgContext` post-authentication in `Start-Decom.ps1`.
- **`OperatorUPN` and `TicketId` included in `evidence.manifest.json`** summary.
- **Workflow return summary** now includes `OperatorUPN`, `TicketId`, and `Sealed` flag.

### Force Mode Governance
- **`TicketId` mandatory in `-Force -NonInteractive` mode** — `Start-Decom.ps1` exits with
  error if TicketId is not supplied in automation mode. Provides change/ticket traceability.

### Repo Security Posture
- **`SECURITY.md` added** — vulnerability disclosure process, severity classification,
  operational security requirements, and known design limitations documented.
- **`docs/threat-model-v1.5.md` added** — full STRIDE-aligned threat model with asset
  inventory, trust boundaries, mitigations, residual risks, and evidence quality table.

### Pester Coverage (v1.5 — 41 tests across 11 context blocks)
New tests: SECURITY.md presence, threat model doc presence, version string v1.5,
SHA-256 determinism and sensitivity, Seal-DecomEvidenceEvent hash chain correctness,
tamper detection, SealEvidence default true, NoSeal flag, OperatorUPN in context,
TicketId governance enforcement, Write-DecomEvidenceManifest export, workflow summary fields.

## v1.4 — Hygiene + Spec Completion (2026-04-25)
## v1.3 — Hardening Release (2026-04-25)
## v1.2 — Spec Alignment + Regression Fixes (2026-04-25)
## v1.1 — Remediation Release (2026-04-25)
## v1.0 — Initial Release (2026-04-25)
