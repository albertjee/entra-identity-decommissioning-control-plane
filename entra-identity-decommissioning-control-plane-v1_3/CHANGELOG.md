# Changelog

## v1.3 — Hardening Release (2026-04-25)

### Guardrail Fixes (safety-critical)

- **`Test-DecomCanContinueAfterContainment` — Skipped now blocks in live mode.**
  In v1.2, a Skipped containment action (operator declined ShouldProcess) was allowed
  to pass the continuation check. In live mode this is a control gap — a skipped
  password reset or session revoke must halt the workflow. WhatIf mode still permits
  Skipped (dry-run is expected). Context is now passed to the function to distinguish modes.

- **`Confirm-DecomPhase` — returns `$false` instead of throwing in NonInteractive mode.**
  In v1.2, NonInteractive+no-Force threw an exception, which bypassed the evidence
  chain entirely. Now returns `$false` — callers emit a structured Blocked result
  so the audit trail remains intact. Workflow emits named gate results
  ('Containment Phase Gate', 'License Removal Gate') for full report visibility.

- **`Assert-DecomEvidenceIntegrity` — full forensic field contract.**
  v1.2 only checked non-null and ActionName. v1.3 validates: ActionName, StepId,
  Phase, Status, TimestampUtc, TargetUPN, ControlObjective, RiskMitigated.
  All required for the "forensic-grade" audit defensibility claim.

### Readability Fix

- **`Licensing.psm1` expanded into readable blocks.**
  Dense minified style from v1.1 replaced with standard PowerShell formatting.
  Logic unchanged — readability and maintainability improved for public repo confidence.

### Workflow Fix

- **`Invoke-DecomWorkflow` passes `$Context` to `Test-DecomCanContinueAfterContainment`.**
  Required for WhatIf-aware containment continuation check introduced above.

### Pester Coverage (v1.3 — 32 tests across 10 context blocks)

New tests added:
- Evidence integrity: passes full result, throws on null, throws on missing ControlObjective, throws on missing RiskMitigated
- Containment continuation: live-mode Skipped blocks, WhatIf Skipped allowed, all-Success allowed
- Confirm-DecomPhase: Force returns true, WhatIf returns true, NonInteractive+no-Force returns false (not throws)
- Workflow ValidationOnly: containment actions absent from results, no StopReason
- Workflow confirmation gate: declined gate emits Blocked result with StopReason
- Group-based license blocker: Blocked status + blocker message when group SKUs detected
- HTML report: ManualFollowUp content rendered in output
- Phase engine: Completed on success, Failed+rethrow on error

## v1.2 — Spec Alignment + Regression Fix Release (2026-04-25)
- 6 regressions fixed from v1.1.
- StepId, ManualFollowUp, mailbox forwarding/delegation, guest warning added.
- MFA methods in snapshot, print stylesheet, ManualFollowUp in HTML report.

## v1.1 — Remediation Release (2026-04-25)
- Modulo bias fix, ShouldProcess null fix, PIM roles, group license detection,
  compliance phase wrapper, auth evidence separated.

## v1.0 — Initial Release (2026-04-25)
- Production-safety release candidate for controlled tenant validation.
