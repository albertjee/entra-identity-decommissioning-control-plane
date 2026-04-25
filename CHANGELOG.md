# Changelog

## v1.4 — Hygiene + Spec Completion Release (2026-04-25)

### Fixes

- **Duplicate `Assert-DecomEvidenceIntegrity` removed from `Evidence.psm1`.**
  Shallow version (null + ActionName only) was exported alongside the full forensic
  contract version in `Guardrails.psm1`. Removed from Evidence.psm1 entirely.

- **`Add-DecomEvidenceEvent` now includes `CorrelationId` and `EvidenceLevel`.**
  Context had these fields but they were not flowing into NDJSON event records,
  making standalone evidence file analysis difficult.

- **`AppRoleAssignment.ReadWrite.All` downgraded to `AppRoleAssignment.Read.All`.**
  Lite discovery does not mutate app role assignments. Write scope was over-privileged.
  `Get-DecomRequiredGraphScopes` exported from Auth.psm1 for testability.

- **`Test-DecomCriticalPhaseSuccess` hardened — Skipped no longer accepted.**
  Previously allowed Skipped as a passing status, which was a latent risk if
  the function was reused outside the containment context. Now only Success
  and Warning are accepted. Containment-specific WhatIf-aware logic remains
  in `Test-DecomCanContinueAfterContainment`.

- **Phase names aligned throughout.**
  Snapshot phase was `BeforeActionSnapshot` in Discovery but `PreActionSnapshot`
  in the workflow. Now consistently `PreActionSnapshot` / `PostActionSnapshot`
  everywhere — workflow, discovery, and tests.

- **Version strings updated to v1.4** across Start-Decom.ps1, Models.psm1,
  Reporting.psm1, and workflow return summary.

- **`Reset-DecomStepCounters` added to Models.psm1.**
  Prevents StepId counter drift in long PowerShell sessions and enables
  clean test isolation.

### Spec Completion

- **Full mailbox delegation discovery added to identity snapshot.**
  v1.3 only captured `GrantSendOnBehalfTo`. v1.4 adds:
  - `FullAccess` permissions via `Get-MailboxPermission`
  - `SendAs` permissions via `Get-RecipientPermission`
  Evidence keys: `FullAccessCount`, `SendAsCount`, `SendOnBehalfCount`.
  ManualFollowUp items generated for each delegation type detected.

### Pester Coverage (v1.4 — 54 tests across 14 context blocks)

New tests added:
- Version hygiene: workflow summary v1.4, Start-Decom.ps1 contains v1.4
- Auth scope contract: exactly 7 scopes, AppRoleAssignment.Read.All not ReadWrite
- Evidence: CorrelationId in event, EvidenceLevel in event, Evidence.psm1 does not export integrity check
- StepId reset behavior: counters reset correctly between runs
- Guardrail hardening: Test-DecomCriticalPhaseSuccess rejects Skipped
- Phase name alignment: Discovery.psm1 and workflow use consistent names
- Delegation schema: FullAccessCount and SendAsCount evidence keys

## v1.3 — Hardening Release (2026-04-25)
## v1.2 — Spec Alignment + Regression Fix Release (2026-04-25)
## v1.1 — Remediation Release (2026-04-25)
## v1.0 — Initial Release (2026-04-25)
