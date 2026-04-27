# Entra Identity Decommissioning Control Plane — Premium v2.0

> **Status:** Complete — batch engine, resume, state persistence, premium remediation phases, batch reporting, diff report, policy overlays, approval gate, and mailbox extended controls.
> Builds on top of Lite v1.5 without modifying any Lite modules.

---

## What Premium adds

Lite v1.5 decommissions one user per run. Premium v2.0 wraps the Lite workflow in a batch engine that processes N users sequentially, checkpoints state to disk after every entry, supports resuming interrupted runs, and adds premium remediation phases not available in Lite.

| Capability | Lite v1.5 | Premium v2.0 |
|---|---|---|
| UPNs per run | 1 | N (unlimited list) |
| Batch envelope | — | `New-DecomBatchContext` |
| Per-UPN lifecycle tracking | — | Pending → Running → Completed/Failed/Skipped |
| Checkpoint on disk | — | `Save-DecomBatchState` (JSON, atomic write) |
| Resume interrupted batch | — | `Restore-DecomBatchState` + `-ResumePath` |
| Batch roll-up summary | — | `Get-DecomBatchSummary` |
| Pre-flight approval gate | — | `Invoke-DecomBatchApproval` (with expiry enforcement) |
| Per-UPN policy overrides | — | `Read-DecomBatchPolicy` / `Get-DecomUpnPolicy` |
| Pre-run diff report | — | `Export-DecomBatchDiffReport` (HTML + JSON, risk-classified) |
| Litigation hold | — | `Set-DecomLitigationHold` |
| License removal | — | `Remove-DecomLicenses` |
| Device disable + wipe/retire | — | `Invoke-DecomDeviceRemediation` |
| App ownership removal | — | `Remove-DecomAppOwnership` |
| Azure RBAC removal | — | `Remove-DecomAzureRBAC` |
| Mail forwarding control | — | `Set-DecomMailForwarding` / `Remove-DecomMailForwarding` |
| Batch HTML/JSON reports | — | `Export-DecomBatchHtmlReport` / `Export-DecomBatchJsonReport` |
| Cross-UPN evidence manifest | — | `Write-DecomBatchEvidenceManifest` |
| Core workflow engine | `Invoke-DecomWorkflow` | same — called per UPN, unchanged |
| PS version | 5.1 | 5.1 (PS7 for v2.1 modules) |

---

## Pester Test Suites

**191/191 Premium tests passing. 41/41 Lite tests passing. 232 total.**

```powershell
# Lite suite — 41 tests (core single-UPN workflow)
Invoke-Pester .\tests\Decom.Tests.ps1 -Output Detailed

# Premium suite — 191 tests (batch control plane + remediation)
Invoke-Pester .\tests\Premium\ -Output Detailed
```

| Test File | Tests | Covers |
|---|---|---|
| `tests/Decom.Tests.ps1` | 41 | Lite workflow — evidence sealing, guardrails, phase engine |
| `tests/Premium/DecomBatch.Tests.ps1` | 57 | BatchContext, BatchState, BatchOrchestrator, resume flow |
| `tests/Premium/DecomBatchReporting.Tests.ps1` | 35 | JSON/HTML batch reports, evidence manifest |
| `tests/Premium/DecomPremiumRemediation.Tests.ps1` | 46 | Compliance, License, Device, AppOwnership, AzureRBAC |
| `tests/Premium/DecomV21.Tests.ps1` | 43 | BatchDiff, BatchPolicy, BatchApproval, MailboxExtended |
| `tests/Premium/DecomCoverageGap.Tests.ps1` | 10 | High-severity gap tests (GAP-05 through GAP-16) |

Pester v5.6.1 required. Tests use function stubs — no Graph or Exchange connectivity needed.

---

## Directory layout

```
src/
  Start-Decom.ps1                     # Lite single-UPN launcher
  Invoke-DecomWorkflow.ps1            # Lite workflow engine
  Modules/                            # Lite modules (14 modules)
  Premium/
    Start-DecomBatch.ps1              # Premium batch launcher
    Modules/
      BatchContext.psm1               # batch envelope, per-UPN entry management
      BatchState.psm1                 # JSON checkpoint: save / restore
      BatchOrchestrator.psm1          # Invoke-DecomBatch: sequential orchestrator
      BatchOrchestratorParallel.psm1  # parallel orchestrator (v2.1 — reserved)
      BatchReporting.psm1             # HTML/JSON batch reports + evidence manifest
      BatchDiff.psm1                  # pre-run diff report with risk classification
      BatchPolicy.psm1                # per-UPN policy overlays from JSON file
      BatchApproval.psm1              # pre-flight approval gate with expiry
      ComplianceRemediation.psm1      # litigation hold
      LicenseRemediation.psm1         # license removal
      DeviceRemediation.psm1          # device disable + Intune wipe/retire
      AppOwnership.psm1               # app registration + SPN ownership removal
      AzureRBAC.psm1                  # Azure RBAC direct assignment removal
      MailboxExtended.psm1            # mail forwarding control (v2.1)
      AccessRemoval.psm1              # group, role, OAuth, auth method removal

tests/
  Decom.Tests.ps1                     # Lite suite — 41 tests
  Premium/
    DecomBatch.Tests.ps1              # 57 tests — Phase 1 modules
    DecomBatchReporting.Tests.ps1     # 35 tests — BatchReporting
    DecomPremiumRemediation.Tests.ps1 # 46 tests — remediation modules
    DecomV21.Tests.ps1                # 43 tests — v2.1 modules
    DecomCoverageGap.Tests.ps1        # 10 tests — high-severity gap coverage

output/
  <BatchId>/
    batch-state.json                  # checkpoint file (resume anchor)
    batch-report.html                 # human-readable batch summary
    batch-report.json                 # machine-readable batch roll-up
    batch-evidence.manifest.json      # cross-UPN evidence integrity index
    batch-diff.html                   # pre-run WhatIf diff report
    batch-diff.json                   # machine-readable diff
    batch-approval.json               # approval audit record
    <sanitised-upn>/
      run.log
      evidence.ndjson
      report.json
      report.html
```

---

## Quick start

### New batch

```powershell
cd src\Premium

.\Start-DecomBatch.ps1 `
    -UpnList        alice@contoso.com, bob@contoso.com, carol@contoso.com `
    -TicketId       CHG-12345 `
    -EvidenceLevel  Forensic `
    -RemoveLicenses `
    -NonInteractive `
    -Force
```

### WhatIf dry run

```powershell
.\Start-DecomBatch.ps1 `
    -UpnList  alice@contoso.com, bob@contoso.com `
    -TicketId CHG-12345 `
    -WhatIfMode
```

### Resume an interrupted batch

```powershell
.\Start-DecomBatch.ps1 `
    -ResumePath 'C:\output\<BatchId>\batch-state.json'
```

### Resume — skip known-bad entries, retry the rest

```powershell
.\Start-DecomBatch.ps1 `
    -ResumePath 'C:\output\<BatchId>\batch-state.json' `
    -SkipFailed
```

---

## Module reference

### BatchContext.psm1

| Function | Description |
|---|---|
| `New-DecomBatchContext` | Creates the batch envelope. Pass `-UpnList` to pre-populate entries. |
| `New-DecomBatchEntry` | Adds a UPN to an existing batch. Idempotent — safe to call twice. |
| `Get-DecomBatchEntry` | Retrieves a single entry by UPN. Returns `$null` if not found. |
| `Set-DecomBatchEntryStatus` | Updates lifecycle status. Sets `StartedUtc` / `CompletedUtc` automatically. |
| `Get-DecomBatchSummary` | Returns roll-up counts and `AllDone` / `AnyFailed` flags. |

**Entry lifecycle:** `Pending` → `Running` → `Completed` / `Failed` / `Skipped` / `Resumed`

### BatchState.psm1

| Function | Description |
|---|---|
| `Get-DecomBatchStatePath` | Returns canonical path: `<OutputRoot>\<BatchId>\batch-state.json` |
| `Save-DecomBatchState` | Serialises batch to JSON. Atomic write via .tmp-then-copy. |
| `Restore-DecomBatchState` | Deserialises from JSON. Reconstructs typed object graph. |

### BatchOrchestrator.psm1

| Function | Description |
|---|---|
| `Invoke-DecomBatch` | Iterates actionable entries, calls Lite `Invoke-DecomWorkflow` per UPN, runs Premium remediation phases, checkpoints after every entry, returns `BatchResult`. |

**Idempotency rules:**

| Entry status | Behaviour |
|---|---|
| `Completed` | Always skipped |
| `Skipped` | Always skipped |
| `Running` (on resume) | Treated as interrupted — re-runs as `Resumed` |
| `Failed` | Re-runs by default; skipped if `-SkipFailed` |
| `Pending` / `Resumed` | Runs normally |

### BatchApproval.psm1

| Function | Description |
|---|---|
| `Invoke-DecomBatchApproval` | Validates pre-signed approval file. Enforces BatchId binding, TicketId match, Approved flag, and ExpiresUtc expiry. |
| `Get-DecomApprovalStatus` | Reads current approval record from disk. |

### BatchPolicy.psm1

| Function | Description |
|---|---|
| `Read-DecomBatchPolicy` | Loads and validates a JSON policy file. |
| `Get-DecomUpnPolicy` | Resolves effective policy for a UPN — merges DefaultPolicy with UPN-specific overrides. |
| `New-DecomBatchPolicyTemplate` | Generates a starter policy JSON file. |

### BatchReporting.psm1

| Function | Description |
|---|---|
| `Export-DecomBatchJsonReport` | Writes machine-readable JSON roll-up to `<BatchId>\batch-report.json`. |
| `Export-DecomBatchHtmlReport` | Writes print-ready HTML summary to `<BatchId>\batch-report.html`. |
| `Write-DecomBatchEvidenceManifest` | Writes cross-UPN evidence index with SHA-256 hashes to `<BatchId>\batch-evidence.manifest.json`. |

### BatchDiff.psm1

| Function | Description |
|---|---|
| `New-DecomBatchDiffEntry` | Creates a diff entry with risk inference (High/Medium/Low) and change type. |
| `Export-DecomBatchDiffReport` | Writes HTML + JSON pre-run diff report. |

### Premium Remediation Modules

| Module | Key Functions |
|---|---|
| `ComplianceRemediation.psm1` | `Set-DecomLitigationHold` |
| `LicenseRemediation.psm1` | `Get-DecomLicenseState`, `Remove-DecomLicenses` |
| `DeviceRemediation.psm1` | `Get-DecomDeviceState`, `Disable-DecomEntraDevices`, `Invoke-DecomDeviceRemediation` |
| `AppOwnership.psm1` | `Get-DecomAppOwnershipState`, `Remove-DecomAppOwnership` |
| `AzureRBAC.psm1` | `Get-DecomAzureRBACState`, `Remove-DecomAzureRBAC` |
| `MailboxExtended.psm1` | `Get-DecomMailForwardingState`, `Set-DecomMailForwarding`, `Remove-DecomMailForwarding` |

---

## Governance rules

- **TicketId is mandatory** when running `-Force -NonInteractive`.
- **Approval gate** (`Invoke-DecomBatchApproval`) must pass before `Invoke-DecomBatch` runs in production. Approval records are time-bound — expired approvals are rejected.
- **BYOD protection is locked** — devices with `TrustType = Workplace` receive selective retire only, never a full wipe, regardless of operator input.
- **Sole-owner protection** — app registrations where the target UPN is the only owner are flagged Warning and not removed automatically.
- The `-Force` flag applies to all UPNs in the batch. Use `-WhatIfMode` for pre-flight dry runs on large lists.

---

## Phases

| Phase | Status | Description |
|---|---|---|
| 1 | Complete | Batch engine, per-UPN lifecycle, resume, state persistence |
| 2 | Complete | Batch reporting, cross-UPN evidence manifest, premium remediation phases |
| 2.1 | Complete | Diff report, policy overlays, approval gate, mailbox extended controls |
| 3 | Planned | Group/role/OAuth/auth method removal automation |
| 4 | Reserved | Parallel execution (MaxParallel — PS5.1 runspace pool) |

---

## PS5.1 compatibility notes

- No 3-argument `Join-Path`
- No `ForEach-Object -Parallel` — sequential only in v2.0
- No `RandomNumberGenerator.Fill` — GUIDs via `[guid]::NewGuid()`
- No .NET 6+ APIs
- `ConvertTo-Json` / `ConvertFrom-Json` depth 6
- Ordered dictionaries use `System.Collections.Specialized.OrderedDictionary` with `OrdinalIgnoreCase` comparer for cross-module boundary stability
