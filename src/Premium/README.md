# Entra Identity Decommissioning Control Plane — Premium v2.0

> **Status:** Phase 1 complete — batch engine, resume, and state persistence.
> Builds on top of Lite v1.5 without modifying any Lite modules.

---

## What Premium adds

Lite v1.5 decommissions one user per run. Premium v2.0 wraps the Lite workflow in a batch engine that processes N users sequentially, checkpoints state to disk after every entry, and supports resuming interrupted runs without re-processing completed work.

| Capability | Lite v1.5 | Premium v2.0 |
|---|---|---|
| UPNs per run | 1 | N (unlimited list) |
| Batch envelope | — | `New-DecomBatchContext` |
| Per-UPN lifecycle tracking | — | Pending → Running → Completed/Failed/Skipped |
| Checkpoint on disk | — | `Save-DecomBatchState` (JSON, atomic write) |
| Resume interrupted batch | — | `Restore-DecomBatchState` + `-ResumePath` |
| Batch roll-up summary | — | `Get-DecomBatchSummary` |
| Core workflow engine | `Invoke-DecomWorkflow` | same — called per UPN, unchanged |
| PS version | 5.1 | 5.1 |

---

## Directory layout

```
src/
  Premium/
    Start-DecomBatch.ps1        # batch launcher (New + Resume parameter sets)
    Modules/
      BatchContext.psm1         # batch envelope, per-UPN entry management
      BatchState.psm1           # JSON checkpoint: save / restore
      BatchOrchestrator.psm1    # Invoke-DecomBatch: sequential orchestrator

tests/
  Premium/
    DecomBatch.Tests.ps1        # Pester v5 suite — 30+ tests across all modules

output/
  <BatchId>/
    batch-state.json            # checkpoint file (resume anchor)
    <sanitised-upn>/
      run.log                   # Lite log
      evidence.ndjson           # Lite hash-chained evidence
      report.json               # Lite JSON report
      report.html               # Lite HTML report
```

---

## Quick start

### New batch

```powershell
cd src\Premium

.\Start-DecomBatch.ps1 `
    -UpnList        alice@contoso.com, bob@contoso.com, carol@contoso.com `
    -TicketId       CHG0012345 `
    -EvidenceLevel  Forensic `
    -RemoveLicenses `
    -NonInteractive `
    -Force
```

### WhatIf (dry run — no mutations)

```powershell
.\Start-DecomBatch.ps1 `
    -UpnList  alice@contoso.com, bob@contoso.com `
    -TicketId CHG0012345 `
    -WhatIfMode
```

### Resume an interrupted batch

```powershell
.\Start-DecomBatch.ps1 `
    -ResumePath 'C:\repo\output\<BatchId>\batch-state.json'
```

### Resume — skip known-bad entries, retry the rest

```powershell
.\Start-DecomBatch.ps1 `
    -ResumePath 'C:\repo\output\<BatchId>\batch-state.json' `
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

**Entry lifecycle statuses:** `Pending` → `Running` → `Completed` / `Failed` / `Skipped` / `Resumed`

### BatchState.psm1

| Function | Description |
|---|---|
| `Get-DecomBatchStatePath` | Returns canonical path: `<OutputRoot>\<BatchId>\batch-state.json` |
| `Save-DecomBatchState` | Serialises batch to JSON. Atomic write via tmp-then-rename. |
| `Restore-DecomBatchState` | Deserialises from JSON. Reconstructs typed `pscustomobject` graph. |

### BatchOrchestrator.psm1

| Function | Description |
|---|---|
| `Invoke-DecomBatch` | Iterates actionable entries, calls Lite `Invoke-DecomWorkflow` per UPN, checkpoints after every entry, returns `BatchResult`. |

**Idempotency rules for `Invoke-DecomBatch`:**

| Entry status | Behaviour |
|---|---|
| `Completed` | Always skipped |
| `Skipped` | Always skipped |
| `Running` (on resume) | Treated as interrupted — re-runs as `Resumed` |
| `Failed` | Re-runs by default; skipped if `-SkipFailed` |
| `Pending` / `Resumed` | Runs normally |

---

## Governance rules

- **TicketId is mandatory** when running `-Force -NonInteractive` (automation mode).
  Omitting it causes an immediate exit before any workflow runs.
- Litigation hold is **not available** in this launcher. It is a Premium Phase 2
  feature with explicit prereq gating. Do not pass `-EnableLitigationHold` —
  it is not a parameter of `Start-DecomBatch.ps1`.
- The `-Force` flag applies to all UPNs in the batch. Use WhatIf for a
  pre-flight dry run when processing large lists.

---

## Running the tests

```powershell
# From repo root
Invoke-Pester .\tests\Premium\DecomBatch.Tests.ps1 -Output Detailed
```

Pester v5.6.1 required. Tests use function stubs — no Graph or Exchange
connectivity needed.

---

## Phases

| Phase | Status | Description |
|---|---|---|
| 1 | Complete | Batch engine, per-UPN lifecycle, resume, state persistence |
| 2 | Planned | Batch-level reporting, cross-UPN evidence manifest, mail forwarding control |
| 3 | Planned | Policy overlays, group/role removal automation, MFA method removal |
| 4 | Reserved | Parallel execution (MaxParallel — PS5.1 runspace pool) |

---

## PS5.1 compatibility notes

- No 3-argument `Join-Path` — all path joins are chained 2-argument calls
- No `ForEach-Object -Parallel` — sequential only
- No `RandomNumberGenerator.Fill` — GUIDs via `[guid]::NewGuid()`
- No `.NET 6+` APIs
- `ConvertTo-Json` / `ConvertFrom-Json` depth 6 — sufficient for current schema
- Ordered hashtables reconstructed via `psobject.Properties` enumeration on restore
