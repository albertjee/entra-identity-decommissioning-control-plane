# Entra Identity Decommissioning Control Plane

**Version:** Lite v1.5 (public) | Premium v2.0 (private — request access)
**Maturity:** Production-safety release candidate for controlled tenant validation
**Author:** Albert Jee — Enterprise Identity Architect | IAM Consultant
**Copyright:** © 2026 Albert Jee. All rights reserved.

---

## Two Editions

### Lite Edition (this repo — public)

Single-UPN decommissioning workflow. Deterministic, evidence-driven, WhatIf-safe. Free for qualified practitioners.

### Premium Edition (private repo — request access)

Multi-UPN batch orchestration built on the Lite foundation. Adds:

- **Batch control plane** — process N UPNs from a single run with per-UPN checkpointing and resume
- **Per-UPN policy overrides** — evidence level, WhatIf, license removal per identity via JSON policy file
- **Pre-flight approval gate** — signed approval record with expiry enforcement before batch execution
- **Premium remediation phases** — litigation hold, license removal, device disable/wipe, app ownership, Azure RBAC removal
- **Batch diff report** — pre-run WhatIf summary showing what would change per UPN with risk classification
- **Batch reporting** — HTML + JSON roll-up reports, cross-UPN evidence manifest with SHA-256 hash chain
- **191/191 Pester tests** — full unit test coverage including 10 high-severity gap tests

**Request access:** Connect on LinkedIn and send a DM referencing this repo.

---

## Executive Summary

The Entra Identity Decommissioning Control Plane is a PowerShell reference implementation for safely decommissioning Microsoft 365 / Entra ID user principals using a deterministic, evidence-driven workflow.

This project treats identity decommissioning as a **control-plane operation**, not a help-desk script. The goal is to reduce revocation latency, preserve mailbox/compliance continuity, block unsafe license removal, and generate audit-defensible evidence for every meaningful action.

---

## Production Safety Position

Designed for controlled production use only after the operator has completed the tenant validation guide and verified required permissions in a lab or pilot tenant.

The tool is intentionally conservative:

- Destructive actions support PowerShell `ShouldProcess`
- `-WhatIf` produces evidence without mutating tenant state
- License removal is blocked when compliance or mailbox prerequisites are unresolved
- Pre-action and post-action snapshots are captured
- Every action emits a forensic-grade evidence event
- JSON, HTML, and NDJSON evidence outputs are generated

---

## Scope (Lite Edition)

### In Scope

- Single UPN decommissioning
- Cloud-only Microsoft 365 / Entra ID tenants
- Microsoft Graph PowerShell SDK
- Exchange Online PowerShell
- Delegated interactive admin authentication
- Password reset
- Session revocation
- Sign-in block
- Mailbox conversion to shared
- Auto-reply configuration
- Litigation Hold enablement
- Retention / archive / hold-aware license readiness checks
- Group, privileged role, ownership, OAuth, and app-role discovery
- Forensic evidence output

### Out of Scope (Lite)

- Multi-UPN batch execution (Premium)
- Hybrid Exchange / AD DS decommissioning
- Automatic group removal
- Automatic privileged-role removal
- Automatic application ownership reassignment
- Automatic OAuth grant removal
- Full Purview eDiscovery case workflow automation

---

## Pester Test Suite (Lite)

A full Pester v5 unit test suite is included covering all Lite workflow phases:

```powershell
Invoke-Pester .\tests\Decom.Tests.ps1 -Output Detailed
```

---

## Requirements

- PowerShell 5.1+ (tested on 5.1 and 7+)
- Microsoft Graph PowerShell SDK
- ExchangeOnlineManagement module
- Admin account with required delegated privileges

```powershell
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Pester -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser
```

---

## Required Graph Scopes

- `User.ReadWrite.All`
- `Directory.ReadWrite.All`
- `Organization.Read.All`
- `RoleManagement.Read.Directory`
- `Application.Read.All`
- `AppRoleAssignment.ReadWrite.All`
- `DelegatedPermissionGrant.Read.All`

---

## Quick Start

### Validation-Only Mode

```powershell
pwsh ./src/Start-Decom.ps1 `
  -TargetUPN user@contoso.com `
  -ValidationOnly `
  -EvidenceLevel Forensic
```

### WhatIf Dry Run

```powershell
pwsh ./src/Start-Decom.ps1 `
  -TargetUPN user@contoso.com `
  -EnableLitigationHold `
  -RemoveLicenses `
  -EvidenceLevel Forensic `
  -WhatIf
```

### Controlled Live Run

```powershell
pwsh ./src/Start-Decom.ps1 `
  -TargetUPN user@contoso.com `
  -EnableLitigationHold `
  -RemoveLicenses `
  -EvidenceLevel Forensic
```

### Non-Interactive Pipeline Mode

```powershell
pwsh ./src/Start-Decom.ps1 `
  -TargetUPN user@contoso.com `
  -EnableLitigationHold `
  -RemoveLicenses `
  -EvidenceLevel Forensic `
  -NonInteractive `
  -Force
```

---

## Output

Each run creates a unique output directory:

```text
output/<RunId>/
  run.log
  evidence.ndjson
  report.json
  report.html
  evidence.manifest.json
```

---

## Workflow Phases

1. Authentication
2. Preflight validation
3. Pre-action identity snapshot
4. Containment
5. Mailbox continuity
6. Compliance controls
7. License readiness and optional removal
8. Post-action identity snapshot
9. Reporting

---

## Repository Layout (Lite Edition)

```text
src/
  Start-Decom.ps1
  Invoke-DecomWorkflow.ps1
  Modules/
    Auth.psm1
    Compliance.psm1
    Containment.psm1
    Discovery.psm1
    Evidence.psm1
    Execution.psm1
    Guardrails.psm1
    Licensing.psm1
    Logging.psm1
    Mailbox.psm1
    Models.psm1
    Reporting.psm1
    State.psm1
    Validation.psm1

docs/
  compliance-model.md
  evidence-model.md
  runbook.md

tests/
  Decom.Tests.ps1

examples/
  sample-report.schema.json
```

---

## GitHub Topics

`entra-id`, `microsoft-365`, `identity-governance`, `zero-trust`, `iam`, `powershell`, `microsoft-graph`, `exchange-online`, `audit`, `security-architecture`

---

## Safety Notice

This project performs identity and mailbox control-plane operations. Validate in a lab or pilot tenant before use. Operators remain responsible for tenant-specific legal, compliance, retention, and HR requirements.
