# Entra Identity Decommissioning Control Plane

**Version:** v1.4  
**Maturity:** Lite rev0.50 — hardened, spec-complete, lab-validated candidate  
**Author:** Albert Jee — Enterprise Identity Architect | IAM Consultant  
**Copyright:** © 2026 Albert Jee. All rights reserved.

## Executive Summary

The Entra Identity Decommissioning Control Plane is a PowerShell reference implementation for safely decommissioning a single Microsoft 365 / Entra ID user principal using a deterministic, evidence-driven workflow.

This project treats identity decommissioning as a **control-plane operation**, not a help-desk script. The goal is to reduce revocation latency, preserve mailbox/compliance continuity, block unsafe license removal, and generate audit-defensible evidence for every meaningful action.

## Version History

| Version | Description |
|---|---|
| v1.4 | Hygiene + spec completion — full delegation discovery, evidence contract, scope fix |
| v1.3 | Hardening — guardrail semantics, evidence integrity, 38 Pester tests |
| v1.2 | Spec alignment — StepId, ManualFollowUp, MFA snapshot, guest guard |
| v1.1 | Remediation — modulo bias fix, PIM roles, group license detection |
| v1.0 | Initial release — production-safety release candidate |

## Production Safety Position

v1.4 is designed for controlled production use after completing the tenant validation guide and verifying required permissions in a lab or pilot tenant.

The tool is intentionally conservative:

* Destructive actions support PowerShell `ShouldProcess`
* `-WhatIf` produces evidence without mutating tenant state
* `-ValidationOnly` runs full discovery and snapshots without any mutations
* License removal is blocked when compliance or mailbox prerequisites are unresolved
* Pre-action and post-action snapshots are captured
* Every action emits a forensic-grade evidence event
* JSON, HTML, and NDJSON evidence outputs are generated
* 54 Pester unit tests — all passing

## Scope

### In Scope

* Single UPN decommissioning
* Cloud-only Microsoft 365 / Entra ID tenants
* Microsoft Graph PowerShell SDK
* Exchange Online PowerShell
* Delegated interactive admin authentication
* Password reset
* Session revocation
* Sign-in block
* Mailbox conversion to shared
* Auto-reply configuration
* Litigation Hold enablement
* Retention / archive / hold-aware license readiness checks
* Group, privileged role, ownership, OAuth, and app-role discovery
* PIM eligible role discovery
* Mailbox delegation discovery (FullAccess, SendAs, SendOnBehalf)
* MFA authentication method discovery
* Guest account detection and warning
* Forensic evidence output

### Out of Scope (Lite edition — deferred to Premium)

* Hybrid Exchange / AD DS decommissioning
* Destructive bulk execution
* Automatic group removal
* Automatic privileged-role removal
* Automatic application ownership reassignment
* Automatic OAuth grant removal
* Full Purview eDiscovery case workflow automation
* Dependency mapping and blast-radius estimation
* Confidence scoring
* Batch orchestration

## Requirements

* PowerShell 5.1+ (7+ recommended)
* Microsoft Graph PowerShell SDK
* ExchangeOnlineManagement module
* Admin account with required delegated privileges

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Pester -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser
```

## Required Graph Scopes

```
User.ReadWrite.All
Directory.ReadWrite.All
Organization.Read.All
RoleManagement.Read.Directory
Application.Read.All
AppRoleAssignment.Read.All
DelegatedPermissionGrant.Read.All
```

## Quick Start

### Validation-Only Mode (no mutations)

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

## Output

Each run creates a unique output directory:

```
output/<RunId>/
  run.log
  evidence.ndjson
  report.json
  report.html
```

## Workflow Phases

1. Authentication
2. Preflight validation
3. Pre-action identity snapshot
4. Containment (password reset, session revoke, sign-in block)
5. Mailbox continuity (convert to shared, auto-reply)
6. Compliance controls (litigation hold, compliance state)
7. License readiness and optional removal
8. Post-action identity snapshot
9. Reporting

## Repository Layout

```
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
  Decom.Tests.ps1  (54 tests, all passing)

examples/
  sample-report.schema.json
```

## GitHub Topics

`entra-id` `microsoft-365` `identity-governance` `zero-trust` `iam` `powershell` `microsoft-graph` `exchange-online` `audit` `security-architecture`

## Safety Notice

This project performs identity and mailbox control-plane operations. Validate in a lab or pilot tenant before use. Operators remain responsible for tenant-specific legal, compliance, retention, and HR requirements.
