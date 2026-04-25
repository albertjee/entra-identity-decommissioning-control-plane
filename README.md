# Entra Identity Decommissioning Control Plane

**Version:** v1.4 Stable  
**Maturity:** Production-safety release candidate for controlled tenant validation  
**Author:** Albert Jee — Enterprise Identity Architect | IAM Consultant  
**Copyright:** © 2026 Albert Jee. All rights reserved.

## Executive Summary

The Entra Identity Decommissioning Control Plane is a PowerShell reference implementation for safely decommissioning a single Microsoft 365 / Entra ID user principal using a deterministic, evidence-driven workflow.

This project treats identity decommissioning as a **control-plane operation**, not a help-desk script. The goal is to reduce revocation latency, preserve mailbox/compliance continuity, block unsafe license removal, and generate audit-defensible evidence for every meaningful action.

## Production Safety Position

v1.0 is designed for controlled production use only after the operator has completed the tenant validation guide and verified required permissions in a lab or pilot tenant.

The tool is intentionally conservative:

- destructive actions support PowerShell `ShouldProcess`
- `-WhatIf` produces evidence without mutating tenant state
- license removal is blocked when compliance or mailbox prerequisites are unresolved
- pre-action and post-action snapshots are captured
- every action emits a forensic-grade evidence event
- JSON, HTML, and NDJSON evidence outputs are generated

## Scope

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

### Out of Scope

- Hybrid Exchange / AD DS decommissioning
- Destructive bulk execution
- Automatic group removal
- Automatic privileged-role removal
- Automatic application ownership reassignment
- Automatic OAuth grant removal
- Full Purview eDiscovery case workflow automation

## Requirements

- PowerShell 7+
- Microsoft Graph PowerShell SDK
- ExchangeOnlineManagement module
- Admin account with required delegated privileges

Recommended modules:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Pester -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser
```

## Required Graph Scopes

The default connection requests:

- `User.ReadWrite.All`
- `Directory.ReadWrite.All`
- `Organization.Read.All`
- `RoleManagement.Read.Directory`
- `Application.Read.All`
- `AppRoleAssignment.ReadWrite.All`
- `DelegatedPermissionGrant.Read.All`

Tenant-specific consent and RBAC may require additional permissions.

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

## Output

Each run creates a unique output directory:

```text
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
4. Containment
5. Mailbox continuity
6. Compliance controls
7. License readiness and optional removal
8. Post-action identity snapshot
9. Reporting

## Repository Layout

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
  architecture.md
  compliance-model.md
  evidence-model.md
  permissions.md
  production-runbook.md
  validation-guide.md

tests/
  Decom.Tests.ps1

examples/
  sample-report.schema.json
```

## GitHub Topics

`entra-id`, `microsoft-365`, `identity-governance`, `zero-trust`, `iam`, `powershell`, `microsoft-graph`, `exchange-online`, `audit`, `security-architecture`

## Safety Notice

This project performs identity and mailbox control-plane operations. Validate in a lab or pilot tenant before use. Operators remain responsible for tenant-specific legal, compliance, retention, and HR requirements.
