# Production Runbook

## 1. Pre-Run Controls

- Confirm HR/legal authorization.
- Confirm target UPN and ticket ID.
- Confirm operator has approved admin role.
- Confirm tenant validation has passed.
- Confirm mailbox, archive, and retention expectations.

## 2. Validation-Only Run

```powershell
pwsh ./src/Start-Decom.ps1 -TargetUPN user@contoso.com -ValidationOnly -EvidenceLevel Forensic
```

Review `report.html`, `report.json`, and `evidence.ndjson`.

## 3. Dry Run

```powershell
pwsh ./src/Start-Decom.ps1 -TargetUPN user@contoso.com -EnableLitigationHold -RemoveLicenses -EvidenceLevel Forensic -WhatIf
```

## 4. Live Run

```powershell
pwsh ./src/Start-Decom.ps1 -TargetUPN user@contoso.com -EnableLitigationHold -RemoveLicenses -EvidenceLevel Forensic
```

## 5. Post-Run Validation

Confirm:

- password reset result captured
- sessions revoked
- sign-in blocked
- mailbox converted or already shared
- compliance state captured
- license readiness result documented
- post-action snapshot created

## 6. Evidence Retention

Attach output artifacts to the authorized change ticket or secure evidence repository.
