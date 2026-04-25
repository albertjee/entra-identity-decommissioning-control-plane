# Threat Model — Entra Identity Decommissioning Control Plane v1.5

## 0. Purpose
This document records the security posture, threats, mitigations, and residual risks for the Entra Identity Decommissioning Control Plane. It accompanies security reviews and audits and prevents implicit risk from becoming accidental risk.

## 1. System Summary
The tool performs identity decommissioning as a deterministic control-plane workflow for a single target UPN using:
- Microsoft Graph PowerShell SDK (delegated interactive auth)
- Exchange Online PowerShell
- Evidence output: `output/<RunId>/` containing `evidence.ndjson`, `report.json`, `report.html`, `run.log`, `evidence.manifest.json`

**This is a scalpel, not a service.** It must be treated accordingly.

## 2. Assets

### High-value assets
- Delegated admin access token (Graph + EXO) — tenant-wide write capability
- Target identity object state
- Mailbox continuity and compliance state
- Evidence artifacts (contain sensitive identity topology)

### Secondary assets
- Discovery outputs (roles, groups, app ownership, OAuth grants, delegation)
- Operator intent signals (TicketId, run mode, confirmation state)

## 3. Trust Boundaries
1. Operator workstation / execution host (PowerShell runtime + filesystem)
2. Microsoft Entra ID / Microsoft Graph control plane
3. Exchange Online control plane
4. Human intent boundary (interactive prompts, `-Force`, `-NonInteractive`, `-WhatIf`)

## 4. Privileges and Blast Radius

### Required Graph scopes (v1.5)
- `User.ReadWrite.All`
- `Directory.ReadWrite.All`
- `Organization.Read.All`
- `RoleManagement.Read.Directory`
- `Application.Read.All`
- `AppRoleAssignment.Read.All` ← read-only (downgraded in v1.4)
- `DelegatedPermissionGrant.Read.All`

### Implication
Compromise of the operator session enables far broader directory mutation than single-user decommissioning. This is architectural, not a code defect. Mitigations are operational.

## 5. Threats (STRIDE-aligned)

### 5.1 Spoofing — Credential / token theft
**Threat:** Stolen delegated admin token enables unauthorized decommissioning or broad directory mutation.

**Required mitigations (external):**
- Privileged Identity Management (JIT activation, short window)
- Phishing-resistant MFA
- Compliant-device Conditional Access
- Privileged Access Workstation (PAW)

**Residual risk:** High (inherent to delegated admin model)

---

### 5.2 Tampering — Evidence artifact modification
**Threat:** Evidence files on disk can be modified after the run.

**v1.5 mitigation:**
- Hash-chain sealing across all NDJSON events (`PrevHash` + `EventHash` per event)
- Final `evidence.manifest.json` with `FinalEventHash` as integrity anchor
- Any event edit, deletion, or reorder breaks the hash chain

**Remaining gap:** Chain can be re-generated if attacker controls both NDJSON and manifest. Full non-repudiation requires signing the manifest or storing `FinalEventHash` in an immutable system (SIEM/WORM/ticketing).

**Residual risk:** Medium (reduced from High in v1.4)

---

### 5.3 Repudiation — Who ran this?
**Threat:** Without operator identity in evidence, "who ran this?" is hard to prove.

**v1.5 mitigation:**
- `OperatorUPN` and `OperatorObjectId` embedded in every evidence event
- `OperatorUPN` and `TicketId` included in `evidence.manifest.json`
- Operator identity resolved from MgContext post-authentication

**Residual risk:** Low-Medium

---

### 5.4 Information Disclosure — Evidence leakage
**Threat:** Evidence outputs contain sensitive identity topology, role relationships, and compliance state.

**Mitigations:**
- Store on encrypted volumes
- Immediately export to protected/immutable storage
- Do not sync `output/` to general-purpose cloud sync (OneDrive, Dropbox, etc.)
- Minimize local retention

**Residual risk:** Medium-High (no built-in encryption at rest)

---

### 5.5 Denial of Service — Wrong-target execution
**Threat:** Incorrect UPN execution (especially in `-Force -NonInteractive`) disables a critical account.

**v1.5 mitigations:**
- `-TicketId` now mandatory in Force+NonInteractive mode
- `OperatorUPN` embedded in evidence for accountability
- Pre-action snapshot provides before-state for recovery reference

**Recommended additional controls (operational):**
- UPN domain allowlist
- Two-person authorization for Force mode

**Residual risk:** High if Force mode is allowed without governance controls

---

### 5.6 Elevation of Privilege — Scope abuse
**Threat:** Broad delegated scopes increase impact of any compromise.

**Mitigations:**
- `AppRoleAssignment.ReadWrite.All` downgraded to `AppRoleAssignment.Read.All` in v1.4
- Discovery separated from mutation where possible

**Residual risk:** High (inherent to delegated admin model)

## 6. Known Gaps (explicit, not accidental)

The following are **intentional Lite edition boundaries**:
- No automatic group membership removal
- No automatic privileged role removal
- No automatic OAuth grant removal
- No automatic application ownership reassignment

These are treated as **mandatory manual follow-up items** surfaced in the HTML report and evidence ManualFollowUp fields.

## 7. Evidence Quality and Integrity (v1.5)

| Property | v1.4 | v1.5 |
|---|---|---|
| Structured schema contract | ✅ | ✅ |
| CorrelationId in events | ✅ | ✅ |
| OperatorUPN in events | ❌ | ✅ |
| Hash-chain sealing | ❌ | ✅ |
| Evidence manifest | ❌ | ✅ |
| Cryptographic signing | ❌ | ❌ (future) |
| Encryption at rest | ❌ | ❌ (future) |

## 8. Operational Security Requirements (non-negotiable for production)

- Run only from hardened admin endpoint (PAW-equivalent)
- PIM activation required and time-limited
- Strong Conditional Access (phishing-resistant MFA + compliant device)
- Force+NonInteractive mode requires TicketId and two-person authorization
- Evidence artifacts treated as sensitive records — encrypted storage or immediate export
