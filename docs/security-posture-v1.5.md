# Entra Identity Decommissioning Control Plane — v1.5
## Security & Risk Posture Summary

### Overview
Version v1.5 represents a **security-hardening and audit-readiness release**.
This release does not materially expand destructive scope. Instead, it closes previously
identified assurance gaps around evidence integrity, disclosure maturity, and documented
risk acceptance.

---

## Key Security Improvements

### ✅ Evidence Tamper-Resistance
- Evidence output is now **tamper-evident** via cryptographic hashing.
- Evidence events are sealed using a chained integrity mechanism (`Write-DecomEvidenceSeal`).
- A run-level manifest (`evidence.manifest.json`) anchors the final integrity state.
- `OperatorUPN` and `OperatorObjectId` embedded in every evidence event.

**Impact:**
Detects post-execution modification, deletion, or reordering of evidence records.
Enables repudiation resistance — who ran this is provable from evidence alone.

---

### ✅ Formal Threat Model (Versioned)
- First-class threat model document included (`docs/threat-model-v1.5.md`):
  - Trust boundaries
  - Threats (STRIDE-aligned)
  - Residual risk table
  - Explicit operational assumptions
- Threat posture is **documented, reviewable, and version-controlled**.

**Impact:**
Eliminates implicit risk assumptions and supports audit review without oral explanation.

---

### ✅ SECURITY.md Added
- Formal vulnerability disclosure expectations established.
- Severity classification defined.
- Operational security requirements documented.

**Impact:**
Improves supply-chain credibility and review maturity.

---

### ✅ Force Mode Governance
- `-TicketId` now mandatory when running `-Force -NonInteractive`.
- Change/ticket reference bound into evidence manifest for audit traceability.

**Impact:**
Automation mode misuse is attributable and traceable.

---

### ✅ Guardrails & Workflow Safety (No Regression)
- Live-mode skip behavior remains blocking.
- Non-interactive execution paths continue to emit terminal evidence.
- Phase gates remain explicit and named.

**Impact:**
No safety regressions from v1.4; correctness preserved across 41 Pester tests.

---

## Known & Accepted Residual Risks

These remain **intentional and documented**, not accidental:

| Risk | Status | Mitigation |
|---|---|---|
| Delegated admin — tenant-wide Graph scopes | Accepted | PIM, CAE, PAW, Conditional Access |
| Force/NonInteractive misuse | Accepted | TicketId, two-person rule, change control |
| Automatic role/group/OAuth removal out of scope | Accepted | Mandatory manual follow-up in report |
| Evidence encryption at rest | Deferred | Operator responsibility — protected storage |
| Cryptographic signing of manifest | Deferred | Hash chain provides detection; signing is next |

---

## Security Posture Verdict

✅ v1.5 moves the project from *"well-designed privileged tooling"* to
✅ *"defensible control-plane tooling suitable for audited environments — under controlled execution conditions."*

This release prioritizes **auditability, evidence integrity, and honesty about risk**,
not false automation safety.
