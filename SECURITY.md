# Security Policy

## Scope
This repository contains a **privileged control-plane reference implementation** for
Entra ID / Microsoft 365 user decommissioning. It is **not** a consumer tool or
unattended automation service.

## Supported Versions

| Version | Supported |
|---|---|
| v1.5 / v1.5a | ✅ Current |
| v1.4 | ✅ Security fixes backported |
| < v1.4 | ❌ Not supported |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report privately:
- Email the repository owner with subject: `[SECURITY] entra-decom-control-plane`
- Include: description, reproduction steps, potential impact, suggested remediation

**Response expectations:**
- Acknowledgement: within 3 business days
- Status update: within 10 business days
- Fix timeline: communicated based on severity

## Severity Classification

| Severity | Examples |
|---|---|
| Critical | Credential exposure, evidence seal bypass, wrong-user execution path |
| High | Guardrail bypass, evidence integrity failure, scope escalation |
| Medium | Information disclosure, evidence leakage, partial containment |
| Low | Documentation gaps, non-security logic errors |

## Security Assumptions (Important)

This project makes explicit assumptions that operators must satisfy:

- Executed only by **privileged administrators** with appropriate role assignments
- Run only from **hardened admin endpoints** (PAW-equivalent)
- Protected by **PIM activation** with short time windows
- Enforced by **phishing-resistant MFA + compliant device** Conditional Access
- Governed by **change control** when using `-Force` or `-NonInteractive`
- `-NonInteractive -Force` mode requires a valid **TicketId** (enforced in code)

Failure to meet these assumptions invalidates the project's safety claims.

## Evidence Handling

Evidence outputs are **security-sensitive artifacts** containing identity topology,
role relationships, and compliance state. Operators are responsible for:

- Secure storage (encrypted volumes or protected storage)
- Controlled retention and access
- Verification of evidence integrity via `evidence.manifest.json`
- Not syncing `output/` to general-purpose cloud sync tools

Evidence is **hash-chain sealed** by default (v1.5+). Encryption at rest is an
operator responsibility.

## Known Design Limitations (not vulnerabilities)

- Single-UPN scope only (Lite edition by design)
- Discovery without automatic remediation of groups, roles, OAuth grants
- No built-in encryption at rest for evidence artifacts
- Delegated auth only (no app-only / workload identity mode)
- Cryptographic signing of manifest is deferred (hash chain provides detection)

## No Warranty

This project is provided as a **reference implementation**. Operators remain
responsible for compliance, legal requirements, tenant-specific governance, and
HR policy decisions.
