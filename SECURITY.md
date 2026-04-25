# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| v1.5 | ✅ Current |
| v1.4 | ✅ Security fixes backported |
| < v1.4 | ❌ Not supported |

## Reporting a Vulnerability

This project performs **privileged identity control-plane operations** against Microsoft 365 / Entra ID tenants. Security issues are treated with high priority.

**To report a vulnerability:**

1. **Do not open a public GitHub issue** for security vulnerabilities.
2. Email: [albertdjee@gmail.com] with subject line `[SECURITY] entra-decom-control-plane`
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested remediation (if known)

**Response commitment:**
- Acknowledgement within 3 business days
- Status update within 10 business days
- Fix timeline communicated based on severity

## Severity Classification

| Severity | Examples |
|---|---|
| Critical | Credential exposure, evidence tampering bypass, wrong-user execution |
| High | Guardrail bypass, evidence integrity failure, scope escalation |
| Medium | Information disclosure, evidence leakage, partial containment |
| Low | Documentation gaps, non-security logic errors |

## Operational Security Requirements

This tool requires privileged delegated admin credentials. Before production use:

- Run only from a **Privileged Access Workstation (PAW)** or equivalent hardened endpoint
- Require **PIM activation** with short time window before execution
- Enforce **phishing-resistant MFA + compliant device** via Conditional Access
- Restrict operator role to named, audited individuals
- For `-NonInteractive -Force` automation mode, require a **TicketId** and two-person authorization

## Evidence Security

Evidence outputs (`evidence.ndjson`, `report.json`, `report.html`, `evidence.manifest.json`) contain sensitive identity topology data.

- Treat evidence artifacts as **sensitive records**
- Store on encrypted volumes or immediately export to protected storage
- Do not sync evidence output folders to general-purpose cloud storage
- Evidence is hash-chain sealed by default (v1.5+); verify `FinalEventHash` in `evidence.manifest.json`

## Known Limitations (by design)

The following are **intentional design boundaries**, not vulnerabilities:

- Single-UPN scope only (Lite edition)
- Discovery without automatic remediation of groups, roles, OAuth grants
- Local filesystem evidence (no built-in encryption at rest)
- Delegated auth (no app-only / workload identity mode)
