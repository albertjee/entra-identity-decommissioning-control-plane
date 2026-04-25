# Tenant Validation Guide

## Lab Tenant Minimum Test Matrix

| Test | Expected Result |
|---|---|
| Module import | All modules import without errors |
| Validation-only | No destructive actions occur |
| WhatIf | Destructive actions are skipped/evidenced |
| Password reset | Success or explicit critical failure |
| Session revoke | Success or explicit critical failure |
| Sign-in block | AccountEnabled becomes false |
| Mailbox conversion | Shared mailbox state verified |
| Auto-reply | Configured when message supplied |
| Litigation Hold | Enabled or blocked with explicit reason |
| License readiness | Blocks when prerequisites fail |
| Reporting | JSON, HTML, NDJSON, and log generated |

## Release Gate

Do not tag as production-ready in a tenant until:

- validation-only run succeeds
- WhatIf run produces no mutations
- one disposable account pilot completes successfully
- evidence artifacts are reviewed by identity/security owner
