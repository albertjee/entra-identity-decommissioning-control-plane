# Tenant Validation Runbook

1. Use a cloud-only disposable test user.
2. Assign a direct license and a mailbox.
3. Run `-WhatIf` first.
4. Review output/report.json and report.html.
5. Run controlled execution only after validation.
6. Preserve run.log, report.json, and report.html as validation evidence.
