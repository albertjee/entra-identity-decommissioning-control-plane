# Red-Team Scenarios — Entra Identity Decommissioning Control Plane v1.5

## Purpose
This document records adversarial thinking about the tool — what a competent red team
or insider threat would attempt, and how v1.5 responds. It is intended to demonstrate
that residual risks are **intentional and governed**, not overlooked.

---

## Scenario 1 — "Clean Evidence, Still a Disaster"

**Goal:** Cause maximum business damage without triggering evidence anomalies.

**Attack**
Privileged insider or compromised admin runs:
```powershell
.\Start-Decom.ps1 -TargetUPN exec@corp.com -NonInteractive -Force -TicketId CHG-FAKE-001
```

**Result**
- Account contained cleanly
- Evidence sealed correctly
- Business impact is real and immediate

**Why v1.5 does NOT stop this**
This is authorized misuse, not a control failure. The tool executes correctly.

**Mitigation (governance, not code)**
- Two-person rule for Force mode
- TicketId validated against real change management system (future)
- PIM approval workflows
- Evidence captures OperatorUPN for accountability

**Verdict:** ✅ Acceptable residual risk — documented, not overlooked.

---

## Scenario 2 — "Steal the Admin Token"

**Goal:** Abuse delegated Graph permissions outside the tool.

**Attack**
- Malware on admin endpoint captures token
- Attacker replays token directly against Graph APIs

**Result**
- Attacker has full tenant write capability
- Tool's guardrails are bypassed entirely

**Why v1.5 cannot fix this**
- Tool executes in delegated admin context
- Compromise occurs before guardrails engage
- This is an endpoint security problem, not application logic

**Mitigation**
- Privileged Access Workstation (PAW)
- Short-lived PIM activation windows
- Token protection (CAE)
- Phishing-resistant MFA + Conditional Access

**Verdict:** ✅ Correct framing — endpoint security problem, not a tool vulnerability.

---

## Scenario 3 — "Tamper With Evidence"

**Goal:** Make misuse look legitimate after the fact.

**Attack**
- Edit `evidence.ndjson` to remove damaging steps
- Regenerate `report.html` to match
- Present altered evidence during audit

**Outcome in v1.4:** Possible — no tamper detection.
**Outcome in v1.5:** **Detected** — hash chain breaks, manifest validation fails.

**Why v1.5 closes this**
- Every event includes `PrevHash` and `EventHash`
- Any modification, deletion, or reordering breaks the chain
- `evidence.manifest.json` anchors the final hash as integrity reference

**Verdict:** ✅ Risk closed in v1.5.

---

## Scenario 4 — "Partial Failure Exploitation"

**Goal:** Leave identity half-contained but appearing safe in evidence.

**Attack**
- Induce transient Graph/EXO errors during containment
- Hope workflow advances past containment with incomplete actions

**Outcome**
- Guardrails detect blocked/failed containment actions
- `Test-DecomCanContinueAfterContainment` blocks forward progress in live mode
- Evidence reflects blocked state explicitly

**Verdict:** ✅ Correct behavior — workflow stops, evidence records truth.

---

## Scenario 5 — "Residual Access Abuse"

**Goal:** Use unremoved OAuth grants, app ownership, or group memberships after decommissioning.

**Attack**
- Account is contained (sign-in blocked, sessions revoked, password reset)
- But OAuth grants, owned app registrations, and privileged role assignments remain
- If account is ever reactivated, attacker regains leverage

**Why this is still possible**
- Automatic removal of these items is explicitly out of scope (Lite edition)
- Discovery captures them but does not remediate

**Mitigation**
- ManualFollowUp items in HTML report flag all detected residuals
- Operators must close these items before marking decommission complete
- Premium edition will automate detection and guided remediation

**Verdict:** ✅ Explicitly documented residual risk — operator accountability required.

---

## Summary Table

| Scenario | v1.4 | v1.5 | Notes |
|---|---|---|---|
| Authorized misuse (Force mode) | Residual | Residual | Governance problem |
| Token theft / endpoint compromise | Residual | Residual | PAW/PIM mitigates |
| Evidence tampering | ❌ Undetected | ✅ Detected | Hash chain closes this |
| Partial containment exploitation | ✅ Blocked | ✅ Blocked | No regression |
| Residual access abuse | Residual | Residual | Manual follow-up required |
