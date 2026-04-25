# Architecture

This project implements identity decommissioning as a control-plane workflow. The system separates orchestration, guardrails, discovery, compliance, licensing, and reporting into independent PowerShell modules.

## Design Principles

1. **Single target identity** — no destructive bulk execution.
2. **Sequence-aware containment** — password reset, session revocation, then sign-in block.
3. **Evidence-first execution** — every action emits structured evidence.
4. **Compliance before licensing** — license removal is blocked until mailbox and compliance preconditions are known.
5. **Forensic-grade reporting** — before/after snapshots and correlation identifiers are included.

## Control Plane Phases

- Authentication
- Validation
- Pre-action snapshot
- Containment
- Mailbox continuity
- Compliance validation
- Licensing
- Post-action snapshot
- Reporting

## Failure Philosophy

Critical control-plane failures stop the workflow. Non-critical discovery failures are warnings and remain visible in evidence output.
