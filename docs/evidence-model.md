# Evidence Model

v1.0 introduces forensic-grade evidence output.

## Evidence Files

Each run generates:

- `report.json` — complete workflow result
- `report.html` — operator-readable summary
- `evidence.ndjson` — line-delimited evidence event stream
- `run.log` — text execution log

## Event Schema

Each evidence event includes:

- SchemaVersion
- ToolVersion
- CorrelationId
- RunId
- TargetUPN
- TimestampUtc
- EvidenceLevel
- Phase
- Action
- Status
- IsCritical
- Message
- ControlObjective
- RiskMitigated
- BeforeState
- AfterState
- Evidence
- Error

## Why NDJSON

NDJSON allows downstream ingestion into SIEM, log analytics, or CI/CD evidence capture without parsing a monolithic report.
