# Compliance Model

The v1.0 compliance model is conservative. It does not assume that a mailbox is safe for license removal merely because it has been converted to shared.

## Compliance Signals

The tool evaluates:

- Litigation Hold state
- In-place hold indicators
- Retention hold state
- Archive mailbox state
- Recipient type
- Compliance tag hold indicator, where surfaced by Exchange Online

## Blocking Philosophy

License removal should be blocked or manually reviewed when:

- mailbox conversion did not complete
- archive mailbox is present
- hold indicators are detected and unresolved
- compliance state could not be read

## Limitations

Purview/eDiscovery state may require additional compliance cmdlets and tenant-specific permissions. This implementation captures Exchange-visible indicators and intentionally surfaces unresolved compliance state as a governance concern.
