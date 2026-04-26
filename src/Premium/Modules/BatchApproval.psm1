# BatchApproval.psm1 — Pre-flight approval gate
# Premium v2.0
#
# Functions:
#   Invoke-DecomBatchApproval  — approval gate requiring change record ID
#   Get-DecomApprovalStatus    — reads the approval record from disk
#
# Design:
#   TICKET ID FORMAT (v2.0):
#   Accepted patterns: CHG-NNNNN, INC-NNNNN, REQ-NNNNN, RITM-NNNNN
#   Format validation + operator attestation is the v2.0 standard.
#   Live ITSM API lookup is a v2.x enhancement — see README.
#
# PS7 compatible (v2.0 baseline)

#Requires -Version 7.0

Set-StrictMode -Version Latest

$script:DefaultTicketPattern = '^(CHG|INC|REQ|RITM)-\d+$'

function Invoke-DecomBatchApproval {
    <#
    .SYNOPSIS
        Enforces a pre-flight approval gate requiring a valid change record ID.

    .DESCRIPTION
        Validates the batch TicketId against the accepted change record format,
        then either prompts interactively or accepts a NonInteractive attestation.

        Interactive mode: Displays batch summary. Operator types YES to attest.
        NonInteractive mode: Requires -TicketId and -OperatorUPN. No prompt.

        In both modes, batch-approval.json is written to the batch directory.

    .PARAMETER Batch
        The batch envelope. Must have TicketId set.

    .PARAMETER NonInteractive
        Skip interactive prompt. Requires -TicketId and -OperatorUPN.

    .PARAMETER TicketId
        Change record ID. If not supplied, uses Batch.TicketId.

    .PARAMETER OperatorUPN
        Identity of the operator. Defaults to Batch.OperatorUPN.

    .PARAMETER TicketPattern
        Regex for valid ticket IDs. Default: ^(CHG|INC|REQ|RITM)-\d+$

    .OUTPUTS
        [bool] — $true if approved. Throws if not approved or ticket invalid.

    .EXAMPLE
        Invoke-DecomBatchApproval -Batch $batch

    .EXAMPLE
        Invoke-DecomBatchApproval -Batch $batch -NonInteractive `
            -TicketId 'CHG-12345' -OperatorUPN 'ops@contoso.com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,
        [switch]$NonInteractive,
        [string]$TicketId,
        [string]$OperatorUPN,
        [string]$TicketPattern = $script:DefaultTicketPattern
    )

    $batchDir         = Join-Path $Batch.OutputRoot $Batch.BatchId
    $null             = New-Item -ItemType Directory -Path $batchDir -Force
    $resolvedTicket   = if ($TicketId)    { $TicketId }    else { $Batch.TicketId }
    $resolvedOperator = if ($OperatorUPN) { $OperatorUPN } else { $Batch.OperatorUPN }

    _ValidateTicketFormat -TicketId $resolvedTicket -Pattern $TicketPattern

    if ($NonInteractive) {
        if ([string]::IsNullOrWhiteSpace($resolvedTicket)) {
            throw 'Invoke-DecomBatchApproval: -TicketId is required in -NonInteractive mode.'
        }
        if ([string]::IsNullOrWhiteSpace($resolvedOperator)) {
            throw 'Invoke-DecomBatchApproval: -OperatorUPN is required in -NonInteractive mode.'
        }
        Write-Host "[Approval] NonInteractive approval accepted. Ticket: $resolvedTicket | Operator: $resolvedOperator" `
            -ForegroundColor Green
    } else {
        _WriteApprovalSummary -Batch $Batch -TicketId $resolvedTicket
        Write-Host ''
        Write-Host "  Change record '$resolvedTicket' validated for format." -ForegroundColor Cyan
        Write-Host '  By typing YES you attest this change record is approved' -ForegroundColor Yellow
        Write-Host '  and authorises this decommissioning batch.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host 'Type YES to proceed, or anything else to abort:' -ForegroundColor Yellow -NoNewline
        $response = Read-Host ' '
        if ($response.Trim() -ne 'YES') {
            throw "Invoke-DecomBatchApproval: batch aborted by operator. Response: '$response'"
        }
        Write-Host '[Approval] Operator attestation recorded.' -ForegroundColor Green
    }

    _WriteApprovalRecord -Batch $Batch -BatchDir $batchDir `
        -TicketId $resolvedTicket -OperatorUPN $resolvedOperator `
        -Method $(if ($NonInteractive) { 'NonInteractive' } else { 'Interactive' })

    return $true
}

function Get-DecomApprovalStatus {
    <#
    .SYNOPSIS
        Reads and returns the approval record for a batch from disk.
        Returns $null if no approval record exists yet.

    .PARAMETER Batch
        The batch envelope.

    .OUTPUTS
        [pscustomobject] approval record, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch
    )

    $path = Join-Path (Join-Path $Batch.OutputRoot $Batch.BatchId) 'batch-approval.json'
    if (-not (Test-Path $path)) { return $null }
    return Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function _ValidateTicketFormat {
    param([string]$TicketId, [string]$Pattern)

    if ([string]::IsNullOrWhiteSpace($TicketId)) {
        throw ("Invoke-DecomBatchApproval: no TicketId supplied. " +
               "A valid change record ID (e.g. CHG-12345) is required.")
    }
    if ($TicketId -notmatch $Pattern) {
        throw ("Invoke-DecomBatchApproval: TicketId '$TicketId' does not match " +
               "the accepted format. Pattern: $Pattern " +
               "(e.g. CHG-12345, INC-99999). Use -TicketPattern to override.")
    }
}

function _WriteApprovalSummary {
    param([pscustomobject]$Batch, [string]$TicketId)

    Write-Host ''
    Write-Host '── Batch Pre-flight Summary ─────────────────────────────' -ForegroundColor Cyan
    Write-Host ("  Batch ID  : {0}" -f $Batch.BatchId)       -ForegroundColor White
    Write-Host ("  Ticket    : {0}" -f $TicketId)             -ForegroundColor White
    Write-Host ("  Operator  : {0}" -f $Batch.OperatorUPN)   -ForegroundColor White
    Write-Host ("  UPNs      : {0}" -f $Batch.Entries.Count) -ForegroundColor White
    Write-Host ("  Evidence  : {0}" -f $Batch.EvidenceLevel) -ForegroundColor White
    Write-Host ("  Mode      : {0}" -f $(if ($Batch.WhatIf) { 'WhatIf (no mutations)' } else { 'LIVE — mutations will occur' })) `
        -ForegroundColor $(if ($Batch.WhatIf) { 'Yellow' } else { 'Red' })
    Write-Host ''
    Write-Host '  UPNs in scope:' -ForegroundColor White
    foreach ($key in $Batch.Entries.Keys) {
        Write-Host ("    · {0}" -f $Batch.Entries[$key].UPN) -ForegroundColor Gray
    }
    Write-Host '─────────────────────────────────────────────────────────' -ForegroundColor Cyan
}

function _WriteApprovalRecord {
    param(
        [pscustomobject]$Batch,
        [string]$BatchDir,
        [string]$TicketId,
        [string]$OperatorUPN,
        [string]$Method
    )

    $record = [ordered]@{
        SchemaVersion  = '2.0'
        RecordType     = 'ApprovalRecord'
        BatchId        = $Batch.BatchId
        TicketId       = $TicketId
        OperatorUPN    = $OperatorUPN
        ApprovalMethod = $Method
        Approved       = $true
        ApprovedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        UPNCount       = $Batch.Entries.Count
        Note           = 'v2.0: ticket format validated. Operator attestation recorded. Live ITSM validation is a v2.x enhancement.'
    }

    $path = Join-Path $BatchDir 'batch-approval.json'
    $record | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
    return [pscustomobject]$record
}

Export-ModuleMember -Function `
    Invoke-DecomBatchApproval, `
    Get-DecomApprovalStatus
