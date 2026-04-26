# BatchContext.psm1 — Batch envelope and per-UPN context management
# Premium v2.0 — Phase 1
#
# Design:
#   New-DecomBatchContext  — creates the outer batch envelope (1 batch : N UPNs)
#   New-DecomBatchEntry    — creates (or retrieves) the per-UPN sub-context
#   Get-DecomBatchEntry    — retrieves a single entry by UPN
#   Set-DecomBatchEntryStatus — updates lifecycle status of one entry
#   Get-DecomBatchSummary  — roll-up counts for progress/reporting
#
# Lifecycle statuses for a batch entry:
#   Pending | Running | Completed | Failed | Skipped | Resumed
#
# PS5.1 compatible — no [ordered] constructor syntax, no 3-arg Join-Path,
# no RandomNumberGenerator.Fill, no .NET 6+ APIs.

#Requires -Version 5.1

Set-StrictMode -Version Latest

# ── Batch envelope ─────────────────────────────────────────────────────────────

function New-DecomBatchContext {
    <#
    .SYNOPSIS
        Creates a batch envelope that wraps per-UPN decommissioning contexts.

    .DESCRIPTION
        New-DecomBatchContext is the Premium v2.0 entry point for multi-user
        decommissioning runs. It returns a batch envelope object. Individual
        UPN contexts are added via New-DecomBatchEntry and tracked inside the
        envelope's Entries ordered dictionary.

        The caller is responsible for persisting the batch object to disk for
        resume support (see State.psm1 Save-DecomBatchState / Restore-DecomBatchState).

    .PARAMETER UpnList
        One or more UPNs to pre-populate as Pending entries. May be empty; UPNs
        can be added later via New-DecomBatchEntry.

    .PARAMETER TicketId
        Change/ticket reference for audit traceability. Mandatory in non-interactive
        automation scenarios (enforced by Start-DecomBatch.ps1).

    .PARAMETER OutputRoot
        Base output directory. Each UPN run gets its own sub-folder:
        <OutputRoot>\<BatchId>\<sanitised-UPN>\

    .PARAMETER EvidenceLevel
        Applied to every per-UPN context unless explicitly overridden. Defaults to Forensic.

    .PARAMETER WhatIfMode
        When set, all per-UPN contexts inherit WhatIf = $true.

    .PARAMETER NonInteractive
        Suppress all interactive prompts for the entire batch.

    .PARAMETER Force
        Skip confirmation gates for the entire batch (requires TicketId).

    .PARAMETER OperatorUPN
        Operator identity recorded in every per-UPN context for non-repudiation.

    .PARAMETER OperatorObjectId
        Operator AAD ObjectId for non-repudiation.

    .PARAMETER MaxParallel
        Reserved for v2.1 parallel execution. Accepted now so batch files
        serialised today are forward-compatible. Currently ignored by
        Invoke-DecomBatch (which is sequential).

    .OUTPUTS
        [pscustomobject] with schema:
          BatchId        [string]  — GUID
          TicketId       [string]
          CreatedUtc     [string]  — ISO-8601
          OutputRoot     [string]
          EvidenceLevel  [string]
          WhatIf         [bool]
          NonInteractive [bool]
          Force          [bool]
          OperatorUPN    [string]
          OperatorObjectId [string]
          MaxParallel    [int]     — reserved
          Entries        [ordered] — keyed by normalised UPN
    #>
    [CmdletBinding()]
    param(
        [string[]]$UpnList = @(),

        [string]$TicketId,

        [Parameter(Mandatory)]
        [string]$OutputRoot,

        [ValidateSet('Standard','Detailed','Forensic')]
        [string]$EvidenceLevel = 'Forensic',

        [switch]$WhatIfMode,
        [switch]$NonInteractive,
        [switch]$Force,

        [string]$OperatorUPN      = '',
        [string]$OperatorObjectId = '',

        [ValidateRange(1,32)]
        [int]$MaxParallel = 1   # sequential only in v2.0
    )

    $batch = [pscustomobject]@{
        BatchId          = [guid]::NewGuid().Guid
        TicketId         = $TicketId
        CreatedUtc       = (Get-Date).ToUniversalTime().ToString('o')
        OutputRoot       = $OutputRoot
        EvidenceLevel    = $EvidenceLevel
        WhatIf           = [bool]$WhatIfMode
        NonInteractive   = [bool]$NonInteractive
        Force            = [bool]$Force
        OperatorUPN      = $OperatorUPN
        OperatorObjectId = $OperatorObjectId
        MaxParallel      = $MaxParallel
        Entries          = $null
    }
    # Add-Member ensures [ordered] type is preserved in PS7 across module boundaries
    $batch | Add-Member -Force -NotePropertyName Entries -NotePropertyValue ([ordered]@{})

    foreach ($upn in $UpnList) {
        if ($upn -and $upn.Trim()) {
            _AddBatchEntry -Batch $batch -UPN $upn.Trim()
        }
    }

    return $batch
}

# ── Per-UPN entry management ───────────────────────────────────────────────────

function New-DecomBatchEntry {
    <#
    .SYNOPSIS
        Adds a UPN to an existing batch envelope as a Pending entry.

    .DESCRIPTION
        Idempotent — calling twice for the same UPN returns the existing entry
        without resetting its status. Returns the entry object (not the batch).

    .PARAMETER Batch
        The batch envelope returned by New-DecomBatchContext.

    .PARAMETER UPN
        The user principal name to add.

    .OUTPUTS
        [pscustomobject] — the batch entry object for this UPN.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,
        [Parameter(Mandatory)][string]$UPN
    )

    $key = $UPN.ToLower().Trim()

    if ($Batch.Entries.Contains($key)) {
        return $Batch.Entries[$key]
    }

    return _AddBatchEntry -Batch $Batch -UPN $UPN.Trim()
}

function Get-DecomBatchEntry {
    <#
    .SYNOPSIS
        Retrieves a single batch entry by UPN. Returns $null if not found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,
        [Parameter(Mandatory)][string]$UPN
    )

    $key = $UPN.ToLower().Trim()
    if ($Batch.Entries.Contains($key)) {
        return $Batch.Entries[$key]
    }
    return $null
}

function Set-DecomBatchEntryStatus {
    <#
    .SYNOPSIS
        Updates the lifecycle status and optional metadata on a batch entry.

    .PARAMETER Batch
        The batch envelope.

    .PARAMETER UPN
        Target UPN.

    .PARAMETER Status
        New status: Pending | Running | Completed | Failed | Skipped | Resumed

    .PARAMETER RunId
        The Lite RunId assigned when this UPN's workflow started.

    .PARAMETER ErrorMessage
        Captured error message on failure.

    .PARAMETER StartedUtc
        ISO-8601 string; set automatically when Status transitions to Running.

    .PARAMETER CompletedUtc
        ISO-8601 string; set automatically when Status transitions to
        Completed, Failed, or Skipped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,
        [Parameter(Mandatory)][string]$UPN,

        [Parameter(Mandatory)]
        [ValidateSet('Pending','Running','Completed','Failed','Skipped','Resumed')]
        [string]$Status,

        [string]$RunId,
        [string]$ErrorMessage
    )

    $key   = $UPN.ToLower().Trim()
    $entry = $Batch.Entries[$key]
    if (-not $entry) {
        throw "Set-DecomBatchEntryStatus: UPN '$UPN' not found in batch '$($Batch.BatchId)'."
    }

    $entry.Status = $Status
    $entry.UpdatedUtc = (Get-Date).ToUniversalTime().ToString('o')

    if ($Status -eq 'Running' -or $Status -eq 'Resumed') {
        if (-not $entry.StartedUtc) {
            $entry.StartedUtc = $entry.UpdatedUtc
        }
    }

    if ($Status -eq 'Completed' -or $Status -eq 'Failed' -or $Status -eq 'Skipped') {
        $entry.CompletedUtc = $entry.UpdatedUtc
    }

    if ($RunId)       { $entry.RunId        = $RunId       }
    if ($ErrorMessage){ $entry.ErrorMessage  = $ErrorMessage }
}

# ── Roll-up ────────────────────────────────────────────────────────────────────

function Get-DecomBatchSummary {
    <#
    .SYNOPSIS
        Returns a roll-up of batch entry statuses plus overall health.

    .OUTPUTS
        [pscustomobject] with fields:
          BatchId, TicketId, TotalCount, Pending, Running, Completed,
          Failed, Skipped, Resumed, AllDone [bool], AnyFailed [bool]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch
    )

    $counts = @{
        Pending   = 0
        Running   = 0
        Completed = 0
        Failed    = 0
        Skipped   = 0
        Resumed   = 0
    }

    foreach ($key in $Batch.Entries.Keys) {
        $s = $Batch.Entries[$key].Status
        if ($counts.ContainsKey($s)) { $counts[$s]++ }
    }

    $total   = $Batch.Entries.Count
    $done    = $counts['Completed'] + $counts['Failed'] + $counts['Skipped']
    $allDone = ($total -gt 0) -and ($done -eq $total)

    return [pscustomobject]@{
        BatchId   = $Batch.BatchId
        TicketId  = $Batch.TicketId
        TotalCount = $total
        Pending   = $counts['Pending']
        Running   = $counts['Running']
        Completed = $counts['Completed']
        Failed    = $counts['Failed']
        Skipped   = $counts['Skipped']
        Resumed   = $counts['Resumed']
        AllDone   = $allDone
        AnyFailed = ($counts['Failed'] -gt 0)
    }
}

# ── Private helpers ────────────────────────────────────────────────────────────

function _AddBatchEntry {
    # Internal — not exported. Caller has already validated/trimmed $UPN.
    param(
        [pscustomobject]$Batch,
        [string]$UPN
    )

    $key = $UPN.ToLower()

    $entry = [pscustomobject]@{
        UPN          = $UPN
        Status       = 'Pending'
        RunId        = $null
        StartedUtc   = $null
        CompletedUtc = $null
        UpdatedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        ErrorMessage = $null
        # Per-UPN DecomRunContext is populated by Invoke-DecomBatch at runtime
        # so it is NOT stored here at creation time (avoids stale context data
        # after resume deserialization).
        OutputPath   = $null   # set by Invoke-DecomBatch before run
    }

    $Batch.Entries[$key] = $entry
    return $entry
}

Export-ModuleMember -Function `
    New-DecomBatchContext, `
    New-DecomBatchEntry, `
    Get-DecomBatchEntry, `
    Set-DecomBatchEntryStatus, `
    Get-DecomBatchSummary
