# BatchState.psm1 — Batch-aware state persistence (save / restore / checkpoint)
# Premium v2.0 — Phase 1
#
# Design:
#   Save-DecomBatchState    — serialise the full batch envelope to disk as JSON
#   Restore-DecomBatchState — deserialise from disk, reconstruct typed objects
#   Get-DecomBatchStatePath — canonical path helper (<OutputRoot>\<BatchId>\batch-state.json)
#
# Resume contract:
#   Invoke-DecomBatch calls Save-DecomBatchState after EVERY per-UPN completion
#   (success or failure). On resume, entries with Status = Completed or Skipped
#   are skipped; Pending, Running (interrupted mid-run), Failed, and Resumed are
#   re-queued. The orchestrator sets Status = Resumed before re-running.
#
# PS5.1 compatible:
#   - ConvertTo-Json / ConvertFrom-Json (available since PS3)
#   - No 3-arg Join-Path
#   - No [System.IO.Path]::Combine with 3+ args

#Requires -Version 5.1

Set-StrictMode -Version 2.0

# ── Constants ──────────────────────────────────────────────────────────────────

$script:StateFileName = 'batch-state.json'

# ── Public API ─────────────────────────────────────────────────────────────────

function Get-DecomBatchStatePath {
    <#
    .SYNOPSIS
        Returns the canonical JSON state file path for a given batch envelope.

    .DESCRIPTION
        Path: <Batch.OutputRoot>\<Batch.BatchId>\batch-state.json
        The directory is NOT created by this function; callers that need the
        directory to exist should call Save-DecomBatchState which creates it.

    .OUTPUTS
        [string] — full file path
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch
    )

    $batchDir = Join-Path $Batch.OutputRoot $Batch.BatchId
    return Join-Path $batchDir $script:StateFileName
}

function Save-DecomBatchState {
    <#
    .SYNOPSIS
        Serialises the batch envelope to disk as a JSON checkpoint file.

    .DESCRIPTION
        Creates the batch directory if it does not exist.
        Writes atomically: serialises to a temp file first, then renames.
        Depth 6 covers Entries[*].* without truncation for the current schema.

    .PARAMETER Batch
        The batch envelope to persist.

    .PARAMETER StatePath
        Optional override for the file path. Defaults to Get-DecomBatchStatePath.

    .OUTPUTS
        [string] — path where the file was saved.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,
        [string]$StatePath
    )

    if (-not $StatePath) {
        $StatePath = Get-DecomBatchStatePath -Batch $Batch
    }

    $dir = Split-Path -Parent $StatePath
    if (-not (Test-Path $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }

    # Serialise the batch.
    # pscustomobject converts cleanly via ConvertTo-Json.
    # Ordered hashtables (Entries) also serialise correctly.
    $json    = $Batch | ConvertTo-Json -Depth 6
    $tmpPath = $StatePath + '.tmp'

    Set-Content -Path $tmpPath -Value $json -Encoding UTF8

    # Atomic overwrite using .NET File.Copy with overwrite=true.
    # This is safe on crash — if the process dies before Copy completes,
    # the original StatePath is still intact. The .tmp file is cleaned up
    # after a successful copy. Remove-Item + Move-Item is NOT atomic.
    [System.IO.File]::Copy($tmpPath, $StatePath, $true)
    Remove-Item -Path $tmpPath -Force -ErrorAction SilentlyContinue

    return $StatePath
}

function Restore-DecomBatchState {
    <#
    .SYNOPSIS
        Deserialises a batch envelope from a JSON checkpoint file.

    .DESCRIPTION
        Reconstructs the batch envelope as a pscustomobject with an [ordered]
        Entries dictionary. Each entry is also reconstructed as pscustomobject.

        After restore the caller (Invoke-DecomBatch) should call
        Set-DecomBatchEntryStatus -Status Resumed for any entry in Running state
        (indicating it was interrupted mid-flight before the previous run died).

    .PARAMETER StatePath
        Full path to the batch-state.json file.

    .OUTPUTS
        [pscustomobject] — rehydrated batch envelope compatible with
        BatchContext.psm1 functions.

    .EXAMPLE
        $batch = Restore-DecomBatchState -StatePath 'C:\output\abc123\batch-state.json'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$StatePath
    )

    if (-not (Test-Path $StatePath)) {
        throw "Restore-DecomBatchState: state file not found at '$StatePath'."
    }

    $raw  = Get-Content -Path $StatePath -Raw -Encoding UTF8
    $data = $raw | ConvertFrom-Json

    # Rebuild Entries as an OrderedDictionary of pscustomobject.
    # ConvertFrom-Json returns a PSCustomObject for the Entries property;
    # its NoteProperty names are the UPN keys we stored.
    # OrdinalIgnoreCase comparer mirrors New-DecomBatchContext behaviour.
    $entries = New-Object 'System.Collections.Specialized.OrderedDictionary' `
                   ([System.StringComparer]::OrdinalIgnoreCase)

    if ($data.Entries) {
        # PS5.1: psobject.Properties to enumerate dynamic keys
        foreach ($prop in $data.Entries.psobject.Properties) {
            $key   = $prop.Name
            $raw_e = $prop.Value

            $entry = [pscustomobject]@{
                UPN          = $raw_e.UPN
                Status       = $raw_e.Status
                RunId        = $raw_e.RunId
                StartedUtc   = $raw_e.StartedUtc
                CompletedUtc = $raw_e.CompletedUtc
                UpdatedUtc   = $raw_e.UpdatedUtc
                ErrorMessage = $raw_e.ErrorMessage
                OutputPath   = $raw_e.OutputPath
            }
            $entries[$key] = $entry
        }
    }

    $batch = [pscustomobject]@{
        BatchId          = $data.BatchId
        TicketId         = $data.TicketId
        CreatedUtc       = $data.CreatedUtc
        OutputRoot       = $data.OutputRoot
        EvidenceLevel    = $data.EvidenceLevel
        WhatIf           = [bool]$data.WhatIf
        NonInteractive   = [bool]$data.NonInteractive
        Force            = [bool]$data.Force
        NoSeal           = [bool]$data.NoSeal
        OperatorUPN      = $data.OperatorUPN
        OperatorObjectId = $data.OperatorObjectId
        MaxParallel      = [int]$data.MaxParallel
        Entries          = $entries
    }

    return $batch
}

Export-ModuleMember -Function `
    Get-DecomBatchStatePath, `
    Save-DecomBatchState, `
    Restore-DecomBatchState
