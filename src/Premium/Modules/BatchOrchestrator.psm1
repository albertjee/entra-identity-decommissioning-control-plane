# BatchOrchestrator.psm1 — Invoke-DecomBatch: sequential multi-UPN orchestrator
# Premium v2.0 — Phase 1
#
# Design:
#   Invoke-DecomBatch iterates over Pending/Failed/Resumed entries in the batch
#   envelope and calls the Lite Invoke-DecomWorkflow for each UPN in sequence.
#   After every UPN (success or failure) it checkpoints state to disk via
#   Save-DecomBatchState so a subsequent resume skips completed work.
#
#   Execution contract:
#     - Completed / Skipped entries → always skipped (idempotency guarantee)
#     - Running entries on resume   → treated as Resumed (interrupted mid-run)
#     - Failed entries              → re-run on resume unless -SkipFailed
#     - Per-UPN output goes to:     <Batch.OutputRoot>\<BatchId>\<sanitised-UPN>\
#
#   This module does NOT import Lite modules itself. The caller (Start-DecomBatch.ps1)
#   is responsible for importing all required Lite + Premium modules in the correct
#   order before calling Invoke-DecomBatch.
#
# PS5.1 compatible — no 3-arg Join-Path, no parallel ForEach-Object -Parallel.

#Requires -Version 5.1

Set-StrictMode -Version Latest

function Invoke-DecomBatch {
    <#
    .SYNOPSIS
        Orchestrates sequential decommissioning of multiple UPNs from a batch envelope.

    .DESCRIPTION
        For each actionable entry in the batch (Pending, Failed on first run or
        resume, Running-interrupted on resume), Invoke-DecomBatch:

          1. Creates a per-UPN output directory.
          2. Calls New-DecomRunContext (from Lite Models.psm1) to build the context.
          3. Initialises Lite logging and evidence store for the run.
          4. Sets entry status to Running and checkpoints.
          5. Calls Invoke-DecomWorkflow (Lite).
          6. Sets entry status to Completed or Failed and checkpoints.
          7. Emits a per-UPN result object into the returned BatchResult.

        A batch summary is computed at the end and returned with all per-UPN results.

    .PARAMETER Batch
        The batch envelope from New-DecomBatchContext or Restore-DecomBatchState.

    .PARAMETER OutOfOfficeMessage
        Forwarded to every per-UPN Invoke-DecomWorkflow call.

    .PARAMETER EnableLitigationHold
        Forwarded to every per-UPN Invoke-DecomWorkflow call.

    .PARAMETER RemoveLicenses
        Forwarded to every per-UPN Invoke-DecomWorkflow call.

    .PARAMETER SkipFailed
        If set, entries with Status = Failed are not retried (useful when batch
        is resumed after partial correction of a specific failure).

    .PARAMETER Cmdlet
        PSCmdlet reference for ShouldProcess / ShouldContinue gates (same
        pattern as Lite Invoke-DecomWorkflow). Pass $PSCmdlet from the caller.

    .OUTPUTS
        [pscustomobject] with:
          BatchId    [string]
          Summary    [pscustomobject]  — from Get-DecomBatchSummary
          Results    [object[]]        — per-UPN DecomWorkflowReturn objects
          Errors     [pscustomobject[]] — entries that failed (for easy inspection)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,

        [string]$OutOfOfficeMessage,
        [switch]$EnableLitigationHold,
        [switch]$RemoveLicenses,
        [switch]$SkipFailed,

        $Cmdlet   # PSCmdlet in production; stub acceptable in tests
    )

    $allResults  = New-Object System.Collections.Generic.List[object]
    $errorBucket = New-Object System.Collections.Generic.List[object]

    foreach ($key in @($Batch.Entries.Keys)) {
        $entry = $Batch.Entries[$key]

        # ── Idempotency gate ──────────────────────────────────────────────────
        if ($entry.Status -eq 'Completed' -or $entry.Status -eq 'Skipped') {
            Write-DecomConsole -Level 'INFO' `
                -Message "[Batch] Skipping $($entry.UPN) — already $($entry.Status)."
            continue
        }

        if ($SkipFailed -and $entry.Status -eq 'Failed') {
            Write-DecomConsole -Level 'WARN' `
                -Message "[Batch] Skipping $($entry.UPN) — status is Failed and -SkipFailed is set."
            continue
        }

        # Running = interrupted mid-flight in a previous run → treat as resume
        if ($entry.Status -eq 'Running') {
            Set-DecomBatchEntryStatus -Batch $Batch -UPN $entry.UPN -Status 'Resumed'
            Write-DecomConsole -Level 'WARN' `
                -Message "[Batch] $($entry.UPN) was interrupted mid-run — resuming."
        }

        # ── Per-UPN setup ─────────────────────────────────────────────────────
        $runId       = [guid]::NewGuid().Guid
        $safeUpn     = _SanitiseUPNForPath -UPN $entry.UPN
        $batchDir    = Join-Path $Batch.OutputRoot $Batch.BatchId
        $upnDir      = Join-Path $batchDir $safeUpn
        $logFile     = Join-Path $upnDir 'run.log'
        $evidenceFile= Join-Path $upnDir 'evidence.ndjson'

        if (-not (Test-Path $upnDir)) {
            $null = New-Item -ItemType Directory -Path $upnDir -Force
        }

        $entry.OutputPath = $upnDir

        # Build per-UPN Lite context from batch-level settings
        $ctx = New-DecomRunContext `
            -TargetUPN       $entry.UPN `
            -TicketId        $Batch.TicketId `
            -OutputPath      $upnDir `
            -EvidenceLevel   $Batch.EvidenceLevel `
            -WhatIfMode:     ([switch]($Batch.WhatIf)) `
            -NonInteractive: ([switch]($Batch.NonInteractive)) `
            -Force:          ([switch]($Batch.Force)) `
            -OperatorUPN     $Batch.OperatorUPN `
            -OperatorObjectId $Batch.OperatorObjectId

        $state = New-DecomState -RunId $runId

        Initialize-DecomLog -Path $logFile
        Initialize-DecomEvidenceStore -Context $ctx -RunId $runId -NdjsonPath $evidenceFile

        # ── Mark Running + checkpoint ─────────────────────────────────────────
        Set-DecomBatchEntryStatus -Batch $Batch -UPN $entry.UPN -Status 'Running' -RunId $runId
        Save-DecomBatchState -Batch $Batch | Out-Null

        Write-DecomConsole -Level 'INFO' `
            -Message "[Batch] Starting $($entry.UPN) | RunId: $runId"

        # ── Run Lite workflow ─────────────────────────────────────────────────
        try {
            $result = Invoke-DecomWorkflow `
                -Context             $ctx `
                -State               $state `
                -OutOfOfficeMessage  $OutOfOfficeMessage `
                -EnableLitigationHold:$EnableLitigationHold `
                -RemoveLicenses:     $RemoveLicenses `
                -Cmdlet              $Cmdlet

            Set-DecomBatchEntryStatus -Batch $Batch -UPN $entry.UPN -Status 'Completed' -RunId $runId

            Write-DecomConsole -Level 'INFO' `
                -Message "[Batch] Completed $($entry.UPN) | Status: $($result.Summary.Status)"

        } catch {
            $errMsg = $_.Exception.Message
            Set-DecomBatchEntryStatus -Batch $Batch -UPN $entry.UPN `
                -Status 'Failed' -RunId $runId -ErrorMessage $errMsg

            # Synthesise a minimal result so the batch result set is complete
            $result = [pscustomobject]@{
                Context    = $ctx
                State      = $state
                Results    = @()
                StopReason = "Unhandled exception: $errMsg"
                Summary    = [pscustomobject]@{
                    TargetUPN     = $entry.UPN
                    RunId         = $runId
                    CorrelationId = $ctx.CorrelationId
                    OperatorUPN   = $Batch.OperatorUPN
                    TicketId      = $Batch.TicketId
                    Status        = 'Failed'
                    Version       = 'v2.0-Premium'
                    EvidenceLevel = $Batch.EvidenceLevel
                    Sealed        = $ctx.SealEvidence
                }
            }

            $errorBucket.Add([pscustomobject]@{
                UPN          = $entry.UPN
                RunId        = $runId
                ErrorMessage = $errMsg
            })

            Write-DecomConsole -Level 'ERROR' `
                -Message "[Batch] FAILED $($entry.UPN): $errMsg"
        }

        $allResults.Add($result)

        # ── Checkpoint after every UPN ────────────────────────────────────────
        Save-DecomBatchState -Batch $Batch | Out-Null
    }

    $summary = Get-DecomBatchSummary -Batch $Batch

    return [pscustomobject]@{
        BatchId = $Batch.BatchId
        Summary = $summary
        Results = $allResults.ToArray()
        Errors  = $errorBucket.ToArray()
    }
}

# ── Private helpers ────────────────────────────────────────────────────────────

function _SanitiseUPNForPath {
    # Replace filesystem-unsafe chars in a UPN to produce a safe dir name.
    # UPNs are email-like; '@' and '.' are safe on Windows/Linux but we
    # strip anything outside [a-zA-Z0-9@._-].
    param([string]$UPN)
    return ($UPN -replace '[^\w@._-]', '_')
}

Export-ModuleMember -Function Invoke-DecomBatch
