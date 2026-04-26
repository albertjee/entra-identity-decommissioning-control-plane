# BatchOrchestratorParallel.psm1 — PS7 parallel batch execution engine
# Premium v2.1 — Feature 5
#
# Functions:
#   Invoke-DecomBatchParallel  — parallel orchestrator using ForEach-Object -Parallel
#
# Design:
#   Invoke-DecomBatchParallel is a PS7-only parallel alternative to
#   Invoke-DecomBatch (sequential). It honours MaxParallel from the batch
#   envelope (plumbed in Phase 1 BatchContext.psm1).
#
#   Key differences from sequential:
#     - Uses ForEach-Object -Parallel (PS7 only) with -ThrottleLimit MaxParallel
#     - Each UPN runs in its own PS7 runspace — fully isolated
#     - Checkpointing uses a mutex to prevent concurrent JSON file corruption
#     - Results are collected via a thread-safe ConcurrentBag
#     - Resume semantics identical to sequential version
#     - Access removal (Phase 3) runs inside each parallel runspace
#
#   Concurrency safety:
#     - Each UPN writes to its own output directory — no file conflicts
#     - batch-state.json is protected by a named mutex during checkpoint writes
#     - $Batch.Entries status updates are serialised via mutex
#
#   Limitations:
#     - Graph/EXO connections are per-runspace — auth prompt fires once per
#       runspace slot, not once per batch. Use -NonInteractive -Force with
#       service account credentials for fully automated parallel runs.
#     - MaxParallel > 8 is not recommended — Graph throttling applies.
#
# PS7 ONLY — requires PowerShell 7.0+
# Do NOT load this module in PS5.1 — import BatchOrchestrator.psm1 instead.

#Requires -Version 7.0

Set-StrictMode -Version Latest

function Invoke-DecomBatchParallel {
    <#
    .SYNOPSIS
        Parallel orchestrator for multi-UPN decommissioning (PS7 only).

    .DESCRIPTION
        Processes multiple UPNs concurrently using ForEach-Object -Parallel.
        Respects Batch.MaxParallel as the throttle limit.

        Idempotency, resume, and fault isolation semantics are identical to
        the sequential Invoke-DecomBatch. The only difference is concurrency.

        IMPORTANT: Caller must import all required Lite and Premium modules
        before calling this function. Module imports inside -Parallel blocks
        use $using: to pass the module paths in.

    .PARAMETER Batch
        The batch envelope from New-DecomBatchContext or Restore-DecomBatchState.
        Batch.MaxParallel controls the throttle limit (default 1 = sequential).

    .PARAMETER LiteModulesPath
        Full path to the Lite src/Modules directory. Required — passed into
        each parallel runspace via $using:.

    .PARAMETER PremiumModulesPath
        Full path to the Premium src/Premium/Modules directory.

    .PARAMETER LiteWorkflowPath
        Full path to Invoke-DecomWorkflow.ps1.

    .PARAMETER OutOfOfficeMessage
        Forwarded to every per-UPN Invoke-DecomWorkflow call.

    .PARAMETER RemoveLicenses
        Forwarded to every per-UPN workflow.

    .PARAMETER SkipGroups
        Skip group membership removal.

    .PARAMETER SkipRoles
        Skip role assignment removal.

    .PARAMETER SkipAuthMethods
        Skip auth method removal.

    .PARAMETER SkipFailed
        Skip entries with Status = Failed on resume.

    .OUTPUTS
        [pscustomobject] with BatchId, Summary, Results, Errors
        (same schema as Invoke-DecomBatch sequential output)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,

        [Parameter(Mandatory)][string]$LiteModulesPath,
        [Parameter(Mandatory)][string]$PremiumModulesPath,
        [Parameter(Mandatory)][string]$LiteWorkflowPath,

        [string]$OutOfOfficeMessage,
        [switch]$RemoveLicenses,
        [switch]$SkipGroups,
        [switch]$SkipRoles,
        [switch]$SkipAuthMethods,
        [switch]$SkipFailed
    )

    # ── Collect actionable entries ─────────────────────────────────────────────
    $actionable = @($Batch.Entries.Keys | ForEach-Object {
        $entry = $Batch.Entries[$_]
        if ($entry.Status -in @('Completed','Skipped')) { return }
        if ($SkipFailed -and $entry.Status -eq 'Failed') { return }
        $entry
    })

    if ($actionable.Count -eq 0) {
        $summary = Get-DecomBatchSummary -Batch $Batch
        return [pscustomobject]@{
            BatchId = $Batch.BatchId
            Summary = $summary
            Results = @()
            Errors  = @()
        }
    }

    # ── Thread-safe collections ────────────────────────────────────────────────
    $resultBag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $errorBag  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

    # ── Named mutex for checkpoint serialisation ───────────────────────────────
    $mutexName = "DecomBatch_$($Batch.BatchId -replace '-','')"

    # ── Capture values for $using: ────────────────────────────────────────────
    $batchId         = $Batch.BatchId
    $batchTicketId   = $Batch.TicketId
    $batchOutputRoot = $Batch.OutputRoot
    $batchEvidence   = $Batch.EvidenceLevel
    $batchWhatIf     = $Batch.WhatIf
    $batchNonInter   = $Batch.NonInteractive
    $batchForce      = $Batch.Force
    $batchOperUPN    = $Batch.OperatorUPN
    $batchOperOid    = $Batch.OperatorObjectId
    $throttle        = [Math]::Max(1, [Math]::Min($Batch.MaxParallel, 32))

    $oooMsg          = $OutOfOfficeMessage
    $remLic          = [bool]$RemoveLicenses
    $skipGrp         = [bool]$SkipGroups
    $skipRol         = [bool]$SkipRoles
    $skipAuth        = [bool]$SkipAuthMethods
    $liteMods        = $LiteModulesPath
    $premMods        = $PremiumModulesPath
    $liteWf          = $LiteWorkflowPath

    Write-Host ("[Parallel] Starting {0} UPNs with MaxParallel={1}" -f $actionable.Count, $throttle) `
        -ForegroundColor Cyan

    # ── Parallel execution ────────────────────────────────────────────────────
    $actionable | ForEach-Object -Parallel {
        $entry       = $_
        $myResultBag = $using:resultBag
        $myErrorBag  = $using:errorBag
        $myMutexName = $using:mutexName
        $myBatchId   = $using:batchId
        $myOutputRoot= $using:batchOutputRoot
        $myTicket    = $using:batchTicketId
        $myEvidence  = $using:batchEvidence
        $myWhatIf    = $using:batchWhatIf
        $myNonInter  = $using:batchNonInter
        $myForce     = $using:batchForce
        $myOperUPN   = $using:batchOperUPN
        $myOperOid   = $using:batchOperOid
        $myLiteMods  = $using:liteMods
        $myPremMods  = $using:premMods
        $myLiteWf    = $using:liteWf
        $myOooMsg    = $using:oooMsg
        $myRemLic    = $using:remLic
        $mySkipGrp   = $using:skipGrp
        $mySkipRol   = $using:skipRol
        $mySkipAuth  = $using:skipAuth

        # ── Import modules inside runspace ────────────────────────────────────
        $liteOrder = @('Models','Logging','Evidence','State','Execution','Guardrails',
                       'Auth','Validation','Discovery','Containment','Mailbox',
                       'Compliance','Licensing','Reporting')
        foreach ($mod in $liteOrder) {
            Import-Module (Join-Path $myLiteMods "$mod.psm1") -Force -DisableNameChecking
        }
        . $myLiteWf

        $premOrder = @('BatchContext','BatchState','BatchOrchestrator',
                       'BatchReporting','AccessRemoval')
        foreach ($mod in $premOrder) {
            Import-Module (Join-Path $myPremMods "$mod.psm1") -Force -DisableNameChecking
        }

        # ── Per-UPN setup ─────────────────────────────────────────────────────
        $runId        = [guid]::NewGuid().Guid
        $safeUpn      = $entry.UPN -replace '[^\w@._-]', '_'
        $batchDir     = Join-Path $myOutputRoot $myBatchId
        $upnDir       = Join-Path $batchDir $safeUpn
        $logFile      = Join-Path $upnDir 'run.log'
        $evidenceFile = Join-Path $upnDir 'evidence.ndjson'

        $null = New-Item -ItemType Directory -Path $upnDir -Force

        $ctx = New-DecomRunContext `
            -TargetUPN        $entry.UPN `
            -TicketId         $myTicket `
            -OutputPath       $upnDir `
            -EvidenceLevel    $myEvidence `
            -WhatIfMode:      ([switch][bool]$myWhatIf) `
            -NonInteractive:  ([switch][bool]$myNonInter) `
            -Force:           ([switch][bool]$myForce) `
            -OperatorUPN      $myOperUPN `
            -OperatorObjectId $myOperOid

        $state = New-DecomState -RunId $runId
        Initialize-DecomLog -Path $logFile
        Initialize-DecomEvidenceStore -Context $ctx -RunId $runId -NdjsonPath $evidenceFile

        # ── Mutex-protected status update + checkpoint ─────────────────────
        $mutex = [System.Threading.Mutex]::new($false, $myMutexName)
        try {
            $mutex.WaitOne() | Out-Null
            $entry.Status    = 'Running'
            $entry.RunId     = $runId
            $entry.UpdatedUtc= (Get-Date).ToUniversalTime().ToString('o')
            if (-not $entry.StartedUtc) { $entry.StartedUtc = $entry.UpdatedUtc }

            # Checkpoint — reconstruct minimal batch for save
            $checkpointBatch = [pscustomobject]@{
                BatchId          = $myBatchId
                TicketId         = $myTicket
                OutputRoot       = $myOutputRoot
                EvidenceLevel    = $myEvidence
                WhatIf           = $myWhatIf
                NonInteractive   = $myNonInter
                Force            = $myForce
                OperatorUPN      = $myOperUPN
                OperatorObjectId = $myOperOid
                MaxParallel      = 1
                CreatedUtc       = ''
                Entries          = $using:Batch.Entries
            }
            Save-DecomBatchState -Batch $checkpointBatch | Out-Null
        } finally {
            $mutex.ReleaseMutex()
            $mutex.Dispose()
        }

        # ── Run workflow ───────────────────────────────────────────────────────
        try {
            $result = Invoke-DecomWorkflow `
                -Context            $ctx `
                -State              $state `
                -OutOfOfficeMessage $myOooMsg `
                -RemoveLicenses:    ([switch][bool]$myRemLic) `
                -Cmdlet             $null

            if (-not $mySkipGrp -or -not $mySkipRol -or -not $mySkipAuth) {
                $accessResults = Invoke-DecomAccessRemoval `
                    -Context         $ctx `
                    -Cmdlet          $null `
                    -SkipGroups:     ([switch][bool]$mySkipGrp) `
                    -SkipRoles:      ([switch][bool]$mySkipRol) `
                    -SkipAuthMethods:([switch][bool]$mySkipAuth)
                foreach ($ar in $accessResults) { $result.Results += $ar }
            }

            # Mutex-protected completion update
            $mutex2 = [System.Threading.Mutex]::new($false, $myMutexName)
            try {
                $mutex2.WaitOne() | Out-Null
                $now = (Get-Date).ToUniversalTime().ToString('o')
                $entry.Status       = 'Completed'
                $entry.CompletedUtc = $now
                $entry.UpdatedUtc   = $now
                Save-DecomBatchState -Batch $checkpointBatch | Out-Null
            } finally {
                $mutex2.ReleaseMutex()
                $mutex2.Dispose()
            }

            $myResultBag.Add($result)

        } catch {
            $errMsg = $_.Exception.Message

            $mutex3 = [System.Threading.Mutex]::new($false, $myMutexName)
            try {
                $mutex3.WaitOne() | Out-Null
                $now = (Get-Date).ToUniversalTime().ToString('o')
                $entry.Status        = 'Failed'
                $entry.CompletedUtc  = $now
                $entry.UpdatedUtc    = $now
                $entry.ErrorMessage  = $errMsg
                Save-DecomBatchState -Batch $checkpointBatch | Out-Null
            } finally {
                $mutex3.ReleaseMutex()
                $mutex3.Dispose()
            }

            $synthResult = [pscustomobject]@{
                Context    = $ctx
                State      = $state
                Results    = @()
                StopReason = "Unhandled exception: $errMsg"
                Summary    = [pscustomobject]@{
                    TargetUPN     = $entry.UPN
                    RunId         = $runId
                    CorrelationId = $ctx.CorrelationId
                    OperatorUPN   = $myOperUPN
                    TicketId      = $myTicket
                    Status        = 'Failed'
                    Version       = 'v2.1-Premium'
                    EvidenceLevel = $myEvidence
                    Sealed        = $ctx.SealEvidence
                }
            }
            $myResultBag.Add($synthResult)
            $myErrorBag.Add([pscustomobject]@{
                UPN          = $entry.UPN
                RunId        = $runId
                ErrorMessage = $errMsg
            })
        }

    } -ThrottleLimit $throttle

    # ── Assemble final result ──────────────────────────────────────────────────
    $summary = Get-DecomBatchSummary -Batch $Batch

    return [pscustomobject]@{
        BatchId = $Batch.BatchId
        Summary = $summary
        Results = $resultBag.ToArray()
        Errors  = $errorBag.ToArray()
    }
}

Export-ModuleMember -Function Invoke-DecomBatchParallel
