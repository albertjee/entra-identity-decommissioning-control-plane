# Start-DecomBatch.ps1 — Premium v2.1 batch launcher
# Orchestrates multi-UPN decommissioning runs via the batch engine.
#
# Usage — new batch:
#   .\Start-DecomBatch.ps1 -UpnList alice@contoso.com,bob@contoso.com `
#       -TicketId CHG0012345 -RemoveLicenses -NonInteractive -Force
#
# Usage — resume interrupted batch:
#   .\Start-DecomBatch.ps1 -ResumePath 'C:\output\<BatchId>\batch-state.json'
#
# Output layout:
#   <RepoRoot>\output\<BatchId>\<sanitised-upn>\run.log
#   <RepoRoot>\output\<BatchId>\<sanitised-upn>\evidence.ndjson
#   <RepoRoot>\output\<BatchId>\<sanitised-upn>\report.json
#   <RepoRoot>\output\<BatchId>\<sanitised-upn>\report.html
#   <RepoRoot>\output\<BatchId>\batch-state.json
#
# PS7 compatible (v2.0). Sequential execution only in v2.0. Parallel is a v2.x feature.

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'New')]
param(
    # ── New batch params ───────────────────────────────────────────────────────
    [Parameter(ParameterSetName = 'New', Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$UpnList,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Resume')]
    [string]$TicketId,

    [Parameter(ParameterSetName = 'New')]
    [string]$OutOfOfficeMessage,

    [Parameter(ParameterSetName = 'New')]
    [ValidateSet('Standard','Detailed','Forensic')]
    [string]$EvidenceLevel = 'Forensic',

    [Parameter(ParameterSetName = 'New')]
    [switch]$RemoveLicenses,

    [Parameter(ParameterSetName = 'New')]
    [switch]$WhatIfMode,

    [Parameter(ParameterSetName = 'New')]
    [switch]$NonInteractive,

    [Parameter(ParameterSetName = 'New')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'New')]
    [switch]$NoSeal,

    [Parameter(ParameterSetName = 'New')]
    [switch]$SkipGroups,

    [Parameter(ParameterSetName = 'New')]
    [switch]$SkipRoles,

    [Parameter(ParameterSetName = 'New')]
    [switch]$SkipAuthMethods,

    [Parameter(ParameterSetName = 'New')]
    [string]$PolicyPath,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Resume')]
    [string]$ApprovalPath,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Resume')]
    [switch]$RequireApproval,

    # ── Resume params ──────────────────────────────────────────────────────────
    [Parameter(ParameterSetName = 'Resume', Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ResumePath,

    [Parameter(ParameterSetName = 'Resume')]
    [switch]$SkipFailed
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ── Resolve paths ──────────────────────────────────────────────────────────────
# Premium lives at: src/Premium/Start-DecomBatch.ps1
# Lite src lives at: src/
# Repo root lives at: ../  (relative to src/)
$PremiumRoot  = Split-Path -Parent $MyInvocation.MyCommand.Path   # src/Premium
$SrcRoot      = Split-Path -Parent $PremiumRoot                    # src/
$RepoRoot     = Split-Path -Parent $SrcRoot                        # repo root
$LiteModules  = Join-Path $SrcRoot 'Modules'
$PremiumMods  = Join-Path $PremiumRoot 'Modules'
$LiteWorkflow = Join-Path $SrcRoot 'Invoke-DecomWorkflow.ps1'
$OutputBase   = Join-Path $RepoRoot 'output'

# ── Import Lite modules (exact order from Start-Decom.ps1) ────────────────────
$liteModuleOrder = @(
    'Models','Logging','Evidence','State','Execution','Guardrails',
    'Auth','Validation','Discovery','Containment','Mailbox','Compliance','Licensing','Reporting'
)
foreach ($mod in $liteModuleOrder) {
    Import-Module (Join-Path $LiteModules "$mod.psm1") -Force -DisableNameChecking
}
. $LiteWorkflow

# ── Import Premium modules ────────────────────────────────────────────────────
$premiumModuleOrder = @('BatchContext','BatchState','BatchApproval','BatchPolicy','AccessRemoval','MailboxExtended','ComplianceRemediation','LicenseRemediation','DeviceRemediation','AppOwnership','AzureRBAC','BatchDiff','BatchReporting','BatchOrchestrator','BatchOrchestratorParallel')
foreach ($mod in $premiumModuleOrder) {
    Import-Module (Join-Path $PremiumMods "$mod.psm1") -Force -DisableNameChecking
}

# ── Ensure output root exists ─────────────────────────────────────────────────
$null = New-Item -ItemType Directory -Path $OutputBase -Force

# ── Build or restore batch envelope ──────────────────────────────────────────
if ($PSCmdlet.ParameterSetName -eq 'Resume') {
    Write-Host "Entra Identity Decommissioning Control Plane — Premium v2.1" -ForegroundColor Cyan
    Write-Host "Mode: RESUME" -ForegroundColor Yellow
    Write-Host "State file: $ResumePath" -ForegroundColor Yellow

    $Batch = Restore-DecomBatchState -StatePath $ResumePath

    Write-Host ("Batch: {0} | UPNs: {1}" -f $Batch.BatchId, $Batch.Entries.Count) -ForegroundColor Cyan

} else {
    # ── Governance gate: TicketId mandatory in automation mode ────────────────
    if ($Force -and $NonInteractive -and -not $TicketId) {
        Write-Error 'TicketId is required when running -Force -NonInteractive. Provide a change/ticket reference for audit traceability.'
        exit 1
    }

    # ── Validate UPN format (warn, don't block — Graph will reject bad ones) ──
    $upnPattern = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
    $badUpns = $UpnList | Where-Object { $_ -notmatch $upnPattern }
    if ($badUpns) {
        Write-Warning "The following UPNs look malformed and may fail at runtime: $($badUpns -join ', ')"
    }

    $Batch = New-DecomBatchContext `
        -UpnList         $UpnList `
        -TicketId        $TicketId `
        -OutputRoot      $OutputBase `
        -EvidenceLevel   $EvidenceLevel `
        -WhatIfMode:     $WhatIfMode `
        -NonInteractive: $NonInteractive `
        -Force:          $Force

    # Store NoSeal on batch envelope so orchestrator can apply it per-UPN
    # before evidence store initialization. Sealing is immutable per run.
    $Batch | Add-Member -NotePropertyName 'NoSeal' -NotePropertyValue ([bool]$NoSeal) -Force

    $StatePath = Get-DecomBatchStatePath -Batch $Batch
    Write-Host "Entra Identity Decommissioning Control Plane — Premium v2.1" -ForegroundColor Cyan
    Write-Host ("Batch: {0} | UPNs: {1} | Ticket: {2} | Mode: {3}" -f `
        $Batch.BatchId, `
        $Batch.Entries.Count, `
        $(if ($TicketId) { $TicketId } else { 'none' }), `
        $(if ($WhatIfMode) { 'WhatIf' } elseif ($NonInteractive) { 'NonInteractive' } else { 'Interactive' })
    ) -ForegroundColor Cyan

    # Initial checkpoint before any work begins
    Save-DecomBatchState -Batch $Batch | Out-Null
    Write-Host "State file: $StatePath" -ForegroundColor DarkGray
}

# ── Load policy file if supplied ─────────────────────────────────────────────
$Policy = $null
if ($PolicyPath) {
    $Policy = Read-DecomBatchPolicy -Path $PolicyPath
    Write-Host "Policy file loaded: $PolicyPath" -ForegroundColor DarkGray
}

# ── Resolve operator identity BEFORE approval gate ───────────────────────────
# Must happen here so approval record contains correct OperatorUPN.
# NonInteractive -RequireApproval is rejected if identity cannot be resolved.
try {
    $mgCtx = Get-MgContext -ErrorAction SilentlyContinue
    if ($mgCtx) {
        $Batch.OperatorUPN = $mgCtx.Account
        $mgUser = Get-MgUser -UserId $mgCtx.Account -Property Id -ErrorAction SilentlyContinue
        if ($mgUser) { $Batch.OperatorObjectId = $mgUser.Id }
    }
} catch {}

if ($RequireApproval -and $NonInteractive -and [string]::IsNullOrWhiteSpace($Batch.OperatorUPN)) {
    throw 'Start-DecomBatch: cannot resolve OperatorUPN from Graph context. ' +
          '-RequireApproval -NonInteractive requires a resolved operator identity for non-repudiation.'
}

# ── Approval gate ─────────────────────────────────────────────────────────────
if ($RequireApproval) {
    Invoke-DecomBatchApproval `
        -Batch           $Batch `
        -NonInteractive: $NonInteractive `
        -ApprovalPath    $ApprovalPath | Out-Null
}

# ── Run the batch ─────────────────────────────────────────────────────────────
# Note: Parallel execution is not available in v2.0.
# BatchOrchestratorParallel.psm1 requires a dedicated HTR pass before production use.
# Sequential execution only. Parallel will be re-introduced in v2.x.
try {
    $BatchResult = Invoke-DecomBatch `
        -Batch               $Batch `
        -OutOfOfficeMessage  $OutOfOfficeMessage `
        -RemoveLicenses:     $RemoveLicenses `
        -SkipGroups:         $SkipGroups `
        -SkipRoles:          $SkipRoles `
        -SkipAuthMethods:    $SkipAuthMethods `
        -SkipFailed:         $SkipFailed `
        -Policy              $Policy `
        -Cmdlet              $PSCmdlet

    # ── Final checkpoint ──────────────────────────────────────────────────────
    Save-DecomBatchState -Batch $Batch | Out-Null

    # ── Batch reports ────────────────────────────────────────────────
    $JsonReportPath   = Export-DecomBatchJsonReport      -Batch $Batch -BatchResult $BatchResult
    $HtmlReportPath   = Export-DecomBatchHtmlReport      -Batch $Batch -BatchResult $BatchResult
    $EvidManifestPath = Write-DecomBatchEvidenceManifest -Batch $Batch

    # ── Diff report (always written — most useful in WhatIf mode) ─────────────
    $DiffPaths = Export-DecomBatchDiffReport -Batch $Batch -BatchResult $BatchResult

    # ── Summary output ────────────────────────────────────────────────────────
    $s = $BatchResult.Summary
    Write-Host '' 
    Write-Host '── Batch complete ───────────────────────────────────────' -ForegroundColor Cyan
    Write-Host ("  Total   : {0}"    -f $s.TotalCount) -ForegroundColor White
    Write-Host ("  Done    : {0}"    -f $s.Completed)  -ForegroundColor Green
    Write-Host ("  Failed  : {0}"    -f $s.Failed)     -ForegroundColor $(if ($s.AnyFailed) { 'Red' } else { 'White' })
    Write-Host ("  Skipped : {0}"    -f $s.Skipped)    -ForegroundColor DarkGray
    Write-Host ("  Output  : {0}"    -f (Join-Path $OutputBase $Batch.BatchId)) -ForegroundColor DarkGray
    Write-Host ("  HTML    : {0}"    -f $HtmlReportPath)   -ForegroundColor DarkGray
    Write-Host ("  JSON    : {0}"    -f $JsonReportPath)   -ForegroundColor DarkGray
    Write-Host ("  Manifest: {0}"    -f $EvidManifestPath) -ForegroundColor DarkGray
    Write-Host ("  Diff HTML: {0}"   -f $DiffPaths.HtmlPath) -ForegroundColor DarkGray
    Write-Host ("  Diff JSON: {0}"   -f $DiffPaths.JsonPath) -ForegroundColor DarkGray

    if ($BatchResult.Errors.Count -gt 0) {
        Write-Host ''
        Write-Host '── Failed entries ───────────────────────────────────────' -ForegroundColor Red
        foreach ($err in $BatchResult.Errors) {
            Write-Host ("  {0}" -f $err.UPN)          -ForegroundColor Red
            Write-Host ("    {0}" -f $err.ErrorMessage) -ForegroundColor DarkRed
        }
        Write-Host ''
        Write-Host 'To retry failed entries:' -ForegroundColor Yellow
        Write-Host ("  .\Start-DecomBatch.ps1 -ResumePath '{0}'" -f (Get-DecomBatchStatePath -Batch $Batch)) -ForegroundColor Yellow
    }

    if ($s.AnyFailed) { exit 2 }
    exit 0

} catch {
    Write-Host ("FATAL: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host 'Batch state has been checkpointed. Resume with:' -ForegroundColor Yellow
    Write-Host ("  .\Start-DecomBatch.ps1 -ResumePath '{0}'" -f (Get-DecomBatchStatePath -Batch $Batch)) -ForegroundColor Yellow
    exit 1
}
