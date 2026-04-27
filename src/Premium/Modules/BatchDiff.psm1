# BatchDiff.psm1 — Structured WhatIf diff / dry-run report
# Premium v2.1 — Feature 1
#
# Functions:
#   New-DecomBatchDiffEntry     — captures a single proposed action for a UPN
#   Export-DecomBatchDiffReport — writes HTML + JSON diff report from a WhatIf run
#
# Design:
#   When Batch.WhatIf = true, Invoke-DecomBatch runs fully but no Graph/EXO
#   mutations occur. This module collects every ActionResult from that run,
#   classifies each as Add/Remove/Modify/Skip, and writes a structured
#   Before vs Proposed diff report at:
#       <OutputRoot>\<BatchId>\batch-diff.html
#       <OutputRoot>\<BatchId>\batch-diff.json
#
#   The diff is grouped by UPN then by Phase so reviewers can scan quickly.
#   Risk level (High/Medium/Low) is inferred from IsCritical + Phase.
#
# PS7 compatible (v2.1 baseline — no PS5.1 restriction)

#Requires -Version 7.0

Set-StrictMode -Version Latest

# ── Risk inference ─────────────────────────────────────────────────────────────

function _InferRisk {
    param([string]$Phase, [bool]$IsCritical, [string]$Status)
    if ($IsCritical -and $Phase -in @('Containment','AccessRemoval')) { return 'High' }
    if ($Phase -in @('Compliance','Licensing','ComplianceRemediation','LicenseRemediation','AzureRBAC','AppOwnership','DeviceRemediation')) { return 'High' }
    if ($Phase -in @('Mailbox','AccessRemoval')) { return 'Medium' }
    return 'Low'
}

function _InferChangeType {
    param([string]$ActionName, [string]$Status)
    if ($Status -eq 'Skipped') { return 'Skip' }
    if ($ActionName -match 'Remove|Revoke|Disable|Strip|Delete') { return 'Remove' }
    if ($ActionName -match 'Convert|Set|Enable|Reset|Block')     { return 'Modify' }
    return 'Action'
}

# ── Public API ─────────────────────────────────────────────────────────────────

function New-DecomBatchDiffEntry {
    <#
    .SYNOPSIS
        Creates a single diff entry from a DecomActionResult.

    .DESCRIPTION
        Called by Export-DecomBatchDiffReport internally. Exposed as public so
        callers can build diff entries manually in tests or custom pipelines.

    .PARAMETER Result
        A DecomActionResult object (from Lite or Premium AccessRemoval).

    .PARAMETER UPN
        Target UPN this result belongs to.

    .OUTPUTS
        [pscustomobject] diff entry with:
          UPN, Phase, ActionName, ChangeType, RiskLevel,
          Status, Message, BeforeState, AfterState, Evidence
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Result,
        [Parameter(Mandatory)][string]$UPN
    )

    [pscustomobject]@{
        UPN        = $UPN
        Phase      = $Result.Phase
        ActionName = $Result.ActionName
        ChangeType = _InferChangeType -ActionName $Result.ActionName -Status $Result.Status
        RiskLevel  = _InferRisk -Phase $Result.Phase -IsCritical $Result.IsCritical -Status $Result.Status
        Status     = $Result.Status
        Message    = $Result.Message
        BeforeState= $Result.BeforeState
        AfterState = $Result.AfterState
        Evidence   = $Result.Evidence
    }
}

function Export-DecomBatchDiffReport {
    <#
    .SYNOPSIS
        Writes HTML + JSON structured diff reports from a WhatIf batch run.

    .DESCRIPTION
        Iterates over all per-UPN workflow results in BatchResult, builds a
        flat list of diff entries, then writes:
            <OutputRoot>\<BatchId>\batch-diff.json
            <OutputRoot>\<BatchId>\batch-diff.html

        The HTML report groups by UPN, colour-codes by risk level, and shows
        a Before vs Proposed state table for each action.

        Intended to be called immediately after Invoke-DecomBatch when
        Batch.WhatIf = true. Can also be called on a live run result for a
        post-hoc change log.

    .PARAMETER Batch
        The batch envelope (post-run).

    .PARAMETER BatchResult
        The object returned by Invoke-DecomBatch.

    .OUTPUTS
        [pscustomobject] with HtmlPath and JsonPath.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,
        [Parameter(Mandatory)][pscustomobject]$BatchResult
    )

    $batchDir = Join-Path $Batch.OutputRoot $Batch.BatchId
    $null     = New-Item -ItemType Directory -Path $batchDir -Force

    # ── Build flat diff list ───────────────────────────────────────────────────
    $diffEntries = [System.Collections.Generic.List[object]]::new()

    foreach ($upnResult in $BatchResult.Results) {
        $upn = $upnResult.Context.TargetUPN
        foreach ($r in $upnResult.Results) {
            $diffEntries.Add((New-DecomBatchDiffEntry -Result $r -UPN $upn))
        }
    }

    # ── JSON output ────────────────────────────────────────────────────────────
    $jsonPath = Join-Path $batchDir 'batch-diff.json'

    $jsonDoc = [ordered]@{
        SchemaVersion = '2.1'
        ReportType    = 'WhatIfDiff'
        BatchId       = $Batch.BatchId
        TicketId      = $Batch.TicketId
        OperatorUPN   = $Batch.OperatorUPN
        WhatIf        = $Batch.WhatIf
        GeneratedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        TotalActions  = $diffEntries.Count
        HighRisk      = @($diffEntries | Where-Object RiskLevel -eq 'High').Count
        MediumRisk    = @($diffEntries | Where-Object RiskLevel -eq 'Medium').Count
        LowRisk       = @($diffEntries | Where-Object RiskLevel -eq 'Low').Count
        Entries       = $diffEntries.ToArray()
    }

    $jsonDoc | ConvertTo-Json -Depth 10 |
        Set-Content -Path $jsonPath -Encoding UTF8

    # ── HTML output ────────────────────────────────────────────────────────────
    $htmlPath = Join-Path $batchDir 'batch-diff.html'

    # Group entries by UPN for HTML rendering
    $byUpn = $diffEntries | Group-Object -Property UPN

    $upnSections = foreach ($grp in $byUpn) {
        $upn   = $grp.Name
        $rows  = foreach ($e in $grp.Group) {
            $riskCss  = switch ($e.RiskLevel) {
                'High'   { 'risk-high'   }
                'Medium' { 'risk-medium' }
                default  { 'risk-low'    }
            }
            $changeCss = switch ($e.ChangeType) {
                'Remove' { 'change-remove' }
                'Modify' { 'change-modify' }
                'Skip'   { 'change-skip'   }
                default  { 'change-action' }
            }
            $before = if ($e.BeforeState -and $e.BeforeState.Count -gt 0) {
                ($e.BeforeState.Keys | ForEach-Object { "$_ = $($e.BeforeState[$_])" }) -join '<br>'
            } else { '—' }
            $after = if ($e.AfterState -and $e.AfterState.Count -gt 0) {
                ($e.AfterState.Keys | ForEach-Object { "$_ = $($e.AfterState[$_])" }) -join '<br>'
            } else { '—' }

            "<tr class='$riskCss'>" +
            "<td><span class='badge $changeCss'>$([System.Net.WebUtility]::HtmlEncode($e.ChangeType))</span></td>" +
            "<td>$([System.Net.WebUtility]::HtmlEncode($e.Phase))</td>" +
            "<td>$([System.Net.WebUtility]::HtmlEncode($e.ActionName))</td>" +
            "<td><span class='risk-badge $riskCss'>$([System.Net.WebUtility]::HtmlEncode($e.RiskLevel))</span></td>" +
            "<td>$([System.Net.WebUtility]::HtmlEncode($e.Message))</td>" +
            "<td class='state-cell'>$before</td>" +
            "<td class='state-cell'>$after</td>" +
            "</tr>"
        }

        $highCount   = @($grp.Group | Where-Object RiskLevel -eq 'High').Count
        $headerClass = if ($highCount -gt 0) { 'upn-header has-high' } else { 'upn-header' }

        "<div class='upn-section'>" +
        "<div class='$headerClass'>" +
        "<span class='upn-name'>$([System.Net.WebUtility]::HtmlEncode($upn))</span>" +
        "<span class='upn-counts'>$($grp.Group.Count) actions" +
        $(if ($highCount -gt 0) { " &nbsp;·&nbsp; <span class='high-count'>$highCount high risk</span>" } else { "" }) +
        "</span></div>" +
        "<table><thead><tr>" +
        "<th>Change</th><th>Phase</th><th>Action</th><th>Risk</th><th>Description</th><th>Before</th><th>Proposed</th>" +
        "</tr></thead><tbody>" +
        ($rows -join "`n") +
        "</tbody></table></div>"
    }

    $modeLabel   = if ($Batch.WhatIf) { 'WhatIf — No changes made' } else { 'Live run change log' }
    $highTotal   = @($diffEntries | Where-Object RiskLevel -eq 'High').Count
    $medTotal    = @($diffEntries | Where-Object RiskLevel -eq 'Medium').Count
    $lowTotal    = @($diffEntries | Where-Object RiskLevel -eq 'Low').Count

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Batch Diff Report — $([System.Net.WebUtility]::HtmlEncode($Batch.BatchId))</title>
<style>
*    { box-sizing: border-box; }
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #172033; font-size: 0.88em; }
h1   { font-size: 1.25em; margin-bottom: 4px; }
p    { margin: 2px 0; color: #444; }
.mode-badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 0.85em;
              font-weight: 500; background: #fff8e5; color: #854f0b; border: 1px solid #f0d080; margin: 6px 0 14px; }
.kpi { display: grid; grid-template-columns: repeat(4, minmax(80px,1fr)); gap: 10px; margin: 12px 0 20px; }
.card { border: 1px solid #d6dbe3; border-radius: 6px; padding: 8px 12px; background: #f8fafc; }
.card .num { font-size: 1.5em; font-weight: 600; line-height: 1.2; }
.card.high   { border-color: #f5c6c6; background: #fff0f0; }
.card.medium { border-color: #f0d080; background: #fff8e5; }
.upn-section { margin-bottom: 20px; }
.upn-header  { display: flex; justify-content: space-between; align-items: center;
               background: #eef2f7; border: 1px solid #d6dbe3; border-bottom: none;
               padding: 7px 12px; border-radius: 6px 6px 0 0; }
.upn-header.has-high { background: #fff0f0; border-color: #f5c6c6; }
.upn-name    { font-weight: 500; font-size: 1em; }
.upn-counts  { font-size: 0.85em; color: #666; }
.high-count  { color: #a32d2d; font-weight: 500; }
table  { width: 100%; border-collapse: collapse; border: 1px solid #d6dbe3;
         border-radius: 0 0 6px 6px; overflow: hidden; margin-bottom: 0; }
th, td { border: 1px solid #d6dbe3; padding: 5px 8px; text-align: left; vertical-align: top; }
th     { background: #f3f6fa; font-size: 0.82em; text-transform: uppercase; letter-spacing: 0.04em; }
.state-cell { font-size: 0.8em; color: #555; font-family: Consolas, monospace; }
tr.risk-high   td { background: #fff5f5; }
tr.risk-medium td { background: #fffbf0; }
tr.risk-low    td { background: #ffffff; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 3px;
         font-size: 0.8em; font-weight: 500; }
.change-remove { background: #fff0f0; color: #a32d2d; }
.change-modify { background: #fff8e5; color: #854f0b; }
.change-skip   { background: #f3f3f3; color: #666; }
.change-action { background: #e6f1fb; color: #185fa5; }
.risk-badge { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: 0.8em; font-weight: 500; }
.risk-high   { background: #fff0f0; color: #a32d2d; }
.risk-medium { background: #fff8e5; color: #854f0b; }
.risk-low    { background: #eef9f0; color: #0f6e56; }
.footer { color: #777; font-size: 0.75em; margin-top: 20px; }

@media print {
  body { margin: 12px; }
  tr.risk-high   td { background: #fff5f5 !important; -webkit-print-color-adjust: exact; }
  tr.risk-medium td { background: #fffbf0 !important; -webkit-print-color-adjust: exact; }
}
</style>
</head>
<body>
<h1>Entra Identity Decommissioning — Batch Diff Report</h1>
<p><strong>Batch ID:</strong> $([System.Net.WebUtility]::HtmlEncode($Batch.BatchId))</p>
<p><strong>Ticket:</strong> $([System.Net.WebUtility]::HtmlEncode($Batch.TicketId)) &nbsp;|&nbsp;
   <strong>Operator:</strong> $([System.Net.WebUtility]::HtmlEncode($Batch.OperatorUPN)) &nbsp;|&nbsp;
   <strong>UPNs:</strong> $($BatchResult.Summary.TotalCount)</p>
<div class="mode-badge">$([System.Net.WebUtility]::HtmlEncode($modeLabel))</div>

<div class="kpi">
  <div class="card"><div class="num">$($diffEntries.Count)</div>Total actions</div>
  <div class="card high"><div class="num">$highTotal</div>High risk</div>
  <div class="card medium"><div class="num">$medTotal</div>Medium risk</div>
  <div class="card"><div class="num">$lowTotal</div>Low risk</div>
</div>

$($upnSections -join "`n")

<p class="footer">&copy; 2026 Albert Jee. All rights reserved. &nbsp;|&nbsp;
Premium v2.1 &nbsp;|&nbsp;
Generated $([System.Net.WebUtility]::HtmlEncode((Get-Date).ToUniversalTime().ToString('o')))</p>
</body>
</html>
"@

    Set-Content -Path $htmlPath -Value $html -Encoding UTF8

    return [pscustomobject]@{
        HtmlPath = $htmlPath
        JsonPath = $jsonPath
    }
}

Export-ModuleMember -Function New-DecomBatchDiffEntry, Export-DecomBatchDiffReport
