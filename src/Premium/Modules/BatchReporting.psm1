# BatchReporting.psm1 — Batch-level reporting and cross-UPN evidence manifest
# Premium v2.0 — Phase 2
#
# Functions:
#   Export-DecomBatchJsonReport   — machine-readable roll-up JSON
#   Export-DecomBatchHtmlReport   — human-readable HTML summary (print-ready)
#   Write-DecomBatchEvidenceManifest — index of every UPN's evidence file + hash
#
# Design principles:
#   - Reads per-UPN report.json files already written by Lite Reporting.psm1
#   - Never re-reads evidence.ndjson directly (Lite owns that format)
#   - Batch manifest is additive — does not replace per-UPN manifests
#   - All output lands in <OutputRoot>\<BatchId>\ (not inside a UPN subfolder)
#   - PS5.1 compatible throughout

#Requires -Version 5.1

Set-StrictMode -Version Latest

# ── JSON roll-up ───────────────────────────────────────────────────────────────

function Export-DecomBatchJsonReport {
    <#
    .SYNOPSIS
        Writes a machine-readable JSON roll-up of the entire batch run.

    .DESCRIPTION
        Aggregates the batch summary, per-UPN entry metadata, and the Summary
        block from each UPN's Lite report.json into a single file:
            <OutputRoot>\<BatchId>\batch-report.json

        Per-UPN full workflow results are NOT embedded (they can be large).
        The per-UPN report.json path is referenced so consumers can drill in.

    .PARAMETER Batch
        The batch envelope (post-run, entries have final statuses).

    .PARAMETER BatchResult
        The object returned by Invoke-DecomBatch.

    .OUTPUTS
        [string] — path to the written file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,
        [Parameter(Mandatory)][pscustomobject]$BatchResult
    )

    $batchDir  = Join-Path $Batch.OutputRoot $Batch.BatchId
    $outPath   = Join-Path $batchDir 'batch-report.json'

    $upnReports = _CollectUpnReportSummaries -Batch $Batch

    $report = [ordered]@{
        SchemaVersion  = '2.0'
        ReportType     = 'BatchSummary'
        BatchId        = $Batch.BatchId
        TicketId       = $Batch.TicketId
        OperatorUPN    = $Batch.OperatorUPN
        EvidenceLevel  = $Batch.EvidenceLevel
        WhatIf         = $Batch.WhatIf
        CreatedUtc     = $Batch.CreatedUtc
        GeneratedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        Summary        = [ordered]@{
            TotalCount = $BatchResult.Summary.TotalCount
            Completed  = $BatchResult.Summary.Completed
            Failed     = $BatchResult.Summary.Failed
            Skipped    = $BatchResult.Summary.Skipped
            AllDone    = $BatchResult.Summary.AllDone
            AnyFailed  = $BatchResult.Summary.AnyFailed
        }
        Entries        = $upnReports
        Errors         = @($BatchResult.Errors | ForEach-Object {
            [ordered]@{
                UPN          = $_.UPN
                RunId        = $_.RunId
                ErrorMessage = $_.ErrorMessage
            }
        })
    }

    $null = _EnsureDir $batchDir
    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $outPath -Encoding UTF8
    return $outPath
}

# ── HTML roll-up ───────────────────────────────────────────────────────────────

function Export-DecomBatchHtmlReport {
    <#
    .SYNOPSIS
        Writes a print-ready HTML batch summary report.

    .DESCRIPTION
        Produces a single HTML file at:
            <OutputRoot>\<BatchId>\batch-report.html

        Contains:
          - Batch header (BatchId, TicketId, operator, timestamp)
          - KPI summary cards (total / completed / failed / skipped)
          - Per-UPN results table with status colour coding
          - Links to individual UPN HTML reports (relative paths)
          - Failed entries section with error messages
          - Print stylesheet matching Lite report style

    .PARAMETER Batch
        The batch envelope (post-run).

    .PARAMETER BatchResult
        The object returned by Invoke-DecomBatch.

    .OUTPUTS
        [string] — path to the written file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch,
        [Parameter(Mandatory)][pscustomobject]$BatchResult
    )

    $batchDir = Join-Path $Batch.OutputRoot $Batch.BatchId
    $outPath  = Join-Path $batchDir 'batch-report.html'
    $s        = $BatchResult.Summary

    # ── Per-UPN table rows ────────────────────────────────────────────────────
    $rows = foreach ($key in $Batch.Entries.Keys) {
        $entry    = $Batch.Entries[$key]
        $css      = _StatusToCss $entry.Status
        $reportRel = "$([System.IO.Path]::GetFileName($entry.OutputPath))\report.html"
        $linkCell = if ($entry.OutputPath -and (Test-Path (Join-Path $entry.OutputPath 'report.html'))) {
            "<a href='$([System.Net.WebUtility]::HtmlEncode($reportRel))'>report</a>"
        } else { '—' }

        $errCell = if ($entry.ErrorMessage) {
            "<span class='err'>$([System.Net.WebUtility]::HtmlEncode($entry.ErrorMessage))</span>"
        } else { '' }

        "<tr class='$css'>" +
        "<td>$([System.Net.WebUtility]::HtmlEncode($entry.UPN))</td>" +
        "<td>$([System.Net.WebUtility]::HtmlEncode($entry.Status))</td>" +
        "<td>$([System.Net.WebUtility]::HtmlEncode($entry.RunId))</td>" +
        "<td>$([System.Net.WebUtility]::HtmlEncode($entry.StartedUtc))</td>" +
        "<td>$([System.Net.WebUtility]::HtmlEncode($entry.CompletedUtc))</td>" +
        "<td>$errCell</td>" +
        "<td>$linkCell</td>" +
        "</tr>"
    }

    $modeLabel = if ($Batch.WhatIf) { 'WhatIf (dry run)' } else { 'Live' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Batch Decommissioning Report — $([System.Net.WebUtility]::HtmlEncode($Batch.BatchId))</title>
<style>
body  { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #172033; }
h1    { font-size: 1.3em; margin-bottom: 4px; }
h2    { font-size: 1.05em; margin: 24px 0 8px; }
p     { margin: 2px 0; font-size: 0.88em; color: #444; }
.kpi  { display: grid; grid-template-columns: repeat(4, minmax(90px,1fr)); gap: 10px; margin: 16px 0; }
.card { border: 1px solid #d6dbe3; border-radius: 6px; padding: 10px 14px;
        background: #f8fafc; font-size: 0.9em; }
.card .num  { font-size: 1.6em; font-weight: 600; line-height: 1.1; }
.card.fail  { border-color: #f5c6c6; background: #fff0f0; }
.card.ok    { border-color: #b7e4c7; background: #eef9f0; }
table { border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 0.83em; }
th,td { border: 1px solid #d6dbe3; padding: 6px 8px; text-align: left; vertical-align: top; }
th    { background: #eef2f7; }
tr.Completed td { background: #eef9f0; }
tr.Failed    td { background: #fff0f0; }
tr.Skipped   td { background: #f3f3f3; }
tr.Resumed   td { background: #fff8e5; }
tr.Pending   td { background: #f8fafc; }
tr.Running   td { background: #e8f4fd; }
.err  { color: #a32d2d; font-size: 0.92em; }
.footer { color: #777; font-size: 0.75em; margin-top: 20px; }
a { color: #185fa5; }

@media print {
  body { margin: 12px; font-size: 0.8em; }
  .kpi { grid-template-columns: repeat(4,1fr); }
  tr.Completed td { background: #eef9f0 !important; -webkit-print-color-adjust: exact; }
  tr.Failed    td { background: #fff0f0 !important; -webkit-print-color-adjust: exact; }
  tr.Skipped   td { background: #f3f3f3 !important; -webkit-print-color-adjust: exact; }
}
</style>
</head>
<body>
<h1>Entra Identity Decommissioning — Batch Report</h1>
<p><strong>Batch ID:</strong> $([System.Net.WebUtility]::HtmlEncode($Batch.BatchId))</p>
<p><strong>Ticket:</strong> $([System.Net.WebUtility]::HtmlEncode($Batch.TicketId)) &nbsp;|&nbsp;
   <strong>Operator:</strong> $([System.Net.WebUtility]::HtmlEncode($Batch.OperatorUPN)) &nbsp;|&nbsp;
   <strong>Mode:</strong> $([System.Net.WebUtility]::HtmlEncode($modeLabel)) &nbsp;|&nbsp;
   <strong>Evidence:</strong> $([System.Net.WebUtility]::HtmlEncode($Batch.EvidenceLevel))</p>
<p><strong>Started:</strong> $([System.Net.WebUtility]::HtmlEncode($Batch.CreatedUtc))</p>

<div class="kpi">
  <div class="card"><div class="num">$($s.TotalCount)</div>Total</div>
  <div class="card ok"><div class="num">$($s.Completed)</div>Completed</div>
  <div class="card $(if($s.AnyFailed){'fail'}else{'card'})"><div class="num">$($s.Failed)</div>Failed</div>
  <div class="card"><div class="num">$($s.Skipped)</div>Skipped</div>
</div>

<h2>Per-UPN Results</h2>
<table>
  <thead>
    <tr>
      <th>UPN</th><th>Status</th><th>Run ID</th>
      <th>Started (UTC)</th><th>Completed (UTC)</th>
      <th>Error</th><th>Report</th>
    </tr>
  </thead>
  <tbody>
$($rows -join "`n")
  </tbody>
</table>

$(if ($BatchResult.Errors.Count -gt 0) {
"<h2>Failed entries</h2><table><thead><tr><th>UPN</th><th>Run ID</th><th>Error</th></tr></thead><tbody>" +
($BatchResult.Errors | ForEach-Object {
    "<tr class='Failed'><td>$([System.Net.WebUtility]::HtmlEncode($_.UPN))</td>" +
    "<td>$([System.Net.WebUtility]::HtmlEncode($_.RunId))</td>" +
    "<td>$([System.Net.WebUtility]::HtmlEncode($_.ErrorMessage))</td></tr>"
}) -join "`n" +
"</tbody></table>"
})

<p class="footer">&copy; 2026 Albert Jee. All rights reserved. &nbsp;|&nbsp;
Premium v2.0 &nbsp;|&nbsp;
Generated $([System.Net.WebUtility]::HtmlEncode((Get-Date).ToUniversalTime().ToString('o')))</p>
</body>
</html>
"@

    $null = _EnsureDir $batchDir
    Set-Content -Path $outPath -Value $html -Encoding UTF8
    return $outPath
}

# ── Cross-UPN evidence manifest ────────────────────────────────────────────────

function Write-DecomBatchEvidenceManifest {
    <#
    .SYNOPSIS
        Writes a cross-UPN evidence manifest indexing every UPN's evidence files.

    .DESCRIPTION
        Produces <OutputRoot>\<BatchId>\batch-evidence.manifest.json

        For each completed UPN entry, reads the per-UPN evidence.manifest.json
        (written by Lite Write-DecomEvidenceManifest) and includes its key fields
        plus a SHA-256 hash of the evidence.ndjson file for integrity anchoring.

        The batch manifest does NOT re-hash individual NDJSON events — it hashes
        the entire file as a single integrity check. Individual event chain
        integrity is the responsibility of the per-UPN Lite manifest.

    .PARAMETER Batch
        The batch envelope (post-run).

    .OUTPUTS
        [string] — path to the written manifest file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Batch
    )

    $batchDir = Join-Path $Batch.OutputRoot $Batch.BatchId
    $outPath  = Join-Path $batchDir 'batch-evidence.manifest.json'

    $entries = [System.Collections.Generic.List[object]]::new()

    foreach ($key in $Batch.Entries.Keys) {
        $entry = $Batch.Entries[$key]

        $entryManifest = [ordered]@{
            UPN          = $entry.UPN
            Status       = $entry.Status
            RunId        = $entry.RunId
            OutputPath   = $entry.OutputPath
            StartedUtc   = $entry.StartedUtc
            CompletedUtc = $entry.CompletedUtc
            # Per-UPN Lite manifest fields (read from disk if available)
            LiteManifest       = $null
            NdjsonFileHash     = $null
            NdjsonFileSizeBytes= $null
        }

        if ($entry.OutputPath -and (Test-Path $entry.OutputPath)) {
            # Read per-UPN Lite evidence.manifest.json
            $liteManifestPath = Join-Path $entry.OutputPath 'evidence.manifest.json'
            if (Test-Path $liteManifestPath) {
                try {
                    $lm = Get-Content $liteManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
                    $entryManifest.LiteManifest = [ordered]@{
                        SchemaVersion  = $lm.SchemaVersion
                        RunId          = $lm.RunId
                        CorrelationId  = $lm.CorrelationId
                        Sealed         = $lm.Sealed
                        FinalEventHash = $lm.FinalEventHash
                        EventCount     = $lm.EventCount
                        GeneratedUtc   = $lm.GeneratedUtc
                    }
                } catch {
                    $entryManifest.LiteManifest = "ERROR reading: $_"
                }
            }

            # Hash the evidence.ndjson file for batch-level integrity anchor
            $ndjsonPath = Join-Path $entry.OutputPath 'evidence.ndjson'
            if (Test-Path $ndjsonPath) {
                try {
                    $fi = Get-Item $ndjsonPath
                    $entryManifest.NdjsonFileSizeBytes = $fi.Length
                    $entryManifest.NdjsonFileHash = _HashFile $ndjsonPath
                } catch {
                    $entryManifest.NdjsonFileHash = "ERROR: $_"
                }
            }
        }

        $entries.Add([pscustomobject]$entryManifest)
    }

    $manifest = [ordered]@{
        SchemaVersion = '2.0'
        ManifestType  = 'BatchEvidenceManifest'
        BatchId       = $Batch.BatchId
        TicketId      = $Batch.TicketId
        OperatorUPN   = $Batch.OperatorUPN
        GeneratedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        EntryCount    = $entries.Count
        Entries       = $entries.ToArray()
    }

    $null = _EnsureDir $batchDir
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $outPath -Encoding UTF8
    return $outPath
}

# ── Private helpers ────────────────────────────────────────────────────────────

function _EnsureDir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function _StatusToCss {
    param([string]$Status)
    # Maps entry status to a CSS class name used in the HTML report.
    switch ($Status) {
        'Completed' { return 'Completed' }
        'Failed'    { return 'Failed'    }
        'Skipped'   { return 'Skipped'   }
        'Resumed'   { return 'Resumed'   }
        'Running'   { return 'Running'   }
        default     { return 'Pending'   }
    }
}

function _HashFile {
    # SHA-256 hash of a file's raw bytes. PS5.1 compatible.
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join ''
        } finally {
            $stream.Dispose()
        }
    } finally {
        $sha.Dispose()
    }
}

function _CollectUpnReportSummaries {
    # Reads per-UPN report.json Summary block from disk. Falls back to
    # entry metadata if the file is missing (e.g. run failed before report).
    param([pscustomobject]$Batch)

    $out = [System.Collections.Generic.List[object]]::new()

    foreach ($key in $Batch.Entries.Keys) {
        $entry = $Batch.Entries[$key]

        $upnRecord = [ordered]@{
            UPN          = $entry.UPN
            Status       = $entry.Status
            RunId        = $entry.RunId
            StartedUtc   = $entry.StartedUtc
            CompletedUtc = $entry.CompletedUtc
            ErrorMessage = $entry.ErrorMessage
            OutputPath   = $entry.OutputPath
            LiteSummary  = $null
        }

        if ($entry.OutputPath) {
            $jsonPath = Join-Path $entry.OutputPath 'report.json'
            if (Test-Path $jsonPath) {
                try {
                    $liteReport = Get-Content $jsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
                    if ($liteReport.Summary) {
                        $upnRecord.LiteSummary = [ordered]@{
                            Status        = $liteReport.Summary.Status
                            Version       = $liteReport.Summary.Version
                            EvidenceLevel = $liteReport.Summary.EvidenceLevel
                            Sealed        = $liteReport.Summary.Sealed
                            CorrelationId = $liteReport.Summary.CorrelationId
                        }
                    }
                } catch {}
            }
        }

        $out.Add([pscustomobject]$upnRecord)
    }

    return $out.ToArray()
}

Export-ModuleMember -Function `
    Export-DecomBatchJsonReport, `
    Export-DecomBatchHtmlReport, `
    Write-DecomBatchEvidenceManifest
