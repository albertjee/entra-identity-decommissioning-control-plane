# Reporting.psm1 — HTML and JSON evidence report generation
# v1.4: ManualFollowUp column added to HTML report table.
#        Print stylesheet added (@media print) for audit/compliance handoff.
#        Status row color coding retained and extended to include ManualFollowUp indicator.

function ConvertTo-DecomHtmlEncoded {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Export-DecomJsonReport {
    param([pscustomobject]$WorkflowResult, [string]$Path)
    $WorkflowResult | ConvertTo-Json -Depth 30 | Set-Content -Path $Path -Encoding UTF8
}

function Get-DecomStatusCounts {
    param([object[]]$Results)
    [pscustomobject]@{
        Success = @($Results | Where-Object Status -eq 'Success').Count
        Warning = @($Results | Where-Object Status -eq 'Warning').Count
        Blocked = @($Results | Where-Object Status -eq 'Blocked').Count
        Failed  = @($Results | Where-Object Status -eq 'Failed').Count
        Skipped = @($Results | Where-Object Status -eq 'Skipped').Count
    }
}

function Format-DecomEvidenceValue {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return (@($Value | ForEach-Object {
            if ($_ -is [psobject]) { ($_.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ' }
            else { [string]$_ }
        }) -join ', ')
    }
    if ($Value -is [psobject]) { return ($Value.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ' }
    return [string]$Value
}

function Get-DecomEvidenceSummary {
    param([hashtable]$Evidence)
    if (-not $Evidence -or $Evidence.Keys.Count -eq 0) { return '' }
    return ($Evidence.Keys | ForEach-Object { '{0}: {1}' -f $_, (Format-DecomEvidenceValue -Value $Evidence[$_]) }) -join ' | '
}

function Export-DecomHtmlReport {
    param([pscustomobject]$WorkflowResult, [string]$Path)
    $Counts = Get-DecomStatusCounts -Results $WorkflowResult.Results

    $rows = foreach ($r in $WorkflowResult.Results) {
        $css = switch ($r.Status) {
            'Success' { 'ok'      }
            'Warning' { 'warn'    }
            'Blocked' { 'blocked' }
            'Failed'  { 'failed'  }
            'Skipped' { 'skipped' }
            default   { 'other'   }
        }
        $ev  = ConvertTo-DecomHtmlEncoded (Get-DecomEvidenceSummary -Evidence $r.Evidence)
        $mfu = if ($r.ManualFollowUp -and @($r.ManualFollowUp).Count -gt 0) {
            '<ul>' + (@($r.ManualFollowUp) | ForEach-Object { "<li>$(ConvertTo-DecomHtmlEncoded $_)</li>" }) + '</ul>'
        } else { '' }
        "<tr class='$css'>" +
        "<td>$(ConvertTo-DecomHtmlEncoded $r.StepId)</td>" +
        "<td>$(ConvertTo-DecomHtmlEncoded $r.Phase)</td>" +
        "<td>$(ConvertTo-DecomHtmlEncoded $r.ActionName)</td>" +
        "<td>$(ConvertTo-DecomHtmlEncoded $r.Status)</td>" +
        "<td>$(ConvertTo-DecomHtmlEncoded $r.Message)</td>" +
        "<td>$ev</td>" +
        "<td>$mfu</td>" +
        "<td>$(ConvertTo-DecomHtmlEncoded $r.ControlObjective)</td>" +
        "</tr>"
    }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Entra Identity Decommissioning Evidence Report</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #172033; }
h1   { font-size: 1.4em; }
table { border-collapse: collapse; width: 100%; margin-top: 16px; font-size: 0.85em; }
th, td { border: 1px solid #d6dbe3; padding: 7px 9px; text-align: left; vertical-align: top; }
th { background: #eef2f7; }
.summary { display: grid; grid-template-columns: repeat(5, minmax(90px, 1fr)); gap: 10px; margin: 16px 0; }
.card { border: 1px solid #d6dbe3; border-radius: 6px; padding: 10px; background: #f8fafc; font-size: 0.9em; }
tr.ok      td { background: #eef9f0; }
tr.warn    td { background: #fff8e5; }
tr.blocked td, tr.failed td { background: #fff0f0; }
tr.skipped td { background: #f3f3f3; }
ul { margin: 4px 0; padding-left: 18px; }
.footer { color: #777; font-size: 0.75em; margin-top: 16px; }

@media print {
    body { margin: 12px; font-size: 0.8em; }
    .summary { grid-template-columns: repeat(5, 1fr); }
    tr.ok      td { background: #eef9f0 !important; -webkit-print-color-adjust: exact; }
    tr.warn    td { background: #fff8e5 !important; -webkit-print-color-adjust: exact; }
    tr.blocked td, tr.failed td { background: #fff0f0 !important; -webkit-print-color-adjust: exact; }
    tr.skipped td { background: #f3f3f3 !important; -webkit-print-color-adjust: exact; }
}
</style>
</head>
<body>
<h1>Entra Identity Decommissioning Evidence Report</h1>
<p><strong>Target:</strong> $(ConvertTo-DecomHtmlEncoded $WorkflowResult.Context.TargetUPN)</p>
<p><strong>Run ID:</strong> $(ConvertTo-DecomHtmlEncoded $WorkflowResult.State.RunId) &nbsp;|&nbsp;
   <strong>Correlation ID:</strong> $(ConvertTo-DecomHtmlEncoded $WorkflowResult.Context.CorrelationId) &nbsp;|&nbsp;
   <strong>Version:</strong> v1.4 &nbsp;|&nbsp;
   <strong>Evidence Level:</strong> $(ConvertTo-DecomHtmlEncoded $WorkflowResult.Context.EvidenceLevel)</p>
<div class="summary">
  <div class="card"><strong>Success</strong><br>$($Counts.Success)</div>
  <div class="card"><strong>Warning</strong><br>$($Counts.Warning)</div>
  <div class="card"><strong>Blocked</strong><br>$($Counts.Blocked)</div>
  <div class="card"><strong>Failed</strong><br>$($Counts.Failed)</div>
  <div class="card"><strong>Skipped</strong><br>$($Counts.Skipped)</div>
</div>
<table>
  <thead>
    <tr>
      <th>Step ID</th><th>Phase</th><th>Action</th><th>Status</th>
      <th>Message</th><th>Evidence</th><th>Manual Follow-Up</th><th>Control Objective</th>
    </tr>
  </thead>
  <tbody>
$(($rows -join "`n"))
  </tbody>
</table>
<p class="footer">© 2026 Albert Jee. All rights reserved. | Generated $(ConvertTo-DecomHtmlEncoded (Get-Date).ToUniversalTime().ToString('o'))</p>
</body>
</html>
"@
    Set-Content -Path $Path -Value $html -Encoding UTF8
}

Export-ModuleMember -Function ConvertTo-DecomHtmlEncoded, Export-DecomJsonReport, Get-DecomStatusCounts, Format-DecomEvidenceValue, Get-DecomEvidenceSummary, Export-DecomHtmlReport
