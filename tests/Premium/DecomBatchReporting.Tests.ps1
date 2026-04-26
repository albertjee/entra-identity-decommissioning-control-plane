# DecomBatchReporting.Tests.ps1 — Pester v5 / PS7
# BatchReporting.psm1
# Run: Invoke-Pester .\tests\Premium\DecomBatchReporting.Tests.ps1 -Output Detailed

BeforeAll {
    $repoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $liteMods    = Join-Path $repoRoot 'src\Modules'
    $premiumMods = Join-Path $repoRoot 'src\Premium\Modules'

    Import-Module (Join-Path $liteMods    'Models.psm1')         -Force -DisableNameChecking
    Import-Module (Join-Path $liteMods    'Logging.psm1')        -Force -DisableNameChecking
    Import-Module (Join-Path $liteMods    'Evidence.psm1')       -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchState.psm1')     -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchReporting.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchContext.psm1')   -Force -DisableNameChecking

    $script:baseDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DecomRpt-' + [guid]::NewGuid().Guid)
    New-Item -ItemType Directory -Path $script:baseDir -Force | Out-Null

    function Get-TestEntries { param($Batch)
        $p = $Batch.PSObject.Properties['Entries']; if ($null -eq $p) { return $null }; return $p.Value }

    function script:New-TestBR { param($Batch, $Errors = @())
        [pscustomobject]@{ BatchId=$Batch.BatchId; Summary=(Get-DecomBatchSummary -Batch $Batch); Results=@(); Errors=$Errors } }
}

AfterAll {
    if (Test-Path $script:baseDir) { Remove-Item $script:baseDir -Recurse -Force }
}

Describe 'Export-DecomBatchJsonReport' {

    BeforeEach {
        $script:b = New-DecomBatchContext -OutputRoot $script:baseDir `
            -UpnList @('a@c.com','b@c.com') -TicketId 'CHG-JSON' -OperatorUPN 'op@c.com'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'a@c.com' -Status 'Completed' -RunId 'r1'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'b@c.com' -Status 'Failed' -RunId 'r2' -ErrorMessage 'Graph 403'
        $script:br = New-TestBR -Batch $script:b -Errors @([pscustomobject]@{ UPN='b@c.com'; RunId='r2'; ErrorMessage='Graph 403' })
    }

    It 'creates the batch-report.json file' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        Test-Path $path | Should -BeTrue
        $path | Should -Match 'batch-report\.json$'
    }

    It 'file is valid JSON' {
        { Get-Content (Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br) -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'report contains correct BatchId' {
        $r = Get-Content (Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br) -Raw | ConvertFrom-Json
        $r.BatchId | Should -Be $script:b.BatchId
    }

    It 'report contains TicketId and OperatorUPN' {
        $r = Get-Content (Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br) -Raw | ConvertFrom-Json
        $r.TicketId    | Should -Be 'CHG-JSON'
        $r.OperatorUPN | Should -Be 'op@c.com'
    }

    It 'Summary counts are correct' {
        $r = Get-Content (Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br) -Raw | ConvertFrom-Json
        $r.Summary.TotalCount | Should -Be 2
        $r.Summary.Completed  | Should -Be 1
        $r.Summary.Failed     | Should -Be 1
        $r.Summary.AnyFailed  | Should -Be $true
    }

    It 'Entries array has one record per UPN' {
        $r = Get-Content (Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br) -Raw | ConvertFrom-Json
        @($r.Entries).Count | Should -Be 2
    }

    It 'Errors array contains failed UPN' {
        $r = Get-Content (Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br) -Raw | ConvertFrom-Json
        $r.Errors[0].UPN          | Should -Be 'b@c.com'
        $r.Errors[0].ErrorMessage | Should -Be 'Graph 403'
    }

    It 'SchemaVersion is 2.0' {
        $r = Get-Content (Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br) -Raw | ConvertFrom-Json
        $r.SchemaVersion | Should -Be '2.0'
    }

    It 'GeneratedUtc is present' {
        $r = Get-Content (Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br) -Raw | ConvertFrom-Json
        $r.GeneratedUtc | Should -Not -BeNullOrEmpty
    }

    It 'overwrites cleanly on second call' {
        Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br | Out-Null
        { Get-Content (Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br) -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'works for empty batch' {
        $e = New-DecomBatchContext -OutputRoot $script:baseDir
        $r = Get-Content (Export-DecomBatchJsonReport -Batch $e -BatchResult (New-TestBR -Batch $e)) -Raw | ConvertFrom-Json
        $r.Summary.TotalCount | Should -Be 0
    }
}

Describe 'Export-DecomBatchHtmlReport' {

    BeforeEach {
        $script:b = New-DecomBatchContext -OutputRoot $script:baseDir `
            -UpnList @('alice@c.com','bob@c.com') -TicketId 'CHG-HTML'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'alice@c.com' -Status 'Completed' -RunId 'r-alice'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'bob@c.com'   -Status 'Failed'    -RunId 'r-bob' -ErrorMessage 'EXO timeout'
        $script:br = New-TestBR -Batch $script:b -Errors @([pscustomobject]@{ UPN='bob@c.com'; RunId='r-bob'; ErrorMessage='EXO timeout' })
    }

    It 'creates the batch-report.html file' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        Test-Path $path | Should -BeTrue
        $path | Should -Match 'batch-report\.html$'
    }

    It 'file contains DOCTYPE html' {
        Get-Content (Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br) -Raw | Should -Match '<!DOCTYPE html>'
    }

    It 'file contains BatchId' {
        Get-Content (Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br) -Raw | Should -BeLike "*$($script:b.BatchId)*"
    }

    It 'file contains TicketId' {
        Get-Content (Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br) -Raw | Should -Match 'CHG-HTML'
    }

    It 'file contains both UPNs' {
        $html = Get-Content (Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br) -Raw
        $html | Should -Match 'alice@c\.com'
        $html | Should -Match 'bob@c\.com'
    }

    It 'file contains error message' {
        Get-Content (Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br) -Raw | Should -Match 'EXO timeout'
    }

    It 'file contains KPI summary cards' {
        $html = Get-Content (Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br) -Raw
        $html | Should -Match 'class="kpi"'
    }

    It 'file contains print media query' {
        Get-Content (Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br) -Raw | Should -Match '@media print'
    }

    It 'file contains copyright footer' {
        Get-Content (Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br) -Raw | Should -Match 'Albert Jee'
    }

    It 'WhatIf mode label appears in report' {
        $wb  = New-DecomBatchContext -OutputRoot $script:baseDir -WhatIfMode
        Get-Content (Export-DecomBatchHtmlReport -Batch $wb -BatchResult (New-TestBR -Batch $wb)) -Raw | Should -Match 'WhatIf'
    }

    It 'no Failed section when no errors' {
        $c = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('ok@c.com')
        Set-DecomBatchEntryStatus -Batch $c -UPN 'ok@c.com' -Status 'Completed'
        Get-Content (Export-DecomBatchHtmlReport -Batch $c -BatchResult (New-TestBR -Batch $c)) -Raw | Should -Not -Match 'Failed entries'
    }
}

Describe 'Write-DecomBatchEvidenceManifest' {

    BeforeEach {
        $script:b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('m@c.com') -TicketId 'CHG-EVID'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'm@c.com' -Status 'Completed' -RunId 'r-m'
        $upnDir = Join-Path (Join-Path $script:baseDir $script:b.BatchId) 'm@c.com'
        New-Item -ItemType Directory -Path $upnDir -Force | Out-Null
        (Get-TestEntries $script:b)['m@c.com'].OutputPath = $upnDir
        Set-Content (Join-Path $upnDir 'evidence.ndjson') '{"RunId":"r-m","Phase":"Test"}' -Encoding UTF8
        @{ SchemaVersion='1.0'; RunId='r-m'; CorrelationId='corr-123'; TargetUPN='m@c.com'
           Sealed=$true; FinalEventHash='abc123'; EventCount=1
           GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o') } |
            ConvertTo-Json | Set-Content (Join-Path $upnDir 'evidence.manifest.json') -Encoding UTF8
    }

    It 'creates batch-evidence.manifest.json' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        Test-Path $path | Should -BeTrue
        $path | Should -Match 'batch-evidence\.manifest\.json$'
    }

    It 'file is valid JSON' {
        { Get-Content (Write-DecomBatchEvidenceManifest -Batch $script:b) -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'manifest contains BatchId' {
        (Get-Content (Write-DecomBatchEvidenceManifest -Batch $script:b) -Raw | ConvertFrom-Json).BatchId | Should -Be $script:b.BatchId
    }

    It 'manifest SchemaVersion is 2.0' {
        (Get-Content (Write-DecomBatchEvidenceManifest -Batch $script:b) -Raw | ConvertFrom-Json).SchemaVersion | Should -Be '2.0'
    }

    It 'manifest EntryCount matches batch entry count' {
        (Get-Content (Write-DecomBatchEvidenceManifest -Batch $script:b) -Raw | ConvertFrom-Json).EntryCount | Should -Be 1
    }

    It 'entry contains NdjsonFileHash' {
        $m = Get-Content (Write-DecomBatchEvidenceManifest -Batch $script:b) -Raw | ConvertFrom-Json
        $m.Entries[0].NdjsonFileHash | Should -Not -BeNullOrEmpty
        $m.Entries[0].NdjsonFileHash | Should -Match '^[0-9a-f]{64}$'
    }

    It 'entry contains NdjsonFileSizeBytes' {
        (Get-Content (Write-DecomBatchEvidenceManifest -Batch $script:b) -Raw | ConvertFrom-Json).Entries[0].NdjsonFileSizeBytes | Should -BeGreaterThan 0
    }

    It 'entry LiteManifest contains FinalEventHash' {
        (Get-Content (Write-DecomBatchEvidenceManifest -Batch $script:b) -Raw | ConvertFrom-Json).Entries[0].LiteManifest.FinalEventHash | Should -Be 'abc123'
    }

    It 'handles entry with no output path gracefully' {
        $b2 = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('nodir@c.com')
        Set-DecomBatchEntryStatus -Batch $b2 -UPN 'nodir@c.com' -Status 'Failed'
        { Write-DecomBatchEvidenceManifest -Batch $b2 } | Should -Not -Throw
    }

    It 'handles missing evidence.ndjson gracefully' {
        $b3 = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('noevid@c.com')
        Set-DecomBatchEntryStatus -Batch $b3 -UPN 'noevid@c.com' -Status 'Completed'
        $ed = Join-Path (Join-Path $script:baseDir $b3.BatchId) 'noevid@c.com'
        New-Item -ItemType Directory -Path $ed -Force | Out-Null
        (Get-TestEntries $b3)['noevid@c.com'].OutputPath = $ed
        $m = Get-Content (Write-DecomBatchEvidenceManifest -Batch $b3) -Raw | ConvertFrom-Json
        $m.Entries[0].NdjsonFileHash | Should -BeNullOrEmpty
    }

    It 'GeneratedUtc is present' {
        (Get-Content (Write-DecomBatchEvidenceManifest -Batch $script:b) -Raw | ConvertFrom-Json).GeneratedUtc | Should -Not -BeNullOrEmpty
    }
}

Describe 'Phase 2 - output file layout' {

    It 'all three report files land in OutputRoot\BatchId' {
        $b      = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('layout@c.com')
        Set-DecomBatchEntryStatus -Batch $b -UPN 'layout@c.com' -Status 'Completed'
        $br     = New-TestBR -Batch $b
        $json   = Export-DecomBatchJsonReport      -Batch $b -BatchResult $br
        $html   = Export-DecomBatchHtmlReport      -Batch $b -BatchResult $br
        $manif  = Write-DecomBatchEvidenceManifest -Batch $b
        $expect = Join-Path $script:baseDir $b.BatchId
        (Split-Path $json  -Parent) | Should -Be $expect
        (Split-Path $html  -Parent) | Should -Be $expect
        (Split-Path $manif -Parent) | Should -Be $expect
    }
}

