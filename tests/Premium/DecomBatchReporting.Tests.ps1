# DecomBatchReporting.Tests.ps1 — Pester v5 tests for BatchReporting.psm1
# Premium v2.0 — Phase 2
#
# Run from repo root:
#   Invoke-Pester .\tests\Premium\DecomBatchReporting.Tests.ps1 -Output Detailed

BeforeAll {
    $repoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $premiumMods = Join-Path $repoRoot 'src\Premium\Modules'

    # Load Phase 1 modules (BatchReporting depends on BatchContext)
    Import-Module (Join-Path $premiumMods 'BatchContext.psm1')   -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchState.psm1')     -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchReporting.psm1') -Force -DisableNameChecking

    # ── Shared test helpers ────────────────────────────────────────────────────
    function New-TestBatchResult {
        param([pscustomobject]$Batch)
        $summary = Get-DecomBatchSummary -Batch $Batch
        [pscustomobject]@{
            BatchId = $Batch.BatchId
            Summary = $summary
            Results = @()
            Errors  = @()
        }
    }

    function New-TestBatchResultWithError {
        param([pscustomobject]$Batch, [string]$FailedUPN, [string]$ErrMsg)
        $summary = Get-DecomBatchSummary -Batch $Batch
        [pscustomobject]@{
            BatchId = $Batch.BatchId
            Summary = $summary
            Results = @()
            Errors  = @([pscustomobject]@{ UPN = $FailedUPN; RunId = 'run-err'; ErrorMessage = $ErrMsg })
        }
    }

    # Shared temp dir for all test groups
    $script:baseDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DecomRptTest-' + [guid]::NewGuid().Guid)
    $null = New-Item -ItemType Directory -Path $script:baseDir -Force
}

AfterAll {
    if (Test-Path $script:baseDir) {
        Remove-Item -Path $script:baseDir -Recurse -Force
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'Export-DecomBatchJsonReport' {

    BeforeEach {
        $script:b = New-DecomBatchContext -OutputRoot $script:baseDir `
            -UpnList @('a@c.com','b@c.com') -TicketId 'CHG-JSON' -OperatorUPN 'op@c.com'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'a@c.com' -Status 'Completed' -RunId 'r1'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'b@c.com' -Status 'Failed'    -RunId 'r2' -ErrorMessage 'Graph 403'
        $script:br = New-TestBatchResultWithError -Batch $script:b -FailedUPN 'b@c.com' -ErrMsg 'Graph 403'
    }

    It 'creates the batch-report.json file' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        Test-Path $path | Should -BeTrue
        $path | Should -Match 'batch-report\.json$'
    }

    It 'file is valid JSON' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        { Get-Content $path -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'report contains correct BatchId' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        $r = Get-Content $path -Raw | ConvertFrom-Json
        $r.BatchId | Should -Be $script:b.BatchId
    }

    It 'report contains TicketId and OperatorUPN' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        $r = Get-Content $path -Raw | ConvertFrom-Json
        $r.TicketId    | Should -Be 'CHG-JSON'
        $r.OperatorUPN | Should -Be 'op@c.com'
    }

    It 'Summary counts are correct' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        $r = Get-Content $path -Raw | ConvertFrom-Json
        $r.Summary.TotalCount | Should -Be 2
        $r.Summary.Completed  | Should -Be 1
        $r.Summary.Failed     | Should -Be 1
        $r.Summary.AnyFailed  | Should -Be $true
    }

    It 'Entries array has one record per UPN' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        $r = Get-Content $path -Raw | ConvertFrom-Json
        @($r.Entries).Count | Should -Be 2
    }

    It 'Errors array contains failed UPN' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        $r = Get-Content $path -Raw | ConvertFrom-Json
        @($r.Errors).Count     | Should -Be 1
        $r.Errors[0].UPN       | Should -Be 'b@c.com'
        $r.Errors[0].ErrorMessage | Should -Be 'Graph 403'
    }

    It 'SchemaVersion is 2.0' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        $r = Get-Content $path -Raw | ConvertFrom-Json
        $r.SchemaVersion | Should -Be '2.0'
    }

    It 'GeneratedUtc is present and non-empty' {
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        $r = Get-Content $path -Raw | ConvertFrom-Json
        $r.GeneratedUtc | Should -Not -BeNullOrEmpty
    }

    It 'overwrites cleanly on second call' {
        Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br | Out-Null
        $path = Export-DecomBatchJsonReport -Batch $script:b -BatchResult $script:br
        { Get-Content $path -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'works for empty batch' {
        $empty = New-DecomBatchContext -OutputRoot $script:baseDir
        $emptyResult = New-TestBatchResult -Batch $empty
        $path = Export-DecomBatchJsonReport -Batch $empty -BatchResult $emptyResult
        $r = Get-Content $path -Raw | ConvertFrom-Json
        $r.Summary.TotalCount | Should -Be 0
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'Export-DecomBatchHtmlReport' {

    BeforeEach {
        $script:b = New-DecomBatchContext -OutputRoot $script:baseDir `
            -UpnList @('alice@c.com','bob@c.com') -TicketId 'CHG-HTML'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'alice@c.com' -Status 'Completed' -RunId 'r-alice'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'bob@c.com'   -Status 'Failed'    -RunId 'r-bob' -ErrorMessage 'EXO timeout'
        $script:br = New-TestBatchResultWithError -Batch $script:b -FailedUPN 'bob@c.com' -ErrMsg 'EXO timeout'
    }

    It 'creates the batch-report.html file' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        Test-Path $path | Should -BeTrue
        $path | Should -Match 'batch-report\.html$'
    }

    It 'file contains DOCTYPE html' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        $content = Get-Content $path -Raw
        $content | Should -Match '<!DOCTYPE html>'
    }

    It 'file contains BatchId' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        $content = Get-Content $path -Raw
        $content | Should -Match [regex]::Escape($script:b.BatchId)
    }

    It 'file contains TicketId' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        $content = Get-Content $path -Raw
        $content | Should -Match 'CHG-HTML'
    }

    It 'file contains both UPNs' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        $content = Get-Content $path -Raw
        $content | Should -Match 'alice@c\.com'
        $content | Should -Match 'bob@c\.com'
    }

    It 'file contains error message in Failed entries section' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        $content = Get-Content $path -Raw
        $content | Should -Match 'EXO timeout'
    }

    It 'file contains KPI summary cards' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        $content = Get-Content $path -Raw
        $content | Should -Match 'class="kpi"'
        $content | Should -Match 'Completed'
        $content | Should -Match 'Failed'
    }

    It 'file contains print media query' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        $content = Get-Content $path -Raw
        $content | Should -Match '@media print'
    }

    It 'file contains copyright footer' {
        $path = Export-DecomBatchHtmlReport -Batch $script:b -BatchResult $script:br
        $content = Get-Content $path -Raw
        $content | Should -Match 'Albert Jee'
    }

    It 'WhatIf mode label appears in report' {
        $wb = New-DecomBatchContext -OutputRoot $script:baseDir -WhatIfMode
        $wbr = New-TestBatchResult -Batch $wb
        $path = Export-DecomBatchHtmlReport -Batch $wb -BatchResult $wbr
        $content = Get-Content $path -Raw
        $content | Should -Match 'WhatIf'
    }

    It 'no Failed section when no errors' {
        $clean = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('ok@c.com')
        Set-DecomBatchEntryStatus -Batch $clean -UPN 'ok@c.com' -Status 'Completed'
        $cleanResult = New-TestBatchResult -Batch $clean
        $path = Export-DecomBatchHtmlReport -Batch $clean -BatchResult $cleanResult
        $content = Get-Content $path -Raw
        $content | Should -Not -Match 'Failed entries'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'Write-DecomBatchEvidenceManifest' {

    BeforeEach {
        $script:b = New-DecomBatchContext -OutputRoot $script:baseDir `
            -UpnList @('m@c.com') -TicketId 'CHG-EVID'
        Set-DecomBatchEntryStatus -Batch $script:b -UPN 'm@c.com' -Status 'Completed' -RunId 'r-m'

        # Simulate a UPN output directory with evidence files
        $upnDir = Join-Path (Join-Path $script:baseDir $script:b.BatchId) 'm@c.com'
        $null = New-Item -ItemType Directory -Path $upnDir -Force
        $script:b.Entries['m@c.com'].OutputPath = $upnDir

        # Write fake evidence.ndjson
        Set-Content -Path (Join-Path $upnDir 'evidence.ndjson') `
            -Value '{"RunId":"r-m","Phase":"Containment","ActionName":"Test"}' -Encoding UTF8

        # Write fake Lite evidence.manifest.json
        $liteManifest = [ordered]@{
            SchemaVersion  = '1.0'
            RunId          = 'r-m'
            CorrelationId  = 'corr-123'
            TargetUPN      = 'm@c.com'
            Sealed         = $true
            FinalEventHash = 'abc123def456'
            EventCount     = 1
            GeneratedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        }
        $liteManifest | ConvertTo-Json | Set-Content `
            -Path (Join-Path $upnDir 'evidence.manifest.json') -Encoding UTF8
    }

    It 'creates batch-evidence.manifest.json' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        Test-Path $path | Should -BeTrue
        $path | Should -Match 'batch-evidence\.manifest\.json$'
    }

    It 'file is valid JSON' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        { Get-Content $path -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'manifest contains BatchId' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.BatchId | Should -Be $script:b.BatchId
    }

    It 'manifest SchemaVersion is 2.0' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.SchemaVersion | Should -Be '2.0'
    }

    It 'manifest EntryCount matches batch entry count' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.EntryCount | Should -Be 1
    }

    It 'entry contains NdjsonFileHash when ndjson exists' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.Entries[0].NdjsonFileHash | Should -Not -BeNullOrEmpty
        $m.Entries[0].NdjsonFileHash | Should -Match '^[0-9a-f]{64}$'
    }

    It 'entry contains NdjsonFileSizeBytes' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.Entries[0].NdjsonFileSizeBytes | Should -BeGreaterThan 0
    }

    It 'entry LiteManifest contains FinalEventHash from Lite manifest' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.Entries[0].LiteManifest.FinalEventHash | Should -Be 'abc123def456'
    }

    It 'entry LiteManifest.Sealed reflects Lite manifest value' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.Entries[0].LiteManifest.Sealed | Should -Be $true
    }

    It 'handles entry with no output path gracefully' {
        $b2 = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('nodir@c.com')
        Set-DecomBatchEntryStatus -Batch $b2 -UPN 'nodir@c.com' -Status 'Failed'
        # OutputPath intentionally left null
        { Write-DecomBatchEvidenceManifest -Batch $b2 } | Should -Not -Throw
    }

    It 'handles missing evidence.ndjson gracefully' {
        $b3 = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('noevid@c.com')
        Set-DecomBatchEntryStatus -Batch $b3 -UPN 'noevid@c.com' -Status 'Completed'
        $emptyDir = Join-Path (Join-Path $script:baseDir $b3.BatchId) 'noevid@c.com'
        $null = New-Item -ItemType Directory -Path $emptyDir -Force
        $b3.Entries['noevid@c.com'].OutputPath = $emptyDir
        $path = Write-DecomBatchEvidenceManifest -Batch $b3
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.Entries[0].NdjsonFileHash | Should -BeNullOrEmpty
    }

    It 'GeneratedUtc is present' {
        $path = Write-DecomBatchEvidenceManifest -Batch $script:b
        $m = Get-Content $path -Raw | ConvertFrom-Json
        $m.GeneratedUtc | Should -Not -BeNullOrEmpty
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'Phase 2 — output file layout' {

    It 'all three report files land in <OutputRoot>\<BatchId>\' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('layout@c.com')
        Set-DecomBatchEntryStatus -Batch $b -UPN 'layout@c.com' -Status 'Completed'
        $br = New-TestBatchResult -Batch $b

        $jsonPath  = Export-DecomBatchJsonReport      -Batch $b -BatchResult $br
        $htmlPath  = Export-DecomBatchHtmlReport      -Batch $b -BatchResult $br
        $manifPath = Write-DecomBatchEvidenceManifest -Batch $b

        $expectedDir = Join-Path $script:baseDir $b.BatchId

        (Split-Path $jsonPath  -Parent) | Should -Be $expectedDir
        (Split-Path $htmlPath  -Parent) | Should -Be $expectedDir
        (Split-Path $manifPath -Parent) | Should -Be $expectedDir
    }
}
