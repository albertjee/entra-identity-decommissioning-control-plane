Describe 'Public Lite package boundary' {
    It 'does not expose evidence-grade sealing implementation terms outside approved documentation' {
        $root = Split-Path -Parent $PSScriptRoot
        $approvedDocumentation = @(
            'README.md',
            'CHANGELOG.md',
            'SECURITY.md'
        )
        $approvedDocumentationPrefix = 'docs/'
        $boundaryTestPath = 'tests/PublicBoundary.Tests.ps1'
        $blockedTerms = @(
            'Get-DecomSha256Hex',
            'Write-DecomEvidenceSeal',
            'EvidencePrevHash',
            'PrevHash',
            'EventHash',
            'FinalEventHash',
            'SealEvidence',
            'trusted anchor',
            'tamper-evident sealing',
            'SHA-256 hash-chain'
        )

        $trackedFiles = git -C $root ls-files
        $hits = foreach ($file in $trackedFiles) {
            $normalized = $file -replace '\\', '/'
            if ($normalized -in $approvedDocumentation) { continue }
            if ($normalized.StartsWith($approvedDocumentationPrefix)) { continue }
            if ($normalized -eq $boundaryTestPath) { continue }

            $path = Join-Path $root $file
            $content = Get-Content -LiteralPath $path -Raw -ErrorAction SilentlyContinue
            foreach ($term in $blockedTerms) {
                if ($content -like "*$term*") {
                    [pscustomobject]@{
                        Path = $normalized
                        Term = $term
                    }
                }
            }
        }

        $hits | Should -BeNullOrEmpty
    }
}
