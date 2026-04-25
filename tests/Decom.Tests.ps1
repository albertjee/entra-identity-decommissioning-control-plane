Describe 'Entra Identity Decommissioning Control Plane v1.0' {
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot '..' 'src' 'Modules'
        Import-Module (Join-Path $modulePath 'Models.psm1') -Force
        Import-Module (Join-Path $modulePath 'Guardrails.psm1') -Force
        Import-Module (Join-Path $modulePath 'Reporting.psm1') -Force
        Import-Module (Join-Path $modulePath 'Containment.psm1') -Force
    }

    It 'creates a forensic run context' {
        $ctx = New-DecomRunContext -TargetUPN 'user@contoso.com' -OutputPath 'output/test' -EvidenceLevel Forensic
        $ctx.TargetUPN | Should -Be 'user@contoso.com'
        $ctx.EvidenceLevel | Should -Be 'Forensic'
        $ctx.CorrelationId | Should -Not -BeNullOrEmpty
    }

    It 'treats blocked critical results as stop conditions' {
        $r = New-DecomActionResult -ActionName 'Test' -Phase 'Validation' -Status 'Blocked' -IsCritical $true -TargetUPN 'user@contoso.com' -Message 'Blocked'
        $decision = Get-DecomStopDecision -Results @($r)
        $decision.ShouldStop | Should -BeTrue
    }

    It 'HTML-encodes report fields' {
        ConvertTo-DecomHtmlEncoded '<script>alert(1)</script>' | Should -Be '&lt;script&gt;alert(1)&lt;/script&gt;'
    }

    It 'generates cryptographic password with requested length' {
        (New-DecomSecurePassword -Length 40).Length | Should -Be 40
    }
}
