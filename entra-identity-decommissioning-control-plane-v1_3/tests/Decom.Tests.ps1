# Decom.Tests.ps1 — Pester v5 test suite
# v1.3: Added workflow behavioral tests — ValidationOnly, confirmation gates,
#        live-mode Skipped containment blocking, group license blocker,
#        phase state transitions, evidence integrity, HTML ManualFollowUp,
#        NonInteractive+no-Force returns Blocked (not throws).

BeforeAll {
    # ── Graph / Exchange stubs ─────────────────────────────────────────────────
    function Get-MgUser {
        param([string]$UserId, [string[]]$Property)
        [pscustomobject]@{
            Id                 = 'test-id'
            UserPrincipalName  = $UserId
            DisplayName        = 'Test User'
            AccountEnabled     = $true
            UserType           = 'Member'
            AssignedLicenses   = @()
        }
    }
    function Get-EXOMailbox {
        param([string]$Identity, [string]$ErrorAction)
        [pscustomobject]@{
            RecipientTypeDetails   = 'UserMailbox'
            ForwardingSmtpAddress  = $null
            ForwardingAddress      = $null
            GrantSendOnBehalfTo    = @()
            ArchiveStatus          = 'None'
            LitigationHoldEnabled  = $false
            InPlaceHolds           = @()
            RetentionHoldEnabled   = $false
            ComplianceTagHoldApplied = $false
        }
    }
    function Get-MgUserLicenseDetail                             { param([string]$UserId, [string]$ErrorAction) @() }
    function Get-MgRoleManagementDirectoryRoleAssignment         { param([switch]$All, [string]$ErrorAction) @() }
    function Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance { param([switch]$All, [string]$ErrorAction) @() }
    function Get-MgUserMemberOf                                  { param([string]$UserId, [switch]$All, [string]$ErrorAction) @() }
    function Get-MgUserOwnedObject                               { param([string]$UserId, [switch]$All, [string]$ErrorAction) @() }
    function Get-MgUserAppRoleAssignment                         { param([string]$UserId, [switch]$All, [string]$ErrorAction) @() }
    function Get-MgUserOauth2PermissionGrant                     { param([string]$UserId, [switch]$All, [string]$ErrorAction) @() }
    function Get-MgUserAuthenticationMethod                      { param([string]$UserId, [string]$ErrorAction) @() }
    function Write-DecomConsole                                  { param([string]$Level, [string]$Message) }
    function Add-DecomEvidenceEvent                              { param([pscustomobject]$Context, [string]$Phase, [string]$ActionName, [string]$Status, [bool]$IsCritical, [string]$Message, [hashtable]$Evidence, [hashtable]$BeforeState, [hashtable]$AfterState, [string]$ControlObjective, [string]$RiskMitigated) }
    function Initialize-DecomLog                                 { param([string]$Path) }
    function Initialize-DecomEvidenceStore                       { param([pscustomobject]$Context, [string]$RunId) }
    function Set-DecomPhaseState                                 { param([pscustomobject]$State, [string]$Phase, [string]$Status) }
    function New-DecomState                                      { param([string]$RunId) [pscustomobject]@{ RunId = $RunId; Phases = [ordered]@{} } }
    function Connect-DecomGraph                                  { param([pscustomobject]$Context) New-DecomActionResult -ActionName 'Connect Microsoft Graph' -Phase 'Authentication' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Connected.' -ControlObjective 'Auth' -RiskMitigated 'Unauth' }
    function Connect-DecomExchange                               { param([pscustomobject]$Context) New-DecomActionResult -ActionName 'Connect Exchange Online' -Phase 'Authentication' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Connected.' -ControlObjective 'Auth' -RiskMitigated 'Unauth' }
    function Get-DecomBaselineState                              { param([pscustomobject]$Context) New-DecomActionResult -ActionName 'Validate Target UPN' -Phase 'Validation' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Validated.' -ControlObjective 'Validate' -RiskMitigated 'Wrong user' }
    function Get-DecomIdentitySnapshot                           { param([pscustomobject]$Context, [string]$SnapshotName) New-DecomActionResult -ActionName "Collect $SnapshotName Identity Snapshot" -Phase "$($SnapshotName)ActionSnapshot" -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'Snapshot.' -ControlObjective 'Snapshot' -RiskMitigated 'Blind' }
    function Reset-DecomPassword                                 { param([pscustomobject]$Context, $Cmdlet) if ($Context.WhatIf) { return New-DecomSkippedBecauseWhatIf -ActionName 'Reset Password' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Next' }; New-DecomActionResult -ActionName 'Reset Password' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Reset.' -ControlObjective 'Invalidate creds' -RiskMitigated 'Reuse' }
    function Revoke-DecomSessions                                { param([pscustomobject]$Context, $Cmdlet) if ($Context.WhatIf) { return New-DecomSkippedBecauseWhatIf -ActionName 'Revoke Sessions' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Next' }; New-DecomActionResult -ActionName 'Revoke Sessions' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Revoked.' -ControlObjective 'Revoke' -RiskMitigated 'Persist' }
    function Disable-DecomSignIn                                 { param([pscustomobject]$Context, $Cmdlet) if ($Context.WhatIf) { return New-DecomSkippedBecauseWhatIf -ActionName 'Block Sign-In' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Next' }; New-DecomActionResult -ActionName 'Block Sign-In' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Blocked.' -ControlObjective 'Deny auth' -RiskMitigated 'Access' }
    function Convert-DecomMailboxToShared                        { param([pscustomobject]$Context, $Cmdlet) New-DecomActionResult -ActionName 'Convert Mailbox To Shared' -Phase 'Mailbox' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Converted.' -ControlObjective 'Mailbox' -RiskMitigated 'Loss' }
    function Set-DecomAutoReply                                  { param([pscustomobject]$Context, [string]$Message, $Cmdlet) New-DecomActionResult -ActionName 'Set Out-of-Office' -Phase 'Mailbox' -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'No message.' -ControlObjective 'Comms' -RiskMitigated 'Orphan' }
    function Get-DecomComplianceState                            { param([pscustomobject]$Context) New-DecomActionResult -ActionName 'Evaluate Compliance State' -Phase 'Compliance' -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'Evaluated.' -ControlObjective 'Compliance' -RiskMitigated 'Loss' }
    function Enable-DecomLitigationHold                          { param([pscustomobject]$Context, $Cmdlet) New-DecomActionResult -ActionName 'Enable Litigation Hold' -Phase 'Compliance' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Enabled.' -ControlObjective 'Hold' -RiskMitigated 'Data loss' }
    function Test-DecomLicenseRemovalReadiness                   { param([object[]]$Results, [pscustomobject]$Context) New-DecomActionResult -ActionName 'Check License Removal Readiness' -Phase 'Licensing' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Ready.' -ControlObjective 'License' -RiskMitigated 'Premature' }
    function Remove-DecomLicenses                                { param([pscustomobject]$Context, $Cmdlet) New-DecomActionResult -ActionName 'Remove Licenses' -Phase 'Licensing' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Removed.' -ControlObjective 'License' -RiskMitigated 'Spend' }
}

Describe 'Entra Identity Decommissioning Control Plane v1.3' {

    BeforeAll {
        $root        = Split-Path -Parent $PSScriptRoot
        $modulesPath = Join-Path $root 'src' 'Modules'
        Import-Module (Join-Path $modulesPath 'Models.psm1')      -Force
        Import-Module (Join-Path $modulesPath 'Guardrails.psm1')  -Force
        Import-Module (Join-Path $modulesPath 'Containment.psm1') -Force
        Import-Module (Join-Path $modulesPath 'Reporting.psm1')   -Force
        Import-Module (Join-Path $modulesPath 'Validation.psm1')  -Force
        Import-Module (Join-Path $modulesPath 'Discovery.psm1')   -Force
        Import-Module (Join-Path $modulesPath 'Execution.psm1')   -Force
        Import-Module (Join-Path $modulesPath 'Licensing.psm1')   -Force
        . (Join-Path $root 'src' 'Invoke-DecomWorkflow.ps1')
    }

    # ── Schema ─────────────────────────────────────────────────────────────────

    Context 'Action result schema' {

        It 'StepId is present and non-empty' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Validation' -Status 'Success' `
                -IsCritical $false -TargetUPN 'u@c.com' -Message 'ok'
            $r.StepId | Should -Not -BeNullOrEmpty
        }

        It 'StepId follows PHASE-NNN format' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Containment' -Status 'Success' `
                -IsCritical $false -TargetUPN 'u@c.com' -Message 'ok'
            $r.StepId | Should -Match '^CONTAINMENT-\d{3}$'
        }

        It 'ManualFollowUp defaults to empty array' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Validation' -Status 'Success' `
                -IsCritical $false -TargetUPN 'u@c.com' -Message 'ok'
            $null -ne $r.ManualFollowUp | Should -BeTrue
            @($r.ManualFollowUp).Count | Should -Be 0
        }

        It 'ManualFollowUp carries supplied items' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Validation' -Status 'Warning' `
                -IsCritical $false -TargetUPN 'u@c.com' -Message 'ok' `
                -ManualFollowUp @('Review groups', 'Remove OAuth')
            @($r.ManualFollowUp).Count | Should -Be 2
        }

        It 'Context has all required v1.3 fields' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' `
                -EvidenceLevel 'Forensic' -ValidationOnly
            $ctx.TargetUPN      | Should -Be 'u@c.com'
            $ctx.EvidenceLevel  | Should -Be 'Forensic'
            $ctx.ValidationOnly | Should -BeTrue
            $ctx.CorrelationId  | Should -Not -BeNullOrEmpty
            $ctx.WhatIf         | Should -BeFalse
        }
    }

    # ── Evidence integrity ─────────────────────────────────────────────────────

    Context 'Evidence integrity validation' {

        It 'passes a fully populated result' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Containment' -Status 'Success' `
                -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' `
                -ControlObjective 'Invalidate creds' -RiskMitigated 'Reuse'
            { Assert-DecomEvidenceIntegrity -Result $r } | Should -Not -Throw
        }

        It 'throws on null result' {
            { Assert-DecomEvidenceIntegrity -Result $null } | Should -Throw
        }

        It 'throws when ControlObjective is missing' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Containment' -Status 'Success' `
                -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok'
            # ControlObjective not supplied — should fail integrity check
            $r.ControlObjective = $null
            { Assert-DecomEvidenceIntegrity -Result $r } | Should -Throw
        }

        It 'throws when RiskMitigated is missing' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Containment' -Status 'Success' `
                -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' -ControlObjective 'Auth'
            $r.RiskMitigated = $null
            { Assert-DecomEvidenceIntegrity -Result $r } | Should -Throw
        }
    }

    # ── Stop decision ──────────────────────────────────────────────────────────

    Context 'Stop decision logic' {

        It 'stops on critical Failed' {
            $r = New-DecomActionResult -ActionName 'T' -Phase 'V' -Status 'Failed' `
                -IsCritical $true -TargetUPN 'u@c.com' -Message 'f'
            (Get-DecomStopDecision -Results @($r)).ShouldStop | Should -BeTrue
        }

        It 'stops on critical Blocked' {
            $r = New-DecomActionResult -ActionName 'T' -Phase 'L' -Status 'Blocked' `
                -IsCritical $true -TargetUPN 'u@c.com' -Message 'b'
            (Get-DecomStopDecision -Results @($r)).ShouldStop | Should -BeTrue
        }

        It 'stops on null in array' {
            (Get-DecomStopDecision -Results @($null)).ShouldStop | Should -BeTrue
        }

        It 'does not stop on non-critical Warning' {
            $r = New-DecomActionResult -ActionName 'T' -Phase 'C' -Status 'Warning' `
                -IsCritical $false -TargetUPN 'u@c.com' -Message 'w'
            (Get-DecomStopDecision -Results @($r)).ShouldStop | Should -BeFalse
        }

        It 'does not stop on Skipped' {
            $r = New-DecomSkippedBecauseWhatIf -ActionName 'T' -Phase 'C' -TargetUPN 'u@c.com' -RecommendedNext 'N'
            (Get-DecomStopDecision -Results @($r)).ShouldStop | Should -BeFalse
        }
    }

    # ── Containment guardrails ─────────────────────────────────────────────────

    Context 'Containment continuation logic' {

        It 'allows continuation when all containment actions succeed in live mode' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $results = @(
                (New-DecomActionResult -ActionName 'Reset Password'  -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' -ControlObjective 'x' -RiskMitigated 'y'),
                (New-DecomActionResult -ActionName 'Revoke Sessions' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' -ControlObjective 'x' -RiskMitigated 'y'),
                (New-DecomActionResult -ActionName 'Block Sign-In'   -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' -ControlObjective 'x' -RiskMitigated 'y')
            )
            Test-DecomCanContinueAfterContainment -Results $results -Context $ctx | Should -BeTrue
        }

        It 'blocks continuation when containment action is Skipped in live mode' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $results = @(
                (New-DecomSkippedBecauseWhatIf -ActionName 'Reset Password'  -Phase 'Containment' -TargetUPN 'u@c.com' -RecommendedNext 'N'),
                (New-DecomActionResult         -ActionName 'Revoke Sessions' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' -ControlObjective 'x' -RiskMitigated 'y'),
                (New-DecomActionResult         -ActionName 'Block Sign-In'   -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' -ControlObjective 'x' -RiskMitigated 'y')
            )
            # Live mode — Skipped should block
            Test-DecomCanContinueAfterContainment -Results $results -Context $ctx | Should -BeFalse
        }

        It 'allows continuation when containment is Skipped in WhatIf mode' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -WhatIfMode
            $results = @(
                (New-DecomSkippedBecauseWhatIf -ActionName 'Reset Password'  -Phase 'Containment' -TargetUPN 'u@c.com' -RecommendedNext 'N'),
                (New-DecomSkippedBecauseWhatIf -ActionName 'Revoke Sessions' -Phase 'Containment' -TargetUPN 'u@c.com' -RecommendedNext 'N'),
                (New-DecomSkippedBecauseWhatIf -ActionName 'Block Sign-In'   -Phase 'Containment' -TargetUPN 'u@c.com' -RecommendedNext 'N')
            )
            # WhatIf mode — Skipped is acceptable
            Test-DecomCanContinueAfterContainment -Results $results -Context $ctx | Should -BeTrue
        }
    }

    # ── WhatIf guard ───────────────────────────────────────────────────────────

    Context 'WhatIf guard in containment functions' {

        It 'Reset-DecomPassword returns Skipped when WhatIf' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -WhatIfMode
            $r   = Reset-DecomPassword -Context $ctx -Cmdlet $null
            $r | Should -Not -BeNullOrEmpty
            $r.Status | Should -Be 'Skipped'
        }

        It 'Revoke-DecomSessions returns Skipped when WhatIf' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -WhatIfMode
            (Revoke-DecomSessions -Context $ctx -Cmdlet $null).Status | Should -Be 'Skipped'
        }

        It 'Disable-DecomSignIn returns Skipped when WhatIf' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -WhatIfMode
            (Disable-DecomSignIn -Context $ctx -Cmdlet $null).Status | Should -Be 'Skipped'
        }
    }

    # ── Confirm-DecomPhase ─────────────────────────────────────────────────────

    Context 'Confirm-DecomPhase gate behavior' {

        It 'returns true when Force is set' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -Force
            Confirm-DecomPhase -Context $ctx -Cmdlet $null -PhaseName 'Test' -Message 'Go?' | Should -BeTrue
        }

        It 'returns true when WhatIf is set' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -WhatIfMode
            Confirm-DecomPhase -Context $ctx -Cmdlet $null -PhaseName 'Test' -Message 'Go?' | Should -BeTrue
        }

        It 'returns false (not throws) in NonInteractive mode without Force' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -NonInteractive
            # v1.3: must return $false, not throw
            { Confirm-DecomPhase -Context $ctx -Cmdlet $null -PhaseName 'Test' -Message 'Go?' } | Should -Not -Throw
            Confirm-DecomPhase -Context $ctx -Cmdlet $null -PhaseName 'Test' -Message 'Go?' | Should -BeFalse
        }
    }

    # ── Workflow behavioral tests ──────────────────────────────────────────────

    Context 'Workflow — ValidationOnly mode' {

        It 'stops after pre-action snapshot and does not call containment' {
            $ctx   = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -ValidationOnly -Force
            $state = New-DecomState -RunId 'test-run'
            $result = Invoke-DecomWorkflow -Context $ctx -State $state -Cmdlet $null

            # No StopReason — ValidationOnly is a clean exit
            $result.StopReason | Should -BeNullOrEmpty

            # Containment actions must NOT appear in results
            $containmentActions = $result.Results | Where-Object { $_.ActionName -in @('Reset Password','Revoke Sessions','Block Sign-In') }
            @($containmentActions).Count | Should -Be 0
        }
    }

    Context 'Workflow — Containment confirmation gate' {

        It 'emits Blocked result and stops when gate is declined' {
            # NonInteractive without Force — gate returns $false
            $ctx   = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -NonInteractive
            $state = New-DecomState -RunId 'test-run'
            $result = Invoke-DecomWorkflow -Context $ctx -State $state -Cmdlet $null

            $result.StopReason | Should -Not -BeNullOrEmpty
            $gateResult = $result.Results | Where-Object { $_.ActionName -eq 'Containment Phase Gate' }
            $gateResult | Should -Not -BeNullOrEmpty
            $gateResult.Status | Should -Be 'Blocked'
        }
    }

    # ── Group-based license blocker ────────────────────────────────────────────

    Context 'License readiness — group-based license detection' {

        It 'blocks license removal readiness when group-based SKUs detected' {
            # Stub Get-MgUser to return a direct license and GetMgUserLicenseDetail to return more
            # (simulating group-inherited additional SKU)
            function Get-MgUser {
                param([string]$UserId, [string[]]$Property)
                [pscustomobject]@{
                    Id               = 'test-id'
                    UserPrincipalName = $UserId
                    DisplayName      = 'Test'
                    AccountEnabled   = $true
                    UserType         = 'Member'
                    AssignedLicenses = @([pscustomobject]@{ SkuId = 'sku-direct-001' })
                }
            }
            function Get-MgUserLicenseDetail {
                param([string]$UserId, [string]$ErrorAction)
                @(
                    [pscustomobject]@{ SkuId = 'sku-direct-001'; SkuPartNumber = 'DIRECT' },
                    [pscustomobject]@{ SkuId = 'sku-group-002';  SkuPartNumber = 'GROUP'  }
                )
            }

            $ctx         = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $mailboxOk   = New-DecomActionResult -ActionName 'Convert Mailbox To Shared' -Phase 'Mailbox' `
                -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' `
                -ControlObjective 'x' -RiskMitigated 'y'
            $r = Test-DecomLicenseRemovalReadiness -Results @($mailboxOk) -Context $ctx

            $r.Status | Should -Be 'Blocked'
            @($r.BlockerMessages).Count | Should -BeGreaterThan 0
            $r.BlockerMessages[0] | Should -Match 'Group-based'
        }
    }

    # ── Guest account guard ────────────────────────────────────────────────────

    Context 'Guest account warning' {

        It 'Validation returns Warning for Guest UserType' {
            function Get-MgUser {
                param([string]$UserId, [string[]]$Property)
                [pscustomobject]@{ Id='g-id'; UserPrincipalName=$UserId; DisplayName='Guest';
                    AccountEnabled=$true; UserType='Guest'; AssignedLicenses=@() }
            }
            $ctx = New-DecomRunContext -TargetUPN 'guest@ext.com' -OutputPath 'out'
            $r   = Get-DecomBaselineState -Context $ctx
            $r.Status | Should -Be 'Warning'
            @($r.WarningMessages).Count | Should -BeGreaterThan 0
            @($r.ManualFollowUp).Count  | Should -BeGreaterThan 0
        }
    }

    # ── Password generation ────────────────────────────────────────────────────

    Context 'Secure password generation' {

        It 'generates password of requested length' {
            (New-DecomSecurePassword -Length 40).Length | Should -Be 40
        }

        It 'generates password of default length 32' {
            (New-DecomSecurePassword).Length | Should -Be 32
        }

        It 'two passwords are not identical' {
            New-DecomSecurePassword | Should -Not -Be (New-DecomSecurePassword)
        }
    }

    # ── HTML report ────────────────────────────────────────────────────────────

    Context 'HTML report' {

        It 'encodes dangerous content' {
            ConvertTo-DecomHtmlEncoded '<script>alert(1)</script>' | Should -Be '&lt;script&gt;alert(1)&lt;/script&gt;'
        }

        It 'encodes null as empty string' {
            ConvertTo-DecomHtmlEncoded $null | Should -Be ''
        }

        It 'HTML report contains ManualFollowUp content when present' {
            $ctx   = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $state = New-DecomState -RunId 'rpt-test'
            $r = New-DecomActionResult -ActionName 'Test Action' -Phase 'Validation' -Status 'Warning' `
                -IsCritical $false -TargetUPN 'u@c.com' -Message 'Check this' `
                -ManualFollowUp @('Review B2B access paths') `
                -ControlObjective 'x' -RiskMitigated 'y'
            $wfResult = [pscustomobject]@{
                Context = $ctx
                State   = $state
                Results = @($r)
            }
            $tmpPath = [System.IO.Path]::GetTempFileName() + '.html'
            Export-DecomHtmlReport -WorkflowResult $wfResult -Path $tmpPath
            $html = Get-Content $tmpPath -Raw
            $html | Should -Match 'Review B2B access paths'
            Remove-Item $tmpPath -ErrorAction SilentlyContinue
        }
    }

    # ── Discovery snapshot ─────────────────────────────────────────────────────

    Context 'Identity snapshot evidence fields' {

        It 'includes MfaMethodCount' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $r   = Get-DecomIdentitySnapshot -Context $ctx -SnapshotName 'Before'
            $r.Evidence.Keys | Should -Contain 'MfaMethodCount'
        }

        It 'includes ForwardingActive' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $r   = Get-DecomIdentitySnapshot -Context $ctx -SnapshotName 'Before'
            $r.Evidence.Keys | Should -Contain 'ForwardingActive'
        }

        It 'includes EligibleRoleCount' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $r   = Get-DecomIdentitySnapshot -Context $ctx -SnapshotName 'Before'
            $r.Evidence.Keys | Should -Contain 'EligibleRoleCount'
        }
    }

    # ── Phase engine ───────────────────────────────────────────────────────────

    Context 'Phase engine state transitions' {

        It 'Invoke-DecomPhase sets Completed on success' {
            $state = [pscustomobject]@{ RunId = 'x'; Phases = [ordered]@{} }
            $transitions = [System.Collections.Generic.List[string]]::new()
            # Override Set-DecomPhaseState to capture calls
            function Set-DecomPhaseState {
                param([pscustomobject]$State, [string]$Phase, [string]$Status)
                $transitions.Add("$Phase=$Status")
            }
            Invoke-DecomPhase -State $state -Phase 'TestPhase' -ScriptBlock { $true | Out-Null }
            $transitions | Should -Contain 'TestPhase=InProgress'
            $transitions | Should -Contain 'TestPhase=Completed'
        }

        It 'Invoke-DecomPhase sets Failed and rethrows on error' {
            $state = [pscustomobject]@{ RunId = 'x'; Phases = [ordered]@{} }
            $transitions = [System.Collections.Generic.List[string]]::new()
            function Set-DecomPhaseState {
                param([pscustomobject]$State, [string]$Phase, [string]$Status)
                $transitions.Add("$Phase=$Status")
            }
            { Invoke-DecomPhase -State $state -Phase 'BadPhase' -ScriptBlock { throw 'Boom' } } | Should -Throw
            $transitions | Should -Contain 'BadPhase=Failed'
        }
    }
}
