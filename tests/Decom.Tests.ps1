# Decom.Tests.ps1 — Pester v5 test suite
# v1.5: Added tests for evidence sealing, operator identity, TicketId enforcement,
#        manifest generation, SealEvidence flag, hash chain verification,
#        SECURITY.md presence, threat model doc presence.

BeforeAll {
    function Get-MgUser                                          { param([string]$UserId, [string[]]$Property) [pscustomobject]@{Id='test-id';UserPrincipalName=$UserId;DisplayName='Test User';AccountEnabled=$true;UserType='Member';AssignedLicenses=@()} }
    function Get-EXOMailbox                                      { param([string]$Identity, [string]$ErrorAction) [pscustomobject]@{RecipientTypeDetails='UserMailbox';ForwardingSmtpAddress=$null;ForwardingAddress=$null;GrantSendOnBehalfTo=@();ArchiveStatus='None';LitigationHoldEnabled=$false;InPlaceHolds=@();RetentionHoldEnabled=$false;ComplianceTagHoldApplied=$false} }
    function Get-MailboxPermission                               { param([string]$Identity, [string]$ErrorAction) @() }
    function Get-RecipientPermission                             { param([string]$Identity, [string]$ErrorAction) @() }
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
    function New-DecomState                                      { param([string]$RunId) [pscustomobject]@{ RunId=$RunId; Phases=[ordered]@{} } }
    function Connect-DecomGraph                                  { param([pscustomobject]$Context) New-DecomActionResult -ActionName 'Connect Microsoft Graph' -Phase 'Authentication' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Connected.' -ControlObjective 'Auth' -RiskMitigated 'Unauth' }
    function Connect-DecomExchange                               { param([pscustomobject]$Context) New-DecomActionResult -ActionName 'Connect Exchange Online' -Phase 'Authentication' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Connected.' -ControlObjective 'Auth' -RiskMitigated 'Unauth' }
    function Get-DecomBaselineState                              { param([pscustomobject]$Context) New-DecomActionResult -ActionName 'Validate Target UPN' -Phase 'Validation' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Validated.' -ControlObjective 'Validate' -RiskMitigated 'Wrong user' }
    function Get-DecomIdentitySnapshot                           { param([pscustomobject]$Context, [string]$SnapshotName) $ph=if($SnapshotName -eq 'Before'){'PreActionSnapshot'}else{'PostActionSnapshot'}; New-DecomActionResult -ActionName "Collect $SnapshotName Identity Snapshot" -Phase $ph -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'Snapshot.' -ControlObjective 'Snapshot' -RiskMitigated 'Blind' }
    function Reset-DecomPassword                                 { param([pscustomobject]$Context, $Cmdlet) if($Context.WhatIf){return New-DecomSkippedBecauseWhatIf -ActionName 'Reset Password' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Next'}; New-DecomActionResult -ActionName 'Reset Password' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Reset.' -ControlObjective 'Invalidate creds' -RiskMitigated 'Reuse' }
    function Revoke-DecomSessions                                { param([pscustomobject]$Context, $Cmdlet) if($Context.WhatIf){return New-DecomSkippedBecauseWhatIf -ActionName 'Revoke Sessions' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Next'}; New-DecomActionResult -ActionName 'Revoke Sessions' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Revoked.' -ControlObjective 'Revoke' -RiskMitigated 'Persist' }
    function Disable-DecomSignIn                                 { param([pscustomobject]$Context, $Cmdlet) if($Context.WhatIf){return New-DecomSkippedBecauseWhatIf -ActionName 'Block Sign-In' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Next'}; New-DecomActionResult -ActionName 'Block Sign-In' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Blocked.' -ControlObjective 'Deny auth' -RiskMitigated 'Access' }
    function Convert-DecomMailboxToShared                        { param([pscustomobject]$Context, $Cmdlet) New-DecomActionResult -ActionName 'Convert Mailbox To Shared' -Phase 'Mailbox' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Converted.' -ControlObjective 'Mailbox' -RiskMitigated 'Loss' }
    function Set-DecomAutoReply                                  { param([pscustomobject]$Context, [string]$Message, $Cmdlet) New-DecomActionResult -ActionName 'Set Out-of-Office' -Phase 'Mailbox' -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'No message.' -ControlObjective 'Comms' -RiskMitigated 'Orphan' }
    function Get-DecomComplianceState                            { param([pscustomobject]$Context) New-DecomActionResult -ActionName 'Evaluate Compliance State' -Phase 'Compliance' -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'Evaluated.' -ControlObjective 'Compliance' -RiskMitigated 'Loss' }
    function Enable-DecomLitigationHold                          { param([pscustomobject]$Context, $Cmdlet) New-DecomActionResult -ActionName 'Enable Litigation Hold' -Phase 'Compliance' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Enabled.' -ControlObjective 'Hold' -RiskMitigated 'Data loss' }
    function Test-DecomLicenseRemovalReadiness                   { param([object[]]$Results, [pscustomobject]$Context) New-DecomActionResult -ActionName 'Check License Removal Readiness' -Phase 'Licensing' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Ready.' -ControlObjective 'License' -RiskMitigated 'Premature' }
    function Remove-DecomLicenses                                { param([pscustomobject]$Context, $Cmdlet) New-DecomActionResult -ActionName 'Remove Licenses' -Phase 'Licensing' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Removed.' -ControlObjective 'License' -RiskMitigated 'Spend' }
    function Get-DecomRequiredGraphScopes                        { return @('User.ReadWrite.All','Directory.ReadWrite.All','Organization.Read.All','RoleManagement.Read.Directory','Application.Read.All','AppRoleAssignment.Read.All','DelegatedPermissionGrant.Read.All') }
    function Write-DecomEvidenceManifest                         { param([pscustomobject]$Context, [string]$OutputPath) }
    function Initialize-DecomEvidenceStore                       { param([pscustomobject]$Context, [string]$RunId, [string]$NdjsonPath) $Context|Add-Member -Force -NotePropertyName Evidence -NotePropertyValue ([System.Collections.Generic.List[object]]::new()); $Context|Add-Member -Force -NotePropertyName RunId -NotePropertyValue $RunId; $Context|Add-Member -Force -NotePropertyName EvidencePrevHash -NotePropertyValue 'GENESIS' }
}

Describe 'Entra Identity Decommissioning Control Plane v1.5' {

    BeforeAll {
        $root        = Split-Path -Parent $PSScriptRoot
        $srcPath     = Join-Path $root 'src'
        $modulesPath = Join-Path $srcPath 'Modules'
        Import-Module (Join-Path $modulesPath 'Models.psm1')      -Force
        Import-Module (Join-Path $modulesPath 'Guardrails.psm1')  -Force
        Import-Module (Join-Path $modulesPath 'Containment.psm1') -Force
        Import-Module (Join-Path $modulesPath 'Reporting.psm1')   -Force
        Import-Module (Join-Path $modulesPath 'Validation.psm1')  -Force
        Import-Module (Join-Path $modulesPath 'Discovery.psm1')   -Force
        Import-Module (Join-Path $modulesPath 'Execution.psm1')   -Force
        Import-Module (Join-Path $modulesPath 'Licensing.psm1')   -Force
        Import-Module (Join-Path $modulesPath 'Auth.psm1')        -Force
        Import-Module (Join-Path $modulesPath 'Evidence.psm1')    -Force
        . (Join-Path $srcPath 'Invoke-DecomWorkflow.ps1')
    }

    # ── Repo hygiene ───────────────────────────────────────────────────────────

    Context 'Repo hygiene' {

        It 'SECURITY.md exists in repo root' {
            $root = Split-Path -Parent $PSScriptRoot
            Test-Path (Join-Path $root 'SECURITY.md') | Should -BeTrue
        }

        It 'threat model doc exists in docs folder' {
            $root = Split-Path -Parent $PSScriptRoot
            $docs = Join-Path $root 'docs'
            (Get-ChildItem $docs -Filter 'threat-model*.md' -ErrorAction SilentlyContinue).Count | Should -BeGreaterThan 0
        }

        It 'Start-Decom.ps1 references v1.5' {
            $root    = Split-Path -Parent $PSScriptRoot
            $content = Get-Content (Join-Path (Join-Path $root 'src') 'Start-Decom.ps1') -Raw
            $content | Should -Match 'v1\.5'
        }

        It 'workflow return summary version is v1.5' {
            $ctx   = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -ValidationOnly -Force -WhatIfMode
            $state = New-DecomState -RunId 'ver-test'
            $result = Invoke-DecomWorkflow -Context $ctx -State $state -Cmdlet ([pscustomobject]@{})
            $result.Summary.Version | Should -Be 'v1.5'
        }
    }

    # ── Evidence sealing ───────────────────────────────────────────────────────

    Context 'Evidence sealing — hash chain' {

        It 'Get-DecomSha256Hex returns 64-char hex string' {
            $hash = Get-DecomSha256Hex -Text 'test input'
            $hash.Length | Should -Be 64
            $hash | Should -Match '^[0-9a-f]{64}$'
        }

        It 'Get-DecomSha256Hex is deterministic' {
            Get-DecomSha256Hex 'hello' | Should -Be (Get-DecomSha256Hex 'hello')
        }

        It 'Get-DecomSha256Hex is sensitive to input changes' {
            Get-DecomSha256Hex 'hello' | Should -Not -Be (Get-DecomSha256Hex 'Hello')
        }

        It 'Write-DecomEvidenceSeal adds EventHash and PrevHash' {
            $ev     = @{ ActionName='Test'; Status='Success'; TimestampUtc='2026-04-25T00:00:00Z' }
            $sealed = Write-DecomEvidenceSeal -Event $ev -PrevHash 'GENESIS'
            $sealed.Event.Keys | Should -Contain 'EventHash'
            $sealed.Event.Keys | Should -Contain 'PrevHash'
            $sealed.Event['PrevHash'] | Should -Be 'GENESIS'
            $sealed.NewPrevHash | Should -Not -BeNullOrEmpty
        }

        It 'Write-DecomEvidenceSeal produces different hashes for different inputs' {
            $ev1 = @{ ActionName='ResetPassword'; Status='Success' }
            $ev2 = @{ ActionName='RevokeSession'; Status='Success' }
            $s1  = Write-DecomEvidenceSeal -Event $ev1 -PrevHash 'GENESIS'
            $s2  = Write-DecomEvidenceSeal -Event $ev2 -PrevHash 'GENESIS'
            $s1.NewPrevHash | Should -Not -Be $s2.NewPrevHash
        }

        It 'hash chain links events correctly' {
            $ev1     = @{ ActionName='Step1'; Status='Success' }
            $sealed1 = Write-DecomEvidenceSeal -Event $ev1 -PrevHash 'GENESIS'
            $ev2     = @{ ActionName='Step2'; Status='Success' }
            $sealed2 = Write-DecomEvidenceSeal -Event $ev2 -PrevHash $sealed1.NewPrevHash
            $sealed2.Event['PrevHash'] | Should -Be $sealed1.NewPrevHash
        }

        It 'tampered event produces different hash' {
            $ev      = @{ ActionName='Reset'; Status='Success'; Message='ok' }
            $sealed  = Write-DecomEvidenceSeal -Event $ev -PrevHash 'GENESIS'
            $originalHash = $sealed.NewPrevHash
            # Simulate tampering
            $tampered = @{ ActionName='Reset'; Status='Failed'; Message='tampered' }
            $resealed = Write-DecomEvidenceSeal -Event $tampered -PrevHash 'GENESIS'
            $resealed.NewPrevHash | Should -Not -Be $originalHash
        }
    }

    # ── Context — operator identity and sealing flag ───────────────────────────

    Context 'Context — v1.5 fields' {

        It 'SealEvidence defaults to true' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $ctx.SealEvidence | Should -BeTrue
        }

        It 'NoSeal flag disables sealing' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -NoSeal
            $ctx.SealEvidence | Should -BeFalse
        }

        It 'OperatorUPN can be set on context' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -OperatorUPN 'admin@contoso.com'
            $ctx.OperatorUPN | Should -Be 'admin@contoso.com'
        }

        It 'TicketId flows into context' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -TicketId 'CHG-12345'
            $ctx.TicketId | Should -Be 'CHG-12345'
        }

        It 'workflow summary includes OperatorUPN and TicketId' {
            $ctx   = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -ValidationOnly -Force -WhatIfMode -OperatorUPN 'admin@contoso.com' -TicketId 'CHG-001'
            $state = New-DecomState -RunId 'sum-test'
            $result = Invoke-DecomWorkflow -Context $ctx -State $state -Cmdlet ([pscustomobject]@{})
            $result.Summary.OperatorUPN | Should -Be 'admin@contoso.com'
            $result.Summary.TicketId    | Should -Be 'CHG-001'
        }
    }

    # ── TicketId enforcement ───────────────────────────────────────────────────

    Context 'Force mode governance — TicketId enforcement' {

        It 'Start-Decom.ps1 contains TicketId mandatory check for Force+NonInteractive' {
            $root    = Split-Path -Parent $PSScriptRoot
            $content = Get-Content (Join-Path (Join-Path $root 'src') 'Start-Decom.ps1') -Raw
            $content | Should -Match 'TicketId.*required'
        }

        It 'Force+NonInteractive without TicketId should be documented as error' {
            # Verify the enforcement logic exists in source
            $root    = Split-Path -Parent $PSScriptRoot
            $content = Get-Content (Join-Path (Join-Path $root 'src') 'Start-Decom.ps1') -Raw
            $content | Should -Match 'Force.*NonInteractive.*TicketId|TicketId.*Force.*NonInteractive'
        }
    }

    # ── Evidence module exports ────────────────────────────────────────────────

    Context 'Evidence module contract' {

        It 'Evidence.psm1 exports Write-DecomEvidenceManifest' {
            $mod = Get-Module Evidence -ErrorAction SilentlyContinue
            if ($mod) { $mod.ExportedFunctions.Keys | Should -Contain 'Write-DecomEvidenceManifest' }
            else { Set-ItResult -Skipped -Because 'Evidence module not loaded by name' }
        }

        It 'Evidence.psm1 exports Get-DecomSha256Hex' {
            $mod = Get-Module Evidence -ErrorAction SilentlyContinue
            if ($mod) { $mod.ExportedFunctions.Keys | Should -Contain 'Get-DecomSha256Hex' }
            else { Set-ItResult -Skipped -Because 'Evidence module not loaded by name' }
        }

        It 'Evidence.psm1 does not export Assert-DecomEvidenceIntegrity' {
            $mod = Get-Module Evidence -ErrorAction SilentlyContinue
            if ($mod) { $mod.ExportedFunctions.Keys | Should -Not -Contain 'Assert-DecomEvidenceIntegrity' }
            else { Set-ItResult -Skipped -Because 'Evidence module not loaded by name' }
        }
    }

    # ── Schema ─────────────────────────────────────────────────────────────────

    Context 'Action result schema' {

        It 'StepId present and non-empty' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Validation' -Status 'Success' -IsCritical $false -TargetUPN 'u@c.com' -Message 'ok'
            $r.StepId | Should -Not -BeNullOrEmpty
        }

        It 'StepId follows PHASE-NNN format' {
            Reset-DecomStepCounters
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Containment' -Status 'Success' -IsCritical $false -TargetUPN 'u@c.com' -Message 'ok'
            $r.StepId | Should -Match '^CONTAINMENT-\d{3}$'
        }

        It 'ManualFollowUp defaults to empty array' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Validation' -Status 'Success' -IsCritical $false -TargetUPN 'u@c.com' -Message 'ok'
            @($r.ManualFollowUp).Count | Should -Be 0
        }

        It 'Context has all required v1.5 fields' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -EvidenceLevel 'Forensic' -ValidationOnly
            $ctx.TargetUPN      | Should -Be 'u@c.com'
            $ctx.EvidenceLevel  | Should -Be 'Forensic'
            $ctx.ValidationOnly | Should -BeTrue
            $ctx.CorrelationId  | Should -Not -BeNullOrEmpty
            $ctx.SealEvidence   | Should -BeTrue
        }
    }

    # ── Auth scopes ────────────────────────────────────────────────────────────

    Context 'Auth scope contract' {

        It 'requires exactly 7 Graph scopes' {
            @(Get-DecomRequiredGraphScopes).Count | Should -Be 7
        }

        It 'includes AppRoleAssignment.Read.All not ReadWrite' {
            $scopes = Get-DecomRequiredGraphScopes
            $scopes | Should -Contain 'AppRoleAssignment.Read.All'
            $scopes | Should -Not -Contain 'AppRoleAssignment.ReadWrite.All'
        }
    }

    # ── Evidence integrity ─────────────────────────────────────────────────────

    Context 'Evidence integrity contract' {

        It 'Assert-DecomEvidenceIntegrity passes full result' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' -ControlObjective 'Auth' -RiskMitigated 'Unauth'
            { Assert-DecomEvidenceIntegrity -Result $r } | Should -Not -Throw
        }

        It 'Assert-DecomEvidenceIntegrity throws on null' {
            { Assert-DecomEvidenceIntegrity -Result $null } | Should -Throw
        }

        It 'Assert-DecomEvidenceIntegrity throws on missing ControlObjective' {
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok'
            $r.ControlObjective = $null
            { Assert-DecomEvidenceIntegrity -Result $r } | Should -Throw
        }
    }

    # ── Guardrail hardening ────────────────────────────────────────────────────

    Context 'Guardrail hardening' {

        It 'Test-DecomCriticalPhaseSuccess rejects Skipped' {
            $r = New-DecomActionResult -ActionName 'Reset Password' -Phase 'Containment' -Status 'Skipped' -IsCritical $false -TargetUPN 'u@c.com' -Message 'skipped'
            Test-DecomCriticalPhaseSuccess -Results @($r) -ActionNames @('Reset Password') | Should -BeFalse
        }

        It 'Containment blocks Skipped in live mode' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $results = @(
                (New-DecomSkippedBecauseWhatIf -ActionName 'Reset Password'  -Phase 'Containment' -TargetUPN 'u@c.com' -RecommendedNext 'N'),
                (New-DecomActionResult         -ActionName 'Revoke Sessions' -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' -ControlObjective 'x' -RiskMitigated 'y'),
                (New-DecomActionResult         -ActionName 'Block Sign-In'   -Phase 'Containment' -Status 'Success' -IsCritical $true -TargetUPN 'u@c.com' -Message 'ok' -ControlObjective 'x' -RiskMitigated 'y')
            )
            Test-DecomCanContinueAfterContainment -Results $results -Context $ctx | Should -BeFalse
        }
    }

    # ── WhatIf guard ───────────────────────────────────────────────────────────

    Context 'WhatIf guard' {

        It 'Reset-DecomPassword returns Skipped when WhatIf' {
            $ctx = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out' -WhatIfMode
            (Reset-DecomPassword -Context $ctx -Cmdlet $null).Status | Should -Be 'Skipped'
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

    # ── Password generation ────────────────────────────────────────────────────

    Context 'Secure password generation' {

        It 'generates password of requested length' {
            (New-DecomSecurePassword -Length 40).Length | Should -Be 40
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

        It 'report contains ManualFollowUp content' {
            $ctx   = New-DecomRunContext -TargetUPN 'u@c.com' -OutputPath 'out'
            $state = New-DecomState -RunId 'rpt-test'
            $r = New-DecomActionResult -ActionName 'Test' -Phase 'Validation' -Status 'Warning' -IsCritical $false -TargetUPN 'u@c.com' -Message 'Check this' -ManualFollowUp @('Review B2B access paths') -ControlObjective 'x' -RiskMitigated 'y'
            $wfResult = [pscustomobject]@{ Context=$ctx; State=$state; Results=@($r) }
            $tmpPath  = [System.IO.Path]::GetTempFileName() + '.html'
            Export-DecomHtmlReport -WorkflowResult $wfResult -Path $tmpPath
            $html = Get-Content $tmpPath -Raw
            $html | Should -Match 'Review B2B access paths'
            Remove-Item $tmpPath -ErrorAction SilentlyContinue
        }
    }

    # ── Phase engine ───────────────────────────────────────────────────────────

    Context 'Phase engine state transitions' {

        BeforeAll {
            $sp = Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'src') 'Modules'
            Import-Module (Join-Path $sp 'State.psm1') -Force
        }

        It 'marks phase Completed on success' {
            $state = New-DecomState -RunId 'phase-test'
            Invoke-DecomPhase -State $state -Phase 'TestPhase' -ScriptBlock { $true | Out-Null }
            $state.Phases['TestPhase'].Status | Should -Be 'Completed'
        }

        It 'marks phase Failed and rethrows on error' {
            $state = New-DecomState -RunId 'phase-err'
            { Invoke-DecomPhase -State $state -Phase 'BadPhase' -ScriptBlock { throw 'Boom' } } | Should -Throw
            $state.Phases['BadPhase'].Status | Should -Be 'Failed'
        }
    }
}
