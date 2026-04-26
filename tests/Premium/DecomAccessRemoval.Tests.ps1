# DecomAccessRemoval.Tests.ps1 — Pester v5 tests for AccessRemoval.psm1
# Premium v2.0 — Phase 3
#
# Run from repo root:
#   Invoke-Pester .\tests\Premium\DecomAccessRemoval.Tests.ps1 -Output Detailed

BeforeAll {
    $repoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $liteMods    = Join-Path $repoRoot 'src\Modules'
    $premiumMods = Join-Path $repoRoot 'src\Premium\Modules'

    # ── Lite stubs ─────────────────────────────────────────────────────────────
    Import-Module (Join-Path $liteMods 'Models.psm1')  -Force -DisableNameChecking
    Import-Module (Join-Path $liteMods 'Logging.psm1') -Force -DisableNameChecking

    function Write-DecomConsole { param([string]$Level,[string]$Message) }
    function Add-DecomEvidenceEvent {
        param([pscustomobject]$Context,[string]$Phase,[string]$ActionName,
              [string]$Status,[bool]$IsCritical,[string]$Message,
              [hashtable]$BeforeState,[hashtable]$AfterState,[hashtable]$Evidence,
              [string]$ControlObjective,[string]$RiskMitigated)
    }
    function Resolve-DecomRoleName {
        param([string]$RoleDefinitionId)
        return "Role-$RoleDefinitionId"
    }

    # ── Graph stubs — happy path ───────────────────────────────────────────────
    function Get-MgUser {
        param([string]$UserId,[string[]]$Property)
        [pscustomobject]@{ Id = 'uid-001'; UserPrincipalName = $UserId }
    }

    function Get-MgUserMemberOf {
        param([string]$UserId,[switch]$All,[string]$ErrorAction)
        @(
            [pscustomobject]@{
                Id = 'grp-001'
                AdditionalProperties = @{
                    '@odata.type' = '#microsoft.graph.group'
                    'displayName' = 'SG-Finance'
                }
            },
            [pscustomobject]@{
                Id = 'grp-002'
                AdditionalProperties = @{
                    '@odata.type' = '#microsoft.graph.group'
                    'displayName' = 'SG-IT'
                }
            }
        )
    }

    function Get-MgGroup {
        param([string]$GroupId,[string[]]$Property,[string]$ErrorAction)
        [pscustomobject]@{
            DisplayName        = "Group-$GroupId"
            MembershipRule     = $null         # not dynamic
            IsAssignableToRole = $false
        }
    }

    function Remove-MgGroupMemberByRef {
        param([string]$GroupId,[string]$DirectoryObjectId,[string]$ErrorAction)
        # no-op stub — success
    }

    function Get-MgRoleManagementDirectoryRoleAssignment {
        param([string]$Filter,[switch]$All,[string]$ErrorAction)
        @(
            [pscustomobject]@{
                Id               = 'ra-001'
                PrincipalId      = 'uid-001'
                RoleDefinitionId = 'rdid-GlobalAdmin'
                DirectoryScopeId = '/'
            }
        )
    }

    function Remove-MgRoleManagementDirectoryRoleAssignment {
        param([string]$UnifiedRoleAssignmentId,[string]$ErrorAction)
        # no-op stub — success
    }

    function Get-MgRoleManagementDirectoryRoleEligibilitySchedule {
        param([string]$Filter,[switch]$All,[string]$ErrorAction)
        @(
            [pscustomobject]@{
                Id               = 'sched-001'
                PrincipalId      = 'uid-001'
                RoleDefinitionId = 'rdid-UserAdmin'
                DirectoryScopeId = '/'
            }
        )
    }

    function New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest {
        param([hashtable]$BodyParameter,[string]$ErrorAction)
        # no-op stub — success
    }

    function Get-MgUserAuthenticationMethod {
        param([string]$UserId,[string]$ErrorAction)
        @(
            [pscustomobject]@{
                Id = 'meth-001'
                AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod' }
            },
            [pscustomobject]@{
                Id = 'meth-002'
                AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethod' }
            }
        )
    }

    function Remove-MgUserAuthenticationPhoneMethod {
        param([string]$UserId,[string]$PhoneAuthenticationMethodId,[string]$ErrorAction) }
    function Remove-MgUserAuthenticationFido2Method {
        param([string]$UserId,[string]$Fido2AuthenticationMethodId,[string]$ErrorAction) }
    function Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod {
        param([string]$UserId,[string]$MicrosoftAuthenticatorAuthenticationMethodId,[string]$ErrorAction) }
    function Remove-MgUserAuthenticationSoftwareOathMethod {
        param([string]$UserId,[string]$SoftwareOathAuthenticationMethodId,[string]$ErrorAction) }
    function Remove-MgUserAuthenticationEmailMethod {
        param([string]$UserId,[string]$EmailAuthenticationMethodId,[string]$ErrorAction) }

    # ── Load module under test ─────────────────────────────────────────────────
    Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking

    # ── Helper: build a test context ──────────────────────────────────────────
    function New-TestContext {
        param([switch]$WhatIf)
        [pscustomobject]@{
            TargetUPN        = 'user@contoso.com'
            TicketId         = 'CHG-TEST'
            OutputPath       = $env:TEMP
            EvidenceLevel    = 'Forensic'
            WhatIf           = [bool]$WhatIf
            NonInteractive   = $false
            Force            = $false
            SealEvidence     = $true
            OperatorUPN      = 'admin@contoso.com'
            OperatorObjectId = 'op-oid-001'
            CorrelationId    = [guid]::NewGuid().Guid
            Evidence         = [System.Collections.Generic.List[object]]::new()
            RunId            = [guid]::NewGuid().Guid
            EvidencePrevHash = 'GENESIS'
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'Remove-DecomGroupMemberships — happy path' {

    It 'returns a DecomActionResult' {
        $ctx = New-TestContext
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r | Should -Not -BeNullOrEmpty
        $r.ActionName | Should -Be 'Remove Group Memberships'
    }

    It 'returns Success when all groups removed' {
        $ctx = New-TestContext
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Status | Should -Be 'Success'
    }

    It 'Evidence.GroupsFound matches mocked memberships' {
        $ctx = New-TestContext
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Evidence.GroupsFound | Should -Be 2
        $r.Evidence.Removed     | Should -Be 2
    }

    It 'Phase is AccessRemoval' {
        $ctx = New-TestContext
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Phase | Should -Be 'AccessRemoval'
    }
}

Describe 'Remove-DecomGroupMemberships — WhatIf' {

    It 'does not call Remove-MgGroupMemberByRef in WhatIf mode' {
        $ctx = New-TestContext -WhatIf
        $removed = 0
        function Remove-MgGroupMemberByRef { param([string]$GroupId,[string]$DirectoryObjectId,[string]$ErrorAction)
            $script:removed++ }
        $script:removed = 0
        Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null | Out-Null
        $script:removed | Should -Be 0
    }

    It 'still reports groups found in WhatIf mode' {
        $ctx = New-TestContext -WhatIf
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Evidence.GroupsFound | Should -Be 2
    }

    It 'WhatIf message prefix appears in result message' {
        $ctx = New-TestContext -WhatIf
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Message | Should -Match '\[WhatIf\]'
    }
}

Describe 'Remove-DecomGroupMemberships — edge cases' {

    It 'returns Skipped when user has no group memberships' {
        function Get-MgUserMemberOf { param([string]$UserId,[switch]$All,[string]$ErrorAction) @() }
        $ctx = New-TestContext
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Status | Should -Be 'Skipped'
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }

    It 'skips dynamic groups' {
        function Get-MgGroup { param([string]$GroupId,[string[]]$Property,[string]$ErrorAction)
            [pscustomobject]@{ DisplayName = 'DynGroup'; MembershipRule = 'user.dept -eq "IT"'; IsAssignableToRole = $false }
        }
        $ctx = New-TestContext
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Evidence.Skipped | Should -Be 2
        $r.Evidence.Removed | Should -Be 0
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }

    It 'skips role-assignable groups' {
        function Get-MgGroup { param([string]$GroupId,[string[]]$Property,[string]$ErrorAction)
            [pscustomobject]@{ DisplayName = 'RoleGroup'; MembershipRule = $null; IsAssignableToRole = $true }
        }
        $ctx = New-TestContext
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Evidence.Skipped | Should -Be 2
        $r.Evidence.Removed | Should -Be 0
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }

    It 'returns Warning (not Fatal) when some groups fail' {
        function Remove-MgGroupMemberByRef { param([string]$GroupId,[string]$DirectoryObjectId,[string]$ErrorAction)
            if ($GroupId -eq 'grp-001') { throw 'Access denied' }
        }
        $ctx = New-TestContext
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Status | Should -Be 'Warning'
        $r.Evidence.Failed  | Should -Be 1
        $r.Evidence.Removed | Should -Be 1
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }

    It 'returns Failed when ALL groups fail' {
        function Remove-MgGroupMemberByRef { param([string]$GroupId,[string]$DirectoryObjectId,[string]$ErrorAction)
            throw 'Access denied' }
        $ctx = New-TestContext
        $r = Remove-DecomGroupMemberships -Context $ctx -Cmdlet $null
        $r.Status | Should -Be 'Failed'
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'Remove-DecomRoleAssignments — happy path' {

    It 'returns two results (active + eligible)' {
        $ctx = New-TestContext
        $results = @(Remove-DecomRoleAssignments -Context $ctx -Cmdlet $null)
        $results.Count | Should -Be 2
    }

    It 'first result is active role removal' {
        $ctx = New-TestContext
        $results = @(Remove-DecomRoleAssignments -Context $ctx -Cmdlet $null)
        $results[0].ActionName | Should -Be 'Remove Active Role Assignments'
    }

    It 'second result is PIM-eligible removal' {
        $ctx = New-TestContext
        $results = @(Remove-DecomRoleAssignments -Context $ctx -Cmdlet $null)
        $results[1].ActionName | Should -Be 'Remove PIM-Eligible Role Assignments'
    }

    It 'active result status is Success' {
        $ctx = New-TestContext
        $results = @(Remove-DecomRoleAssignments -Context $ctx -Cmdlet $null)
        $results[0].Status | Should -Be 'Success'
        $results[0].Evidence.Removed | Should -Be 1
    }

    It 'eligible result status is Success' {
        $ctx = New-TestContext
        $results = @(Remove-DecomRoleAssignments -Context $ctx -Cmdlet $null)
        $results[1].Status | Should -Be 'Success'
        $results[1].Evidence.Removed | Should -Be 1
    }
}

Describe 'Remove-DecomRoleAssignments — WhatIf' {

    It 'does not call Remove-MgRoleManagementDirectoryRoleAssignment in WhatIf' {
        $script:activeCalled = 0
        function Remove-MgRoleManagementDirectoryRoleAssignment {
            param([string]$UnifiedRoleAssignmentId,[string]$ErrorAction)
            $script:activeCalled++
        }
        $ctx = New-TestContext -WhatIf
        Remove-DecomRoleAssignments -Context $ctx -Cmdlet $null | Out-Null
        $script:activeCalled | Should -Be 0
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }

    It 'does not call New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest in WhatIf' {
        $script:eligCalled = 0
        function New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest {
            param([hashtable]$BodyParameter,[string]$ErrorAction)
            $script:eligCalled++
        }
        $ctx = New-TestContext -WhatIf
        Remove-DecomRoleAssignments -Context $ctx -Cmdlet $null | Out-Null
        $script:eligCalled | Should -Be 0
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }
}

Describe 'Remove-DecomRoleAssignments — edge cases' {

    It 'active result is Skipped when no active assignments' {
        function Get-MgRoleManagementDirectoryRoleAssignment {
            param([string]$Filter,[switch]$All,[string]$ErrorAction) @() }
        $ctx = New-TestContext
        $r = @(Remove-DecomRoleAssignments -Context $ctx -Cmdlet $null)
        $r[0].Status | Should -Be 'Skipped'
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }

    It 'eligible result is Skipped when no eligible schedules' {
        function Get-MgRoleManagementDirectoryRoleEligibilitySchedule {
            param([string]$Filter,[switch]$All,[string]$ErrorAction) @() }
        $ctx = New-TestContext
        $r = @(Remove-DecomRoleAssignments -Context $ctx -Cmdlet $null)
        $r[1].Status | Should -Be 'Skipped'
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'Remove-DecomAuthMethods — happy path' {

    It 'returns a DecomActionResult' {
        $ctx = New-TestContext
        $r = Remove-DecomAuthMethods -Context $ctx -Cmdlet $null
        $r | Should -Not -BeNullOrEmpty
        $r.ActionName | Should -Be 'Remove Authentication Methods'
    }

    It 'returns Success when all methods removed' {
        $ctx = New-TestContext
        $r = Remove-DecomAuthMethods -Context $ctx -Cmdlet $null
        $r.Status | Should -Be 'Success'
    }

    It 'Evidence.MethodsFound matches mocked methods' {
        $ctx = New-TestContext
        $r = Remove-DecomAuthMethods -Context $ctx -Cmdlet $null
        $r.Evidence.MethodsFound | Should -Be 2
        $r.Evidence.Removed      | Should -Be 2
    }
}

Describe 'Remove-DecomAuthMethods — WhatIf' {

    It 'does not call any Remove-MgUserAuthentication* in WhatIf mode' {
        $script:removeCalled = 0
        function Remove-MgUserAuthenticationPhoneMethod {
            param([string]$UserId,[string]$PhoneAuthenticationMethodId,[string]$ErrorAction)
            $script:removeCalled++ }
        function Remove-MgUserAuthenticationFido2Method {
            param([string]$UserId,[string]$Fido2AuthenticationMethodId,[string]$ErrorAction)
            $script:removeCalled++ }
        $ctx = New-TestContext -WhatIf
        Remove-DecomAuthMethods -Context $ctx -Cmdlet $null | Out-Null
        $script:removeCalled | Should -Be 0
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }
}

Describe 'Remove-DecomAuthMethods — edge cases' {

    It 'returns Skipped when no auth methods found' {
        function Get-MgUserAuthenticationMethod { param([string]$UserId,[string]$ErrorAction) @() }
        $ctx = New-TestContext
        $r = Remove-DecomAuthMethods -Context $ctx -Cmdlet $null
        $r.Status | Should -Be 'Skipped'
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }

    It 'skips windowsHelloForBusiness method type' {
        function Get-MgUserAuthenticationMethod { param([string]$UserId,[string]$ErrorAction)
            @([pscustomobject]@{
                Id = 'whfb-001'
                AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' }
            })
        }
        $ctx = New-TestContext
        $r = Remove-DecomAuthMethods -Context $ctx -Cmdlet $null
        $r.Evidence.Skipped | Should -Be 1
        $r.Evidence.Removed | Should -Be 0
        $r.WarningMessages.Count | Should -BeGreaterThan 0
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }

    It 'returns Warning when some methods fail' {
        function Remove-MgUserAuthenticationPhoneMethod {
            param([string]$UserId,[string]$PhoneAuthenticationMethodId,[string]$ErrorAction)
            throw 'Method locked' }
        $ctx = New-TestContext
        $r = Remove-DecomAuthMethods -Context $ctx -Cmdlet $null
        $r.Status    | Should -Be 'Warning'
        $r.Evidence.Failed  | Should -Be 1
        $r.Evidence.Removed | Should -Be 1
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'Invoke-DecomAccessRemoval — orchestration' {

    It 'returns results for all three steps by default' {
        $ctx = New-TestContext
        $results = @(Invoke-DecomAccessRemoval -Context $ctx -Cmdlet $null)
        # Groups=1, Roles=2, AuthMethods=1 = 4 total
        $results.Count | Should -Be 4
    }

    It 'skips groups when -SkipGroups' {
        $ctx = New-TestContext
        $results = @(Invoke-DecomAccessRemoval -Context $ctx -Cmdlet $null -SkipGroups)
        $results | Where-Object { $_.ActionName -eq 'Remove Group Memberships' } | Should -BeNullOrEmpty
    }

    It 'skips roles when -SkipRoles' {
        $ctx = New-TestContext
        $results = @(Invoke-DecomAccessRemoval -Context $ctx -Cmdlet $null -SkipRoles)
        $results | Where-Object { $_.ActionName -match 'Role' } | Should -BeNullOrEmpty
    }

    It 'skips auth methods when -SkipAuthMethods' {
        $ctx = New-TestContext
        $results = @(Invoke-DecomAccessRemoval -Context $ctx -Cmdlet $null -SkipAuthMethods)
        $results | Where-Object { $_.ActionName -eq 'Remove Authentication Methods' } | Should -BeNullOrEmpty
    }

    It 'continues after group failure — still runs roles and auth methods' {
        function Remove-MgGroupMemberByRef {
            param([string]$GroupId,[string]$DirectoryObjectId,[string]$ErrorAction)
            throw 'Graph 403' }
        $ctx = New-TestContext
        $results = @(Invoke-DecomAccessRemoval -Context $ctx -Cmdlet $null)
        # Should still have role + auth results despite group failure
        $results | Where-Object { $_.ActionName -match 'Role' }   | Should -Not -BeNullOrEmpty
        $results | Where-Object { $_.ActionName -match 'Auth' }   | Should -Not -BeNullOrEmpty
        Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1') -Force -DisableNameChecking
    }

    It 'all results have Phase = AccessRemoval' {
        $ctx = New-TestContext
        $results = @(Invoke-DecomAccessRemoval -Context $ctx -Cmdlet $null)
        $results | ForEach-Object { $_.Phase | Should -Be 'AccessRemoval' }
    }
}
