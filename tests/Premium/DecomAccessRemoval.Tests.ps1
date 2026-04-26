# DecomAccessRemoval.Tests.ps1 — Pester v5 / PS7
# AccessRemoval.psm1
# Run: Invoke-Pester .\tests\Premium\DecomAccessRemoval.Tests.ps1 -Output Detailed

BeforeAll {
    $repoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $liteMods    = Join-Path $repoRoot 'src\Modules'
    $premiumMods = Join-Path $repoRoot 'src\Premium\Modules'

    Import-Module (Join-Path $liteMods    'Models.psm1')       -Force -DisableNameChecking
    Import-Module (Join-Path $liteMods    'Logging.psm1')      -Force -DisableNameChecking
    Import-Module (Join-Path $liteMods    'Evidence.psm1')     -Force -DisableNameChecking
    Import-Module (Join-Path $liteMods    'Discovery.psm1')      -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'AccessRemoval.psm1')   -Force -DisableNameChecking

    function script:New-TestContext {
        param([switch]$WhatIf)
        [pscustomobject]@{
            TargetUPN='user@contoso.com'; TicketId='CHG-TEST'; OutputPath=$env:TEMP
            EvidenceLevel='Forensic'; WhatIf=[bool]$WhatIf; NonInteractive=$false
            Force=$false; SealEvidence=$true; OperatorUPN='admin@contoso.com'
            OperatorObjectId='op-oid-001'; CorrelationId=[guid]::NewGuid().Guid
            Evidence=[System.Collections.Generic.List[object]]::new()
            RunId=[guid]::NewGuid().Guid; EvidencePrevHash='GENESIS'
        }
    }

    # Default happy-path Mocks inside AccessRemoval module scope
    Mock -ModuleName AccessRemoval Get-MgUser {
        [pscustomobject]@{ Id='uid-001'; UserPrincipalName='user@contoso.com' }
    }
    Mock -ModuleName AccessRemoval Get-MgUserMemberOf {
        @(
            [pscustomobject]@{ Id='grp-001'; AdditionalProperties=@{ '@odata.type'='#microsoft.graph.group'; 'displayName'='SG-Finance' } },
            [pscustomobject]@{ Id='grp-002'; AdditionalProperties=@{ '@odata.type'='#microsoft.graph.group'; 'displayName'='SG-IT' } }
        )
    }
    Mock -ModuleName AccessRemoval Get-MgGroup {
        [pscustomobject]@{ DisplayName='TestGroup'; MembershipRule=$null; IsAssignableToRole=$false }
    }
    Mock -ModuleName AccessRemoval Remove-MgGroupMemberByRef { }
    Mock -ModuleName AccessRemoval Get-MgRoleManagementDirectoryRoleAssignment {
        @([pscustomobject]@{ Id='ra-001'; PrincipalId='uid-001'; RoleDefinitionId='rdid-GA'; DirectoryScopeId='/' })
    }
    Mock -ModuleName AccessRemoval Remove-MgRoleManagementDirectoryRoleAssignment { }
    Mock -ModuleName AccessRemoval Get-MgRoleManagementDirectoryRoleEligibilitySchedule {
        @([pscustomobject]@{ Id='sched-001'; PrincipalId='uid-001'; RoleDefinitionId='rdid-UA'; DirectoryScopeId='/' })
    }
    Mock -ModuleName AccessRemoval New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest { }
    Mock -ModuleName AccessRemoval Get-MgUserAuthenticationMethod {
        @(
            [pscustomobject]@{ Id='meth-001'; AdditionalProperties=@{ '@odata.type'='#microsoft.graph.phoneAuthenticationMethod' } },
            [pscustomobject]@{ Id='meth-002'; AdditionalProperties=@{ '@odata.type'='#microsoft.graph.fido2AuthenticationMethod' } }
        )
    }
    Mock -ModuleName AccessRemoval Remove-MgUserAuthenticationPhoneMethod { }
    Mock -ModuleName AccessRemoval Remove-MgUserAuthenticationFido2Method { }
    Mock -ModuleName AccessRemoval Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod { }
    Mock -ModuleName AccessRemoval Remove-MgUserAuthenticationSoftwareOathMethod { }
    Mock -ModuleName AccessRemoval Remove-MgUserAuthenticationEmailMethod { }
    Mock -ModuleName AccessRemoval Add-DecomEvidenceEvent { }
    Mock -ModuleName AccessRemoval Write-DecomConsole { }
    Mock -ModuleName AccessRemoval Resolve-DecomRoleName { param($RoleDefinitionId) "Role-$RoleDefinitionId" }
}

Describe 'Remove-DecomGroupMemberships - happy path' {

    It 'returns a DecomActionResult' {
        $r = Remove-DecomGroupMemberships -Context (New-TestContext) -Cmdlet $null
        $r.ActionName | Should -Be 'Remove Group Memberships'
    }

    It 'returns Success when all groups removed' {
        (Remove-DecomGroupMemberships -Context (New-TestContext) -Cmdlet $null).Status | Should -Be 'Success'
    }

    It 'Evidence.GroupsFound matches mocked memberships' {
        $r = Remove-DecomGroupMemberships -Context (New-TestContext) -Cmdlet $null
        $r.Evidence.GroupsFound | Should -Be 2
        $r.Evidence.Removed     | Should -Be 2
    }

    It 'Phase is AccessRemoval' {
        (Remove-DecomGroupMemberships -Context (New-TestContext) -Cmdlet $null).Phase | Should -Be 'AccessRemoval'
    }
}

Describe 'Remove-DecomGroupMemberships - WhatIf' {

    It 'does not call Remove-MgGroupMemberByRef in WhatIf mode' {
        Remove-DecomGroupMemberships -Context (New-TestContext -WhatIf) -Cmdlet $null | Out-Null
        Should -Invoke Remove-MgGroupMemberByRef -ModuleName AccessRemoval -Times 0 -Exactly
    }

    It 'still reports groups found in WhatIf mode' {
        (Remove-DecomGroupMemberships -Context (New-TestContext -WhatIf) -Cmdlet $null).Evidence.GroupsFound | Should -Be 2
    }

    It 'WhatIf message prefix appears in result message' {
        (Remove-DecomGroupMemberships -Context (New-TestContext -WhatIf) -Cmdlet $null).Message | Should -Match '\[WhatIf\]'
    }
}

Describe 'Remove-DecomGroupMemberships - edge cases' {

    It 'returns Skipped when user has no group memberships' {
        Mock -ModuleName AccessRemoval Get-MgUserMemberOf { @() }
        (Remove-DecomGroupMemberships -Context (New-TestContext) -Cmdlet $null).Status | Should -Be 'Skipped'
    }

    It 'skips dynamic groups' {
        Mock -ModuleName AccessRemoval Get-MgGroup {
            [pscustomobject]@{ DisplayName='DynGrp'; MembershipRule='user.dept -eq "IT"'; IsAssignableToRole=$false }
        }
        $r = Remove-DecomGroupMemberships -Context (New-TestContext) -Cmdlet $null
        $r.Evidence.Skipped | Should -Be 2
        $r.Evidence.Removed | Should -Be 0
    }

    It 'skips role-assignable groups' {
        Mock -ModuleName AccessRemoval Get-MgGroup {
            [pscustomobject]@{ DisplayName='RoleGrp'; MembershipRule=$null; IsAssignableToRole=$true }
        }
        $r = Remove-DecomGroupMemberships -Context (New-TestContext) -Cmdlet $null
        $r.Evidence.Skipped | Should -Be 2
        $r.Evidence.Removed | Should -Be 0
    }

    It 'returns Warning when some groups fail' {
        $script:callCount = 0
        Mock -ModuleName AccessRemoval Remove-MgGroupMemberByRef {
            $script:callCount++
            if ($script:callCount -eq 1) { throw 'Access denied' }
        }
        $r = Remove-DecomGroupMemberships -Context (New-TestContext) -Cmdlet $null
        $r.Status           | Should -Be 'Warning'
        $r.Evidence.Failed  | Should -Be 1
        $r.Evidence.Removed | Should -Be 1
    }

    It 'returns Failed when ALL groups fail' {
        Mock -ModuleName AccessRemoval Remove-MgGroupMemberByRef { throw 'Access denied' }
        (Remove-DecomGroupMemberships -Context (New-TestContext) -Cmdlet $null).Status | Should -Be 'Failed'
    }
}

Describe 'Remove-DecomRoleAssignments - happy path' {

    It 'returns two results (active + eligible)' {
        @(Remove-DecomRoleAssignments -Context (New-TestContext) -Cmdlet $null).Count | Should -Be 2
    }

    It 'first result is active role removal' {
        (@(Remove-DecomRoleAssignments -Context (New-TestContext) -Cmdlet $null))[0].ActionName | Should -Be 'Remove Active Role Assignments'
    }

    It 'second result is PIM-eligible removal' {
        (@(Remove-DecomRoleAssignments -Context (New-TestContext) -Cmdlet $null))[1].ActionName | Should -Be 'Remove PIM-Eligible Role Assignments'
    }

    It 'active result status is Success' {
        $r = (@(Remove-DecomRoleAssignments -Context (New-TestContext) -Cmdlet $null))[0]
        $r.Status           | Should -Be 'Success'
        $r.Evidence.Removed | Should -Be 1
    }

    It 'eligible result status is Success' {
        $r = (@(Remove-DecomRoleAssignments -Context (New-TestContext) -Cmdlet $null))[1]
        $r.Status           | Should -Be 'Success'
        $r.Evidence.Removed | Should -Be 1
    }
}

Describe 'Remove-DecomRoleAssignments - WhatIf' {

    It 'does not call Remove active role in WhatIf' {
        Remove-DecomRoleAssignments -Context (New-TestContext -WhatIf) -Cmdlet $null | Out-Null
        Should -Invoke Remove-MgRoleManagementDirectoryRoleAssignment -ModuleName AccessRemoval -Times 0 -Exactly
    }

    It 'does not call New eligible schedule request in WhatIf' {
        Remove-DecomRoleAssignments -Context (New-TestContext -WhatIf) -Cmdlet $null | Out-Null
        Should -Invoke New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -ModuleName AccessRemoval -Times 0 -Exactly
    }
}

Describe 'Remove-DecomRoleAssignments - edge cases' {

    It 'active result is Skipped when no active assignments' {
        Mock -ModuleName AccessRemoval Get-MgRoleManagementDirectoryRoleAssignment { @() }
        (@(Remove-DecomRoleAssignments -Context (New-TestContext) -Cmdlet $null))[0].Status | Should -Be 'Skipped'
    }

    It 'eligible result is Skipped when no eligible schedules' {
        Mock -ModuleName AccessRemoval Get-MgRoleManagementDirectoryRoleEligibilitySchedule { @() }
        (@(Remove-DecomRoleAssignments -Context (New-TestContext) -Cmdlet $null))[1].Status | Should -Be 'Skipped'
    }
}

Describe 'Remove-DecomAuthMethods - happy path' {

    It 'returns a DecomActionResult' {
        (Remove-DecomAuthMethods -Context (New-TestContext) -Cmdlet $null).ActionName | Should -Be 'Remove Authentication Methods'
    }

    It 'returns Success when all methods removed' {
        (Remove-DecomAuthMethods -Context (New-TestContext) -Cmdlet $null).Status | Should -Be 'Success'
    }

    It 'Evidence.MethodsFound matches mocked methods' {
        $r = Remove-DecomAuthMethods -Context (New-TestContext) -Cmdlet $null
        $r.Evidence.MethodsFound | Should -Be 2
        $r.Evidence.Removed      | Should -Be 2
    }
}

Describe 'Remove-DecomAuthMethods - WhatIf' {

    It 'does not call Remove-MgUserAuthentication* in WhatIf mode' {
        Remove-DecomAuthMethods -Context (New-TestContext -WhatIf) -Cmdlet $null | Out-Null
        Should -Invoke Remove-MgUserAuthenticationPhoneMethod -ModuleName AccessRemoval -Times 0 -Exactly
        Should -Invoke Remove-MgUserAuthenticationFido2Method -ModuleName AccessRemoval -Times 0 -Exactly
    }
}

Describe 'Remove-DecomAuthMethods - edge cases' {

    It 'returns Skipped when no auth methods found' {
        Mock -ModuleName AccessRemoval Get-MgUserAuthenticationMethod { @() }
        (Remove-DecomAuthMethods -Context (New-TestContext) -Cmdlet $null).Status | Should -Be 'Skipped'
    }

    It 'skips windowsHelloForBusiness method type' {
        Mock -ModuleName AccessRemoval Get-MgUserAuthenticationMethod {
            @([pscustomobject]@{ Id='whfb-001'; AdditionalProperties=@{ '@odata.type'='#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' } })
        }
        $r = Remove-DecomAuthMethods -Context (New-TestContext) -Cmdlet $null
        $r.Evidence.Skipped      | Should -Be 1
        $r.Evidence.Removed      | Should -Be 0
        $r.WarningMessages.Count | Should -BeGreaterThan 0
    }

    It 'returns Warning when some methods fail' {
        Mock -ModuleName AccessRemoval Remove-MgUserAuthenticationPhoneMethod { throw 'Method locked' }
        $r = Remove-DecomAuthMethods -Context (New-TestContext) -Cmdlet $null
        $r.Status           | Should -Be 'Warning'
        $r.Evidence.Failed  | Should -Be 1
        $r.Evidence.Removed | Should -Be 1
    }
}

Describe 'Invoke-DecomAccessRemoval - orchestration' {

    It 'returns results for all three steps by default' {
        # Groups=1, ActiveRoles=1, EligibleRoles=1, AuthMethods=1 = 4
        @(Invoke-DecomAccessRemoval -Context (New-TestContext) -Cmdlet $null).Count | Should -Be 4
    }

    It 'skips groups when -SkipGroups' {
        $r = @(Invoke-DecomAccessRemoval -Context (New-TestContext) -Cmdlet $null -SkipGroups)
        $r | Where-Object { $_.ActionName -eq 'Remove Group Memberships' } | Should -BeNullOrEmpty
    }

    It 'skips roles when -SkipRoles' {
        $r = @(Invoke-DecomAccessRemoval -Context (New-TestContext) -Cmdlet $null -SkipRoles)
        $r | Where-Object { $_.ActionName -match 'Role' } | Should -BeNullOrEmpty
    }

    It 'skips auth methods when -SkipAuthMethods' {
        $r = @(Invoke-DecomAccessRemoval -Context (New-TestContext) -Cmdlet $null -SkipAuthMethods)
        $r | Where-Object { $_.ActionName -eq 'Remove Authentication Methods' } | Should -BeNullOrEmpty
    }

    It 'continues after group failure - still runs roles and auth methods' {
        Mock -ModuleName AccessRemoval Remove-MgGroupMemberByRef { throw 'Graph 403' }
        $r = @(Invoke-DecomAccessRemoval -Context (New-TestContext) -Cmdlet $null)
        $r | Where-Object { $_.ActionName -match 'Role' } | Should -Not -BeNullOrEmpty
        $r | Where-Object { $_.ActionName -match 'Auth' } | Should -Not -BeNullOrEmpty
    }

    It 'all results have Phase = AccessRemoval' {
        @(Invoke-DecomAccessRemoval -Context (New-TestContext) -Cmdlet $null) |
            ForEach-Object { $_.Phase | Should -Be 'AccessRemoval' }
    }
}
