# AccessRemoval.psm1 — Identity access surface cleanup
# Premium v2.0 — Phase 3
#
# Functions:
#   Remove-DecomGroupMemberships    — remove user from all Entra/M365 groups
#   Remove-DecomRoleAssignments     — remove active + PIM-eligible role assignments
#   Remove-DecomAuthMethods         — remove all registered MFA/auth methods
#   Invoke-DecomAccessRemoval       — orchestrates all three in correct order
#
# Required Graph scopes (in addition to Lite scopes):
#   GroupMember.ReadWrite.All           — group removal
#   RoleManagement.ReadWrite.Directory  — active + PIM role removal
#   UserAuthenticationMethod.ReadWrite.All — auth method removal
#
# Design:
#   - Every removal is WhatIf-aware (logs intent, does not mutate when WhatIf = true)
#   - Every removal writes an evidence event via Add-DecomEvidenceEvent (Lite)
#   - Failures are non-fatal per-item — one bad group removal does not stop the rest
#   - Results follow the Lite New-DecomActionResult contract exactly
#   - Dynamic groups and role-assignable groups are skipped (can't remove members)
#   - Auth method type '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
#     is skipped — requires device context, cannot be removed via Graph
#
# PS5.1 compatible throughout

#Requires -Version 5.1

Set-StrictMode -Version Latest

# ── Constants ──────────────────────────────────────────────────────────────────

# Auth method types that cannot be removed via Graph user endpoint
$script:SkippedAuthMethodTypes = @(
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'
)

# ── Public orchestrator ────────────────────────────────────────────────────────

function Invoke-DecomAccessRemoval {
    <#
    .SYNOPSIS
        Orchestrates all three access removal steps for a single UPN.

    .DESCRIPTION
        Runs in order:
          1. Remove-DecomGroupMemberships
          2. Remove-DecomRoleAssignments
          3. Remove-DecomAuthMethods

        Each step is independent — a failure in one does not block the others.
        Returns an array of DecomActionResult objects compatible with Lite results.

    .PARAMETER Context
        Lite DecomRunContext for the target UPN.

    .PARAMETER Cmdlet
        PSCmdlet reference for ShouldProcess gates.

    .PARAMETER SkipGroups
        Skip group membership removal.

    .PARAMETER SkipRoles
        Skip role assignment removal.

    .PARAMETER SkipAuthMethods
        Skip MFA/auth method removal.

    .OUTPUTS
        [object[]] — array of DecomActionResult objects
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        $Cmdlet,
        [switch]$SkipGroups,
        [switch]$SkipRoles,
        [switch]$SkipAuthMethods
    )

    $results = New-Object System.Collections.Generic.List[object]

    if (-not $SkipGroups) {
        $results.Add((Remove-DecomGroupMemberships -Context $Context -Cmdlet $Cmdlet))
    }

    if (-not $SkipRoles) {
        foreach ($r in @(Remove-DecomRoleAssignments -Context $Context -Cmdlet $Cmdlet)) {
            $results.Add($r)
        }
    }

    if (-not $SkipAuthMethods) {
        $results.Add((Remove-DecomAuthMethods -Context $Context -Cmdlet $Cmdlet))
    }

    return $results.ToArray()
}

# ── Group membership removal ───────────────────────────────────────────────────

function Remove-DecomGroupMemberships {
    <#
    .SYNOPSIS
        Removes the target user from all Entra ID / M365 group memberships.

    .DESCRIPTION
        Enumerates all group memberships via Get-MgUserMemberOf, then calls
        Remove-MgGroupMemberByRef for each removable group.

        Skipped automatically:
          - Dynamic groups (MembershipRule present) — Graph rejects member removal
          - Role-assignable groups — require privileged role to modify
          - Groups where removal fails — logged as Warning, not Fatal

        WhatIf-aware: when Context.WhatIf = true, enumerates and logs but
        does not call Remove-MgGroupMemberByRef.

    .PARAMETER Context
        Lite DecomRunContext for the target UPN.

    .PARAMETER Cmdlet
        PSCmdlet for ShouldProcess.

    .OUTPUTS
        [pscustomobject] — single DecomActionResult summarising the removal run.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        $Cmdlet
    )

    $phase      = 'AccessRemoval'
    $actionName = 'Remove Group Memberships'

    try {
        # Resolve ObjectId
        $user = Get-MgUser -UserId $Context.TargetUPN -Property Id, UserPrincipalName -ErrorAction Stop
        $uid  = $user.Id

        # Enumerate all group memberships
        $allMemberships = @(Get-MgUserMemberOf -UserId $uid -All -ErrorAction Stop |
            Where-Object { $_.AdditionalProperties['@odata.type'] -match 'group' })

        if ($allMemberships.Count -eq 0) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message 'No group memberships found — nothing to remove.' `
                -Evidence @{ GroupsFound = 0; Removed = 0; Skipped = 0; Failed = 0 } `
                -ControlObjective 'Remove all group-based access paths' `
                -RiskMitigated 'Residual access via group membership'
        }

        $removed  = [System.Collections.Generic.List[string]]::new()
        $skipped  = [System.Collections.Generic.List[string]]::new()
        $failed   = [System.Collections.Generic.List[string]]::new()
        $warnings = [System.Collections.Generic.List[string]]::new()

        foreach ($membership in $allMemberships) {
            $gid         = $membership.Id
            $displayName = $membership.AdditionalProperties['displayName']
            $isDynamic   = $false
            $isRoleAssignable = $false

            # Check group type to detect dynamic / role-assignable
            try {
                $grp = Get-MgGroup -GroupId $gid `
                    -Property DisplayName, MembershipRule, IsAssignableToRole `
                    -ErrorAction Stop
                $isDynamic        = -not [string]::IsNullOrEmpty($grp.MembershipRule)
                $isRoleAssignable = [bool]$grp.IsAssignableToRole
            } catch {
                # Can't read group properties — skip to be safe
                $skipped.Add("$displayName (properties unreadable)")
                $warnings.Add("Could not read properties for group '$displayName' ($gid) — skipped.")
                continue
            }

            if ($isDynamic) {
                $skipped.Add("$displayName (dynamic)")
                continue
            }

            if ($isRoleAssignable) {
                $skipped.Add("$displayName (role-assignable — requires privileged role)")
                $warnings.Add("Group '$displayName' is role-assignable. Manual removal may be required.")
                continue
            }

            if ($Context.WhatIf) {
                $removed.Add("$displayName [WhatIf]")
                continue
            }

            try {
                Remove-MgGroupMemberByRef -GroupId $gid -DirectoryObjectId $uid -ErrorAction Stop
                $removed.Add($displayName)

                Add-DecomEvidenceEvent -Context $Context -Phase $phase `
                    -ActionName "Remove Group: $displayName" `
                    -Status 'Success' -IsCritical $false `
                    -Message "Removed from group '$displayName' ($gid)" `
                    -AfterState @{ GroupId = $gid; GroupName = $displayName; MemberRemoved = $true } `
                    -ControlObjective 'Remove group-based access path' `
                    -RiskMitigated 'Residual access via group membership' | Out-Null

            } catch {
                $errMsg = $_.Exception.Message
                $failed.Add("$displayName: $errMsg")
                $warnings.Add("Failed to remove from '$displayName': $errMsg")
            }
        }

        $status = if ($failed.Count -gt 0 -and $removed.Count -eq 0) { 'Failed' }
                  elseif ($failed.Count -gt 0) { 'Warning' }
                  else { 'Success' }

        $summary = "Groups found: $($allMemberships.Count) | " +
                   "Removed: $($removed.Count) | " +
                   "Skipped: $($skipped.Count) | " +
                   "Failed: $($failed.Count)"

        if ($Context.WhatIf) { $summary = "[WhatIf] $summary" }

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status $status -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message $summary `
            -Evidence @{
                GroupsFound  = $allMemberships.Count
                Removed      = $removed.Count
                Skipped      = $skipped.Count
                Failed       = $failed.Count
                RemovedList  = $removed.ToArray()
                SkippedList  = $skipped.ToArray()
                FailedList   = $failed.ToArray()
            } `
            -WarningMessages $warnings.ToArray() `
            -ControlObjective 'Remove all group-based access paths' `
            -RiskMitigated 'Residual access via group membership'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Failed' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message "Group membership removal failed: $($_.Exception.Message)" `
            -FailureClass 'GraphError' `
            -ControlObjective 'Remove all group-based access paths' `
            -RiskMitigated 'Residual access via group membership'
    }
}

# ── Role assignment removal ────────────────────────────────────────────────────

function Remove-DecomRoleAssignments {
    <#
    .SYNOPSIS
        Removes all active and PIM-eligible Entra ID role assignments.

    .DESCRIPTION
        Active assignments:   Delete-MgRoleManagementDirectoryRoleAssignment
        PIM eligible:         Remove-MgRoleManagementDirectoryRoleEligibilitySchedule

        Returns TWO DecomActionResult objects — one for active, one for eligible —
        so each shows up as a distinct step in the Lite-compatible results list.

        WhatIf-aware: enumerates and logs but does not mutate.

    .PARAMETER Context
        Lite DecomRunContext for the target UPN.

    .PARAMETER Cmdlet
        PSCmdlet for ShouldProcess.

    .OUTPUTS
        [pscustomobject[]] — two DecomActionResult objects (active, eligible).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        $Cmdlet
    )

    $phase = 'AccessRemoval'
    $uid   = $null

    try {
        $user = Get-MgUser -UserId $Context.TargetUPN -Property Id -ErrorAction Stop
        $uid  = $user.Id
    } catch {
        $errResult = New-DecomActionResult -ActionName 'Remove Role Assignments' -Phase $phase `
            -Status 'Failed' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message "Could not resolve user ObjectId: $($_.Exception.Message)" `
            -FailureClass 'GraphError' `
            -ControlObjective 'Remove all Entra role assignments' `
            -RiskMitigated 'Privileged role access on disabled account'
        return @($errResult)
    }

    $activeResult   = _RemoveActiveRoles   -Context $Context -UserId $uid -Phase $phase
    $eligibleResult = _RemoveEligibleRoles -Context $Context -UserId $uid -Phase $phase

    return @($activeResult, $eligibleResult)
}

# ── Auth method removal ────────────────────────────────────────────────────────

function Remove-DecomAuthMethods {
    <#
    .SYNOPSIS
        Removes all removable MFA and authentication methods from the target user.

    .DESCRIPTION
        Enumerates methods via Get-MgUserAuthenticationMethod, then calls the
        appropriate type-specific Delete endpoint for each removable method.

        Skipped method types (cannot be removed via Graph user endpoint):
          - windowsHelloForBusinessAuthenticationMethod
          - temporaryAccessPassAuthenticationMethod

        WhatIf-aware: enumerates and logs but does not call Delete.

    .PARAMETER Context
        Lite DecomRunContext.

    .PARAMETER Cmdlet
        PSCmdlet for ShouldProcess.

    .OUTPUTS
        [pscustomobject] — single DecomActionResult.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        $Cmdlet
    )

    $phase      = 'AccessRemoval'
    $actionName = 'Remove Authentication Methods'

    try {
        $user    = Get-MgUser -UserId $Context.TargetUPN -Property Id -ErrorAction Stop
        $uid     = $user.Id
        $methods = @(Get-MgUserAuthenticationMethod -UserId $uid -ErrorAction Stop)

        if ($methods.Count -eq 0) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message 'No authentication methods found — nothing to remove.' `
                -Evidence @{ MethodsFound = 0; Removed = 0; Skipped = 0; Failed = 0 } `
                -ControlObjective 'Remove all registered authentication methods' `
                -RiskMitigated 'Latent re-entry via registered auth method'
        }

        $removed  = [System.Collections.Generic.List[string]]::new()
        $skipped  = [System.Collections.Generic.List[string]]::new()
        $failed   = [System.Collections.Generic.List[string]]::new()
        $warnings = [System.Collections.Generic.List[string]]::new()

        foreach ($method in $methods) {
            $methodType = $method.AdditionalProperties['@odata.type']
            $methodId   = $method.Id

            if ($script:SkippedAuthMethodTypes -contains $methodType) {
                $skipped.Add($methodType)
                $warnings.Add("Auth method type '$methodType' cannot be removed via Graph — manual removal required.")
                continue
            }

            if ($Context.WhatIf) {
                $removed.Add("$methodType [WhatIf]")
                continue
            }

            $deleteOk = _DeleteAuthMethod -UserId $uid -MethodId $methodId -MethodType $methodType

            if ($deleteOk.Success) {
                $removed.Add($methodType)

                Add-DecomEvidenceEvent -Context $Context -Phase $phase `
                    -ActionName "Remove Auth Method: $methodType" `
                    -Status 'Success' -IsCritical $false `
                    -Message "Removed auth method '$methodType' (Id: $methodId)" `
                    -AfterState @{ MethodType = $methodType; MethodId = $methodId; Removed = $true } `
                    -ControlObjective 'Remove registered authentication method' `
                    -RiskMitigated 'Latent re-entry via registered auth method' | Out-Null
            } else {
                $failed.Add("$methodType : $($deleteOk.Error)")
                $warnings.Add("Failed to remove '$methodType': $($deleteOk.Error)")
            }
        }

        $status = if ($failed.Count -gt 0 -and $removed.Count -eq 0) { 'Failed' }
                  elseif ($failed.Count -gt 0) { 'Warning' }
                  else { 'Success' }

        $summary = "Methods found: $($methods.Count) | " +
                   "Removed: $($removed.Count) | " +
                   "Skipped: $($skipped.Count) | " +
                   "Failed: $($failed.Count)"

        if ($Context.WhatIf) { $summary = "[WhatIf] $summary" }

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status $status -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message $summary `
            -Evidence @{
                MethodsFound = $methods.Count
                Removed      = $removed.Count
                Skipped      = $skipped.Count
                Failed       = $failed.Count
                RemovedList  = $removed.ToArray()
                SkippedList  = $skipped.ToArray()
                FailedList   = $failed.ToArray()
            } `
            -WarningMessages $warnings.ToArray() `
            -ControlObjective 'Remove all registered authentication methods' `
            -RiskMitigated 'Latent re-entry via registered auth method'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Failed' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message "Auth method removal failed: $($_.Exception.Message)" `
            -FailureClass 'GraphError' `
            -ControlObjective 'Remove all registered authentication methods' `
            -RiskMitigated 'Latent re-entry via registered auth method'
    }
}

# ── Private helpers ────────────────────────────────────────────────────────────

function _RemoveActiveRoles {
    param([pscustomobject]$Context, [string]$UserId, [string]$Phase)

    $actionName = 'Remove Active Role Assignments'
    $removed    = [System.Collections.Generic.List[string]]::new()
    $failed     = [System.Collections.Generic.List[string]]::new()
    $warnings   = [System.Collections.Generic.List[string]]::new()

    try {
        $assignments = @(Get-MgRoleManagementDirectoryRoleAssignment `
            -Filter "principalId eq '$UserId'" -All -ErrorAction Stop)

        if ($assignments.Count -eq 0) {
            return New-DecomActionResult -ActionName $actionName -Phase $Phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message 'No active role assignments found.' `
                -Evidence @{ AssignmentsFound = 0; Removed = 0; Failed = 0 } `
                -ControlObjective 'Remove active Entra role assignments' `
                -RiskMitigated 'Privileged role access on disabled account'
        }

        foreach ($a in $assignments) {
            $roleName = Resolve-DecomRoleName $a.RoleDefinitionId

            if ($Context.WhatIf) {
                $removed.Add("$roleName [WhatIf]")
                continue
            }

            try {
                Remove-MgRoleManagementDirectoryRoleAssignment `
                    -UnifiedRoleAssignmentId $a.Id -ErrorAction Stop
                $removed.Add($roleName)

                Add-DecomEvidenceEvent -Context $Context -Phase $Phase `
                    -ActionName "Remove Active Role: $roleName" `
                    -Status 'Success' -IsCritical $true `
                    -Message "Removed active role assignment '$roleName' (AssignmentId: $($a.Id))" `
                    -AfterState @{ RoleName = $roleName; AssignmentId = $a.Id; Type = 'Active'; Removed = $true } `
                    -ControlObjective 'Remove active Entra role assignment' `
                    -RiskMitigated 'Privileged role access on disabled account' | Out-Null

            } catch {
                $failed.Add("$roleName : $($_.Exception.Message)")
                $warnings.Add("Failed to remove active role '$roleName': $($_.Exception.Message)")
            }
        }

        $status  = if ($failed.Count -gt 0 -and $removed.Count -eq 0) { 'Failed' }
                   elseif ($failed.Count -gt 0) { 'Warning' }
                   else { 'Success' }
        $summary = "Active assignments found: $($assignments.Count) | Removed: $($removed.Count) | Failed: $($failed.Count)"
        if ($Context.WhatIf) { $summary = "[WhatIf] $summary" }

        return New-DecomActionResult -ActionName $actionName -Phase $Phase `
            -Status $status -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message $summary `
            -Evidence @{
                AssignmentsFound = $assignments.Count
                Removed          = $removed.Count
                Failed           = $failed.Count
                RemovedList      = $removed.ToArray()
                FailedList       = $failed.ToArray()
            } `
            -WarningMessages $warnings.ToArray() `
            -ControlObjective 'Remove active Entra role assignments' `
            -RiskMitigated 'Privileged role access on disabled account'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $Phase `
            -Status 'Failed' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message "Active role removal failed: $($_.Exception.Message)" `
            -FailureClass 'GraphError' `
            -ControlObjective 'Remove active Entra role assignments' `
            -RiskMitigated 'Privileged role access on disabled account'
    }
}

function _RemoveEligibleRoles {
    param([pscustomobject]$Context, [string]$UserId, [string]$Phase)

    $actionName = 'Remove PIM-Eligible Role Assignments'
    $removed    = [System.Collections.Generic.List[string]]::new()
    $failed     = [System.Collections.Generic.List[string]]::new()
    $warnings   = [System.Collections.Generic.List[string]]::new()

    try {
        # PIM eligible schedules — different endpoint from active assignments
        $schedules = @(Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
            -Filter "principalId eq '$UserId'" -All -ErrorAction SilentlyContinue)

        if ($schedules.Count -eq 0) {
            return New-DecomActionResult -ActionName $actionName -Phase $Phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message 'No PIM-eligible role assignments found.' `
                -Evidence @{ SchedulesFound = 0; Removed = 0; Failed = 0 } `
                -ControlObjective 'Remove PIM-eligible role assignments' `
                -RiskMitigated 'Dormant privileged escalation path'
        }

        foreach ($s in $schedules) {
            $roleName = Resolve-DecomRoleName $s.RoleDefinitionId

            if ($Context.WhatIf) {
                $removed.Add("$roleName [WhatIf]")
                continue
            }

            try {
                # PIM eligible removal requires a roleEligibilityScheduleRequest
                # with action = 'adminRemove'
                $body = @{
                    action           = 'adminRemove'
                    principalId      = $UserId
                    roleDefinitionId = $s.RoleDefinitionId
                    directoryScopeId = $s.DirectoryScopeId
                }
                New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest `
                    -BodyParameter $body -ErrorAction Stop | Out-Null

                $removed.Add($roleName)

                Add-DecomEvidenceEvent -Context $Context -Phase $Phase `
                    -ActionName "Remove PIM-Eligible Role: $roleName" `
                    -Status 'Success' -IsCritical $true `
                    -Message "Removed PIM-eligible role '$roleName' (ScheduleId: $($s.Id))" `
                    -AfterState @{ RoleName = $roleName; ScheduleId = $s.Id; Type = 'Eligible'; Removed = $true } `
                    -ControlObjective 'Remove PIM-eligible role assignment' `
                    -RiskMitigated 'Dormant privileged escalation path' | Out-Null

            } catch {
                $failed.Add("$roleName : $($_.Exception.Message)")
                $warnings.Add("Failed to remove PIM-eligible role '$roleName': $($_.Exception.Message)")
            }
        }

        $status  = if ($failed.Count -gt 0 -and $removed.Count -eq 0) { 'Failed' }
                   elseif ($failed.Count -gt 0) { 'Warning' }
                   else { 'Success' }
        $summary = "Eligible schedules found: $($schedules.Count) | Removed: $($removed.Count) | Failed: $($failed.Count)"
        if ($Context.WhatIf) { $summary = "[WhatIf] $summary" }

        return New-DecomActionResult -ActionName $actionName -Phase $Phase `
            -Status $status -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message $summary `
            -Evidence @{
                SchedulesFound = $schedules.Count
                Removed        = $removed.Count
                Failed         = $failed.Count
                RemovedList    = $removed.ToArray()
                FailedList     = $failed.ToArray()
            } `
            -WarningMessages $warnings.ToArray() `
            -ControlObjective 'Remove PIM-eligible role assignments' `
            -RiskMitigated 'Dormant privileged escalation path'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $Phase `
            -Status 'Failed' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "PIM eligible role removal failed: $($_.Exception.Message)" `
            -FailureClass 'GraphError' `
            -WarningMessages @('PIM eligible role removal requires RoleManagement.ReadWrite.Directory scope.') `
            -ControlObjective 'Remove PIM-eligible role assignments' `
            -RiskMitigated 'Dormant privileged escalation path'
    }
}

function _DeleteAuthMethod {
    # Dispatches to the correct type-specific Graph Delete endpoint.
    # Returns @{ Success = [bool]; Error = [string] }
    param([string]$UserId, [string]$MethodId, [string]$MethodType)

    try {
        switch -Wildcard ($MethodType) {
            '*phoneAuthenticationMethod' {
                Remove-MgUserAuthenticationPhoneMethod `
                    -UserId $UserId -PhoneAuthenticationMethodId $MethodId -ErrorAction Stop
            }
            '*microsoftAuthenticatorAuthenticationMethod' {
                Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod `
                    -UserId $UserId -MicrosoftAuthenticatorAuthenticationMethodId $MethodId -ErrorAction Stop
            }
            '*fido2AuthenticationMethod' {
                Remove-MgUserAuthenticationFido2Method `
                    -UserId $UserId -Fido2AuthenticationMethodId $MethodId -ErrorAction Stop
            }
            '*softwareOathAuthenticationMethod' {
                Remove-MgUserAuthenticationSoftwareOathMethod `
                    -UserId $UserId -SoftwareOathAuthenticationMethodId $MethodId -ErrorAction Stop
            }
            '*emailAuthenticationMethod' {
                Remove-MgUserAuthenticationEmailMethod `
                    -UserId $UserId -EmailAuthenticationMethodId $MethodId -ErrorAction Stop
            }
            default {
                return @{ Success = $false; Error = "No Delete handler for method type '$MethodType'" }
            }
        }
        return @{ Success = $true; Error = $null }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

Export-ModuleMember -Function `
    Invoke-DecomAccessRemoval, `
    Remove-DecomGroupMemberships, `
    Remove-DecomRoleAssignments, `
    Remove-DecomAuthMethods
