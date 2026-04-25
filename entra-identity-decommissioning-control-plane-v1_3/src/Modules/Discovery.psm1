# Discovery.psm1 — Identity snapshot and access discovery
# v1.2: Mailbox forwarding/delegation review added (spec requirement — was missing in v1.1).
#        MFA authentication methods added to snapshot (Lite-appropriate discovery).
#        PIM eligible role collection retained from v1.1.
#        Resolve-DecomRoleName helper retained.

function Resolve-DecomRoleName {
    param([string]$RoleDefinitionId)
    try {
        $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $RoleDefinitionId -ErrorAction Stop
        if ($rd.DisplayName) { return $rd.DisplayName }
    } catch {}
    return $RoleDefinitionId
}

function Get-DecomIdentitySnapshot {
    [CmdletBinding()]
    param(
        [pscustomobject]$Context,
        [ValidateSet('Before','After')]
        [string]$SnapshotName = 'Before'
    )
    try {
        $u = Get-MgUser -UserId $Context.TargetUPN -Property Id, UserPrincipalName, DisplayName, AccountEnabled, UserType

        # Group memberships
        $groups = @(Get-MgUserMemberOf -UserId $u.Id -All -ErrorAction SilentlyContinue |
            Where-Object { $_.AdditionalProperties['@odata.type'] -match 'group' } |
            ForEach-Object { $_.AdditionalProperties['displayName'] })

        # Active privileged role assignments
        $active = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction SilentlyContinue |
            Where-Object { $_.PrincipalId -eq $u.Id })

        # PIM eligible role assignments
        $eligible = @()
        try {
            $eligible = @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction SilentlyContinue |
                Where-Object { $_.PrincipalId -eq $u.Id })
        } catch {
            Write-DecomConsole -Level 'WARN' -Message "PIM eligible role query failed: $($_.Exception.Message)"
        }

        # Resolve role display names and tag assignment type
        $roles = @()
        foreach ($a in $active) {
            $roles += [pscustomobject]@{
                RoleName         = Resolve-DecomRoleName $a.RoleDefinitionId
                AssignmentType   = 'Active'
                RoleDefinitionId = $a.RoleDefinitionId
                DirectoryScopeId = $a.DirectoryScopeId
            }
        }
        foreach ($a in $eligible) {
            $roles += [pscustomobject]@{
                RoleName         = Resolve-DecomRoleName $a.RoleDefinitionId
                AssignmentType   = 'Eligible'
                RoleDefinitionId = $a.RoleDefinitionId
                DirectoryScopeId = $a.DirectoryScopeId
            }
        }

        # Owned objects
        $owned = @(Get-MgUserOwnedObject -UserId $u.Id -All -ErrorAction SilentlyContinue)
        $ownedTypes = @($owned | ForEach-Object { $_.AdditionalProperties['@odata.type'] })

        # App role assignments and OAuth grants
        $appRoles   = @()
        $oauthGrants = @()
        try { $appRoles   = @(Get-MgUserAppRoleAssignment -UserId $u.Id -All -ErrorAction SilentlyContinue | Select-Object ResourceDisplayName, AppRoleId, PrincipalDisplayName) } catch {}
        try { $oauthGrants = @(Get-MgUserOauth2PermissionGrant -UserId $u.Id -All -ErrorAction SilentlyContinue | Select-Object ClientId, ConsentType, Scope) } catch {}

        # Mailbox forwarding and delegation — spec requirement (was missing in v1.1)
        $mailboxDetail = $null
        $manualFollowUp = @()
        try {
            $mbx = Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop |
                Select-Object RecipientTypeDetails, ForwardingSmtpAddress, ForwardingAddress,
                              DeliverToMailboxAndForward, GrantSendOnBehalfTo,
                              ArchiveStatus, LitigationHoldEnabled
            $mailboxDetail = $mbx

            if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) {
                $manualFollowUp += "Mailbox forwarding is active. Review and disable: ForwardingSmtpAddress=$($mbx.ForwardingSmtpAddress) ForwardingAddress=$($mbx.ForwardingAddress)"
            }
            if (@($mbx.GrantSendOnBehalfTo).Count -gt 0) {
                $manualFollowUp += "Send-on-behalf delegation detected ($(@($mbx.GrantSendOnBehalfTo).Count) delegates). Review and remove as appropriate."
            }
        } catch {}

        # MFA authentication methods
        $mfaMethods = @()
        try {
            $mfaMethods = @(Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction SilentlyContinue |
                ForEach-Object { $_.AdditionalProperties['@odata.type'] })
            if ($mfaMethods.Count -gt 0) {
                $manualFollowUp += "Registered MFA methods detected ($($mfaMethods.Count)). Review and remove authenticator registrations post-decommission if account will not be reused."
            }
        } catch {
            Write-DecomConsole -Level 'WARN' -Message "MFA method query failed: $($_.Exception.Message)"
        }

        $ev = @{
            GroupCount              = $groups.Count
            ActiveRoleCount         = @($active).Count
            EligibleRoleCount       = @($eligible).Count
            RoleCount               = @($roles).Count
            OwnedObjectCount        = $ownedTypes.Count
            AppRoleAssignmentCount  = @($appRoles).Count
            OAuthGrantCount         = @($oauthGrants).Count
            MfaMethodCount          = $mfaMethods.Count
            ForwardingActive        = ($null -ne $mailboxDetail -and ($mailboxDetail.ForwardingSmtpAddress -or $mailboxDetail.ForwardingAddress))
            DelegationCount         = if ($mailboxDetail) { @($mailboxDetail.GrantSendOnBehalfTo).Count } else { 0 }
        }

        $snapshot = [pscustomobject]@{
            Snapshot            = $SnapshotName
            UserId              = $u.Id
            UPN                 = $u.UserPrincipalName
            DisplayName         = $u.DisplayName
            AccountEnabled      = $u.AccountEnabled
            UserType            = $u.UserType
            GroupMemberships    = $groups
            PrivilegedRoles     = $roles
            OwnedObjectTypes    = $ownedTypes
            AppRoleAssignments  = $appRoles
            OAuthGrants         = $oauthGrants
            MfaMethods          = $mfaMethods
            Mailbox             = $mailboxDetail
        }

        $r = New-DecomActionResult -ActionName "Collect $SnapshotName Identity Snapshot" `
            -Phase "$($SnapshotName)ActionSnapshot" -Status 'Success' -IsCritical $false `
            -TargetUPN $Context.TargetUPN -Message "$SnapshotName identity snapshot collected." `
            -Evidence $ev -AfterState @{ Snapshot = $SnapshotName } `
            -ManualFollowUp $manualFollowUp `
            -ControlObjective 'Capture identity blast-radius evidence' `
            -RiskMitigated 'Unprovable revocation state'

        Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName `
            -Status $r.Status -IsCritical $r.IsCritical -Message $r.Message `
            -Evidence $ev -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
        return $r

    } catch {
        return New-DecomActionResult -ActionName "Collect $SnapshotName Identity Snapshot" `
            -Phase "$($SnapshotName)ActionSnapshot" -Status 'Warning' -IsCritical $false `
            -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
            -WarningMessages @('Snapshot collection incomplete.') -FailureClass 'Recoverable'
    }
}

Export-ModuleMember -Function Get-DecomIdentitySnapshot, Resolve-DecomRoleName
