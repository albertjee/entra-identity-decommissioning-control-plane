# Discovery.psm1 — Identity snapshot and access discovery
# v1.4: Full mailbox delegation added — FullAccess and SendAs permissions
#        captured alongside existing SendOnBehalf (GrantSendOnBehalfTo).
#        Phase name aligned: snapshot phase is now consistently
#        'PreActionSnapshot' / 'PostActionSnapshot' matching workflow phase names.

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
    # v1.4: Phase name aligned with workflow phase names
    $phaseName = if ($SnapshotName -eq 'Before') { 'PreActionSnapshot' } else { 'PostActionSnapshot' }

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
        $owned     = @(Get-MgUserOwnedObject -UserId $u.Id -All -ErrorAction SilentlyContinue)
        $ownedTypes = @($owned | ForEach-Object { $_.AdditionalProperties['@odata.type'] })

        # App role assignments and OAuth grants
        $appRoles    = @()
        $oauthGrants = @()
        try { $appRoles    = @(Get-MgUserAppRoleAssignment -UserId $u.Id -All -ErrorAction SilentlyContinue | Select-Object ResourceDisplayName, AppRoleId, PrincipalDisplayName) } catch {}
        try { $oauthGrants = @(Get-MgUserOauth2PermissionGrant -UserId $u.Id -All -ErrorAction SilentlyContinue | Select-Object ClientId, ConsentType, Scope) } catch {}

        # Mailbox detail — forwarding, SendOnBehalf, FullAccess, SendAs
        $mailboxDetail  = $null
        $manualFollowUp = @()
        $fullAccessCount = 0
        $sendAsCount     = 0

        try {
            $mbx = Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop |
                Select-Object RecipientTypeDetails, ForwardingSmtpAddress, ForwardingAddress,
                              DeliverToMailboxAndForward, GrantSendOnBehalfTo,
                              ArchiveStatus, LitigationHoldEnabled

            # v1.4: FullAccess permissions
            try {
                $fullAccess = @(Get-MailboxPermission -Identity $Context.TargetUPN -ErrorAction SilentlyContinue |
                    Where-Object { $_.AccessRights -contains 'FullAccess' -and -not $_.IsInherited -and $_.User -ne 'NT AUTHORITY\SELF' })
                $fullAccessCount = $fullAccess.Count
                if ($fullAccessCount -gt 0) {
                    $manualFollowUp += "FullAccess delegation detected ($fullAccessCount delegate(s)). Review and remove as appropriate."
                }
            } catch {}

            # v1.4: SendAs permissions
            try {
                $sendAs = @(Get-RecipientPermission -Identity $Context.TargetUPN -ErrorAction SilentlyContinue |
                    Where-Object { $_.AccessRights -contains 'SendAs' -and $_.Trustee -ne 'NT AUTHORITY\SELF' })
                $sendAsCount = $sendAs.Count
                if ($sendAsCount -gt 0) {
                    $manualFollowUp += "SendAs delegation detected ($sendAsCount delegate(s)). Review and remove as appropriate."
                }
            } catch {}

            $mailboxDetail = $mbx

            if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) {
                $manualFollowUp += "Mailbox forwarding is active. Review and disable: ForwardingSmtpAddress=$($mbx.ForwardingSmtpAddress) ForwardingAddress=$($mbx.ForwardingAddress)"
            }
            if (@($mbx.GrantSendOnBehalfTo).Count -gt 0) {
                $manualFollowUp += "SendOnBehalf delegation detected ($(@($mbx.GrantSendOnBehalfTo).Count) delegate(s)). Review and remove as appropriate."
            }
        } catch {}

        # MFA authentication methods
        $mfaMethods = @()
        try {
            $mfaMethods = @(Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction SilentlyContinue |
                ForEach-Object { $_.AdditionalProperties['@odata.type'] })
            if ($mfaMethods.Count -gt 0) {
                $manualFollowUp += "Registered MFA methods detected ($($mfaMethods.Count)). Review and remove authenticator registrations post-decommission."
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
            SendOnBehalfCount       = if ($mailboxDetail) { @($mailboxDetail.GrantSendOnBehalfTo).Count } else { 0 }
            FullAccessCount         = $fullAccessCount
            SendAsCount             = $sendAsCount
        }

        $r = New-DecomActionResult -ActionName "Collect $SnapshotName Identity Snapshot" `
            -Phase $phaseName -Status 'Success' -IsCritical $false `
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
            -Phase $phaseName -Status 'Warning' -IsCritical $false `
            -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
            -WarningMessages @('Snapshot collection incomplete.') -FailureClass 'Recoverable'
    }
}

Export-ModuleMember -Function Get-DecomIdentitySnapshot, Resolve-DecomRoleName
