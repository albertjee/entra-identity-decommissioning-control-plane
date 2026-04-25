function Get-DecomIdentitySnapshot {
    [CmdletBinding()]
    param([pscustomobject]$Context,[ValidateSet('Before','After')][string]$SnapshotName)
    try {
        $User=Get-MgUser -UserId $Context.TargetUPN -Property Id,UserPrincipalName,DisplayName,AccountEnabled,UserType
        $MemberOf=@(Get-MgUserMemberOf -UserId $User.Id -All -ErrorAction SilentlyContinue)
        $Groups=@($MemberOf|Where-Object {$_.AdditionalProperties['@odata.type'] -match 'group'}|ForEach-Object {$_.AdditionalProperties['displayName']})
        $Owned=@(Get-MgUserOwnedObject -UserId $User.Id -All -ErrorAction SilentlyContinue)
        $OwnedTypes=@($Owned|ForEach-Object {$_.AdditionalProperties['@odata.type']})
        $Assignments=@(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction SilentlyContinue|Where-Object {$_.PrincipalId -eq $User.Id})
        $Roles=foreach($a in $Assignments){$name=$a.RoleDefinitionId; try{$rd=Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $a.RoleDefinitionId -ErrorAction Stop; if($rd.DisplayName){$name=$rd.DisplayName}}catch{}; [pscustomobject]@{RoleName=$name;RoleDefinitionId=$a.RoleDefinitionId;DirectoryScopeId=$a.DirectoryScopeId;AppScopeId=$a.AppScopeId}}
        $Mailbox=$null; try{$Mailbox=Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop}catch{}
        $AppRoleAssignments=@(); try{$AppRoleAssignments=@(Get-MgUserAppRoleAssignment -UserId $User.Id -All -ErrorAction SilentlyContinue|Select-Object ResourceDisplayName,AppRoleId,PrincipalDisplayName)}catch{}
        $OauthGrants=@(); try{$OauthGrants=@(Get-MgUserOauth2PermissionGrant -UserId $User.Id -All -ErrorAction SilentlyContinue|Select-Object ClientId,ConsentType,Scope)}catch{}
        $Snapshot=[pscustomobject]@{Snapshot=$SnapshotName; UserId=$User.Id; UPN=$User.UserPrincipalName; DisplayName=$User.DisplayName; AccountEnabled=$User.AccountEnabled; UserType=$User.UserType; GroupMemberships=$Groups; PrivilegedRoles=$Roles; OwnedObjectTypes=$OwnedTypes; Mailbox=$(if($Mailbox){[pscustomobject]@{RecipientTypeDetails=$Mailbox.RecipientTypeDetails; ForwardingSmtpAddress=$Mailbox.ForwardingSmtpAddress; GrantSendOnBehalfTo=$Mailbox.GrantSendOnBehalfTo; ArchiveStatus=$Mailbox.ArchiveStatus; LitigationHoldEnabled=$Mailbox.LitigationHoldEnabled}}else{$null}); AppRoleAssignments=$AppRoleAssignments; OAuthGrants=$OauthGrants}
        $r=New-DecomActionResult -ActionName "Collect $SnapshotName Identity Snapshot" -Phase "$SnapshotName`ActionSnapshot" -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN -Message "$SnapshotName identity snapshot collected." -Evidence @{GroupCount=$Groups.Count; RoleCount=@($Roles).Count; OwnedObjectCount=$OwnedTypes.Count; AppRoleAssignmentCount=@($AppRoleAssignments).Count; OAuthGrantCount=@($OauthGrants).Count} -AfterState $Snapshot -ControlObjective 'Capture identity blast-radius evidence' -RiskMitigated 'Unprovable revocation state'
        Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status -IsCritical $r.IsCritical -Message $r.Message -AfterState $Snapshot -Evidence $r.Evidence -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null; $r
    } catch { $r=New-DecomActionResult -ActionName "Collect $SnapshotName Identity Snapshot" -Phase "$SnapshotName`ActionSnapshot" -Status 'Warning' -IsCritical $false -TargetUPN $Context.TargetUPN -Message $_.Exception.Message -WarningMessages @('Snapshot collection incomplete.'); Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status -IsCritical $false -Message $r.Message -ErrorRecord $_ | Out-Null; $r }
}
Export-ModuleMember -Function Get-DecomIdentitySnapshot
