function Get-DecomBaselineState {
    [CmdletBinding()]
    param([pscustomobject]$Context)
    try {
        $User=Get-MgUser -UserId $Context.TargetUPN -Property Id,UserPrincipalName,DisplayName,AccountEnabled,UserType,AssignedLicenses
        if(-not $User){ throw 'Target UPN not found.' }
        $Mailbox=$null; $MailboxExists=$false
        try { $Mailbox=Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop; $MailboxExists=$true } catch {}
        $Licenses=Get-MgUserLicenseDetail -UserId $User.Id -ErrorAction SilentlyContinue
        $ev=@{UserId=$User.Id; DisplayName=$User.DisplayName; AccountEnabled=$User.AccountEnabled; UserType=$User.UserType; MailboxExists=$MailboxExists; MailboxType=$(if($Mailbox){$Mailbox.RecipientTypeDetails}else{$null}); LicenseCount=@($Licenses).Count; SkuPartNumbers=@($Licenses|ForEach-Object {$_.SkuPartNumber})}
        $r=New-DecomActionResult -ActionName 'Validate Target UPN' -Phase 'Validation' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Target UPN validated.' -Evidence $ev -ControlObjective 'Validate target identity before control-plane mutation' -RiskMitigated 'Wrong-user decommissioning'
        Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status -IsCritical $r.IsCritical -Message $r.Message -Evidence $ev | Out-Null; $r
    } catch { $r=New-DecomActionResult -ActionName 'Validate Target UPN' -Phase 'Validation' -Status 'Failed' -IsCritical $true -TargetUPN $Context.TargetUPN -Message $_.Exception.Message -BlockerMessages @('Target validation failed.') -RecommendedNext 'Verify UPN, permissions, and target state'; Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status -IsCritical $true -Message $r.Message -ErrorRecord $_ | Out-Null; $r }
}
Export-ModuleMember -Function Get-DecomBaselineState
