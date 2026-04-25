# Validation.psm1 — Target UPN validation and baseline state collection
# v1.2: Guest/external account warning guard added.
#        UserType=Guest surfaces a ManualFollowUp item — no mailbox or direct licenses expected.

function Get-DecomBaselineState {
    [CmdletBinding()]
    param([pscustomobject]$Context)
    try {
        $u = Get-MgUser -UserId $Context.TargetUPN -Property Id, UserPrincipalName, DisplayName, AccountEnabled, UserType, AssignedLicenses
        if (-not $u) { throw 'Target UPN not found.' }

        $mailbox      = $null
        $mailboxExists = $false
        try { $mailbox = Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop; $mailboxExists = $true } catch {}

        $licenses = @(Get-MgUserLicenseDetail -UserId $u.Id -ErrorAction SilentlyContinue)

        $warnings      = @()
        $manualFollowUp = @()

        # Guest account guard — spec requirement: validate target correctly, warn on guest
        if ($u.UserType -eq 'Guest') {
            $warnings       += 'Target account is a Guest (external user). Mailbox and direct licenses are typically absent. Verify B2B access paths manually.'
            $manualFollowUp += 'Review cross-tenant B2B access and any resource permissions granted to this guest account before proceeding.'
        }

        $ev = @{
            UserId                  = $u.Id
            DisplayName             = $u.DisplayName
            AccountEnabled          = $u.AccountEnabled
            UserType                = $u.UserType
            MailboxExists           = $mailboxExists
            MailboxType             = if ($mailbox) { $mailbox.RecipientTypeDetails } else { $null }
            DirectAssignedLicenseCount = @($u.AssignedLicenses).Count
            LicenseSkuPartNumbers   = @($licenses | ForEach-Object { $_.SkuPartNumber })
        }

        $status = if ($warnings.Count -gt 0) { 'Warning' } else { 'Success' }

        $r = New-DecomActionResult -ActionName 'Validate Target UPN' -Phase 'Validation' -Status $status `
            -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Target UPN validated.' `
            -Evidence $ev -WarningMessages $warnings -ManualFollowUp $manualFollowUp `
            -ControlObjective 'Validate target identity before control-plane mutation' `
            -RiskMitigated 'Wrong-user decommissioning'

        Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName `
            -Status $r.Status -IsCritical $r.IsCritical -Message $r.Message -Evidence $ev `
            -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
        return $r

    } catch {
        return New-DecomActionResult -ActionName 'Validate Target UPN' -Phase 'Validation' -Status 'Failed' `
            -IsCritical $true -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
            -BlockerMessages @('Target validation failed. Verify UPN, permissions, and account state.') `
            -FailureClass 'Critical'
    }
}

Export-ModuleMember -Function Get-DecomBaselineState
