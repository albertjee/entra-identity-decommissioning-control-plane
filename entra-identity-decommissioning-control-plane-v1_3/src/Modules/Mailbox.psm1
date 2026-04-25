# Mailbox.psm1 — Mailbox continuity actions
# v1.2: No changes from v1.1 — WhatIf guard via ShouldProcess is correct here
#        as Mailbox functions are not in the containment critical path.

function Convert-DecomMailboxToShared {
    param([pscustomobject]$Context, $Cmdlet)
    if ($Context.WhatIf) { return New-DecomSkippedBecauseWhatIf -ActionName 'Convert Mailbox To Shared' -Phase 'Mailbox' -TargetUPN $Context.TargetUPN -RecommendedNext 'Set auto reply' }
    if ($Cmdlet.ShouldProcess($Context.TargetUPN, 'Convert mailbox to shared')) {
        try {
            $before = Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop |
                Select-Object RecipientTypeDetails, ArchiveStatus, LitigationHoldEnabled
            if ($before.RecipientTypeDetails -eq 'SharedMailbox') {
                $msg = 'Mailbox is already shared.'
            } else {
                Set-Mailbox -Identity $Context.TargetUPN -Type Shared
                $msg = 'Mailbox converted to shared.'
            }
            $after = Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop |
                Select-Object RecipientTypeDetails, ArchiveStatus, LitigationHoldEnabled
            $r = New-DecomActionResult -ActionName 'Convert Mailbox To Shared' -Phase 'Mailbox' -Status 'Success' `
                -IsCritical $true -TargetUPN $Context.TargetUPN -Message $msg `
                -BeforeState @{ RecipientTypeDetails = $before.RecipientTypeDetails } `
                -AfterState  @{ RecipientTypeDetails = $after.RecipientTypeDetails } `
                -Evidence @{ ConvertedOrAlreadyShared = ($after.RecipientTypeDetails -eq 'SharedMailbox') } `
                -ControlObjective 'Preserve mailbox continuity before license mutation' `
                -RiskMitigated 'Mailbox loss or access disruption'
            Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName `
                -Status $r.Status -IsCritical $true -Message $r.Message `
                -BeforeState @{ RecipientTypeDetails = $before.RecipientTypeDetails } `
                -AfterState  @{ RecipientTypeDetails = $after.RecipientTypeDetails } `
                -Evidence $r.Evidence -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
            return $r
        } catch {
            return New-DecomActionResult -ActionName 'Convert Mailbox To Shared' -Phase 'Mailbox' -Status 'Failed' `
                -IsCritical $true -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
                -BlockerMessages @('Mailbox conversion failed.') -FailureClass 'Critical'
        }
    } else {
        return New-DecomSkippedBecauseWhatIf -ActionName 'Convert Mailbox To Shared' -Phase 'Mailbox' -TargetUPN $Context.TargetUPN -RecommendedNext 'Set auto reply'
    }
}

function Set-DecomAutoReply {
    param([pscustomobject]$Context, [string]$Message, $Cmdlet)
    if ([string]::IsNullOrWhiteSpace($Message)) {
        return New-DecomActionResult -ActionName 'Set Out-of-Office' -Phase 'Mailbox' -Status 'Skipped' `
            -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'No out-of-office message provided.' `
            -ManualFollowUp @('Set mailbox auto-reply manually if required for business continuity.') `
            -RecommendedNext 'Continue to compliance phase'
    }
    if ($Context.WhatIf) { return New-DecomSkippedBecauseWhatIf -ActionName 'Set Out-of-Office' -Phase 'Mailbox' -TargetUPN $Context.TargetUPN -RecommendedNext 'Compliance phase' }
    if ($Cmdlet.ShouldProcess($Context.TargetUPN, 'Set mailbox auto-reply')) {
        try {
            Set-MailboxAutoReplyConfiguration -Identity $Context.TargetUPN -AutoReplyState Enabled `
                -InternalMessage $Message -ExternalMessage $Message -ExternalAudience All
            $r = New-DecomActionResult -ActionName 'Set Out-of-Office' -Phase 'Mailbox' -Status 'Success' `
                -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'Auto reply configured.' `
                -Evidence @{ AutoReplyConfigured = $true; MessageLength = $Message.Length } `
                -ControlObjective 'Preserve business communication continuity' -RiskMitigated 'Orphaned inbound communication'
            Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName `
                -Status $r.Status -IsCritical $false -Message $r.Message -Evidence $r.Evidence `
                -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
            return $r
        } catch {
            return New-DecomActionResult -ActionName 'Set Out-of-Office' -Phase 'Mailbox' -Status 'Warning' `
                -IsCritical $false -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
                -WarningMessages @('Failed to configure auto reply.') -FailureClass 'Recoverable' `
                -ManualFollowUp @('Set mailbox auto-reply manually.')
        }
    } else {
        return New-DecomSkippedBecauseWhatIf -ActionName 'Set Out-of-Office' -Phase 'Mailbox' -TargetUPN $Context.TargetUPN -RecommendedNext 'Compliance phase'
    }
}

Export-ModuleMember -Function Convert-DecomMailboxToShared, Set-DecomAutoReply
