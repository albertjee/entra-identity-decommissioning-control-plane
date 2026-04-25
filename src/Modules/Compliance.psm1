# Compliance.psm1 — Compliance state and Litigation Hold
# v1.2: ManualFollowUp populated for archive and hold conditions.

function Enable-DecomLitigationHold {
    param([pscustomobject]$Context, $Cmdlet)
    if ($Context.WhatIf) { return New-DecomSkippedBecauseWhatIf -ActionName 'Enable Litigation Hold' -Phase 'Compliance' -TargetUPN $Context.TargetUPN -RecommendedNext 'License readiness' }
    if ($Cmdlet.ShouldProcess($Context.TargetUPN, 'Enable Litigation Hold')) {
        try {
            $before = Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop |
                Select-Object LitigationHoldEnabled, LitigationHoldDuration, ArchiveStatus
            if ($before.LitigationHoldEnabled -ne $true) {
                Set-Mailbox -Identity $Context.TargetUPN -LitigationHoldEnabled $true
            }
            $after = Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop |
                Select-Object LitigationHoldEnabled, LitigationHoldDuration, ArchiveStatus
            $r = New-DecomActionResult -ActionName 'Enable Litigation Hold' -Phase 'Compliance' -Status 'Success' `
                -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Litigation Hold enabled or already present.' `
                -BeforeState @{ LitigationHoldEnabled = $before.LitigationHoldEnabled } `
                -AfterState  @{ LitigationHoldEnabled = $after.LitigationHoldEnabled } `
                -Evidence @{ LitigationHoldEnabled = $after.LitigationHoldEnabled } `
                -ControlObjective 'Preserve regulated mailbox evidence' `
                -RiskMitigated 'Data loss before retention requirements satisfied'
            Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName `
                -Status $r.Status -IsCritical $true -Message $r.Message `
                -BeforeState @{ LitigationHoldEnabled = $before.LitigationHoldEnabled } `
                -AfterState  @{ LitigationHoldEnabled = $after.LitigationHoldEnabled } `
                -Evidence $r.Evidence -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
            return $r
        } catch {
            return New-DecomActionResult -ActionName 'Enable Litigation Hold' -Phase 'Compliance' -Status 'Failed' `
                -IsCritical $true -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
                -BlockerMessages @('Failed to enable Litigation Hold.') -FailureClass 'Critical'
        }
    } else {
        return New-DecomSkippedBecauseWhatIf -ActionName 'Enable Litigation Hold' -Phase 'Compliance' -TargetUPN $Context.TargetUPN -RecommendedNext 'License readiness'
    }
}

function Get-DecomComplianceState {
    param([pscustomobject]$Context)
    try {
        $mbx = Get-EXOMailbox -Identity $Context.TargetUPN -ErrorAction Stop |
            Select-Object LitigationHoldEnabled, InPlaceHolds, RetentionHoldEnabled,
                          ArchiveStatus, RecipientTypeDetails, ComplianceTagHoldApplied
        $warnings       = @()
        $manualFollowUp = @()
        if ($mbx.ArchiveStatus -and $mbx.ArchiveStatus -ne 'None') {
            $warnings       += 'Archive mailbox exists; tenant-specific validation required before license removal.'
            $manualFollowUp += 'Validate archive mailbox retention requirements before removing Exchange Online license.'
        }
        if (@($mbx.InPlaceHolds).Count -gt 0) {
            $warnings       += 'In-place or Purview-originated hold indicators detected.'
            $manualFollowUp += 'Review Purview/eDiscovery holds before modifying mailbox or removing licenses.'
        }
        $ev = @{
            LitigationHoldEnabled    = $mbx.LitigationHoldEnabled
            InPlaceHoldCount         = @($mbx.InPlaceHolds).Count
            RetentionHoldEnabled     = $mbx.RetentionHoldEnabled
            ArchiveStatus            = $mbx.ArchiveStatus
            ComplianceTagHoldApplied = $mbx.ComplianceTagHoldApplied
            RecipientTypeDetails     = $mbx.RecipientTypeDetails
        }
        $status = if ($warnings.Count -gt 0) { 'Warning' } else { 'Success' }
        $r = New-DecomActionResult -ActionName 'Evaluate Compliance State' -Phase 'Compliance' -Status $status `
            -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'Compliance state evaluated.' `
            -Evidence $ev -WarningMessages $warnings -ManualFollowUp $manualFollowUp `
            -ControlObjective 'Identify compliance blockers before license mutation' `
            -RiskMitigated 'Premature license removal under retention or hold conditions'
        Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName `
            -Status $r.Status -IsCritical $false -Message $r.Message -Evidence $ev `
            -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
        return $r
    } catch {
        return New-DecomActionResult -ActionName 'Evaluate Compliance State' -Phase 'Compliance' -Status 'Warning' `
            -IsCritical $false -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
            -WarningMessages @('Unable to fully evaluate compliance state.') -FailureClass 'Recoverable' `
            -ManualFollowUp @('Manually verify Litigation Hold, archive, and Purview hold status.')
    }
}

Export-ModuleMember -Function Enable-DecomLitigationHold, Get-DecomComplianceState
