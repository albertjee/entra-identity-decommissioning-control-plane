# LicenseRemediation.psm1 — License removal
# Premium v2.0
#
# Functions:
#   Get-DecomLicenseState    — snapshot all assigned SKUs before removal
#   Remove-DecomLicenses     — remove all assigned licenses from target UPN
#
# Design:
#   License removal is separated from compliance controls (ComplianceRemediation)
#   because it is an access/entitlement action, not a compliance action.
#
#   SEQUENCING RULE (LOCKED — enforced by BatchOrchestrator):
#   License removal MUST run AFTER Litigation Hold (ComplianceRemediation).
#   Removing Exchange Online Plan 2 before enabling LH causes LH to fail.
#   BatchOrchestrator enforces this order. Do not call out of sequence.
#
#   SNAPSHOT BEFORE REMOVAL:
#   Get-DecomLicenseState is always called before removal to capture a
#   complete before-state for the evidence report. The list of removed
#   SKUs is included in the audit trail so licenses can be reassigned
#   to another user if needed.
#
#   WHAT IS REMOVED:
#   All directly assigned SKUs are removed. Group-based license assignments
#   cannot be removed here — they require the user to be removed from the
#   licensing group (handled by AccessRemoval.psm1 group membership removal).
#   This module logs group-based assignments as informational evidence but
#   does not attempt to remove them.
#
# Required Graph permissions:
#   User.ReadWrite.All
#   Directory.ReadWrite.All
#
# PS7 compatible (v2.0 baseline)

#Requires -Version 7.0

Set-StrictMode -Version Latest

function Get-DecomLicenseState {
    <#
    .SYNOPSIS
        Returns all assigned licenses for the target UPN as a structured object.

    .DESCRIPTION
        Snapshots all directly assigned and group-based SKUs before removal.
        Used to capture before-state for the evidence report and to identify
        which licenses are directly assigned vs group-inherited.

    .PARAMETER Context
        Premium DecomRunContext.

    .OUTPUTS
        [pscustomobject] with DirectAssigned, GroupBased, and Total counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context
    )

    try {
        $user = Get-MgUser -UserId $Context.TargetUPN `
            -Property AssignedLicenses, LicenseAssignmentStates `
            -ErrorAction Stop

        # Separate direct assignments from group-based
        $directSkus = @($user.AssignedLicenses | Where-Object { $_.SkuId })

        $groupBased = @()
        $direct     = @()

        if ($null -ne $user.LicenseAssignmentStates) {
            $groupBased = @($user.LicenseAssignmentStates |
                Where-Object { $_.AssignedByGroup -ne $null } |
                Select-Object -ExpandProperty SkuId)

            $direct = @($user.LicenseAssignmentStates |
                Where-Object { $_.AssignedByGroup -eq $null } |
                Select-Object -ExpandProperty SkuId)
        } else {
            # Fallback — treat all as direct if LicenseAssignmentStates unavailable
            $direct = @($directSkus | Select-Object -ExpandProperty SkuId)
        }

        return [pscustomobject]@{
            DirectAssignedSkuIds  = $direct
            GroupBasedSkuIds      = $groupBased
            AllAssignedSkuIds     = @($directSkus | Select-Object -ExpandProperty SkuId)
            DirectCount           = $direct.Count
            GroupBasedCount       = $groupBased.Count
            TotalCount            = $directSkus.Count
        }
    } catch {
        throw "Get-DecomLicenseState: failed to read licenses for '$($Context.TargetUPN)': $($_.Exception.Message)"
    }
}

function Remove-DecomLicenses {
    <#
    .SYNOPSIS
        Removes all directly assigned licenses from the target UPN.

    .DESCRIPTION
        Removes all directly assigned SKUs via Set-MgUserLicense.
        Group-based license assignments are logged as informational evidence
        but are not removed here — they require group membership removal
        (handled by AccessRemoval.psm1).

        SEQUENCING RULE: Must run AFTER Set-DecomLitigationHold.
        Removing Exchange Online Plan 2 before enabling LH causes LH to fail.
        BatchOrchestrator enforces this order automatically.

        Safe to call when no licenses are assigned — returns Skipped.
        WhatIf-aware: logs intent but does not call Set-MgUserLicense.

    .PARAMETER Context
        Premium DecomRunContext.

    .PARAMETER Cmdlet
        PSCmdlet reference for ShouldProcess support.

    .OUTPUTS
        [pscustomobject] DecomActionResult
        Status values:
          Success — all directly assigned licenses removed
          Warning — some licenses failed to remove (partial removal)
          Skipped — no directly assigned licenses found
          Failed  — removal attempt threw for all licenses

    .EXAMPLE
        Remove-DecomLicenses -Context $ctx
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        $Cmdlet
    )

    $phase      = 'LicenseRemediation'
    $actionName = 'Remove Licenses'

    try {
        $licenseState = Get-DecomLicenseState -Context $Context

        $before = @{
            DirectAssignedSkuIds = $licenseState.DirectAssignedSkuIds
            GroupBasedSkuIds     = $licenseState.GroupBasedSkuIds
            DirectCount          = $licenseState.DirectCount
            GroupBasedCount      = $licenseState.GroupBasedCount
        }

        # Nothing directly assigned — skip cleanly
        if ($licenseState.DirectCount -eq 0) {
            $groupNote = if ($licenseState.GroupBasedCount -gt 0) {
                " Note: $($licenseState.GroupBasedCount) group-based license(s) detected — remove via group membership (AccessRemoval)."
            } else { '' }

            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "No directly assigned licenses found — nothing to remove.$groupNote" `
                -Evidence $before `
                -ControlObjective 'Remove license entitlements to prevent unauthorised service access' `
                -RiskMitigated 'Continued access to licensed services post-offboard'
        }

        # WhatIf — log intent only
        if ($Context.WhatIf) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "[WhatIf] Would remove $($licenseState.DirectCount) directly assigned license(s): $($licenseState.DirectAssignedSkuIds -join ', ')" `
                -BeforeState $before `
                -AfterState  @{ DirectAssignedSkuIds = @(); DirectCount = 0 } `
                -ControlObjective 'Remove license entitlements to prevent unauthorised service access' `
                -RiskMitigated 'Continued access to licensed services post-offboard'
        }

        # Remove all directly assigned SKUs in one Graph call
        Set-MgUserLicense -UserId $Context.TargetUPN `
            -RemoveLicenses $licenseState.DirectAssignedSkuIds `
            -AddLicenses @() `
            -ErrorAction Stop

        # Verify removal
        $postState = Get-DecomLicenseState -Context $Context

        $after = @{
            DirectAssignedSkuIds = $postState.DirectAssignedSkuIds
            DirectCount          = $postState.DirectCount
        }

        # Check for partial removal
        $removed  = $licenseState.DirectCount - $postState.DirectCount
        $remaining = $postState.DirectCount

        if ($remaining -gt 0) {
            $warnMsg = "$removed of $($licenseState.DirectCount) license(s) removed. " +
                       "$remaining remain — may be group-based or removal failed for some SKUs."

            Add-DecomEvidenceEvent -Context $Context -Phase $phase `
                -ActionName $actionName -Status 'Warning' -IsCritical $false `
                -Message $warnMsg -BeforeState $before -AfterState $after `
                -ControlObjective 'Remove license entitlements to prevent unauthorised service access' `
                -RiskMitigated 'Continued access to licensed services post-offboard' | Out-Null

            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Warning' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message $warnMsg -BeforeState $before -AfterState $after `
                -ControlObjective 'Remove license entitlements to prevent unauthorised service access' `
                -RiskMitigated 'Continued access to licensed services post-offboard'
        }

        $groupNote = if ($licenseState.GroupBasedCount -gt 0) {
            " Note: $($licenseState.GroupBasedCount) group-based license(s) not removed — remove via group membership."
        } else { '' }

        Add-DecomEvidenceEvent -Context $Context -Phase $phase `
            -ActionName $actionName -Status 'Success' -IsCritical $false `
            -Message "Removed $removed directly assigned license(s).$groupNote" `
            -BeforeState $before -AfterState $after `
            -ControlObjective 'Remove license entitlements to prevent unauthorised service access' `
            -RiskMitigated 'Continued access to licensed services post-offboard' | Out-Null

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "Removed $removed directly assigned license(s) from '$($Context.TargetUPN)'.$groupNote" `
            -BeforeState $before -AfterState $after `
            -ControlObjective 'Remove license entitlements to prevent unauthorised service access' `
            -RiskMitigated 'Continued access to licensed services post-offboard'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Failed' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "License removal failed for '$($Context.TargetUPN)': $($_.Exception.Message)" `
            -FailureClass 'GraphError' `
            -ControlObjective 'Remove license entitlements to prevent unauthorised service access' `
            -RiskMitigated 'Continued access to licensed services post-offboard'
    }
}

Export-ModuleMember -Function `
    Get-DecomLicenseState, `
    Remove-DecomLicenses
