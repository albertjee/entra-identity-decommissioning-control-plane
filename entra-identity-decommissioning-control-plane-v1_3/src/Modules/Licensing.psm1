# Licensing.psm1 — License inspection, readiness gate, and guarded removal
# v1.3: Expanded into readable blocks (was dense/minified in v1.1/v1.2 — readability fix).
#        Logic unchanged from v1.2.

function Get-DecomLicensePartition {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    # Get the user object with direct license assignments
    $u = Get-MgUser -UserId $Context.TargetUPN -Property Id, AssignedLicenses

    # Direct assignments are on the user object itself
    $directSkuIds = @($u.AssignedLicenses | ForEach-Object { $_.SkuId })

    # Resolved license detail (includes group-inherited)
    $details   = @(Get-MgUserLicenseDetail -UserId $u.Id -ErrorAction SilentlyContinue)
    $allSkuIds = @($details | ForEach-Object { $_.SkuId })

    # Group-based = in resolved detail but not in direct assignments
    $groupSkuIds = @($allSkuIds | Where-Object { $_ -notin $directSkuIds })

    return [pscustomobject]@{
        UserId           = $u.Id
        DirectSkuIds     = $directSkuIds
        GroupBasedSkuIds = $groupSkuIds
        AllSkuIds        = $allSkuIds
    }
}

function Test-DecomLicenseRemovalReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][pscustomobject]$Context
    )
    $blockers = @()

    try {
        $p = Get-DecomLicensePartition -Context $Context

        # Blocker: group-based licenses detected
        if (@($p.GroupBasedSkuIds).Count -gt 0) {
            $blockers += "Group-based license assignments detected ($(@($p.GroupBasedSkuIds).Count) SKU(s)). " +
                         "Remove via group membership before running Remove-DecomLicenses."
        }

        # Blocker: mailbox conversion must be complete first
        $mailboxResult = $Results |
            Where-Object { $_.ActionName -eq 'Convert Mailbox To Shared' } |
            Select-Object -Last 1
        if (-not $mailboxResult -or $mailboxResult.Status -ne 'Success') {
            $blockers += 'Mailbox must be converted to shared before license removal.'
        }

        $ev = @{
            DirectLicenseCount     = @($p.DirectSkuIds).Count
            GroupBasedLicenseCount = @($p.GroupBasedSkuIds).Count
            BlockerCount           = $blockers.Count
        }

        if ($blockers.Count -gt 0) {
            return New-DecomActionResult `
                -ActionName      'Check License Removal Readiness' `
                -Phase           'Licensing' `
                -Status          'Blocked' `
                -IsCritical      $true `
                -TargetUPN       $Context.TargetUPN `
                -Message         'License removal blocked by governance prerequisites.' `
                -BlockerMessages $blockers `
                -Evidence        $ev `
                -FailureClass    'Blocked' `
                -ControlObjective 'Prevent unsafe service-plan removal' `
                -RiskMitigated   'Mailbox or compliance data loss from premature license removal'
        }

        return New-DecomActionResult `
            -ActionName      'Check License Removal Readiness' `
            -Phase           'Licensing' `
            -Status          'Success' `
            -IsCritical      $true `
            -TargetUPN       $Context.TargetUPN `
            -Message         'License removal prerequisites satisfied.' `
            -Evidence        $ev `
            -RecommendedNext 'Remove licenses if approved' `
            -ControlObjective 'Prevent unsafe service-plan removal' `
            -RiskMitigated   'Mailbox or compliance data loss from premature license removal'

    } catch {
        return New-DecomActionResult `
            -ActionName   'Check License Removal Readiness' `
            -Phase        'Licensing' `
            -Status       'Failed' `
            -IsCritical   $true `
            -TargetUPN    $Context.TargetUPN `
            -Message      $_.Exception.Message `
            -FailureClass 'Critical'
    }
}

function Remove-DecomLicenses {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [System.Management.Automation.PSCmdlet]$Cmdlet
    )

    # WhatIf guard first
    if ($Context.WhatIf) {
        return New-DecomSkippedBecauseWhatIf `
            -ActionName      'Remove Licenses' `
            -Phase           'Licensing' `
            -TargetUPN       $Context.TargetUPN `
            -RecommendedNext 'Proceed to post-action snapshot'
    }

    $p = Get-DecomLicensePartition -Context $Context

    # Hard block on group-based licenses — Set-MgUserLicense cannot remove these
    if (@($p.GroupBasedSkuIds).Count -gt 0) {
        return New-DecomActionResult `
            -ActionName      'Remove Licenses' `
            -Phase           'Licensing' `
            -Status          'Blocked' `
            -IsCritical      $true `
            -TargetUPN       $Context.TargetUPN `
            -Message         'Group-based licensing detected; direct removal blocked.' `
            -BlockerMessages @('Remove licensing group membership first, then re-run.') `
            -FailureClass    'Blocked' `
            -ControlObjective 'Prevent failed license removal' `
            -RiskMitigated   'Runtime error from attempting to remove group-inherited licenses'
    }

    # Nothing to remove
    if (@($p.DirectSkuIds).Count -eq 0) {
        return New-DecomActionResult `
            -ActionName  'Remove Licenses' `
            -Phase       'Licensing' `
            -Status      'Skipped' `
            -IsCritical  $false `
            -TargetUPN   $Context.TargetUPN `
            -Message     'No direct licenses assigned — nothing to remove.'
    }

    if ($Cmdlet.ShouldProcess($Context.TargetUPN, "Remove $(@($p.DirectSkuIds).Count) direct license assignment(s)")) {
        try {
            Set-MgUserLicense -UserId $p.UserId -AddLicenses @() -RemoveLicenses $p.DirectSkuIds | Out-Null
            $after = @(Get-MgUserLicenseDetail -UserId $p.UserId -ErrorAction SilentlyContinue)

            $r = New-DecomActionResult `
                -ActionName      'Remove Licenses' `
                -Phase           'Licensing' `
                -Status          'Success' `
                -IsCritical      $true `
                -TargetUPN       $Context.TargetUPN `
                -Message         'Direct licenses removed.' `
                -BeforeState     @{ DirectSkuIds = $p.DirectSkuIds } `
                -AfterState      @{ RemainingLicenseCount = $after.Count } `
                -Evidence        @{ RemovedSkuIds = $p.DirectSkuIds; RemainingCount = $after.Count } `
                -ControlObjective 'Remove paid service entitlement after governance prerequisites met' `
                -RiskMitigated   'Ongoing license spend after safe decommissioning'

            Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName `
                -Status $r.Status -IsCritical $true -Message $r.Message `
                -BeforeState @{ DirectSkuIds = $p.DirectSkuIds } `
                -AfterState  @{ RemainingLicenseCount = $after.Count } `
                -Evidence $r.Evidence `
                -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null

            return $r

        } catch {
            return New-DecomActionResult `
                -ActionName      'Remove Licenses' `
                -Phase           'Licensing' `
                -Status          'Failed' `
                -IsCritical      $true `
                -TargetUPN       $Context.TargetUPN `
                -Message         $_.Exception.Message `
                -BlockerMessages @('License removal failed.') `
                -FailureClass    'Critical'
        }
    } else {
        return New-DecomSkippedBecauseWhatIf `
            -ActionName      'Remove Licenses' `
            -Phase           'Licensing' `
            -TargetUPN       $Context.TargetUPN `
            -RecommendedNext 'Proceed to post-action snapshot'
    }
}

Export-ModuleMember -Function Get-DecomLicensePartition, Test-DecomLicenseRemovalReadiness, Remove-DecomLicenses
