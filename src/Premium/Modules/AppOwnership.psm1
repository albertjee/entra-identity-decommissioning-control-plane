# AppOwnership.psm1 — Application and service principal ownership remediation
# Premium v2.0
#
# Functions:
#   Get-DecomAppOwnershipState    — enumerate all app registrations and SPNs owned by UPN
#   Remove-DecomAppOwnership      — remove UPN as owner from app registrations and SPNs
#
# Design:
#   When a user is decommissioned, any app registrations or service principals
#   they own become orphaned if ownership is not transferred or removed.
#   Orphaned apps with no owner are a governance risk — nobody can manage,
#   rotate credentials, or decommission them after the owner is gone.
#
#   This module removes the departing user as an owner. It does NOT delete
#   the app or the SPN. Deletion is a separate decision requiring business
#   approval. The evidence report surfaces all affected apps so ownership
#   can be manually reassigned post-run if needed.
#
#   SINGLE OWNER GUARD:
#   If the target UPN is the ONLY owner of an app, removing them would leave
#   the app with no owner. This module detects this condition and returns
#   Warning with full evidence rather than removing the last owner silently.
#   The operator must manually assign a new owner before the departed user
#   can be safely removed from that app.
#
# Required Graph permissions:
#   Application.ReadWrite.All
#   Directory.ReadWrite.All
#
# PS7 compatible (v2.0 baseline)

#Requires -Version 7.0

Set-StrictMode -Version Latest

function Get-DecomAppOwnershipState {
    <#
    .SYNOPSIS
        Enumerates all app registrations and service principals owned by the target UPN.

    .DESCRIPTION
        Returns two lists:
          AppRegistrations — Entra app registration objects where UPN is an owner
          ServicePrincipals — Enterprise app SPN objects where UPN is an owner

        For each object, the full current owner list is captured so the
        single-owner guard can be applied before removal.

    .PARAMETER Context
        Premium DecomRunContext.

    .OUTPUTS
        [pscustomobject] with AppRegistrations, ServicePrincipals, and summary counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context
    )

    try {
        $userId = (Get-MgUser -UserId $Context.TargetUPN -Property Id -ErrorAction Stop).Id

        # App registrations owned by this user
        $ownedApps = @(Get-MgUserOwnedObject -UserId $Context.TargetUPN -All -ErrorAction Stop |
            Where-Object { $_.'@odata.type' -eq '#microsoft.graph.application' })

        $appList = foreach ($app in $ownedApps) {
            $owners = @(Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction SilentlyContinue)
            [pscustomobject]@{
                Id           = $app.Id
                DisplayName  = $app.AdditionalProperties['displayName']
                AppId        = $app.AdditionalProperties['appId']
                OwnerCount   = $owners.Count
                OwnerIds     = @($owners | Select-Object -ExpandProperty Id)
                IsSoleOwner  = ($owners.Count -eq 1)
            }
        }

        # Service principals owned by this user
        $ownedSpns = @(Get-MgUserOwnedObject -UserId $Context.TargetUPN -All -ErrorAction Stop |
            Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' })

        $spnList = foreach ($spn in $ownedSpns) {
            $owners = @(Get-MgServicePrincipalOwner -ServicePrincipalId $spn.Id -All -ErrorAction SilentlyContinue)
            [pscustomobject]@{
                Id          = $spn.Id
                DisplayName = $spn.AdditionalProperties['displayName']
                AppId       = $spn.AdditionalProperties['appId']
                OwnerCount  = $owners.Count
                OwnerIds    = @($owners | Select-Object -ExpandProperty Id)
                IsSoleOwner = ($owners.Count -eq 1)
            }
        }

        return [pscustomobject]@{
            UserId              = $userId
            AppRegistrations    = @($appList)
            ServicePrincipals   = @($spnList)
            AppCount            = @($appList).Count
            SpnCount            = @($spnList).Count
            SoleOwnerAppCount   = @($appList | Where-Object { $_.IsSoleOwner }).Count
            SoleOwnerSpnCount   = @($spnList | Where-Object { $_.IsSoleOwner }).Count
        }
    } catch {
        throw "Get-DecomAppOwnershipState: failed for '$($Context.TargetUPN)': $($_.Exception.Message)"
    }
}

function Remove-DecomAppOwnership {
    <#
    .SYNOPSIS
        Removes the target UPN as owner from all app registrations and service principals.

    .DESCRIPTION
        Iterates all owned app registrations and SPNs. For each:
          - If UPN is the sole owner: returns Warning, does NOT remove.
            Operator must assign a new owner before UPN can be removed.
          - If UPN is one of multiple owners: removes UPN as owner.

        Does NOT delete the app or SPN. Ownership removal only.
        WhatIf-aware. Full evidence trail per app and SPN processed.

    .PARAMETER Context
        Premium DecomRunContext.

    .PARAMETER AppOwnershipState
        Output of Get-DecomAppOwnershipState. If not supplied, called internally.

    .PARAMETER Cmdlet
        PSCmdlet reference for ShouldProcess support.

    .OUTPUTS
        [pscustomobject] DecomActionResult with Evidence.Results array.
        Status values:
          Success — all non-sole-owner apps and SPNs processed
          Warning — one or more apps/SPNs where UPN is sole owner (not removed)
          Skipped — no owned apps or SPNs found
          Failed  — Graph call threw
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [pscustomobject]$AppOwnershipState,
        $Cmdlet
    )

    $phase      = 'AppOwnership'
    $actionName = 'Remove App Ownership'

    try {
        if (-not $AppOwnershipState) {
            $AppOwnershipState = Get-DecomAppOwnershipState -Context $Context
        }

        $totalObjects = $AppOwnershipState.AppCount + $AppOwnershipState.SpnCount

        if ($totalObjects -eq 0) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message 'No owned app registrations or service principals found.' `
                -ControlObjective 'Remove ownership of apps to prevent orphaned registrations' `
                -RiskMitigated 'Orphaned apps with no owner after user decommission'
        }

        if ($Context.WhatIf) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "[WhatIf] Would process $($AppOwnershipState.AppCount) app registration(s) and $($AppOwnershipState.SpnCount) SPN(s). Sole-owner warnings: $($AppOwnershipState.SoleOwnerAppCount + $AppOwnershipState.SoleOwnerSpnCount)." `
                -ControlObjective 'Remove ownership of apps to prevent orphaned registrations' `
                -RiskMitigated 'Orphaned apps with no owner after user decommission'
        }

        $results     = [System.Collections.Generic.List[pscustomobject]]::new()
        $soleOwner   = 0
        $removed     = 0
        $failed      = 0

        # Process app registrations
        foreach ($app in $AppOwnershipState.AppRegistrations) {
            $r = _RemoveOwnerFromObject -Context $Context `
                -ObjectId $app.Id -DisplayName $app.DisplayName `
                -ObjectType 'AppRegistration' -IsSoleOwner $app.IsSoleOwner `
                -RemoveCmd { Remove-MgApplicationOwnerByRef -ApplicationId $app.Id -DirectoryObjectId $AppOwnershipState.UserId -ErrorAction Stop }
            $results.Add($r)
            if ($r.Status -eq 'Warning')  { $soleOwner++ }
            elseif ($r.Status -eq 'Success') { $removed++ }
            else { $failed++ }
        }

        # Process service principals
        foreach ($spn in $AppOwnershipState.ServicePrincipals) {
            $r = _RemoveOwnerFromObject -Context $Context `
                -ObjectId $spn.Id -DisplayName $spn.DisplayName `
                -ObjectType 'ServicePrincipal' -IsSoleOwner $spn.IsSoleOwner `
                -RemoveCmd { Remove-MgServicePrincipalOwnerByRef -ServicePrincipalId $spn.Id -DirectoryObjectId $AppOwnershipState.UserId -ErrorAction Stop }
            $results.Add($r)
            if ($r.Status -eq 'Warning')  { $soleOwner++ }
            elseif ($r.Status -eq 'Success') { $removed++ }
            else { $failed++ }
        }

        $status = if ($failed -gt 0 -and $removed -eq 0) { 'Failed' } `
                  elseif ($soleOwner -gt 0 -or $failed -gt 0) { 'Warning' } `
                  else { 'Success' }

        $summary = "Removed from $removed object(s). Sole-owner warnings: $soleOwner. Failed: $failed."

        Add-DecomEvidenceEvent -Context $Context -Phase $phase `
            -ActionName $actionName -Status $status -IsCritical $false `
            -Message $summary -Evidence @{ Results = $results } `
            -ControlObjective 'Remove ownership of apps to prevent orphaned registrations' `
            -RiskMitigated 'Orphaned apps with no owner after user decommission' | Out-Null

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status $status -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message $summary -Evidence @{ Results = $results } `
            -ControlObjective 'Remove ownership of apps to prevent orphaned registrations' `
            -RiskMitigated 'Orphaned apps with no owner after user decommission'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Failed' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "App ownership removal failed: $($_.Exception.Message)" `
            -FailureClass 'GraphError' `
            -ControlObjective 'Remove ownership of apps to prevent orphaned registrations' `
            -RiskMitigated 'Orphaned apps with no owner after user decommission'
    }
}

# ── Private helpers ────────────────────────────────────────────────────────────

function _RemoveOwnerFromObject {
    # Removes the target user as owner from a single app or SPN.
    # Enforces sole-owner guard — returns Warning without removing if sole owner.
    param(
        [pscustomobject]$Context,
        [string]$ObjectId,
        [string]$DisplayName,
        [string]$ObjectType,
        [bool]$IsSoleOwner,
        [scriptblock]$RemoveCmd
    )

    if ($IsSoleOwner) {
        return [pscustomobject]@{
            ObjectId    = $ObjectId
            DisplayName = $DisplayName
            ObjectType  = $ObjectType
            Status      = 'Warning'
            Note        = 'Sole owner — ownership not removed. Assign a new owner first, then re-run.'
        }
    }

    try {
        & $RemoveCmd
        return [pscustomobject]@{
            ObjectId    = $ObjectId
            DisplayName = $DisplayName
            ObjectType  = $ObjectType
            Status      = 'Success'
            Note        = $null
        }
    } catch {
        return [pscustomobject]@{
            ObjectId    = $ObjectId
            DisplayName = $DisplayName
            ObjectType  = $ObjectType
            Status      = 'Failed'
            Note        = $_.Exception.Message
        }
    }
}

Export-ModuleMember -Function `
    Get-DecomAppOwnershipState, `
    Remove-DecomAppOwnership
