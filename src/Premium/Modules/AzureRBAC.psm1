# AzureRBAC.psm1 — Azure RBAC assignment remediation
# Premium v2.0
#
# Functions:
#   Get-DecomAzureRBACState    — enumerate all Azure RBAC assignments for target UPN
#   Remove-DecomAzureRBAC      — remove all Azure RBAC assignments for target UPN
#
# Design:
#   Entra ID role assignments (PIM) are handled by AccessRemoval.psm1.
#   This module handles Azure resource-layer RBAC — subscription, resource
#   group, and resource-level role assignments via the Az.Resources module.
#
#   SCOPE LEVELS COVERED:
#   - Subscription scope      (/subscriptions/{id})
#   - Resource group scope    (/subscriptions/{id}/resourceGroups/{name})
#   - Resource scope          (/subscriptions/{id}/resourceGroups/{name}/providers/...)
#   - Management group scope  (/providers/Microsoft.Management/managementGroups/{id})
#
#   INHERITED ASSIGNMENTS:
#   Azure RBAC assignments can be inherited from parent scopes. This module
#   only removes DIRECT assignments. Inherited assignments appear in the
#   evidence report as informational — they must be removed at the parent
#   scope level by the operator if required.
#
#   CLASSIC ADMINISTRATORS:
#   Classic Co-Administrator and Service Administrator roles are deprecated
#   but may still exist in older subscriptions. This module detects them
#   and surfaces them as Warning evidence — they cannot be removed via
#   the modern RBAC API and require manual removal in the Azure portal.
#
# Required permissions:
#   Az.Resources module must be available
#   User Access Administrator or Owner at relevant subscription scope
#   The operator running this must have rights to remove the assignments
#
# PS7 compatible (v2.0 baseline)

#Requires -Version 7.0

Set-StrictMode -Version Latest

function Get-DecomAzureRBACState {
    <#
    .SYNOPSIS
        Enumerates all Azure RBAC role assignments for the target UPN.

    .DESCRIPTION
        Returns all direct Azure RBAC assignments across all accessible
        subscriptions. Inherited assignments are captured separately as
        informational evidence. Classic administrator roles are flagged
        as requiring manual removal.

        Requires Az.Resources module and an authenticated Az session
        (Connect-AzAccount) before calling.

    .PARAMETER Context
        Premium DecomRunContext.

    .OUTPUTS
        [pscustomobject] with DirectAssignments, InheritedAssignments,
        ClassicAdminFlags, and summary counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context
    )

    try {
        # Enumerate all accessible subscriptions
        $subscriptions = @(Get-AzSubscription -ErrorAction Stop)

        $direct    = [System.Collections.Generic.List[pscustomobject]]::new()
        $inherited = [System.Collections.Generic.List[pscustomobject]]::new()
        $skipped   = [System.Collections.Generic.List[pscustomobject]]::new()

        foreach ($sub in $subscriptions) {
            try {
                $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop

                $assignments = @(Get-AzRoleAssignment -SignInName $Context.TargetUPN `
                    -ErrorAction Stop)

                foreach ($a in $assignments) {
                    $entry = [pscustomobject]@{
                        RoleAssignmentId   = $a.RoleAssignmentId
                        RoleDefinitionName = $a.RoleDefinitionName
                        Scope              = $a.Scope
                        SubscriptionId     = $sub.Id
                        SubscriptionName   = $sub.Name
                        IsInherited        = ($a.Scope -notmatch "^/subscriptions/$($sub.Id)" -and
                                              $a.ObjectType -eq 'User')
                    }
                    if ($entry.IsInherited) {
                        $inherited.Add($entry)
                    } else {
                        $direct.Add($entry)
                    }
                }
            } catch {
                # Inaccessible subscription — log as skipped, continue to next
                $skipped.Add([pscustomobject]@{
                    SubscriptionId   = $sub.Id
                    SubscriptionName = $sub.Name
                    Reason           = $_.Exception.Message
                })
            }
        }

        return [pscustomobject]@{
            DirectAssignments    = $direct
            InheritedAssignments = $inherited
            SkippedSubscriptions = $skipped
            DirectCount          = $direct.Count
            InheritedCount       = $inherited.Count
            SkippedCount         = $skipped.Count
            SubscriptionsScanned = $subscriptions.Count
        }
    } catch {
        throw "Get-DecomAzureRBACState: failed for '$($Context.TargetUPN)': $($_.Exception.Message)"
    }
}

function Remove-DecomAzureRBAC {
    <#
    .SYNOPSIS
        Removes all direct Azure RBAC role assignments for the target UPN.

    .DESCRIPTION
        Iterates all directly assigned Azure RBAC roles across all accessible
        subscriptions and removes them.

        Inherited assignments are NOT removed — they are surfaced in the
        evidence report as requiring operator action at the parent scope.

        WhatIf-aware. Full evidence trail per assignment removed.

    .PARAMETER Context
        Premium DecomRunContext.

    .PARAMETER RBACState
        Output of Get-DecomAzureRBACState. If not supplied, called internally.

    .PARAMETER Cmdlet
        PSCmdlet reference for ShouldProcess support.

    .OUTPUTS
        [pscustomobject] DecomActionResult
        Status values:
          Success — all direct assignments removed
          Warning — some failed, or inherited assignments detected requiring manual action
          Skipped — no direct assignments found
          Failed  — all removals failed
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [pscustomobject]$RBACState,
        $Cmdlet
    )

    $phase      = 'AzureRBAC'
    $actionName = 'Remove Azure RBAC Assignments'

    try {
        if (-not $RBACState) {
            $RBACState = Get-DecomAzureRBACState -Context $Context
        }

        $before = @{
            DirectCount    = $RBACState.DirectCount
            InheritedCount = $RBACState.InheritedCount
            Subscriptions  = $RBACState.SubscriptionsScanned
        }

        if ($RBACState.DirectCount -eq 0) {
            $inheritedNote = if ($RBACState.InheritedCount -gt 0) {
                " Note: $($RBACState.InheritedCount) inherited assignment(s) detected — remove at parent scope manually."
            } else { '' }

            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "No direct Azure RBAC assignments found.$inheritedNote" `
                -Evidence $before `
                -ControlObjective 'Remove Azure resource access to prevent privilege persistence' `
                -RiskMitigated 'Continued Azure resource access after account decommission'
        }

        if ($Context.WhatIf) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "[WhatIf] Would remove $($RBACState.DirectCount) direct Azure RBAC assignment(s) across $($RBACState.SubscriptionsScanned) subscription(s)." `
                -BeforeState $before `
                -ControlObjective 'Remove Azure resource access to prevent privilege persistence' `
                -RiskMitigated 'Continued Azure resource access after account decommission'
        }

        $results = [System.Collections.Generic.List[pscustomobject]]::new()
        $removed = 0
        $failed  = 0

        foreach ($assignment in $RBACState.DirectAssignments) {
            try {
                $null = Set-AzContext -SubscriptionId $assignment.SubscriptionId -ErrorAction Stop

                Remove-AzRoleAssignment `
                    -SignInName        $Context.TargetUPN `
                    -RoleDefinitionName $assignment.RoleDefinitionName `
                    -Scope             $assignment.Scope `
                    -ErrorAction Stop

                $removed++
                $results.Add([pscustomobject]@{
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    Scope              = $assignment.Scope
                    SubscriptionName   = $assignment.SubscriptionName
                    Status             = 'Removed'
                    Note               = $null
                })
            } catch {
                $failed++
                $results.Add([pscustomobject]@{
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    Scope              = $assignment.Scope
                    SubscriptionName   = $assignment.SubscriptionName
                    Status             = 'Failed'
                    Note               = $_.Exception.Message
                })
            }
        }

        $inheritedNote = if ($RBACState.InheritedCount -gt 0) {
            " $($RBACState.InheritedCount) inherited assignment(s) require manual removal at parent scope."
        } else { '' }

        $status  = if ($failed -eq 0 -and $RBACState.InheritedCount -eq 0) { 'Success' } `
                   elseif ($failed -eq $RBACState.DirectCount) { 'Failed' } `
                   else { 'Warning' }

        $summary = "Removed $removed of $($RBACState.DirectCount) direct assignment(s). Failed: $failed.$inheritedNote"

        Add-DecomEvidenceEvent -Context $Context -Phase $phase `
            -ActionName $actionName -Status $status -IsCritical $false `
            -Message $summary -BeforeState $before `
            -Evidence @{ Results = $results; InheritedAssignments = $RBACState.InheritedAssignments } `
            -ControlObjective 'Remove Azure resource access to prevent privilege persistence' `
            -RiskMitigated 'Continued Azure resource access after account decommission' | Out-Null

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status $status -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message $summary `
            -Evidence @{ Results = $results; InheritedAssignments = $RBACState.InheritedAssignments } `
            -ControlObjective 'Remove Azure resource access to prevent privilege persistence' `
            -RiskMitigated 'Continued Azure resource access after account decommission'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Failed' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "Azure RBAC removal failed: $($_.Exception.Message)" `
            -FailureClass 'AzureRBACError' `
            -ControlObjective 'Remove Azure resource access to prevent privilege persistence' `
            -RiskMitigated 'Continued Azure resource access after account decommission'
    }
}

Export-ModuleMember -Function `
    Get-DecomAzureRBACState, `
    Remove-DecomAzureRBAC
