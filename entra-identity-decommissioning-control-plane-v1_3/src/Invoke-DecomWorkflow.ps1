# Invoke-DecomWorkflow.ps1 — Canonical workflow orchestrator
# v1.3: Confirm-DecomPhase now returns $false instead of throwing —
#        caller emits a structured Blocked result to preserve audit chain.
#        Test-DecomCanContinueAfterContainment now receives $Context for WhatIf awareness.

function Invoke-DecomWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][pscustomobject]$State,
        [string]$OutOfOfficeMessage,
        [switch]$EnableLitigationHold,
        [switch]$RemoveLicenses,
        $Cmdlet  # PSCmdlet in production; pscustomobject stub acceptable in test
    )

    $Results = New-Object System.Collections.Generic.List[object]

    # Phase 1 — Authentication
    Invoke-DecomPhase -State $State -Phase 'Authentication' -ScriptBlock {
        $Results.Add((Connect-DecomGraph    -Context $Context))
        $Results.Add((Connect-DecomExchange -Context $Context))
    }
    $d = Get-DecomStopDecision -Results $Results
    if ($d.ShouldStop) { return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason $d.Reason }

    # Phase 2 — Validation
    Invoke-DecomPhase -State $State -Phase 'Validation' -ScriptBlock {
        $Results.Add((Get-DecomBaselineState -Context $Context))
    }
    $d = Get-DecomStopDecision -Results $Results
    if ($d.ShouldStop) { return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason $d.Reason }

    # Phase 3 — Pre-action snapshot
    Invoke-DecomPhase -State $State -Phase 'PreActionSnapshot' -ScriptBlock {
        $Results.Add((Get-DecomIdentitySnapshot -Context $Context -SnapshotName 'Before'))
    }

    # ValidationOnly early exit
    if ($Context.ValidationOnly) {
        return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason $null
    }

    # Phase 4 — Containment (guarded)
    if (-not (Confirm-DecomPhase -Context $Context -Cmdlet $Cmdlet -PhaseName 'Containment' -Message 'Proceed with immediate containment actions?')) {
        $Results.Add((New-DecomActionResult -ActionName 'Containment Phase Gate' -Phase 'Containment' `
            -Status 'Blocked' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message 'Containment not confirmed — operator declined or NonInteractive mode without -Force.' `
            -BlockerMessages @('Use -Force with -NonInteractive, or confirm interactively.') `
            -ControlObjective 'Require explicit operator approval before destructive containment' `
            -RiskMitigated 'Unapproved identity mutation'))
        return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Containment not confirmed.'
    }
    Invoke-DecomPhase -State $State -Phase 'Containment' -ScriptBlock {
        $Results.Add((Reset-DecomPassword  -Context $Context -Cmdlet $Cmdlet))
        $Results.Add((Revoke-DecomSessions -Context $Context -Cmdlet $Cmdlet))
        $Results.Add((Disable-DecomSignIn  -Context $Context -Cmdlet $Cmdlet))
    }
    $d = Get-DecomStopDecision -Results $Results
    # v1.3: Pass $Context so WhatIf-aware containment check works correctly
    if ($d.ShouldStop -or -not (Test-DecomCanContinueAfterContainment -Results $Results -Context $Context)) {
        return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Containment phase did not complete safely.'
    }

    # Phase 5 — Mailbox continuity
    Invoke-DecomPhase -State $State -Phase 'Mailbox' -ScriptBlock {
        $Results.Add((Convert-DecomMailboxToShared -Context $Context -Cmdlet $Cmdlet))
        $Results.Add((Set-DecomAutoReply -Context $Context -Message $OutOfOfficeMessage -Cmdlet $Cmdlet))
    }
    $d = Get-DecomStopDecision -Results $Results
    if ($d.ShouldStop) { return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Mailbox phase failed.' }

    # Phase 6 — Compliance (always wrapped)
    Invoke-DecomPhase -State $State -Phase 'Compliance' -ScriptBlock {
        if ($EnableLitigationHold) { $Results.Add((Enable-DecomLitigationHold -Context $Context -Cmdlet $Cmdlet)) }
        $Results.Add((Get-DecomComplianceState -Context $Context))
    }
    $d = Get-DecomStopDecision -Results $Results
    if ($d.ShouldStop) { return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Compliance phase failed.' }

    # Phase 7 — Licensing (guarded)
    Invoke-DecomPhase -State $State -Phase 'Licensing' -ScriptBlock {
        $Results.Add((Test-DecomLicenseRemovalReadiness -Results $Results -Context $Context))
        if ($RemoveLicenses) {
            if (Confirm-DecomPhase -Context $Context -Cmdlet $Cmdlet -PhaseName 'LicenseRemoval' -Message 'Proceed with license removal?') {
                $readiness = $Results | Where-Object { $_.ActionName -eq 'Check License Removal Readiness' } | Select-Object -Last 1
                if ($readiness.Status -eq 'Success') {
                    $Results.Add((Remove-DecomLicenses -Context $Context -Cmdlet $Cmdlet))
                }
            } else {
                $Results.Add((New-DecomActionResult -ActionName 'License Removal Gate' -Phase 'Licensing' `
                    -Status 'Blocked' -IsCritical $false -TargetUPN $Context.TargetUPN `
                    -Message 'License removal not confirmed — operator declined or NonInteractive mode without -Force.' `
                    -RecommendedNext 'Manually remove licenses after confirming compliance prerequisites.' `
                    -ControlObjective 'Require explicit operator approval before license removal' `
                    -RiskMitigated 'Premature license removal'))
            }
        }
    }

    # Phase 8 — Post-action snapshot
    Invoke-DecomPhase -State $State -Phase 'PostActionSnapshot' -ScriptBlock {
        $Results.Add((Get-DecomIdentitySnapshot -Context $Context -SnapshotName 'After'))
    }

    return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason $null
}
