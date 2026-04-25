function Invoke-DecomWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Context,
        [Parameter(Mandatory = $true)][pscustomobject]$State,
        [string]$OutOfOfficeMessage,
        [switch]$EnableLitigationHold,
        [switch]$RemoveLicenses,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCmdlet]$Cmdlet
    )

    $Results = New-Object System.Collections.Generic.List[object]

    Invoke-DecomPhase -State $State -Phase 'Authentication' -ScriptBlock {
        $Results.Add((Connect-DecomServices -Context $Context))
    }
    if ((Get-DecomStopDecision -Results $Results).ShouldStop) { return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Authentication failed.' }

    Invoke-DecomPhase -State $State -Phase 'Validation' -ScriptBlock {
        $Results.Add((Get-DecomBaselineState -Context $Context))
    }
    if ((Get-DecomStopDecision -Results $Results).ShouldStop) { return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Validation failed.' }

    Invoke-DecomPhase -State $State -Phase 'PreActionSnapshot' -ScriptBlock {
        $Results.Add((Get-DecomIdentitySnapshot -Context $Context -SnapshotName 'Before'))
    }

    if ($Context.ValidationOnly) {
        return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason $null
    }

    if (-not (Confirm-DecomPhase -Context $Context -Cmdlet $Cmdlet -PhaseName 'Containment' -Message 'Proceed with immediate containment actions?')) {
        return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Containment not confirmed.'
    }

    Invoke-DecomPhase -State $State -Phase 'Containment' -ScriptBlock {
        $Results.Add((Reset-DecomPassword -Context $Context -Cmdlet $Cmdlet))
        $Results.Add((Revoke-DecomSessions -Context $Context -Cmdlet $Cmdlet))
        $Results.Add((Disable-DecomSignIn -Context $Context -Cmdlet $Cmdlet))
    }
    $Decision = Get-DecomStopDecision -Results $Results
    if ($Decision.ShouldStop -or -not (Test-DecomCanContinueAfterContainment -Results $Results)) {
        return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Containment phase did not complete safely.'
    }

    Invoke-DecomPhase -State $State -Phase 'Mailbox' -ScriptBlock {
        $Results.Add((Convert-DecomMailboxToShared -Context $Context -Cmdlet $Cmdlet))
        $Results.Add((Set-DecomAutoReply -Context $Context -Message $OutOfOfficeMessage -Cmdlet $Cmdlet))
    }
    if ((Get-DecomStopDecision -Results $Results).ShouldStop) { return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Mailbox phase failed.' }

    if ($EnableLitigationHold) {
        Invoke-DecomPhase -State $State -Phase 'Compliance' -ScriptBlock {
            $Results.Add((Enable-DecomLitigationHold -Context $Context -Cmdlet $Cmdlet))
            $Results.Add((Get-DecomComplianceState -Context $Context))
        }
        if ((Get-DecomStopDecision -Results $Results).ShouldStop) { return New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason 'Compliance phase failed.' }
    }
    else {
        $Results.Add((Get-DecomComplianceState -Context $Context))
    }

    Invoke-DecomPhase -State $State -Phase 'Licensing' -ScriptBlock {
        $Results.Add((Test-DecomLicenseRemovalReadiness -Results $Results -Context $Context))
        if ($RemoveLicenses) {
            if (Confirm-DecomPhase -Context $Context -Cmdlet $Cmdlet -PhaseName 'LicenseRemoval' -Message 'Proceed with license removal?') {
                $readiness = $Results | Where-Object ActionName -eq 'Check License Removal Readiness' | Select-Object -Last 1
                if ($readiness.Status -eq 'Success') { $Results.Add((Remove-DecomLicenses -Context $Context -Cmdlet $Cmdlet)) }
            } else {
                $Results.Add((New-DecomActionResult -ActionName 'Remove Licenses' -Phase 'Licensing' -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'License removal not confirmed.' -RecommendedNext 'Proceed to reporting'))
            }
        }
    }

    Invoke-DecomPhase -State $State -Phase 'PostActionSnapshot' -ScriptBlock {
        $Results.Add((Get-DecomIdentitySnapshot -Context $Context -SnapshotName 'After'))
    }

    New-DecomWorkflowReturn -Context $Context -State $State -Results $Results -StopReason $null
}
