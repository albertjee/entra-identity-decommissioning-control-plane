# Guardrails.psm1 — Safety gates and stop-decision logic
# v1.4: Test-DecomCriticalPhaseSuccess hardened — Skipped no longer allowed.
#        Use this function only for non-containment phases where Skipped is acceptable.
#        For containment specifically, use Test-DecomCanContinueAfterContainment.

function New-DecomSkippedBecauseWhatIf {
    param(
        [string]$ActionName,
        [string]$Phase,
        [string]$TargetUPN,
        [string]$RecommendedNext
    )
    New-DecomActionResult `
        -ActionName       $ActionName `
        -Phase            $Phase `
        -Status           'Skipped' `
        -IsCritical       $false `
        -TargetUPN        $TargetUPN `
        -Message          'Action skipped: WhatIf mode active or operator declined ShouldProcess.' `
        -Evidence         @{ WhatIfOrDeclined = $true } `
        -RecommendedNext  $RecommendedNext `
        -FailureClass     'OperatorDeclined' `
        -ControlObjective 'Preserve operator control' `
        -RiskMitigated    'Unapproved destructive change'
}

function Get-DecomStopDecision {
    param([object[]]$Results)
    foreach ($r in $Results) {
        if ($null -eq $r) {
            return [pscustomobject]@{
                ShouldStop = $true
                Reason     = 'Null action result encountered — possible unhandled ShouldProcess decline.'
            }
        }
    }
    $f = $Results |
        Where-Object { $_.IsCritical -eq $true -and $_.Status -in @('Failed','Blocked') } |
        Select-Object -First 1
    if ($f) { return [pscustomobject]@{ ShouldStop = $true; Reason = "Critical failure in action: $($f.ActionName)" } }
    return [pscustomobject]@{ ShouldStop = $false; Reason = $null }
}

function Confirm-DecomPhase {
    param(
        [pscustomobject]$Context,
        $Cmdlet,
        [string]$PhaseName,
        [string]$Message
    )
    if ($Context.WhatIf -or $Context.Force) { return $true }
    if ($Context.NonInteractive -and -not $Context.Force) { return $false }
    return $Cmdlet.ShouldContinue("[$PhaseName] $Message", 'Decommission confirmation')
}

# v1.4: Hardened — Skipped is no longer allowed as a passing status.
# This function is now safe for any phase. Previously allowed Skipped which
# was a latent risk if reused outside containment context.
function Test-DecomCriticalPhaseSuccess {
    param([object[]]$Results, [string[]]$ActionNames)
    foreach ($name in $ActionNames) {
        $r = $Results | Where-Object { $_.ActionName -eq $name } | Select-Object -Last 1
        # v1.4: Only Success and Warning accepted — Skipped is no longer passing
        if (-not $r -or $r.Status -notin @('Success', 'Warning')) { return $false }
    }
    return $true
}

# Containment-specific check — WhatIf-aware Skipped allowance
function Test-DecomCanContinueAfterContainment {
    param(
        [object[]]$Results,
        [pscustomobject]$Context
    )
    $required = @('Reset Password', 'Revoke Sessions', 'Block Sign-In')
    foreach ($name in $required) {
        $r = $Results | Where-Object { $_.ActionName -eq $name } | Select-Object -Last 1
        if (-not $r) { return $false }
        if ($Context.WhatIf -and $r.Status -eq 'Skipped') { continue }
        if ($r.Status -notin @('Success', 'Warning')) { return $false }
    }
    return $true
}

# Full forensic field contract validation
function Assert-DecomEvidenceIntegrity {
    param([object]$Result)
    if ($null -eq $Result)             { throw 'Null action result is not permitted.' }
    if (-not $Result.ActionName)       { throw 'ActionName is missing.' }
    if (-not $Result.StepId)           { throw 'StepId is missing — required for drift tracking.' }
    if (-not $Result.Phase)            { throw 'Phase is missing.' }
    if (-not $Result.Status)           { throw 'Status is missing.' }
    if (-not $Result.TimestampUtc)     { throw 'TimestampUtc is missing.' }
    if (-not $Result.TargetUPN)        { throw 'TargetUPN is missing.' }
    if (-not $Result.ControlObjective) { throw 'ControlObjective is missing — required for forensic audit.' }
    if (-not $Result.RiskMitigated)    { throw 'RiskMitigated is missing — required for forensic audit.' }
    return $true
}

Export-ModuleMember -Function New-DecomSkippedBecauseWhatIf, Get-DecomStopDecision, Confirm-DecomPhase, Test-DecomCriticalPhaseSuccess, Test-DecomCanContinueAfterContainment, Assert-DecomEvidenceIntegrity
