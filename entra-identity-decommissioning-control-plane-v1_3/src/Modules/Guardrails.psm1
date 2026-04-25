# Guardrails.psm1 — Safety gates and stop-decision logic
# v1.3: Test-DecomCanContinueAfterContainment blocks Skipped in live mode.
#        Confirm-DecomPhase returns $false instead of throwing (structured audit trail).
#        Assert-DecomEvidenceIntegrity validates full forensic field contract.

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

# v1.3: Returns $false in NonInteractive+no-Force instead of throwing.
# Callers emit a structured Blocked result — throw bypasses the evidence chain.
function Confirm-DecomPhase {
    param(
        [pscustomobject]$Context,
        [System.Management.Automation.PSCmdlet]$Cmdlet,
        [string]$PhaseName,
        [string]$Message
    )
    if ($Context.WhatIf -or $Context.Force) { return $true }
    if ($Context.NonInteractive -and -not $Context.Force) { return $false }
    return $Cmdlet.ShouldContinue("[$PhaseName] $Message", 'Decommission confirmation')
}

function Test-DecomCriticalPhaseSuccess {
    param([object[]]$Results, [string[]]$ActionNames)
    foreach ($name in $ActionNames) {
        $r = $Results | Where-Object { $_.ActionName -eq $name } | Select-Object -Last 1
        if (-not $r -or $r.Status -notin @('Success','Warning','Skipped')) { return $false }
    }
    return $true
}

# v1.3: Skipped only permitted in WhatIf mode.
# Live mode: skipped containment action = control gap = must not continue.
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

# v1.3: Full forensic field contract — validates all fields required for audit defensibility.
function Assert-DecomEvidenceIntegrity {
    param([object]$Result)
    if ($null -eq $Result)              { throw 'Null action result is not permitted.' }
    if (-not $Result.ActionName)        { throw 'ActionName is missing.' }
    if (-not $Result.StepId)            { throw 'StepId is missing — required for drift tracking.' }
    if (-not $Result.Phase)             { throw 'Phase is missing.' }
    if (-not $Result.Status)            { throw 'Status is missing.' }
    if (-not $Result.TimestampUtc)      { throw 'TimestampUtc is missing.' }
    if (-not $Result.TargetUPN)         { throw 'TargetUPN is missing.' }
    if (-not $Result.ControlObjective)  { throw 'ControlObjective is missing — required for forensic audit.' }
    if (-not $Result.RiskMitigated)     { throw 'RiskMitigated is missing — required for forensic audit.' }
    return $true
}

Export-ModuleMember -Function New-DecomSkippedBecauseWhatIf, Get-DecomStopDecision, Confirm-DecomPhase, Test-DecomCriticalPhaseSuccess, Test-DecomCanContinueAfterContainment, Assert-DecomEvidenceIntegrity
