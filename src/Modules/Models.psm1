# Models.psm1 — Core data contracts for the Decom Control Plane
# v1.5: OperatorUPN, OperatorObjectId added to Context.
#        TicketId mandatory in Force+NonInteractive mode (enforced in Start-Decom.ps1).
#        Version updated to v1.5.

function New-DecomRunContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetUPN,
        [string]$TicketId,
        [Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet('Standard','Detailed','Forensic')]
        [string]$EvidenceLevel = 'Forensic',
        [switch]$WhatIfMode,
        [switch]$NonInteractive,
        [switch]$Force,
        [switch]$ValidationOnly,
        [string]$OperatorUPN,     # v1.5: operator identity for repudiation resistance
        [string]$OperatorObjectId # v1.5: operator AAD ObjectId
    )
    [pscustomobject]@{
        TargetUPN        = $TargetUPN
        TicketId         = $TicketId
        OutputPath       = $OutputPath
        EvidenceLevel    = $EvidenceLevel
        WhatIf           = [bool]$WhatIfMode
        NonInteractive   = [bool]$NonInteractive
        Force            = [bool]$Force
        ValidationOnly   = [bool]$ValidationOnly
        OperatorUPN      = $OperatorUPN
        OperatorObjectId = $OperatorObjectId
        StartedUtc       = (Get-Date).ToUniversalTime().ToString('o')
        CorrelationId    = [guid]::NewGuid().Guid
    }
}

$script:StepCounters = @{}

function New-DecomStepId {
    param([string]$Phase)
    $key = $Phase.ToUpper()
    if (-not $script:StepCounters.ContainsKey($key)) { $script:StepCounters[$key] = 0 }
    $script:StepCounters[$key]++
    return '{0}-{1:D3}' -f $key, $script:StepCounters[$key]
}

function Reset-DecomStepCounters { $script:StepCounters = @{} }

function New-DecomActionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ActionName,
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][bool]$IsCritical,
        [Parameter(Mandatory)][string]$TargetUPN,
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Evidence,
        [hashtable]$BeforeState,
        [hashtable]$AfterState,
        [string[]]$WarningMessages,
        [string[]]$BlockerMessages,
        [string[]]$ManualFollowUp,
        [string]$RecommendedNext,
        [string]$ControlObjective,
        [string]$RiskMitigated,
        [string]$FailureClass,
        [string]$StepId
    )
    [pscustomobject]@{
        StepId           = if ($StepId) { $StepId } else { New-DecomStepId -Phase $Phase }
        ActionName       = $ActionName
        Phase            = $Phase
        Status           = $Status
        IsCritical       = $IsCritical
        FailureClass     = $FailureClass
        TimestampUtc     = (Get-Date).ToUniversalTime().ToString('o')
        TargetUPN        = $TargetUPN
        Message          = $Message
        BeforeState      = if ($BeforeState)     { $BeforeState }     else { @{} }
        AfterState       = if ($AfterState)      { $AfterState }      else { @{} }
        Evidence         = if ($Evidence)        { $Evidence }        else { @{} }
        WarningMessages  = if ($WarningMessages) { $WarningMessages } else { @() }
        BlockerMessages  = if ($BlockerMessages) { $BlockerMessages } else { @() }
        ManualFollowUp   = if ($ManualFollowUp)  { $ManualFollowUp }  else { @() }
        RecommendedNext  = $RecommendedNext
        ControlObjective = $ControlObjective
        RiskMitigated    = $RiskMitigated
    }
}

function New-DecomWorkflowReturn {
    param(
        [pscustomobject]$Context,
        [pscustomobject]$State,
        [object]$Results,
        [string]$StopReason
    )
    [pscustomobject]@{
        Context    = $Context
        State      = $State
        Results    = $Results
        StopReason = $StopReason
        Summary    = [pscustomobject]@{
            TargetUPN     = $Context.TargetUPN
            RunId         = $State.RunId
            CorrelationId = $Context.CorrelationId
            OperatorUPN   = $Context.OperatorUPN
            TicketId      = $Context.TicketId
            Status        = if ($StopReason) { 'Stopped' } else { 'Completed' }
            Version       = 'v1.5'
            EvidenceLevel = $Context.EvidenceLevel
        }
    }
}

Export-ModuleMember -Function New-DecomRunContext, New-DecomActionResult, New-DecomWorkflowReturn, New-DecomStepId, Reset-DecomStepCounters
