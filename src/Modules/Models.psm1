function New-DecomRunContext {
    [CmdletBinding()]
    param([string]$TargetUPN,[string]$TicketId,[string]$OutputPath,[string]$EvidenceLevel,[switch]$WhatIfMode,[switch]$NonInteractive,[switch]$Force,[switch]$ValidationOnly)
    [pscustomobject]@{ TargetUPN=$TargetUPN; TicketId=$TicketId; OutputPath=$OutputPath; EvidenceLevel=$EvidenceLevel; WhatIf=[bool]$WhatIfMode; NonInteractive=[bool]$NonInteractive; Force=[bool]$Force; ValidationOnly=[bool]$ValidationOnly; StartedUtc=(Get-Date).ToUniversalTime().ToString('o'); CorrelationId=[guid]::NewGuid().Guid }
}
function New-DecomActionResult {
    [CmdletBinding()]
    param([string]$ActionName,[string]$Phase,[string]$Status,[bool]$IsCritical,[string]$TargetUPN,[string]$Message,[hashtable]$Evidence,[object]$BeforeState,[object]$AfterState,[string[]]$WarningMessages,[string[]]$BlockerMessages,[string]$RecommendedNext,[string]$ControlObjective,[string]$RiskMitigated)
    [pscustomobject]@{ ActionName=$ActionName; Phase=$Phase; Status=$Status; IsCritical=$IsCritical; TimestampUtc=(Get-Date).ToUniversalTime().ToString('o'); TargetUPN=$TargetUPN; Message=$Message; Evidence=$(if($Evidence){$Evidence}else{@{}}); BeforeState=$BeforeState; AfterState=$AfterState; WarningMessages=$(if($WarningMessages){$WarningMessages}else{@()}); BlockerMessages=$(if($BlockerMessages){$BlockerMessages}else{@()}); RecommendedNext=$RecommendedNext; ControlObjective=$ControlObjective; RiskMitigated=$RiskMitigated }
}
function New-DecomWorkflowReturn { param($Context,$State,$Results,[string]$StopReason) [pscustomobject]@{ Context=$Context; State=$State; Results=$Results; StopReason=$StopReason; Summary=[pscustomobject]@{ TargetUPN=$Context.TargetUPN; RunId=$State.RunId; Status=$(if($StopReason){'Stopped'}else{'Completed'}); Version='v1.0'; EvidenceLevel=$Context.EvidenceLevel } } }
Export-ModuleMember -Function New-DecomRunContext,New-DecomActionResult,New-DecomWorkflowReturn
