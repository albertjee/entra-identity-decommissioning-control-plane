$script:DecomEvidencePath=$null
function Initialize-DecomEvidenceStore { param([Parameter(Mandatory)][string]$Path) $script:DecomEvidencePath=$Path; New-Item -ItemType File -Path $Path -Force | Out-Null }
function Add-DecomEvidenceEvent {
    [CmdletBinding()]
    param([pscustomobject]$Context,[string]$Phase,[string]$ActionName,[string]$Status,[bool]$IsCritical,[string]$Message,[object]$BeforeState,[object]$AfterState,[hashtable]$Evidence,[object]$ErrorRecord,[string]$ControlObjective,[string]$RiskMitigated)
    $event=[pscustomobject]@{ SchemaVersion='1.0'; ToolVersion='v1.0'; CorrelationId=$Context.CorrelationId; RunId=$(Split-Path $Context.OutputPath -Leaf); TargetUPN=$Context.TargetUPN; TimestampUtc=(Get-Date).ToUniversalTime().ToString('o'); EvidenceLevel=$Context.EvidenceLevel; Phase=$Phase; Action=$ActionName; Status=$Status; IsCritical=$IsCritical; Message=$Message; ControlObjective=$ControlObjective; RiskMitigated=$RiskMitigated; BeforeState=$BeforeState; AfterState=$AfterState; Evidence=$(if($Evidence){$Evidence}else{@{}}); Error=$(if($ErrorRecord){ @{ Message=$ErrorRecord.Exception.Message; Type=$ErrorRecord.Exception.GetType().FullName; Category=[string]$ErrorRecord.CategoryInfo.Category } } else { $null }) }
    if($script:DecomEvidencePath){ $event | ConvertTo-Json -Depth 20 -Compress | Add-Content -Path $script:DecomEvidencePath }
    return $event
}
Export-ModuleMember -Function Initialize-DecomEvidenceStore,Add-DecomEvidenceEvent
