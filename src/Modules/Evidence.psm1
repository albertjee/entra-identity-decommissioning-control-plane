# Evidence.psm1 — Evidence store initialization and event emission
# v1.4: Duplicate shallow Assert-DecomEvidenceIntegrity removed — full version
#        lives in Guardrails.psm1. Add-DecomEvidenceEvent now includes
#        CorrelationId and EvidenceLevel from Context for standalone NDJSON usefulness.

$script:DecomEvidencePath = $null

function Initialize-DecomEvidenceStore {
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$RunId
    )
    $Context | Add-Member -Force -NotePropertyName Evidence -NotePropertyValue ([System.Collections.Generic.List[object]]::new())
    $Context | Add-Member -Force -NotePropertyName RunId    -NotePropertyValue $RunId
}

function Add-DecomEvidenceEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [string]$Phase,
        [string]$ActionName,
        [string]$Status,
        [bool]$IsCritical,
        [string]$Message,
        [hashtable]$BeforeState,
        [hashtable]$AfterState,
        [hashtable]$Evidence,
        [string]$ControlObjective,
        [string]$RiskMitigated
    )
    $event = [pscustomobject]@{
        # Run identity — CorrelationId and EvidenceLevel now included for standalone NDJSON usefulness
        RunId          = $Context.RunId
        CorrelationId  = $Context.CorrelationId
        EvidenceLevel  = $Context.EvidenceLevel
        TargetUPN      = $Context.TargetUPN
        TimestampUtc   = (Get-Date).ToUniversalTime().ToString('o')
        # Action identity
        ActionId       = [guid]::NewGuid().Guid
        Phase          = $Phase
        ActionName     = $ActionName
        Status         = $Status
        IsCritical     = $IsCritical
        Message        = $Message
        # Evidence payload
        BeforeState    = if ($BeforeState) { $BeforeState } else { @{} }
        AfterState     = if ($AfterState)  { $AfterState }  else { @{} }
        Evidence       = if ($Evidence)    { $Evidence }    else { @{} }
        # Control framing
        ControlObjective = $ControlObjective
        RiskMitigated    = $RiskMitigated
    }
    $Context.Evidence.Add($event)
    return $event
}

# Assert-DecomEvidenceIntegrity intentionally NOT exported here.
# Full forensic contract validation lives in Guardrails.psm1.
Export-ModuleMember -Function Initialize-DecomEvidenceStore, Add-DecomEvidenceEvent
