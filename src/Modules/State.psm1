function New-DecomState { param([string]$RunId) [pscustomobject]@{ RunId=$RunId; Phases=[ordered]@{} } }
function Set-DecomPhaseState { param([pscustomobject]$State,[string]$Phase,[string]$Status) $State.Phases[$Phase]=[pscustomobject]@{Status=$Status; TimestampUtc=(Get-Date).ToUniversalTime().ToString('o')} }
Export-ModuleMember -Function New-DecomState,Set-DecomPhaseState
