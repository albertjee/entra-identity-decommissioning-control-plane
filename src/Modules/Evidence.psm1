# Evidence.psm1 — Evidence store and event emission.
# v1.5: OperatorUPN and OperatorObjectId added to every evidence event.
#        evidence.manifest.json written at end of run.

# ── Evidence store ─────────────────────────────────────────────────────────────

$script:DecomEvidenceNdjsonPath = $null

function Initialize-DecomEvidenceStore {
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$RunId,
        [string]$NdjsonPath
    )
    $Context | Add-Member -Force -NotePropertyName Evidence         -NotePropertyValue ([System.Collections.Generic.List[object]]::new())
    $Context | Add-Member -Force -NotePropertyName RunId            -NotePropertyValue $RunId
    $script:DecomEvidenceNdjsonPath = $NdjsonPath
    if ($NdjsonPath) { New-Item -ItemType File -Path $NdjsonPath -Force | Out-Null }
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

    $eventHt = [ordered]@{
        # Run identity
        RunId            = $Context.RunId
        CorrelationId    = $Context.CorrelationId
        EvidenceLevel    = $Context.EvidenceLevel
        TargetUPN        = $Context.TargetUPN
        # v1.5: Operator identity in every event for repudiation resistance
        OperatorUPN      = if ($Context.OperatorUPN)      { $Context.OperatorUPN }      else { $null }
        OperatorObjectId = if ($Context.OperatorObjectId) { $Context.OperatorObjectId } else { $null }
        TicketId         = if ($Context.TicketId)         { $Context.TicketId }         else { $null }
        TimestampUtc     = (Get-Date).ToUniversalTime().ToString('o')
        # Action identity
        ActionId         = [guid]::NewGuid().Guid
        Phase            = $Phase
        ActionName       = $ActionName
        Status           = $Status
        IsCritical       = $IsCritical
        Message          = $Message
        # Evidence payload
        BeforeState      = if ($BeforeState) { $BeforeState } else { @{} }
        AfterState       = if ($AfterState)  { $AfterState }  else { @{} }
        Evidence         = if ($Evidence)    { $Evidence }    else { @{} }
        # Control framing
        ControlObjective = $ControlObjective
        RiskMitigated    = $RiskMitigated
    }

    # Add to in-memory list
    $eventObj = [pscustomobject]$eventHt
    $Context.Evidence.Add($eventObj)

    if ($script:DecomEvidenceNdjsonPath) {
        Add-Content -Path $script:DecomEvidenceNdjsonPath `
            -Value ($eventHt | ConvertTo-Json -Depth 50 -Compress)
    }

    return $eventObj
}

# Write final manifest — call once at end of run
function Write-DecomEvidenceManifest {
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$OutputPath
    )
    $manifest = [ordered]@{
        SchemaVersion  = '1.0'
        RunId          = $Context.RunId
        CorrelationId  = $Context.CorrelationId
        TargetUPN      = $Context.TargetUPN
        OperatorUPN    = if ($Context.OperatorUPN) { $Context.OperatorUPN } else { $null }
        TicketId       = if ($Context.TicketId)    { $Context.TicketId }    else { $null }
        EventCount     = $Context.Evidence.Count
        GeneratedUtc   = (Get-Date).ToUniversalTime().ToString('o')
    }
    $manifestPath = Join-Path $OutputPath 'evidence.manifest.json'
    $manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -Encoding UTF8
    return $manifestPath
}

Export-ModuleMember -Function Initialize-DecomEvidenceStore, Add-DecomEvidenceEvent, Write-DecomEvidenceManifest
