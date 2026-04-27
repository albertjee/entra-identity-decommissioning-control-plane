# Execution.psm1 — Phase engine and call wrappers
# v1.2: Invoke-DecomPhase restored to this module (was incorrectly moved into
#        Invoke-DecomWorkflow.ps1 in v1.1 — separation of concerns fix).
#        Invoke-DecomGraphCall / Invoke-DecomExchangeCall retain try/catch context
#        wrappers — available for callers that want structured error enrichment.

# Set-DecomPhaseState is defined in State.psm1 — import it so Invoke-DecomPhase
# can call it regardless of module load order in the caller's session.
$script:stateMod = Join-Path $PSScriptRoot 'State.psm1'
if (Test-Path $script:stateMod) {
    Import-Module $script:stateMod -Force -DisableNameChecking
}

function Invoke-DecomPhase {
    param(
        [pscustomobject]$State,
        [string]$Phase,
        [scriptblock]$ScriptBlock
    )
    Set-DecomPhaseState -State $State -Phase $Phase -Status 'InProgress'
    try {
        & $ScriptBlock
        Set-DecomPhaseState -State $State -Phase $Phase -Status 'Completed'
    } catch {
        Set-DecomPhaseState -State $State -Phase $Phase -Status 'Failed'
        throw
    }
}

function Invoke-DecomGraphCall {
    param([scriptblock]$ScriptBlock, [string]$OperationName)
    try { & $ScriptBlock }
    catch { throw "Graph operation failed [$OperationName]: $($_.Exception.Message)" }
}

function Invoke-DecomExchangeCall {
    param([scriptblock]$ScriptBlock, [string]$OperationName)
    try { & $ScriptBlock }
    catch { throw "Exchange operation failed [$OperationName]: $($_.Exception.Message)" }
}

Export-ModuleMember -Function Invoke-DecomPhase, Invoke-DecomGraphCall, Invoke-DecomExchangeCall
