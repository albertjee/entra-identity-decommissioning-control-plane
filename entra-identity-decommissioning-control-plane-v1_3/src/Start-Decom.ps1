# Start-Decom.ps1 — Launcher / workflow controller
# v1.2: ValidationOnly switch restored (was dropped in v1.1 — regression fix).
#        EvidenceLevel param restored.
#        CorrelationId and full Context contract restored.
#        Module load order: Models first, then consumers.

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$TargetUPN,

    [Parameter(Mandatory = $false)]
    [string]$OutOfOfficeMessage,

    [Parameter(Mandatory = $false)]
    [string]$TicketId,

    [ValidateSet('Standard','Detailed','Forensic')]
    [string]$EvidenceLevel = 'Forensic',

    [switch]$EnableLitigationHold,
    [switch]$RemoveLicenses,
    [switch]$ValidationOnly,
    [switch]$NonInteractive,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root        = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulesPath = Join-Path $Root 'Modules'

$moduleOrder = @(
    'Models','Logging','Evidence','State','Execution','Guardrails',
    'Auth','Validation','Discovery','Containment','Mailbox','Compliance','Licensing','Reporting'
)
foreach ($module in $moduleOrder) {
    Import-Module (Join-Path $ModulesPath "$module.psm1") -Force -DisableNameChecking
}
. (Join-Path $Root 'Invoke-DecomWorkflow.ps1')

$RunId      = [guid]::NewGuid().Guid
$OutputRoot = Join-Path (Join-Path (Split-Path $Root -Parent) 'output') $RunId
$null       = New-Item -ItemType Directory -Path $OutputRoot -Force
$LogFile    = Join-Path $OutputRoot 'run.log'
$EvidenceFile = Join-Path $OutputRoot 'evidence.ndjson'

Initialize-DecomLog -Path $LogFile

$Context = New-DecomRunContext `
    -TargetUPN      $TargetUPN `
    -TicketId       $TicketId `
    -OutputPath     $OutputRoot `
    -EvidenceLevel  $EvidenceLevel `
    -WhatIfMode:    ([bool]$WhatIfPreference) `
    -NonInteractive:$NonInteractive `
    -Force:         $Force `
    -ValidationOnly:$ValidationOnly

$State = New-DecomState -RunId $RunId
Initialize-DecomEvidenceStore -Context $Context -RunId $RunId

Write-DecomConsole -Level 'INFO' -Message "Entra Identity Decommissioning Control Plane v1.2"
Write-DecomConsole -Level 'INFO' -Message "Target: $TargetUPN | RunId: $RunId | Mode: $(if($ValidationOnly){'ValidationOnly'}elseif($WhatIfPreference){'WhatIf'}else{'Live'})"

try {
    $Result = Invoke-DecomWorkflow `
        -Context             $Context `
        -State               $State `
        -OutOfOfficeMessage  $OutOfOfficeMessage `
        -EnableLitigationHold:$EnableLitigationHold `
        -RemoveLicenses:     $RemoveLicenses `
        -Cmdlet              $PSCmdlet

    $JsonPath = Join-Path $OutputRoot 'report.json'
    $HtmlPath = Join-Path $OutputRoot 'report.html'
    Export-DecomJsonReport -WorkflowResult $Result -Path $JsonPath
    Export-DecomHtmlReport -WorkflowResult $Result -Path $HtmlPath

    Write-DecomConsole -Level 'INFO' -Message "Workflow completed. Output: $OutputRoot"
    if ($Result.StopReason) {
        Write-DecomConsole -Level 'WARN' -Message "Stop reason: $($Result.StopReason)"
        exit 2
    }
    exit 0

} catch {
    Write-DecomConsole -Level 'ERROR' -Message $_.Exception.Message
    exit 1
}
