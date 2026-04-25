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

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulesPath = Join-Path $Root 'Modules'

$moduleOrder = @(
    'Models','Logging','Evidence','State','Execution','Auth','Validation','Guardrails',
    'Discovery','Containment','Mailbox','Compliance','Licensing','Reporting'
)
foreach ($module in $moduleOrder) {
    Import-Module (Join-Path $ModulesPath "$module.psm1") -Force -DisableNameChecking
}
. (Join-Path $Root 'Invoke-DecomWorkflow.ps1')

$RunId = [guid]::NewGuid().Guid
$OutputRoot = Join-Path (Join-Path (Split-Path $Root -Parent) 'output') $RunId
$null = New-Item -ItemType Directory -Path $OutputRoot -Force
$LogFile = Join-Path $OutputRoot 'run.log'
$EvidenceFile = Join-Path $OutputRoot 'evidence.ndjson'

Initialize-DecomLog -Path $LogFile
Initialize-DecomEvidenceStore -Path $EvidenceFile

$Context = New-DecomRunContext `
    -TargetUPN $TargetUPN `
    -TicketId $TicketId `
    -OutputPath $OutputRoot `
    -EvidenceLevel $EvidenceLevel `
    -WhatIfMode:([bool]$WhatIfPreference) `
    -NonInteractive:$NonInteractive `
    -Force:$Force `
    -ValidationOnly:$ValidationOnly

$State = New-DecomState -RunId $RunId
Write-DecomConsole -Level 'INFO' -Message "Starting Entra identity decommissioning workflow for $TargetUPN. RunId=$RunId"

try {
    $Result = Invoke-DecomWorkflow `
        -Context $Context `
        -State $State `
        -OutOfOfficeMessage $OutOfOfficeMessage `
        -EnableLitigationHold:$EnableLitigationHold `
        -RemoveLicenses:$RemoveLicenses `
        -Cmdlet $PSCmdlet

    $JsonPath = Join-Path $OutputRoot 'report.json'
    $HtmlPath = Join-Path $OutputRoot 'report.html'
    Export-DecomJsonReport -WorkflowResult $Result -Path $JsonPath
    Export-DecomHtmlReport -WorkflowResult $Result -Path $HtmlPath

    Write-DecomConsole -Level 'INFO' -Message "Workflow completed. OutputPath=$OutputRoot"
    if ($Result.StopReason) { exit 2 }
    exit 0
}
catch {
    Write-DecomConsole -Level 'ERROR' -Message $_.Exception.Message
    Add-DecomEvidenceEvent -Context $Context -Phase 'Fatal' -ActionName 'Unhandled Exception' -Status 'Failed' -IsCritical $true -Message $_.Exception.Message -ErrorRecord $_
    throw
}
