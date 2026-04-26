# MailboxExtended.psm1 — Mail forwarding control
# Premium v2.0
#
# Functions:
#   Get-DecomMailForwardingState — snapshot current forwarding state
#   Set-DecomMailForwarding      — configure or clear mail forwarding
#   Remove-DecomMailForwarding   — explicitly clear all forwarding settings
#
# Note: Litigation Hold moved to ComplianceRemediation.psm1
#
# Design:
#   Lite Discovery.psm1 captures forwarding as evidence (snapshot-only).
#   This module adds the mutation layer — allowing Premium to actually
#   set or clear ForwardingSmtpAddress and ForwardingAddress as part of
#   an automated offboarding run.
#
#   Forwarding decisions are policy-driven — this module does NOT decide
#   where to forward. The caller (BatchOrchestrator or policy file) supplies
#   the forwarding target. Clearing forwarding is always safe to automate.
#
# Required EXO permissions:
#   Recipient Management role or equivalent
#
# PS7 compatible (v2.1 baseline)

#Requires -Version 7.0

Set-StrictMode -Version Latest

function Get-DecomMailForwardingState {
    <#
    .SYNOPSIS
        Returns current mail forwarding state for a UPN as a structured object.

    .OUTPUTS
        [pscustomobject] with ForwardingSmtpAddress, ForwardingAddress,
        DeliverToMailboxAndForward, RecipientTypeDetails
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context
    )

    try {
        $mbx = Get-EXOMailbox -Identity $Context.TargetUPN `
            -Property ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward, RecipientTypeDetails `
            -ErrorAction Stop

        return [pscustomobject]@{
            ForwardingSmtpAddress      = $mbx.ForwardingSmtpAddress
            ForwardingAddress          = $mbx.ForwardingAddress
            DeliverToMailboxAndForward = $mbx.DeliverToMailboxAndForward
            RecipientTypeDetails       = $mbx.RecipientTypeDetails
            IsForwardingActive         = ($null -ne $mbx.ForwardingSmtpAddress -or
                                          $null -ne $mbx.ForwardingAddress)
        }
    } catch {
        throw "Get-DecomMailForwardingState: failed to read mailbox for '$($Context.TargetUPN)': $($_.Exception.Message)"
    }
}

function Set-DecomMailForwarding {
    <#
    .SYNOPSIS
        Configures mail forwarding on the target mailbox.

    .DESCRIPTION
        Sets ForwardingSmtpAddress (external SMTP) or ForwardingAddress
        (internal recipient) on the mailbox. Only one can be active at a time —
        if both are supplied, ForwardingSmtpAddress takes precedence and
        ForwardingAddress is cleared.

        DeliverToMailboxAndForward controls whether a copy stays in the mailbox.
        Default is $false (forward only, no local copy) which is the correct
        behaviour for offboarding.

        WhatIf-aware: logs intent but does not call Set-Mailbox when
        Context.WhatIf = true.

    .PARAMETER Context
        Lite DecomRunContext.

    .PARAMETER ForwardToSmtp
        External SMTP address to forward to (e.g. manager@contoso.com).

    .PARAMETER ForwardToRecipient
        Internal recipient display name or alias to forward to.

    .PARAMETER DeliverToMailboxAndForward
        Keep a copy in the mailbox AND forward. Default: $false.

    .PARAMETER Cmdlet
        PSCmdlet for ShouldProcess.

    .OUTPUTS
        [pscustomobject] DecomActionResult
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [string]$ForwardToSmtp,
        [string]$ForwardToRecipient,
        [bool]$DeliverToMailboxAndForward = $false,
        $Cmdlet
    )

    $phase      = 'Mailbox'
    $actionName = 'Set Mail Forwarding'

    if (-not $ForwardToSmtp -and -not $ForwardToRecipient) {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message 'No forwarding target supplied — skipped.' `
            -ControlObjective 'Configure mail forwarding for business continuity' `
            -RiskMitigated 'Missed business communications post-offboard'
    }

    try {
        $before = Get-DecomMailForwardingState -Context $Context

        if ($Context.WhatIf) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "[WhatIf] Would set forwarding to: $(if($ForwardToSmtp){$ForwardToSmtp}else{$ForwardToRecipient})" `
                -BeforeState @{
                    ForwardingSmtpAddress = $before.ForwardingSmtpAddress
                    ForwardingAddress     = $before.ForwardingAddress
                } `
                -AfterState @{
                    ForwardingSmtpAddress = $ForwardToSmtp
                    ForwardingAddress     = $ForwardToRecipient
                    DeliverAndForward     = $DeliverToMailboxAndForward
                } `
                -ControlObjective 'Configure mail forwarding for business continuity' `
                -RiskMitigated 'Missed business communications post-offboard'
        }

        $setParams = @{
            Identity                   = $Context.TargetUPN
            DeliverToMailboxAndForward = $DeliverToMailboxAndForward
        }

        if ($ForwardToSmtp) {
            $setParams['ForwardingSmtpAddress'] = $ForwardToSmtp
            $setParams['ForwardingAddress']     = $null   # clear internal if setting SMTP
        } else {
            $setParams['ForwardingAddress']     = $ForwardToRecipient
            $setParams['ForwardingSmtpAddress'] = $null   # clear SMTP if setting internal
        }

        _InvokeSetMailboxWithRetry -Params $setParams

        $after = Get-DecomMailForwardingState -Context $Context

        Add-DecomEvidenceEvent -Context $Context -Phase $phase `
            -ActionName $actionName -Status 'Success' -IsCritical $false `
            -Message "Mail forwarding set to: $(if($ForwardToSmtp){$ForwardToSmtp}else{$ForwardToRecipient})" `
            -BeforeState @{
                ForwardingSmtpAddress = $before.ForwardingSmtpAddress
                ForwardingAddress     = $before.ForwardingAddress
            } `
            -AfterState @{
                ForwardingSmtpAddress = $after.ForwardingSmtpAddress
                ForwardingAddress     = $after.ForwardingAddress
                DeliverAndForward     = $after.DeliverToMailboxAndForward
            } `
            -ControlObjective 'Configure mail forwarding for business continuity' `
            -RiskMitigated 'Missed business communications post-offboard' | Out-Null

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "Mail forwarding configured to: $(if($ForwardToSmtp){$ForwardToSmtp}else{$ForwardToRecipient})" `
            -BeforeState @{ ForwardingSmtpAddress = $before.ForwardingSmtpAddress; ForwardingAddress = $before.ForwardingAddress } `
            -AfterState  @{ ForwardingSmtpAddress = $after.ForwardingSmtpAddress;  ForwardingAddress = $after.ForwardingAddress } `
            -ControlObjective 'Configure mail forwarding for business continuity' `
            -RiskMitigated 'Missed business communications post-offboard'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Failed' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "Mail forwarding configuration failed: $($_.Exception.Message)" `
            -FailureClass 'ExchangeError' `
            -ControlObjective 'Configure mail forwarding for business continuity' `
            -RiskMitigated 'Missed business communications post-offboard'
    }
}

function Remove-DecomMailForwarding {
    <#
    .SYNOPSIS
        Clears all mail forwarding settings from the target mailbox.

    .DESCRIPTION
        Sets ForwardingSmtpAddress = $null, ForwardingAddress = $null,
        DeliverToMailboxAndForward = $false.

        Safe to call even if no forwarding is configured — returns Skipped.
        WhatIf-aware.

    .PARAMETER Context
        Lite DecomRunContext.

    .PARAMETER Cmdlet
        PSCmdlet for ShouldProcess.

    .OUTPUTS
        [pscustomobject] DecomActionResult
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        $Cmdlet
    )

    $phase      = 'Mailbox'
    $actionName = 'Remove Mail Forwarding'

    try {
        $before = Get-DecomMailForwardingState -Context $Context

        if (-not $before.IsForwardingActive) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message 'No active mail forwarding found — nothing to clear.' `
                -Evidence @{ ForwardingWasActive = $false } `
                -ControlObjective 'Clear mail forwarding to prevent data leakage' `
                -RiskMitigated 'Continued mail flow to unauthorised recipient'
        }

        if ($Context.WhatIf) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "[WhatIf] Would clear forwarding: SMTP=$($before.ForwardingSmtpAddress) Internal=$($before.ForwardingAddress)" `
                -BeforeState @{ ForwardingSmtpAddress = $before.ForwardingSmtpAddress; ForwardingAddress = $before.ForwardingAddress } `
                -AfterState  @{ ForwardingSmtpAddress = $null; ForwardingAddress = $null } `
                -ControlObjective 'Clear mail forwarding to prevent data leakage' `
                -RiskMitigated 'Continued mail flow to unauthorised recipient'
        }

        _InvokeSetMailboxWithRetry -Params @{
            Identity                    = $Context.TargetUPN
            ForwardingSmtpAddress       = $null
            ForwardingAddress           = $null
            DeliverToMailboxAndForward  = $false
        }

        Add-DecomEvidenceEvent -Context $Context -Phase $phase `
            -ActionName $actionName -Status 'Success' -IsCritical $false `
            -Message 'Mail forwarding cleared.' `
            -BeforeState @{ ForwardingSmtpAddress = $before.ForwardingSmtpAddress; ForwardingAddress = $before.ForwardingAddress } `
            -AfterState  @{ ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverAndForward = $false } `
            -ControlObjective 'Clear mail forwarding to prevent data leakage' `
            -RiskMitigated 'Continued mail flow to unauthorised recipient' | Out-Null

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "Mail forwarding cleared. Was: SMTP=$($before.ForwardingSmtpAddress) Internal=$($before.ForwardingAddress)" `
            -BeforeState @{ ForwardingSmtpAddress = $before.ForwardingSmtpAddress; ForwardingAddress = $before.ForwardingAddress } `
            -AfterState  @{ ForwardingSmtpAddress = $null; ForwardingAddress = $null } `
            -ControlObjective 'Clear mail forwarding to prevent data leakage' `
            -RiskMitigated 'Continued mail flow to unauthorised recipient'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Failed' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "Mail forwarding removal failed: $($_.Exception.Message)" `
            -FailureClass 'ExchangeError' `
            -ControlObjective 'Clear mail forwarding to prevent data leakage' `
            -RiskMitigated 'Continued mail flow to unauthorised recipient'
    }
}

function _InvokeSetMailboxWithRetry {
    # Wraps Set-Mailbox with a retry loop to handle EXO replication lag after
    # Entra ID session termination. Exchange Online may not have synced the
    # identity state yet, causing transient ManagementObjectNotFoundException
    # or WriteErrorException on the first attempt.
    param(
        [hashtable]$Params,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 15
    )
    $attempt = 0
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            Set-Mailbox @Params -ErrorAction Stop
            return
        } catch {
            $msg = $_.Exception.Message
            $isTransient = ($msg -match 'ManagementObjectNotFoundException' -or
                            $msg -match 'WriteErrorException' -or
                            $msg -match 'temporarily unavailable' -or
                            $msg -match 'couldn''t be found')
            if ($isTransient -and $attempt -lt $MaxAttempts) {
                Start-Sleep -Seconds $DelaySeconds
            } else {
                throw
            }
        }
    }
}

Export-ModuleMember -Function `
    Get-DecomMailForwardingState, `
    Set-DecomMailForwarding, `
    Remove-DecomMailForwarding, `
