# ComplianceRemediation.psm1 — Mailbox compliance controls
# Premium v2.0
#
# Functions:
#   Set-DecomLitigationHold — enable (default) or disable Litigation Hold
#
# Design:
#   Compliance controls are separated from mailbox forwarding (MailboxExtended)
#   because they operate under different permission boundaries and will grow
#   independently in v2.x (eDiscovery holds, retention policies, inactive
#   mailbox conversion).
#
#   SEQUENCING RULE (LOCKED — enforced by BatchOrchestrator):
#   Set-DecomLitigationHold MUST run BEFORE license removal.
#   Exchange Online Plan 2 (or E3/E5) license is required for LH.
#   Stripping the license first causes LH to fail silently or throw.
#
#   DEFAULT BEHAVIOUR:
#   ALL decommissioned users are placed on Litigation Hold by default.
#   Operator must explicitly pass -LitigationHold:$false to opt out.
#   This default is intentional and must not be changed without explicit
#   operator override in the batch policy file or at runtime.
#
#   FAILURE BEHAVIOUR (v2.0 policy):
#   If LH fails and -LitigationHold:$false was NOT passed, the result
#   is returned with Status = 'Warning'. The batch run continues.
#   License removal and all other steps proceed regardless.
#   The operator resolves LH manually post-run using the evidence report.
#   A WARNING status surfaces prominently in the batch summary HTML report.
#
#   APPROVAL GATE (v2.0):
#   Change record ID (e.g. CHG-12345) validated by format at runtime.
#   Operator attestation acceptable for v2.0. Live ITSM API lookup is
#   a v2.x enhancement. See README for details.
#
# Required EXO permissions:
#   Compliance Admin or Organization Management role
#   (Recipient Management is insufficient for Litigation Hold)
#
# Required EXO license on target mailbox:
#   Exchange Online Plan 2, Microsoft 365 E3, or Microsoft 365 E5
#
# PS7 compatible (v2.0 baseline)

#Requires -Version 7.0

Set-StrictMode -Version Latest

function Set-DecomLitigationHold {
    <#
    .SYNOPSIS
        Enables or disables Litigation Hold on the target mailbox.

    .DESCRIPTION
        Default behaviour: enables Litigation Hold on the target mailbox.
        Pass -LitigationHold:$false to explicitly disable (opt-out).

        SEQUENCING RULE: This function must always be called BEFORE license
        removal. Exchange Online Plan 2 or equivalent license is required for
        Litigation Hold. BatchOrchestrator enforces this order automatically.

        FAILURE BEHAVIOUR: If LH fails and the caller did not opt out via
        -LitigationHold:$false, the result is returned with Status = 'Warning'.
        The batch run continues. License removal and all remaining decommission
        steps proceed. The operator resolves LH manually post-run.

        A post-Set-Mailbox verification gate confirms the hold actually changed
        state. If the cmdlet succeeds but the hold state does not change (e.g.
        wrong license tier), a Warning is returned rather than a false Success.

        WhatIf-aware: logs intent but does not call Set-Mailbox when
        Context.WhatIf = true.

    .PARAMETER Context
        Premium DecomRunContext containing TargetUPN, WhatIf flag, and
        correlation identifiers.

    .PARAMETER LitigationHold
        Enable ($true, default) or disable ($false) Litigation Hold.
        Pass -LitigationHold:$false to opt out at runtime.
        Default: $true — all decommissioned users placed on hold.

    .PARAMETER LitigationHoldDuration
        Optional hold duration in days. Default: 0 (indefinite).
        Indefinite is the correct default for decommissioning scenarios.
        Only supply a value if your legal team has specified a retention window.

    .PARAMETER Cmdlet
        PSCmdlet reference for ShouldProcess support.

    .OUTPUTS
        [pscustomobject] DecomActionResult
        Status values:
          Success — hold state changed and verified
          Warning — cmdlet ran but hold state did not change (check license)
                  — or cmdlet threw (EXO error, replication lag, wrong perms)
          Skipped — mailbox already in target hold state, no change needed

    .EXAMPLE
        # Enable LH (default — no flag needed)
        Set-DecomLitigationHold -Context $ctx

    .EXAMPLE
        # Opt out of LH for this UPN
        Set-DecomLitigationHold -Context $ctx -LitigationHold:$false

    .EXAMPLE
        # Enable LH with 7-year retention window
        Set-DecomLitigationHold -Context $ctx -LitigationHoldDuration 2555
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [bool]$LitigationHold         = $true,
        [int]$LitigationHoldDuration  = 0,
        $Cmdlet
    )

    $phase      = 'Compliance'
    $actionName = 'Set Litigation Hold'

    try {
        # Snapshot before state
        $mbx = Get-EXOMailbox -Identity $Context.TargetUPN `
            -Property LitigationHoldEnabled, LitigationHoldDuration, LitigationHoldOwner `
            -ErrorAction Stop

        $before = @{
            LitigationHoldEnabled  = $mbx.LitigationHoldEnabled
            LitigationHoldDuration = $mbx.LitigationHoldDuration
            LitigationHoldOwner    = $mbx.LitigationHoldOwner
        }

        # Already in target state — skip cleanly (idempotent)
        if ($mbx.LitigationHoldEnabled -eq $LitigationHold) {
            $state = if ($LitigationHold) { 'already enabled' } else { 'already disabled' }
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Skipped' -IsCritical $true -TargetUPN $Context.TargetUPN `
                -Message "Litigation Hold $state on '$($Context.TargetUPN)' — no change required." `
                -Evidence $before `
                -ControlObjective 'Preserve mailbox content for legal and compliance purposes' `
                -RiskMitigated 'Evidence destruction, eDiscovery failure, regulatory breach'
        }

        # WhatIf — log intent only
        if ($Context.WhatIf) {
            $intent = if ($LitigationHold) { 'enable' } else { 'disable' }
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN `
                -Message "[WhatIf] Would $intent Litigation Hold on '$($Context.TargetUPN)'." `
                -BeforeState $before `
                -AfterState  @{ LitigationHoldEnabled = $LitigationHold } `
                -ControlObjective 'Preserve mailbox content for legal and compliance purposes' `
                -RiskMitigated 'Evidence destruction, eDiscovery failure, regulatory breach'
        }

        # Build Set-Mailbox params
        $setParams = @{
            Identity              = $Context.TargetUPN
            LitigationHoldEnabled = $LitigationHold
        }

        if ($LitigationHold -and $LitigationHoldDuration -gt 0) {
            $setParams['LitigationHoldDuration'] = $LitigationHoldDuration
        }

        # Use retry wrapper for EXO replication lag resilience
        _InvokeExoWithRetry -Params $setParams

        # Verification gate — confirm hold state actually changed
        $mbxAfter = Get-EXOMailbox -Identity $Context.TargetUPN `
            -Property LitigationHoldEnabled, LitigationHoldDuration `
            -ErrorAction Stop

        $after = @{
            LitigationHoldEnabled  = $mbxAfter.LitigationHoldEnabled
            LitigationHoldDuration = $mbxAfter.LitigationHoldDuration
        }

        if ($mbxAfter.LitigationHoldEnabled -ne $LitigationHold) {
            # Cmdlet ran but hold did not take effect — likely wrong license tier
            $warnMsg = 'Set-Mailbox completed but LitigationHoldEnabled did not reach ' +
                       'expected state. Verify target mailbox has Exchange Online Plan 2 ' +
                       'or equivalent license. Operator review required.'

            Add-DecomEvidenceEvent -Context $Context -Phase $phase `
                -ActionName $actionName -Status 'Warning' -IsCritical $true `
                -Message $warnMsg -BeforeState $before -AfterState $after `
                -ControlObjective 'Preserve mailbox content for legal and compliance purposes' `
                -RiskMitigated 'Evidence destruction, eDiscovery failure, regulatory breach' | Out-Null

            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Warning' -IsCritical $true -TargetUPN $Context.TargetUPN `
                -Message $warnMsg -BeforeState $before -AfterState $after `
                -ControlObjective 'Preserve mailbox content for legal and compliance purposes' `
                -RiskMitigated 'Evidence destruction, eDiscovery failure, regulatory breach'
        }

        $action = if ($LitigationHold) { 'enabled' } else { 'disabled' }

        Add-DecomEvidenceEvent -Context $Context -Phase $phase `
            -ActionName $actionName -Status 'Success' -IsCritical $true `
            -Message "Litigation Hold $action on '$($Context.TargetUPN)'." `
            -BeforeState $before -AfterState $after `
            -ControlObjective 'Preserve mailbox content for legal and compliance purposes' `
            -RiskMitigated 'Evidence destruction, eDiscovery failure, regulatory breach' | Out-Null

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message "Litigation Hold $action successfully on '$($Context.TargetUPN)'." `
            -BeforeState $before -AfterState $after `
            -ControlObjective 'Preserve mailbox content for legal and compliance purposes' `
            -RiskMitigated 'Evidence destruction, eDiscovery failure, regulatory breach'

    } catch {
        # Log Warning and continue — v2.0 failure policy for LH
        $errMsg = "Litigation Hold operation failed for '$($Context.TargetUPN)': $($_.Exception.Message)"

        Add-DecomEvidenceEvent -Context $Context -Phase $phase `
            -ActionName $actionName -Status 'Warning' -IsCritical $true `
            -Message $errMsg `
            -ControlObjective 'Preserve mailbox content for legal and compliance purposes' `
            -RiskMitigated 'Evidence destruction, eDiscovery failure, regulatory breach' | Out-Null

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Warning' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message $errMsg -FailureClass 'ExchangeComplianceError' `
            -ControlObjective 'Preserve mailbox content for legal and compliance purposes' `
            -RiskMitigated 'Evidence destruction, eDiscovery failure, regulatory breach'
    }
}

# ── Private helpers ────────────────────────────────────────────────────────────

function _InvokeExoWithRetry {
    # Wraps Set-Mailbox with a retry loop to handle EXO replication lag.
    # Exchange Online may not have synced identity state after Entra session
    # termination, causing transient errors on first attempt.
    param(
        [hashtable]$Params,
        [int]$MaxAttempts  = 3,
        [int]$DelaySeconds = 15
    )
    $attempt = 0
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            Set-Mailbox @Params -ErrorAction Stop
            return
        } catch {
            $msg         = $_.Exception.Message
            $isTransient = ($msg -match 'ManagementObjectNotFoundException' -or
                            $msg -match 'WriteErrorException'               -or
                            $msg -match 'temporarily unavailable'           -or
                            $msg -match 'couldn''t be found')
            if ($isTransient -and $attempt -lt $MaxAttempts) {
                Start-Sleep -Seconds $DelaySeconds
            } else {
                throw
            }
        }
    }
}

Export-ModuleMember -Function Set-DecomLitigationHold
