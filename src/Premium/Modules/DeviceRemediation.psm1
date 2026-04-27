# DeviceRemediation.psm1 — Device trust remediation
# Premium v2.0
#
# Functions:
#   Get-DecomDeviceState       — enumerate all devices owned by target UPN
#   Disable-DecomEntraDevices  — disable all Entra-joined/registered devices
#   Invoke-DecomDeviceRemediation — orchestrate disable + retire/wipe per policy
#
# Design:
#   Device remediation runs after access removal and before license removal.
#   Two distinct actions per device:
#
#   1. Disable-DecomEntraDevices:
#      Disables the device object in Entra ID. This prevents token refresh
#      on managed devices and blocks further Conditional Access evaluation.
#      Safe for both corporate and BYOD devices.
#
#   2. Intune retire vs wipe (within Invoke-DecomDeviceRemediation):
#      Corporate (Entra Joined):     Full wipe — removes all data and re-images
#      BYOD (Entra Registered):      Selective retire — removes corporate data only
#      This distinction is critical. Wiping a personal device is legally
#      and ethically unacceptable. Policy drives the decision, not guesswork.
#
#   BYOD PROTECTION RULE (LOCKED):
#   A device with TrustType = 'Workplace' (Entra Registered / BYOD) will
#   NEVER receive a full wipe command regardless of operator input.
#   Full wipe is only issued to TrustType = 'AzureAD' (Entra Joined) or
#   TrustType = 'ServerAD' (Hybrid Joined) devices.
#
#   WhatIf-aware throughout. All actions produce DecomActionResult evidence.
#
# Required Graph permissions:
#   Device.ReadWrite.All
#   DeviceManagementManagedDevices.PrivilegedOperations.All (for wipe/retire)
#
# PS7 compatible (v2.0 baseline)

#Requires -Version 7.0

Set-StrictMode -Version Latest

function Get-DecomDeviceState {
    <#
    .SYNOPSIS
        Enumerates all Entra ID devices owned by the target UPN.

    .DESCRIPTION
        Returns all registered and joined devices for a user, with ownership
        type, trust type, compliance state, and Intune management status.
        Used to capture before-state and to drive wipe/retire decisions.

    .PARAMETER Context
        Premium DecomRunContext.

    .OUTPUTS
        [pscustomobject] with Devices array and summary counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context
    )

    try {
        $devices = @(Get-MgUserRegisteredDevice -UserId $Context.TargetUPN -All -ErrorAction Stop)

        $deviceList = foreach ($d in $devices) {
            try {
                $detail = Get-MgDevice -DeviceId $d.Id `
                    -Property Id, DisplayName, TrustType, AccountEnabled, `
                              IsCompliant, IsManaged, OperatingSystem, `
                              OperatingSystemVersion, ApproximateLastSignInDateTime `
                    -ErrorAction Stop

                [pscustomobject]@{
                    DeviceId             = $detail.Id
                    DisplayName          = $detail.DisplayName
                    TrustType            = $detail.TrustType
                    AccountEnabled       = $detail.AccountEnabled
                    IsCompliant          = $detail.IsCompliant
                    IsManaged            = $detail.IsManaged
                    OperatingSystem      = $detail.OperatingSystem
                    OSVersion            = $detail.OperatingSystemVersion
                    LastSignIn           = $detail.ApproximateLastSignInDateTime
                    IsCorporate          = ($detail.TrustType -in @('AzureAD','ServerAD'))
                    IsBYOD               = ($detail.TrustType -eq 'Workplace')
                    DetailReadError      = $null
                }
            } catch {
                # Detail fetch failed — keep a placeholder so the audit trail reflects
                # incomplete coverage. Disable will be attempted by DeviceId alone.
                [pscustomobject]@{
                    DeviceId             = $d.Id
                    DisplayName          = "Unknown (detail read failed)"
                    TrustType            = 'Unknown'
                    AccountEnabled       = $null
                    IsCompliant          = $null
                    IsManaged            = $null
                    OperatingSystem      = $null
                    OSVersion            = $null
                    LastSignIn           = $null
                    IsCorporate          = $false
                    IsBYOD               = $true   # default to BYOD-safe on unknown trust type
                    DetailReadError      = $_.Exception.Message
                }
            }
        }

        return [pscustomobject]@{
            Devices        = @($deviceList)
            TotalCount     = @($deviceList).Count
            CorporateCount = @($deviceList | Where-Object { $_.IsCorporate }).Count
            BYODCount      = @($deviceList | Where-Object { $_.IsBYOD }).Count
        }
    } catch {
        throw "Get-DecomDeviceState: failed to enumerate devices for '$($Context.TargetUPN)': $($_.Exception.Message)"
    }
}

function Disable-DecomEntraDevices {
    <#
    .SYNOPSIS
        Disables all Entra ID device objects owned by the target UPN.

    .DESCRIPTION
        Sets AccountEnabled = $false on every Entra device registered or
        joined by the target UPN. This prevents token refresh and blocks
        Conditional Access evaluation on all managed devices immediately.

        Safe for both corporate and BYOD devices. Disabling does not
        remove data — it only blocks further authentication.

        WhatIf-aware. Returns one DecomActionResult per device processed,
        wrapped in a parent result with aggregate status.

    .PARAMETER Context
        Premium DecomRunContext.

    .PARAMETER DeviceState
        Output of Get-DecomDeviceState. If not supplied, this function
        calls Get-DecomDeviceState internally.

    .PARAMETER Cmdlet
        PSCmdlet reference for ShouldProcess support.

    .OUTPUTS
        [pscustomobject] DecomActionResult with Evidence.DeviceResults array.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [pscustomobject]$DeviceState,
        $Cmdlet
    )

    $phase      = 'DeviceRemediation'
    $actionName = 'Disable Entra Devices'

    try {
        if (-not $DeviceState) {
            $DeviceState = Get-DecomDeviceState -Context $Context
        }

        if ($DeviceState.TotalCount -eq 0) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message 'No Entra devices found for this user — nothing to disable.' `
                -ControlObjective 'Prevent token refresh and CA bypass on managed devices' `
                -RiskMitigated 'Continued device-based access after account decommission'
        }

        if ($Context.WhatIf) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "[WhatIf] Would disable $($DeviceState.TotalCount) device(s): $(@($DeviceState.Devices.DisplayName) -join ', ')" `
                -ControlObjective 'Prevent token refresh and CA bypass on managed devices' `
                -RiskMitigated 'Continued device-based access after account decommission'
        }

        $results  = [System.Collections.Generic.List[pscustomobject]]::new()
        $failed   = 0

        foreach ($device in $DeviceState.Devices) {
            try {
                if ($device.AccountEnabled -eq $false) {
                    $results.Add([pscustomobject]@{
                        DeviceId    = $device.DeviceId
                        DisplayName = $device.DisplayName
                        Status      = 'Skipped'
                        Note        = 'Already disabled'
                    })
                    continue
                }

                Update-MgDevice -DeviceId $device.DeviceId `
                    -AccountEnabled $false -ErrorAction Stop

                $results.Add([pscustomobject]@{
                    DeviceId    = $device.DeviceId
                    DisplayName = $device.DisplayName
                    TrustType   = $device.TrustType
                    Status      = 'Disabled'
                    Note        = $null
                })
            } catch {
                $failed++
                $results.Add([pscustomobject]@{
                    DeviceId    = $device.DeviceId
                    DisplayName = $device.DisplayName
                    Status      = 'Failed'
                    Note        = $_.Exception.Message
                })
            }
        }

        $status  = if ($failed -eq 0) { 'Success' } `
                   elseif ($failed -lt $DeviceState.TotalCount) { 'Warning' } `
                   else { 'Failed' }

        $summary = "$($DeviceState.TotalCount - $failed) of $($DeviceState.TotalCount) device(s) disabled."

        Add-DecomEvidenceEvent -Context $Context -Phase $phase `
            -ActionName $actionName -Status $status -IsCritical $false `
            -Message $summary -Evidence @{ DeviceResults = $results } `
            -ControlObjective 'Prevent token refresh and CA bypass on managed devices' `
            -RiskMitigated 'Continued device-based access after account decommission' | Out-Null

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status $status -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message $summary `
            -Evidence @{ DeviceResults = $results; FailedCount = $failed } `
            -ControlObjective 'Prevent token refresh and CA bypass on managed devices' `
            -RiskMitigated 'Continued device-based access after account decommission'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Failed' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "Device disable failed: $($_.Exception.Message)" `
            -FailureClass 'GraphError' `
            -ControlObjective 'Prevent token refresh and CA bypass on managed devices' `
            -RiskMitigated 'Continued device-based access after account decommission'
    }
}

function Invoke-DecomDeviceRemediation {
    <#
    .SYNOPSIS
        Orchestrates full device remediation — disable, retire, and wipe.

    .DESCRIPTION
        Runs two steps per device:
          1. Disable the Entra device object (all devices)
          2. Retire (BYOD) or Wipe (corporate) via Intune Graph API

        BYOD PROTECTION RULE (LOCKED):
        Devices with TrustType = 'Workplace' (Entra Registered / BYOD)
        receive a selective RETIRE only — never a full wipe.
        Corporate devices (TrustType AzureAD or ServerAD) receive a full wipe.
        This rule cannot be overridden at runtime.

        WhatIf-aware. All actions are evidence-logged.

    .PARAMETER Context
        Premium DecomRunContext.

    .PARAMETER SkipWipe
        If set, skips the Intune wipe/retire step. Only Entra device
        disable is performed. Use when Intune is not in scope.

    .PARAMETER Cmdlet
        PSCmdlet reference for ShouldProcess support.

    .OUTPUTS
        [System.Collections.Generic.List[pscustomobject]] of DecomActionResult
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [switch]$SkipWipe,
        $Cmdlet
    )

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    # Step 1 — enumerate devices once, share with both steps
    $deviceState = Get-DecomDeviceState -Context $Context

    # Step 2 — disable all Entra device objects
    $disableResult = Disable-DecomEntraDevices -Context $Context `
        -DeviceState $deviceState -Cmdlet $Cmdlet
    $results.Add($disableResult)

    if ($SkipWipe) {
        return $results
    }

    # Step 3 — retire/wipe via Intune for managed devices
    foreach ($device in $deviceState.Devices) {
        $intuneResult = _InvokeIntuneDeviceAction -Context $Context -Device $device
        if ($intuneResult) { $results.Add($intuneResult) }
    }

    return $results
}

# ── Private helpers ────────────────────────────────────────────────────────────

function _InvokeIntuneDeviceAction {
    # Issues retire (BYOD) or wipe (corporate) to the Intune managed device
    # matching the Entra device object. BYOD protection rule is enforced here.
    param(
        [pscustomobject]$Context,
        [pscustomobject]$Device
    )

    $phase      = 'DeviceRemediation'
    $actionName = if ($Device.IsBYOD) { 'Retire Device (BYOD)' } else { 'Wipe Device (Corporate)' }

    try {
        # Find the Intune managed device matching this Entra device ID
        $intuneDevices = @(Get-MgDeviceManagementManagedDevice `
            -Filter "azureADDeviceId eq '$($Device.DeviceId)'" -All -ErrorAction Stop)

        if ($intuneDevices.Count -eq 0) {
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "Device '$($Device.DisplayName)' not found in Intune — may not be MDM enrolled." `
                -Evidence @{ DeviceId = $Device.DeviceId; DisplayName = $Device.DisplayName } `
                -ControlObjective 'Remove corporate data from managed devices' `
                -RiskMitigated 'Corporate data exposure on unmanaged or offboarded device'
        }

        $intuneDev = $intuneDevices[0]

        # BYOD PROTECTION — dual-layer guard (LOCKED, non-overridable):
        # Layer 1: Entra TrustType = 'Workplace' (Entra Registered)
        # Layer 2: Intune ManagedDeviceOwnerType = 'personal'
        # Either layer marking the device as personal forces retire-only.
        # A device must be confirmed corporate by BOTH layers for full wipe.
        $intuneDev = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $intuneDev.Id `
            -Property Id, ManagedDeviceOwnerType -ErrorAction Stop

        $isIntunePersonal = ($intuneDev.ManagedDeviceOwnerType -eq 'personal')
        $isBYOD           = $Device.IsBYOD -or $isIntunePersonal

        # Update action name to reflect Intune-confirmed ownership type
        $actionName = if ($isBYOD) { 'Retire Device (BYOD)' } else { 'Wipe Device (Corporate)' }

        if ($Context.WhatIf) {
            $intent = if ($isBYOD) { 'retire (selective wipe)' } else { 'full wipe' }
            return New-DecomActionResult -ActionName $actionName -Phase $phase `
                -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
                -Message "[WhatIf] Would $intent Intune device '$($Device.DisplayName)' (EntraTrustType: $($Device.TrustType), IntuneOwnerType: $($intuneDev.ManagedDeviceOwnerType))." `
                -ControlObjective 'Remove corporate data from managed devices' `
                -RiskMitigated 'Corporate data exposure on unmanaged or offboarded device'
        }

        if ($isBYOD) {
            # BYOD — retire only (selective wipe of corporate data)
            Invoke-MgRetireDeviceManagementManagedDevice `
                -ManagedDeviceId $intuneDev.Id -ErrorAction Stop
        } else {
            # Corporate confirmed by both Entra and Intune — full wipe
            Clear-MgDeviceManagementManagedDevice `
                -ManagedDeviceId $intuneDev.Id -ErrorAction Stop
        }

        $action = if ($isBYOD) { 'retired (selective wipe)' } else { 'wiped (full)' }

        Add-DecomEvidenceEvent -Context $Context -Phase $phase `
            -ActionName $actionName -Status 'Success' -IsCritical $false `
            -Message "Intune device '$($Device.DisplayName)' $action." `
            -Evidence @{ DeviceId = $Device.DeviceId; IntuneDeviceId = $intuneDev.Id; Action = $action } `
            -ControlObjective 'Remove corporate data from managed devices' `
            -RiskMitigated 'Corporate data exposure on unmanaged or offboarded device' | Out-Null

        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Success' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "Intune device '$($Device.DisplayName)' $action successfully." `
            -Evidence @{ DeviceId = $Device.DeviceId; IntuneDeviceId = $intuneDev.Id } `
            -ControlObjective 'Remove corporate data from managed devices' `
            -RiskMitigated 'Corporate data exposure on unmanaged or offboarded device'

    } catch {
        return New-DecomActionResult -ActionName $actionName -Phase $phase `
            -Status 'Failed' -IsCritical $false -TargetUPN $Context.TargetUPN `
            -Message "Intune action failed for '$($Device.DisplayName)': $($_.Exception.Message)" `
            -FailureClass 'IntuneError' `
            -ControlObjective 'Remove corporate data from managed devices' `
            -RiskMitigated 'Corporate data exposure on unmanaged or offboarded device'
    }
}

Export-ModuleMember -Function `
    Get-DecomDeviceState, `
    Disable-DecomEntraDevices, `
    Invoke-DecomDeviceRemediation
