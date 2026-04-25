function Test-DecomLicenseRemovalReadiness {
    [CmdletBinding()]
    param([object[]]$Results,[pscustomobject]$Context)
    $blockers=@(); $warnings=@()
    $mailbox=$Results|Where-Object {$_.ActionName -eq 'Convert Mailbox To Shared'}|Select-Object -Last 1
    $compliance=$Results|Where-Object {$_.ActionName -eq 'Evaluate Compliance State'}|Select-Object -Last 1
    if(-not $mailbox -or $mailbox.Status -ne 'Success'){ $blockers+='Mailbox must be converted to shared before license removal.' }
    if($compliance){
        if($compliance.Evidence.ArchiveStatus -and $compliance.Evidence.ArchiveStatus -ne 'None'){ $blockers+='Archive mailbox detected; tenant-specific archive/retention validation required before license removal.' }
        if($compliance.Evidence.InPlaceHoldCount -gt 0){ $warnings+='Hold indicators detected; confirm Purview/eDiscovery requirements.' }
    } else { $warnings+='Compliance state was not evaluated.' }
    try { $u=Get-MgUser -UserId $Context.TargetUPN -Property Id; $licenseDetails=@(Get-MgUserLicenseDetail -UserId $u.Id -ErrorAction SilentlyContinue); if($licenseDetails.Count -eq 0){$warnings+='No direct licenses detected.'}; $ev=@{LicenseCount=$licenseDetails.Count; SkuPartNumbers=@($licenseDetails|ForEach-Object {$_.SkuPartNumber}); BlockerCount=$blockers.Count; WarningCount=$warnings.Count} } catch { $ev=@{BlockerCount=$blockers.Count; WarningCount=$warnings.Count; LicenseInventoryError=$_.Exception.Message}; $warnings+='License inventory read failed.' }
    $status=if($blockers.Count -gt 0){'Blocked'}else{'Success'}
    $r=New-DecomActionResult -ActionName 'Check License Removal Readiness' -Phase 'Licensing' -Status $status -IsCritical ($blockers.Count -gt 0) -TargetUPN $Context.TargetUPN -Message $(if($status -eq 'Success'){'License removal prerequisites satisfied.'}else{'License removal blocked by governance prerequisites.'}) -Evidence $ev -WarningMessages $warnings -BlockerMessages $blockers -RecommendedNext $(if($status -eq 'Success'){'Remove licenses if approved'}else{'Resolve blockers before license removal'}) -ControlObjective 'Prevent unsafe service-plan removal' -RiskMitigated 'Mailbox/compliance data loss or service disruption'
    Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status -IsCritical $r.IsCritical -Message $r.Message -Evidence $ev -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
    return $r
}
function Remove-DecomLicenses {
    param([pscustomobject]$Context,[System.Management.Automation.PSCmdlet]$Cmdlet)
    if($Context.WhatIf){return New-DecomSkippedBecauseWhatIf -ActionName 'Remove Licenses' -Phase 'Licensing' -TargetUPN $Context.TargetUPN -RecommendedNext 'Proceed to reporting'}
    try{$u=Get-MgUser -UserId $Context.TargetUPN -Property Id; $before=@(Get-MgUserLicenseDetail -UserId $u.Id); $skuIds=@($before|ForEach-Object {$_.SkuId}); if($skuIds.Count -eq 0){return New-DecomActionResult -ActionName 'Remove Licenses' -Phase 'Licensing' -Status 'Skipped' -IsCritical $false -TargetUPN $Context.TargetUPN -Message 'No licenses assigned.'}; if($Cmdlet.ShouldProcess($Context.TargetUPN,"Remove $($skuIds.Count) license assignments")){Set-MgUserLicense -UserId $u.Id -AddLicenses @() -RemoveLicenses $skuIds|Out-Null}; $after=@(Get-MgUserLicenseDetail -UserId $u.Id); $r=New-DecomActionResult -ActionName 'Remove Licenses' -Phase 'Licensing' -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN -Message 'Assigned licenses removed.' -BeforeState @{SkuIds=$skuIds} -AfterState @{RemainingLicenseCount=$after.Count} -Evidence @{RemovedSkuIds=$skuIds; RemainingLicenseCount=$after.Count} -ControlObjective 'Remove paid service entitlement after governance prerequisites' -RiskMitigated 'Unnecessary license spend after safe decommissioning'; Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status -IsCritical $true -Message $r.Message -BeforeState $r.BeforeState -AfterState $r.AfterState -Evidence $r.Evidence|Out-Null; $r}
    catch{$r=New-DecomActionResult -ActionName 'Remove Licenses' -Phase 'Licensing' -Status 'Failed' -IsCritical $true -TargetUPN $Context.TargetUPN -Message $_.Exception.Message -BlockerMessages @('License removal failed.'); Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status -IsCritical $true -Message $r.Message -ErrorRecord $_|Out-Null; $r}
}
Export-ModuleMember -Function Test-DecomLicenseRemovalReadiness,Remove-DecomLicenses
