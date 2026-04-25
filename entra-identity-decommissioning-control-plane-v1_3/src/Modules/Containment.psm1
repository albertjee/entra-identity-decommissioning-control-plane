# Containment.psm1 — Immediate access containment actions
# v1.2: WhatIf guard restored as FIRST check in every function (regression fix).
#        ShouldProcess else branches retained from v1.1.
#        Rejection-sampling password generation retained from v1.1.

function New-DecomSecurePassword {
    param([int]$Length = 32)
    $chars      = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+'.ToCharArray()
    $maxUnbiased = 256 - (256 % $chars.Length)
    $result     = [System.Text.StringBuilder]::new($Length)
    $buf        = New-Object byte[] 1
    while ($result.Length -lt $Length) {
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($buf)
        if ($buf[0] -lt $maxUnbiased) {
            $null = $result.Append($chars[$buf[0] % $chars.Length])
        }
    }
    return $result.ToString()
}

function Reset-DecomPassword {
    param([pscustomobject]$Context, [System.Management.Automation.PSCmdlet]$Cmdlet)
    # WhatIf guard — must be first, before ShouldProcess
    if ($Context.WhatIf) { return New-DecomSkippedBecauseWhatIf -ActionName 'Reset Password' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Revoke sessions' }
    if ($Cmdlet.ShouldProcess($Context.TargetUPN, 'Reset password')) {
        try {
            $before = Get-MgUser -UserId $Context.TargetUPN -Property AccountEnabled
            $pwd    = New-DecomSecurePassword
            Update-MgUser -UserId $Context.TargetUPN -PasswordProfile @{ ForceChangePasswordNextSignIn = $true; Password = $pwd }
            $r = New-DecomActionResult -ActionName 'Reset Password' -Phase 'Containment' -Status 'Success' -IsCritical $true `
                -TargetUPN $Context.TargetUPN -Message 'Password reset completed.' `
                -BeforeState @{ AccountEnabled = $before.AccountEnabled } -AfterState @{ PasswordReset = $true } `
                -Evidence @{ PasswordMaterialLogged = $false } `
                -ControlObjective 'Invalidate known credentials' -RiskMitigated 'Credential reuse after termination'
            Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status `
                -IsCritical $true -Message $r.Message -BeforeState $r.BeforeState -AfterState $r.AfterState `
                -Evidence $r.Evidence -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
            return $r
        } catch {
            return New-DecomActionResult -ActionName 'Reset Password' -Phase 'Containment' -Status 'Failed' `
                -IsCritical $true -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
                -BlockerMessages @('Password reset failed.') -FailureClass 'Critical'
        }
    } else {
        return New-DecomSkippedBecauseWhatIf -ActionName 'Reset Password' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Revoke sessions'
    }
}

function Revoke-DecomSessions {
    param([pscustomobject]$Context, [System.Management.Automation.PSCmdlet]$Cmdlet)
    if ($Context.WhatIf) { return New-DecomSkippedBecauseWhatIf -ActionName 'Revoke Sessions' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Block sign-in' }
    if ($Cmdlet.ShouldProcess($Context.TargetUPN, 'Revoke sign-in sessions')) {
        try {
            Revoke-MgUserSignInSession -UserId $Context.TargetUPN | Out-Null
            $r = New-DecomActionResult -ActionName 'Revoke Sessions' -Phase 'Containment' -Status 'Success' -IsCritical $true `
                -TargetUPN $Context.TargetUPN -Message 'Active sessions revoked.' `
                -AfterState @{ SessionsRevoked = $true } `
                -ControlObjective 'Reduce token revocation latency' -RiskMitigated 'Persistent token use after decommissioning'
            Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status `
                -IsCritical $true -Message $r.Message -AfterState $r.AfterState `
                -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
            return $r
        } catch {
            return New-DecomActionResult -ActionName 'Revoke Sessions' -Phase 'Containment' -Status 'Failed' `
                -IsCritical $true -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
                -BlockerMessages @('Session revocation failed.') -FailureClass 'Critical'
        }
    } else {
        return New-DecomSkippedBecauseWhatIf -ActionName 'Revoke Sessions' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Block sign-in'
    }
}

function Disable-DecomSignIn {
    param([pscustomobject]$Context, [System.Management.Automation.PSCmdlet]$Cmdlet)
    if ($Context.WhatIf) { return New-DecomSkippedBecauseWhatIf -ActionName 'Block Sign-In' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Mailbox phase' }
    if ($Cmdlet.ShouldProcess($Context.TargetUPN, 'Block sign-in')) {
        try {
            $before = Get-MgUser -UserId $Context.TargetUPN -Property AccountEnabled
            Update-MgUser -UserId $Context.TargetUPN -AccountEnabled:$false
            $after  = Get-MgUser -UserId $Context.TargetUPN -Property AccountEnabled
            $r = New-DecomActionResult -ActionName 'Block Sign-In' -Phase 'Containment' -Status 'Success' -IsCritical $true `
                -TargetUPN $Context.TargetUPN -Message 'Sign-in blocked.' `
                -BeforeState @{ AccountEnabled = $before.AccountEnabled } -AfterState @{ AccountEnabled = $after.AccountEnabled } `
                -Evidence @{ Verified = ($after.AccountEnabled -eq $false) } `
                -ControlObjective 'Deny future interactive authentication' -RiskMitigated 'Continued account access after termination'
            Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName -Status $r.Status `
                -IsCritical $true -Message $r.Message -BeforeState $r.BeforeState -AfterState $r.AfterState `
                -Evidence $r.Evidence -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
            return $r
        } catch {
            return New-DecomActionResult -ActionName 'Block Sign-In' -Phase 'Containment' -Status 'Failed' `
                -IsCritical $true -TargetUPN $Context.TargetUPN -Message $_.Exception.Message `
                -BlockerMessages @('Failed to block sign-in.') -FailureClass 'Critical'
        }
    } else {
        return New-DecomSkippedBecauseWhatIf -ActionName 'Block Sign-In' -Phase 'Containment' -TargetUPN $Context.TargetUPN -RecommendedNext 'Mailbox phase'
    }
}

Export-ModuleMember -Function New-DecomSecurePassword, Reset-DecomPassword, Revoke-DecomSessions, Disable-DecomSignIn
