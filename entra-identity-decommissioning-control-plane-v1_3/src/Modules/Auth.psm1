# Auth.psm1 — Service connection layer
# v1.2: Full 7-scope Graph connection restored (regression fix — v1.1 silently dropped 3 scopes).
#        Connect-DecomServices composite removed — workflow calls Graph and Exchange individually.
#        Each connection emits its own evidence result for full audit trail.

function Connect-DecomGraph {
    [CmdletBinding()]
    param([pscustomobject]$Context)
    # Full scope set required for Discovery (AppRoleAssignment, OAuthGrant) and all control actions
    $Scopes = @(
        'User.ReadWrite.All',
        'Directory.ReadWrite.All',
        'Organization.Read.All',
        'RoleManagement.Read.Directory',
        'Application.Read.All',
        'AppRoleAssignment.ReadWrite.All',
        'DelegatedPermissionGrant.Read.All'
    )
    try {
        Connect-MgGraph -Scopes $Scopes -NoWelcome | Out-Null
        $ctx = Get-MgContext
        $r = New-DecomActionResult -ActionName 'Connect Microsoft Graph' -Phase 'Authentication' `
            -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message 'Connected to Microsoft Graph.' `
            -Evidence @{ TenantId = $ctx.TenantId; Account = $ctx.Account; ScopeCount = $Scopes.Count } `
            -ControlObjective 'Establish authorized Graph control channel' `
            -RiskMitigated 'Unauthorized or incomplete identity-plane execution'
        Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName `
            -Status $r.Status -IsCritical $r.IsCritical -Message $r.Message -Evidence $r.Evidence `
            -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
        return $r
    } catch {
        return New-DecomActionResult -ActionName 'Connect Microsoft Graph' -Phase 'Authentication' `
            -Status 'Failed' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message $_.Exception.Message `
            -BlockerMessages @('Microsoft Graph connection failed. Verify module, scopes, and admin consent.') `
            -FailureClass 'Critical'
    }
}

function Connect-DecomExchange {
    [CmdletBinding()]
    param([pscustomobject]$Context)
    try {
        Connect-ExchangeOnline -ShowBanner:$false | Out-Null
        $r = New-DecomActionResult -ActionName 'Connect Exchange Online' -Phase 'Authentication' `
            -Status 'Success' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message 'Connected to Exchange Online.' `
            -Evidence @{ ExchangeOnline = 'Connected' } `
            -ControlObjective 'Establish mailbox and compliance control channel' `
            -RiskMitigated 'Incomplete mailbox continuity and compliance execution'
        Add-DecomEvidenceEvent -Context $Context -Phase $r.Phase -ActionName $r.ActionName `
            -Status $r.Status -IsCritical $r.IsCritical -Message $r.Message -Evidence $r.Evidence `
            -ControlObjective $r.ControlObjective -RiskMitigated $r.RiskMitigated | Out-Null
        return $r
    } catch {
        return New-DecomActionResult -ActionName 'Connect Exchange Online' -Phase 'Authentication' `
            -Status 'Failed' -IsCritical $true -TargetUPN $Context.TargetUPN `
            -Message $_.Exception.Message `
            -BlockerMessages @('Exchange Online connection failed. Verify EXO module and permissions.') `
            -FailureClass 'Critical'
    }
}

Export-ModuleMember -Function Connect-DecomGraph, Connect-DecomExchange
