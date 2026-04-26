# DecomV21.Tests.ps1 — Pester v5 / PS7
# BatchDiff | BatchPolicy | BatchApproval | MailboxExtended
# Run: Invoke-Pester .\tests\Premium\DecomV21.Tests.ps1 -Output Detailed

BeforeAll {
    $repoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $liteMods    = Join-Path $repoRoot 'src\Modules'
    $premiumMods = Join-Path $repoRoot 'src\Premium\Modules'

    Import-Module (Join-Path $liteMods    'Models.psm1')         -Force -DisableNameChecking
    Import-Module (Join-Path $liteMods    'Logging.psm1')        -Force -DisableNameChecking
    Import-Module (Join-Path $liteMods    'Evidence.psm1')       -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchDiff.psm1')      -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchPolicy.psm1')    -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchApproval.psm1')  -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'MailboxExtended.psm1')-Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchContext.psm1')   -Force -DisableNameChecking

    $script:baseDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DecomV21-' + [guid]::NewGuid().Guid)
    New-Item -ItemType Directory -Path $script:baseDir -Force | Out-Null

    function Get-TestEntries { param($Batch)
        $p = $Batch.PSObject.Properties['Entries']; if ($null -eq $p) { return $null }; return $p.Value }

    function script:New-TestContext {
        param([switch]$WhatIf)
        [pscustomobject]@{
            TargetUPN='user@contoso.com'; TicketId='CHG-TEST'; OutputPath=$env:TEMP
            EvidenceLevel='Forensic'; WhatIf=[bool]$WhatIf; NonInteractive=$false
            Force=$false; SealEvidence=$true; OperatorUPN='admin@contoso.com'
            OperatorObjectId='op-oid-001'; CorrelationId=[guid]::NewGuid().Guid
            Evidence=[System.Collections.Generic.List[object]]::new()
            RunId=[guid]::NewGuid().Guid; EvidencePrevHash='GENESIS'
        }
    }

    function script:New-TestAR {
        param([string]$Phase='Containment',[string]$Action='Reset Password',
              [string]$Status='Success',[bool]$IsCritical=$true)
        [pscustomobject]@{ Phase=$Phase; ActionName=$Action; Status=$Status; IsCritical=$IsCritical
            Message="Test $Action"; BeforeState=@{ State='Before' }; AfterState=@{ State='After' }
            Evidence=@{}; WarningMessages=@(); ManualFollowUp=@() }
    }

    # EXO mocks for MailboxExtended
    Mock -ModuleName MailboxExtended Get-EXOMailbox {
        [pscustomobject]@{ ForwardingSmtpAddress='manager@contoso.com'; ForwardingAddress=$null
            DeliverToMailboxAndForward=$false; RecipientTypeDetails='SharedMailbox' }
    }
    Mock -ModuleName MailboxExtended Set-Mailbox { }
    Mock -ModuleName MailboxExtended Add-DecomEvidenceEvent { }
}

AfterAll {
    if (Test-Path $script:baseDir) { Remove-Item $script:baseDir -Recurse -Force }
}

Describe 'BatchDiff - New-DecomBatchDiffEntry' {

    It 'creates a diff entry with required fields' {
        $e = New-DecomBatchDiffEntry -Result (New-TestAR) -UPN 'u@c.com'
        $e.UPN        | Should -Be 'u@c.com'
        $e.Phase      | Should -Be 'Containment'
        $e.ActionName | Should -Be 'Reset Password'
        $e.Status     | Should -Be 'Success'
    }

    It 'infers High risk for critical Containment actions' {
        (New-DecomBatchDiffEntry -Result (New-TestAR -Phase 'Containment' -IsCritical $true) -UPN 'u@c.com').RiskLevel | Should -Be 'High'
    }

    It 'infers Remove change type for Remove actions' {
        (New-DecomBatchDiffEntry -Result (New-TestAR -Action 'Remove Group Memberships') -UPN 'u@c.com').ChangeType | Should -Be 'Remove'
    }

    It 'infers Modify change type for Set actions' {
        (New-DecomBatchDiffEntry -Result (New-TestAR -Action 'Set Mail Forwarding') -UPN 'u@c.com').ChangeType | Should -Be 'Modify'
    }

    It 'infers Skip change type for Skipped status' {
        (New-DecomBatchDiffEntry -Result (New-TestAR -Status 'Skipped') -UPN 'u@c.com').ChangeType | Should -Be 'Skip'
    }

    It 'infers Low risk for non-critical low-impact actions' {
        (New-DecomBatchDiffEntry -Result (New-TestAR -Phase 'Snapshot' -IsCritical $false) -UPN 'u@c.com').RiskLevel | Should -Be 'Low'
    }
}

Describe 'BatchDiff - Export-DecomBatchDiffReport' {

    BeforeEach {
        $script:b  = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('alice@c.com') -TicketId 'CHG-DIFF' -WhatIfMode
        $ctx       = New-TestContext -WhatIf
        $script:br = [pscustomobject]@{
            BatchId = $script:b.BatchId
            Summary = Get-DecomBatchSummary -Batch $script:b
            Results = @([pscustomobject]@{
                Context=$ctx; State=[pscustomobject]@{ RunId='r1' }; StopReason=$null
                Results=@((New-TestAR -Phase 'Containment' -IsCritical $true),(New-TestAR -Phase 'Mailbox' -IsCritical $false))
                Summary=[pscustomobject]@{ Status='Completed'; TargetUPN='alice@c.com' }
            })
            Errors = @()
        }
    }

    It 'creates both HTML and JSON files' {
        $p = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        Test-Path $p.HtmlPath | Should -BeTrue
        Test-Path $p.JsonPath | Should -BeTrue
    }

    It 'JSON file is valid and has correct schema version' {
        $p = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        $j = Get-Content $p.JsonPath -Raw | ConvertFrom-Json
        $j.SchemaVersion | Should -Be '2.1'
        $j.ReportType    | Should -Be 'WhatIfDiff'
    }

    It 'JSON TotalActions matches result count' {
        $p = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        (Get-Content $p.JsonPath -Raw | ConvertFrom-Json).TotalActions | Should -Be 2
    }

    It 'HTML contains WhatIf mode label' {
        $p = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        Get-Content $p.HtmlPath -Raw | Should -Match 'WhatIf'
    }

    It 'HTML contains UPN' {
        $p = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        Get-Content $p.HtmlPath -Raw | Should -Match 'user@contoso\.com'
    }

    It 'files land in OutputRoot\BatchId' {
        $p   = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        $exp = Join-Path $script:baseDir $script:b.BatchId
        (Split-Path $p.HtmlPath -Parent) | Should -Be $exp
        (Split-Path $p.JsonPath -Parent) | Should -Be $exp
    }

    It 'works for empty batch result' {
        $e  = New-DecomBatchContext -OutputRoot $script:baseDir
        $er = [pscustomobject]@{ BatchId=$e.BatchId; Summary=(Get-DecomBatchSummary -Batch $e); Results=@(); Errors=@() }
        { Export-DecomBatchDiffReport -Batch $e -BatchResult $er } | Should -Not -Throw
    }
}

Describe 'BatchPolicy - Read-DecomBatchPolicy' {

    BeforeAll {
        $script:pd = Join-Path $script:baseDir 'policies'
        New-Item -ItemType Directory -Path $script:pd -Force | Out-Null
        @{ DefaultPolicy=@{ EvidenceLevel='Forensic'; RemoveLicenses=$false
            SkipGroups=$false; SkipRoles=$false; SkipAuthMethods=$false; WhatIf=$false }
           UpnPolicies=@{ 'alice@contoso.com'=@{ EvidenceLevel='Standard'; SkipRoles=$true } }
        } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $script:pd 'valid.json') -Encoding UTF8
        $script:vpp = Join-Path $script:pd 'valid.json'
    }

    It 'loads a valid policy file without error' {
        { Read-DecomBatchPolicy -Path $script:vpp } | Should -Not -Throw
    }

    It 'returns an object with DefaultPolicy' {
        (Read-DecomBatchPolicy -Path $script:vpp).DefaultPolicy | Should -Not -BeNullOrEmpty
    }

    It 'returns an object with UpnPolicies' {
        (Read-DecomBatchPolicy -Path $script:vpp).UpnPolicies | Should -Not -BeNullOrEmpty
    }

    It 'throws for missing file' {
        { Read-DecomBatchPolicy -Path 'C:\does\not\exist\policy.json' } | Should -Throw
    }

    It 'throws for invalid JSON' {
        $p = Join-Path $script:pd 'bad.json'
        Set-Content $p 'not json {{{' -Encoding UTF8
        { Read-DecomBatchPolicy -Path $p } | Should -Throw
    }

    It 'throws for invalid EvidenceLevel' {
        $p = Join-Path $script:pd 'badlevel.json'
        @{ DefaultPolicy=@{ EvidenceLevel='Invalid' } } | ConvertTo-Json | Set-Content $p -Encoding UTF8
        { Read-DecomBatchPolicy -Path $p } | Should -Throw
    }

    It 'throws for non-boolean bool field' {
        $p = Join-Path $script:pd 'badbool.json'
        @{ DefaultPolicy=@{ EvidenceLevel='Forensic'; SkipGroups='yes' } } | ConvertTo-Json | Set-Content $p -Encoding UTF8
        { Read-DecomBatchPolicy -Path $p } | Should -Throw
    }
}

Describe 'BatchPolicy - Get-DecomUpnPolicy' {

    BeforeAll {
        $pp = Join-Path $script:baseDir 'test-policy.json'
        @{ DefaultPolicy=@{ EvidenceLevel='Forensic'; RemoveLicenses=$true
            SkipGroups=$false; SkipRoles=$false; SkipAuthMethods=$false; WhatIf=$false }
           UpnPolicies=@{
               'alice@contoso.com'=@{ EvidenceLevel='Standard'; SkipRoles=$true }
               'BOB@CONTOSO.COM'=@{ WhatIf=$true }
           }
        } | ConvertTo-Json -Depth 5 | Set-Content $pp -Encoding UTF8
        $script:policy = Read-DecomBatchPolicy -Path $pp
    }

    It 'returns defaults when policy is null' {
        $p = Get-DecomUpnPolicy -Policy $null -UPN 'x@c.com'
        $p.EvidenceLevel | Should -Be 'Forensic'
        $p.WhatIf        | Should -Be $false
    }

    It 'returns DefaultPolicy for unknown UPN' {
        $p = Get-DecomUpnPolicy -Policy $script:policy -UPN 'unknown@contoso.com'
        $p.EvidenceLevel  | Should -Be 'Forensic'
        $p.RemoveLicenses | Should -Be $true
    }

    It 'applies UPN-specific override for known UPN' {
        $p = Get-DecomUpnPolicy -Policy $script:policy -UPN 'alice@contoso.com'
        $p.EvidenceLevel | Should -Be 'Standard'
        $p.SkipRoles     | Should -Be $true
    }

    It 'inherits DefaultPolicy fields not overridden' {
        (Get-DecomUpnPolicy -Policy $script:policy -UPN 'alice@contoso.com').RemoveLicenses | Should -Be $true
    }

    It 'UPN lookup is case-insensitive' {
        (Get-DecomUpnPolicy -Policy $script:policy -UPN 'bob@contoso.com').WhatIf | Should -Be $true
    }

    It 'all required fields present in output' {
        $p = Get-DecomUpnPolicy -Policy $null -UPN 'x@c.com'
        $p.PSObject.Properties.Name | Should -Contain 'EvidenceLevel'
        $p.PSObject.Properties.Name | Should -Contain 'SkipGroups'
        $p.PSObject.Properties.Name | Should -Contain 'WhatIf'
    }
}

Describe 'BatchPolicy - New-DecomBatchPolicyTemplate' {

    It 'creates a JSON file' {
        $p = Join-Path $script:baseDir 'tmpl.json'
        New-DecomBatchPolicyTemplate -Path $p | Out-Null
        Test-Path $p | Should -BeTrue
    }

    It 'template is valid JSON' {
        $p = Join-Path $script:baseDir 'tmpl2.json'
        New-DecomBatchPolicyTemplate -Path $p | Out-Null
        { Get-Content $p -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'template contains DefaultPolicy section' {
        $p = Join-Path $script:baseDir 'tmpl3.json'
        New-DecomBatchPolicyTemplate -Path $p | Out-Null
        (Get-Content $p -Raw | ConvertFrom-Json).DefaultPolicy | Should -Not -BeNullOrEmpty
    }
}

Describe 'BatchApproval - New-DecomApprovalRecord' {

    It 'creates a presigned approval file' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        Test-Path (New-DecomApprovalRecord -Batch $b -ApproverUPN 'approver@c.com' -OutputPath $script:baseDir) | Should -BeTrue
    }

    It 'approval file contains correct BatchId' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        $r = Get-Content (New-DecomApprovalRecord -Batch $b -ApproverUPN 'approver@c.com' -OutputPath $script:baseDir) -Raw | ConvertFrom-Json
        $r.BatchId     | Should -Be $b.BatchId
        $r.Approved    | Should -Be $true
        $r.ApproverUPN | Should -Be 'approver@c.com'
    }

    It 'approval file SchemaVersion is 2.1' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        (Get-Content (New-DecomApprovalRecord -Batch $b -ApproverUPN 'a@c.com' -OutputPath $script:baseDir) -Raw | ConvertFrom-Json).SchemaVersion | Should -Be '2.1'
    }
}

Describe 'BatchApproval - Invoke-DecomBatchApproval NonInteractive' {

    It 'succeeds with valid presigned approval file' {
        $b     = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        $aPath = New-DecomApprovalRecord -Batch $b -ApproverUPN 'mgr@c.com' -OutputPath $script:baseDir
        Invoke-DecomBatchApproval -Batch $b -NonInteractive -ApprovalPath $aPath | Should -Be $true
    }

    It 'throws when approval file BatchId does not match' {
        $b1    = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        $b2    = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        $aPath = New-DecomApprovalRecord -Batch $b1 -ApproverUPN 'mgr@c.com' -OutputPath $script:baseDir
        { Invoke-DecomBatchApproval -Batch $b2 -NonInteractive -ApprovalPath $aPath } | Should -Throw
    }

    It 'throws when -ApprovalPath is missing in NonInteractive mode' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        { Invoke-DecomBatchApproval -Batch $b -NonInteractive } | Should -Throw
    }

    It 'throws when approval file not found' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        { Invoke-DecomBatchApproval -Batch $b -NonInteractive -ApprovalPath 'C:\missing.json' } | Should -Throw
    }

    It 'writes batch-approval.json to batch directory' {
        $b     = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        $aPath = New-DecomApprovalRecord -Batch $b -ApproverUPN 'mgr@c.com' -OutputPath $script:baseDir
        Invoke-DecomBatchApproval -Batch $b -NonInteractive -ApprovalPath $aPath | Out-Null
        Test-Path (Join-Path (Join-Path $script:baseDir $b.BatchId) 'batch-approval.json') | Should -BeTrue
    }
}

Describe 'BatchApproval - Get-DecomApprovalStatus' {

    It 'returns null when no approval record exists' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        Get-DecomApprovalStatus -Batch $b | Should -BeNullOrEmpty
    }

    It 'returns approval record after approval' {
        $b     = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        $aPath = New-DecomApprovalRecord -Batch $b -ApproverUPN 'mgr@c.com' -OutputPath $script:baseDir
        Invoke-DecomBatchApproval -Batch $b -NonInteractive -ApprovalPath $aPath | Out-Null
        $r = Get-DecomApprovalStatus -Batch $b
        $r          | Should -Not -BeNullOrEmpty
        $r.Approved | Should -Be $true
    }
}

Describe 'MailboxExtended - Get-DecomMailForwardingState' {

    It 'returns forwarding state object' {
        $s = Get-DecomMailForwardingState -Context (New-TestContext)
        $s.PSObject.Properties.Name | Should -Contain 'ForwardingSmtpAddress'
        $s.PSObject.Properties.Name | Should -Contain 'IsForwardingActive'
    }

    It 'IsForwardingActive is true when ForwardingSmtpAddress is set' {
        (Get-DecomMailForwardingState -Context (New-TestContext)).IsForwardingActive | Should -Be $true
    }

    It 'IsForwardingActive is false when no forwarding configured' {
        Mock -ModuleName MailboxExtended Get-EXOMailbox {
            [pscustomobject]@{ ForwardingSmtpAddress=$null; ForwardingAddress=$null
                DeliverToMailboxAndForward=$false; RecipientTypeDetails='SharedMailbox' }
        }
        (Get-DecomMailForwardingState -Context (New-TestContext)).IsForwardingActive | Should -Be $false
    }
}

Describe 'MailboxExtended - Set-DecomMailForwarding' {

    BeforeEach {
        Mock -ModuleName MailboxExtended Get-EXOMailbox {
            [pscustomobject]@{ ForwardingSmtpAddress='manager@contoso.com'; ForwardingAddress=$null
                DeliverToMailboxAndForward=$false; RecipientTypeDetails='SharedMailbox' }
        }
        Mock -ModuleName MailboxExtended Set-Mailbox { }
    }

    It 'returns Skipped when no forwarding target supplied' {
        (Set-DecomMailForwarding -Context (New-TestContext) -Cmdlet $null).Status | Should -Be 'Skipped'
    }

    It 'returns Success in WhatIf mode' {
        $r = Set-DecomMailForwarding -Context (New-TestContext -WhatIf) -ForwardToSmtp 'mgr@c.com' -Cmdlet $null
        $r.Status  | Should -Be 'Success'
        $r.Message | Should -Match '\[WhatIf\]'
    }

    It 'returns Success in live mode' {
        (Set-DecomMailForwarding -Context (New-TestContext) -ForwardToSmtp 'mgr@c.com' -Cmdlet $null).Status | Should -Be 'Success'
    }

    It 'returns Failed when Set-Mailbox throws' {
        Mock -ModuleName MailboxExtended Set-Mailbox { throw 'EXO access denied' }
        (Set-DecomMailForwarding -Context (New-TestContext) -ForwardToSmtp 'mgr@c.com' -Cmdlet $null).Status | Should -Be 'Failed'
    }
}

Describe 'MailboxExtended - Remove-DecomMailForwarding' {

    BeforeEach {
        Mock -ModuleName MailboxExtended Get-EXOMailbox {
            [pscustomobject]@{ ForwardingSmtpAddress='manager@contoso.com'; ForwardingAddress=$null
                DeliverToMailboxAndForward=$false; RecipientTypeDetails='SharedMailbox' }
        }
        Mock -ModuleName MailboxExtended Set-Mailbox { }
    }

    It 'returns Skipped when no forwarding is active' {
        Mock -ModuleName MailboxExtended Get-EXOMailbox {
            [pscustomobject]@{ ForwardingSmtpAddress=$null; ForwardingAddress=$null
                DeliverToMailboxAndForward=$false; RecipientTypeDetails='SharedMailbox' }
        }
        (Remove-DecomMailForwarding -Context (New-TestContext) -Cmdlet $null).Status | Should -Be 'Skipped'
    }

    It 'returns Success when forwarding is cleared' {
        (Remove-DecomMailForwarding -Context (New-TestContext) -Cmdlet $null).Status | Should -Be 'Success'
    }

    It 'returns Success in WhatIf mode' {
        $r = Remove-DecomMailForwarding -Context (New-TestContext -WhatIf) -Cmdlet $null
        $r.Status  | Should -Be 'Success'
        $r.Message | Should -Match '\[WhatIf\]'
    }

    It 'AfterState shows null forwarding addresses' {
        $r = Remove-DecomMailForwarding -Context (New-TestContext) -Cmdlet $null
        $r.AfterState.ForwardingSmtpAddress | Should -BeNullOrEmpty
        $r.AfterState.ForwardingAddress     | Should -BeNullOrEmpty
    }
}

