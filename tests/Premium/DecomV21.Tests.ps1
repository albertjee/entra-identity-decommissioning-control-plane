# DecomV21.Tests.ps1 — Pester v5 tests for Premium v2.1 modules
# Covers: BatchDiff, BatchPolicy, BatchApproval, MailboxExtended
# (BatchOrchestratorParallel is integration-tested — unit tests here cover
#  the public contract only, not the parallel runspace internals)
#
# Run from repo root:
#   Invoke-Pester .\tests\Premium\DecomV21.Tests.ps1 -Output Detailed

BeforeAll {
    $repoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $liteMods    = Join-Path $repoRoot 'src\Modules'
    $premiumMods = Join-Path $repoRoot 'src\Premium\Modules'

    # ── Lite stubs ─────────────────────────────────────────────────────────────
    Import-Module (Join-Path $liteMods 'Models.psm1')  -Force -DisableNameChecking
    Import-Module (Join-Path $liteMods 'Logging.psm1') -Force -DisableNameChecking

    function Write-DecomConsole { param([string]$Level,[string]$Message) }
    function Add-DecomEvidenceEvent {
        param([pscustomobject]$Context,[string]$Phase,[string]$ActionName,
              [string]$Status,[bool]$IsCritical,[string]$Message,
              [hashtable]$BeforeState,[hashtable]$AfterState,[hashtable]$Evidence,
              [string]$ControlObjective,[string]$RiskMitigated)
    }

    # EXO stubs for MailboxExtended
    # EXO stubs must be Global scope so they intercept module-level calls in PS7
    function Global:Get-EXOMailbox {
        param([string]$Identity,[string[]]$Property,[string]$ErrorAction)
        [pscustomobject]@{
            ForwardingSmtpAddress      = 'manager@contoso.com'
            ForwardingAddress          = $null
            DeliverToMailboxAndForward = $false
            RecipientTypeDetails       = 'SharedMailbox'
        }
    }
    function Global:Set-Mailbox {
        param([string]$Identity,$ForwardingSmtpAddress,$ForwardingAddress,
              [bool]$DeliverToMailboxAndForward,[string]$ErrorAction)
    }

    # ── Load v2.1 modules — BatchContext MUST be last to override any stubs ──────
    Import-Module (Join-Path $premiumMods 'BatchDiff.psm1')      -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchPolicy.psm1')    -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchApproval.psm1')  -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'MailboxExtended.psm1')-Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchContext.psm1')   -Force -DisableNameChecking

    # ── Shared helpers ─────────────────────────────────────────────────────────
    function New-TestContext {
        param([switch]$WhatIf)
        [pscustomobject]@{
            TargetUPN        = 'user@contoso.com'
            TicketId         = 'CHG-TEST'
            OutputPath       = $env:TEMP
            EvidenceLevel    = 'Forensic'
            WhatIf           = [bool]$WhatIf
            NonInteractive   = $false
            Force            = $false
            SealEvidence     = $true
            OperatorUPN      = 'admin@contoso.com'
            OperatorObjectId = 'op-oid-001'
            CorrelationId    = [guid]::NewGuid().Guid
            Evidence         = [System.Collections.Generic.List[object]]::new()
            RunId            = [guid]::NewGuid().Guid
            EvidencePrevHash = 'GENESIS'
        }
    }

    function New-TestActionResult {
        param([string]$Phase='Containment',[string]$Action='Reset Password',
              [string]$Status='Success',[bool]$IsCritical=$true)
        [pscustomobject]@{
            Phase            = $Phase
            ActionName       = $Action
            Status           = $Status
            IsCritical       = $IsCritical
            Message          = "Test result for $Action"
            BeforeState      = @{ State = 'Before' }
            AfterState       = @{ State = 'After' }
            Evidence         = @{}
            WarningMessages  = @()
            ManualFollowUp   = @()
        }
    }

    $script:baseDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DecomV21Test-' + [guid]::NewGuid().Guid)
    $null = New-Item -ItemType Directory -Path $script:baseDir -Force
}

AfterAll {
    if (Test-Path $script:baseDir) {
        Remove-Item -Path $script:baseDir -Recurse -Force
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchDiff — New-DecomBatchDiffEntry' {

    It 'creates a diff entry with required fields' {
        $r = New-TestActionResult
        $e = New-DecomBatchDiffEntry -Result $r -UPN 'u@c.com'
        $e.UPN        | Should -Be 'u@c.com'
        $e.Phase      | Should -Be 'Containment'
        $e.ActionName | Should -Be 'Reset Password'
        $e.Status     | Should -Be 'Success'
    }

    It 'infers High risk for critical Containment actions' {
        $r = New-TestActionResult -Phase 'Containment' -IsCritical $true
        $e = New-DecomBatchDiffEntry -Result $r -UPN 'u@c.com'
        $e.RiskLevel | Should -Be 'High'
    }

    It 'infers Remove change type for Remove actions' {
        $r = New-TestActionResult -Action 'Remove Group Memberships'
        $e = New-DecomBatchDiffEntry -Result $r -UPN 'u@c.com'
        $e.ChangeType | Should -Be 'Remove'
    }

    It 'infers Modify change type for Set actions' {
        $r = New-TestActionResult -Action 'Set Mail Forwarding'
        $e = New-DecomBatchDiffEntry -Result $r -UPN 'u@c.com'
        $e.ChangeType | Should -Be 'Modify'
    }

    It 'infers Skip change type for Skipped status' {
        $r = New-TestActionResult -Status 'Skipped'
        $e = New-DecomBatchDiffEntry -Result $r -UPN 'u@c.com'
        $e.ChangeType | Should -Be 'Skip'
    }

    It 'infers Low risk for non-critical low-impact actions' {
        $r = New-TestActionResult -Phase 'PreActionSnapshot' -IsCritical $false
        $e = New-DecomBatchDiffEntry -Result $r -UPN 'u@c.com'
        $e.RiskLevel | Should -Be 'Low'
    }
}

Describe 'BatchDiff — Export-DecomBatchDiffReport' {

    BeforeEach {
        $script:b = New-DecomBatchContext -OutputRoot $script:baseDir `
            -UpnList @('alice@c.com') -TicketId 'CHG-DIFF' -WhatIfMode

        $ctx = New-TestContext -WhatIf
        $ctx.TargetUPN = 'alice@c.com'

        $script:br = [pscustomobject]@{
            BatchId = $script:b.BatchId
            Summary = Get-DecomBatchSummary -Batch $script:b
            Results = @(
                [pscustomobject]@{
                    Context = $ctx
                    State   = [pscustomobject]@{ RunId = 'r1' }
                    Results = @(
                        (New-TestActionResult -Phase 'Containment' -Action 'Reset Password' -IsCritical $true),
                        (New-TestActionResult -Phase 'Mailbox' -Action 'Convert Mailbox' -IsCritical $false)
                    )
                    StopReason = $null
                    Summary    = [pscustomobject]@{ Status = 'Completed'; TargetUPN = 'alice@c.com' }
                }
            )
            Errors = @()
        }
    }

    It 'creates both HTML and JSON files' {
        $paths = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        Test-Path $paths.HtmlPath | Should -BeTrue
        Test-Path $paths.JsonPath | Should -BeTrue
    }

    It 'JSON file is valid and has correct schema version' {
        $paths = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        $j = Get-Content $paths.JsonPath -Raw | ConvertFrom-Json
        $j.SchemaVersion | Should -Be '2.1'
        $j.ReportType    | Should -Be 'WhatIfDiff'
    }

    It 'JSON TotalActions matches result count' {
        $paths = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        $j = Get-Content $paths.JsonPath -Raw | ConvertFrom-Json
        $j.TotalActions | Should -Be 2
    }

    It 'HTML contains WhatIf mode label' {
        $paths = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        $html = Get-Content $paths.HtmlPath -Raw
        $html | Should -Match 'WhatIf'
    }

    It 'HTML contains UPN' {
        $paths = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        $html = Get-Content $paths.HtmlPath -Raw
        $html | Should -Match 'alice@c\.com'
    }

    It 'HTML contains risk badges' {
        $paths = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        $html = Get-Content $paths.HtmlPath -Raw
        $html | Should -Match 'risk-high|risk-medium|risk-low'
    }

    It 'files land in <OutputRoot>\<BatchId>\' {
        $paths = Export-DecomBatchDiffReport -Batch $script:b -BatchResult $script:br
        $expectedDir = Join-Path $script:baseDir $script:b.BatchId
        (Split-Path $paths.HtmlPath -Parent) | Should -Be $expectedDir
        (Split-Path $paths.JsonPath -Parent) | Should -Be $expectedDir
    }

    It 'works for empty batch result' {
        $empty = New-DecomBatchContext -OutputRoot $script:baseDir
        $emptyResult = [pscustomobject]@{
            BatchId = $empty.BatchId
            Summary = Get-DecomBatchSummary -Batch $empty
            Results = @()
            Errors  = @()
        }
        { Export-DecomBatchDiffReport -Batch $empty -BatchResult $emptyResult } | Should -Not -Throw
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchPolicy — Read-DecomBatchPolicy' {

    BeforeAll {
        $script:policyDir = Join-Path $script:baseDir 'policies'
        $null = New-Item -ItemType Directory -Path $script:policyDir -Force

        # Write a valid policy file
        $validPolicy = @{
            DefaultPolicy = @{
                EvidenceLevel   = 'Forensic'
                RemoveLicenses  = $false
                SkipGroups      = $false
                SkipRoles       = $false
                SkipAuthMethods = $false
                WhatIf          = $false
            }
            UpnPolicies = @{
                'alice@contoso.com' = @{
                    EvidenceLevel = 'Standard'
                    SkipRoles     = $true
                }
            }
        }
        $script:validPolicyPath = Join-Path $script:policyDir 'valid.json'
        $validPolicy | ConvertTo-Json -Depth 5 |
            Set-Content $script:validPolicyPath -Encoding UTF8
    }

    It 'loads a valid policy file without error' {
        { Read-DecomBatchPolicy -Path $script:validPolicyPath } | Should -Not -Throw
    }

    It 'returns an object with DefaultPolicy' {
        $p = Read-DecomBatchPolicy -Path $script:validPolicyPath
        $p.DefaultPolicy | Should -Not -BeNullOrEmpty
    }

    It 'returns an object with UpnPolicies' {
        $p = Read-DecomBatchPolicy -Path $script:validPolicyPath
        $p.UpnPolicies | Should -Not -BeNullOrEmpty
    }

    It 'throws for missing file' {
        { Read-DecomBatchPolicy -Path 'C:\does\not\exist\policy.json' } | Should -Throw
    }

    It 'throws for invalid JSON' {
        $badPath = Join-Path $script:policyDir 'bad.json'
        Set-Content $badPath -Value 'not json {{{' -Encoding UTF8
        { Read-DecomBatchPolicy -Path $badPath } | Should -Throw
    }

    It 'throws for invalid EvidenceLevel' {
        $bad = @{ DefaultPolicy = @{ EvidenceLevel = 'InvalidLevel' } }
        $badPath = Join-Path $script:policyDir 'badlevel.json'
        $bad | ConvertTo-Json | Set-Content $badPath -Encoding UTF8
        { Read-DecomBatchPolicy -Path $badPath } | Should -Throw
    }

    It 'throws for non-boolean bool field' {
        $bad = @{ DefaultPolicy = @{ EvidenceLevel = 'Forensic'; SkipGroups = 'yes' } }
        $badPath = Join-Path $script:policyDir 'badbool.json'
        $bad | ConvertTo-Json | Set-Content $badPath -Encoding UTF8
        { Read-DecomBatchPolicy -Path $badPath } | Should -Throw
    }
}

Describe 'BatchPolicy — Get-DecomUpnPolicy' {

    BeforeAll {
        $validPolicy = @{
            DefaultPolicy = @{
                EvidenceLevel   = 'Forensic'
                RemoveLicenses  = $true
                SkipGroups      = $false
                SkipRoles       = $false
                SkipAuthMethods = $false
                WhatIf          = $false
            }
            UpnPolicies = @{
                'alice@contoso.com' = @{
                    EvidenceLevel = 'Standard'
                    SkipRoles     = $true
                }
                'BOB@CONTOSO.COM' = @{
                    WhatIf = $true
                }
            }
        }
        $pPath = Join-Path $script:baseDir 'test-policy.json'
        $validPolicy | ConvertTo-Json -Depth 5 | Set-Content $pPath -Encoding UTF8
        $script:policy = Read-DecomBatchPolicy -Path $pPath
    }

    It 'returns defaults when policy is null' {
        $p = Get-DecomUpnPolicy -Policy $null -UPN 'anyone@c.com'
        $p.EvidenceLevel | Should -Be 'Forensic'
        $p.WhatIf        | Should -Be $false
    }

    It 'returns DefaultPolicy for unknown UPN' {
        $p = Get-DecomUpnPolicy -Policy $script:policy -UPN 'unknown@contoso.com'
        $p.EvidenceLevel   | Should -Be 'Forensic'
        $p.RemoveLicenses  | Should -Be $true
    }

    It 'applies UPN-specific override for known UPN' {
        $p = Get-DecomUpnPolicy -Policy $script:policy -UPN 'alice@contoso.com'
        $p.EvidenceLevel | Should -Be 'Standard'
        $p.SkipRoles     | Should -Be $true
    }

    It 'inherits DefaultPolicy fields not overridden by UPN policy' {
        $p = Get-DecomUpnPolicy -Policy $script:policy -UPN 'alice@contoso.com'
        $p.RemoveLicenses | Should -Be $true   # from DefaultPolicy
    }

    It 'UPN lookup is case-insensitive' {
        $p1 = Get-DecomUpnPolicy -Policy $script:policy -UPN 'BOB@CONTOSO.COM'
        $p2 = Get-DecomUpnPolicy -Policy $script:policy -UPN 'bob@contoso.com'
        $p1.WhatIf | Should -Be $true
        $p2.WhatIf | Should -Be $true
    }

    It 'all required fields are always present in output' {
        $p = Get-DecomUpnPolicy -Policy $null -UPN 'x@c.com'
        $p.PSObject.Properties.Name | Should -Contain 'EvidenceLevel'
        $p.PSObject.Properties.Name | Should -Contain 'RemoveLicenses'
        $p.PSObject.Properties.Name | Should -Contain 'SkipGroups'
        $p.PSObject.Properties.Name | Should -Contain 'SkipRoles'
        $p.PSObject.Properties.Name | Should -Contain 'SkipAuthMethods'
        $p.PSObject.Properties.Name | Should -Contain 'WhatIf'
    }
}

Describe 'BatchPolicy — New-DecomBatchPolicyTemplate' {

    It 'creates a JSON file at the specified path' {
        $path = Join-Path $script:baseDir 'template.json'
        New-DecomBatchPolicyTemplate -Path $path | Out-Null
        Test-Path $path | Should -BeTrue
    }

    It 'template is valid JSON' {
        $path = Join-Path $script:baseDir 'template2.json'
        New-DecomBatchPolicyTemplate -Path $path | Out-Null
        { Get-Content $path -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'template contains DefaultPolicy section' {
        $path = Join-Path $script:baseDir 'template3.json'
        New-DecomBatchPolicyTemplate -Path $path | Out-Null
        $t = Get-Content $path -Raw | ConvertFrom-Json
        $t.DefaultPolicy | Should -Not -BeNullOrEmpty
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchApproval — Invoke-DecomBatchApproval NonInteractive' {

    It 'succeeds with valid presigned approval file' {
        $b     = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com') -TicketId 'CHG-12345'
        # Create a valid v2.0 approval record manually
        $batchDir = Join-Path $script:baseDir $b.BatchId
        $null = New-Item -ItemType Directory -Path $batchDir -Force
        $aPath = Join-Path $script:baseDir 'approval-valid.json'
        @{
            SchemaVersion  = '2.0'
            RecordType     = 'ApprovalRecord'
            BatchId        = $b.BatchId
            TicketId       = 'CHG-12345'
            OperatorUPN    = 'mgr@c.com'
            ApprovalMethod = 'Interactive'
            Approved       = $true
            ApprovedUtc    = (Get-Date).ToUniversalTime().ToString('o')
            UPNCount       = 1
        } | ConvertTo-Json | Set-Content $aPath -Encoding UTF8
        $result = Invoke-DecomBatchApproval -Batch $b -NonInteractive -TicketId 'CHG-12345' `
            -OperatorUPN 'mgr@c.com' -ApprovalPath $aPath
        $result | Should -Be $true
    }

    It 'throws when approval file BatchId does not match' {
        $b1    = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com') -TicketId 'CHG-12345'
        $b2    = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com') -TicketId 'CHG-12345'
        $aPath = Join-Path $script:baseDir 'approval-mismatch.json'
        @{
            SchemaVersion = '2.0'; RecordType = 'ApprovalRecord'
            BatchId = $b1.BatchId; TicketId = 'CHG-12345'
            OperatorUPN = 'mgr@c.com'; Approved = $true
            ApprovedUtc = (Get-Date).ToUniversalTime().ToString('o')
        } | ConvertTo-Json | Set-Content $aPath -Encoding UTF8
        { Invoke-DecomBatchApproval -Batch $b2 -NonInteractive -TicketId 'CHG-12345' `
            -OperatorUPN 'mgr@c.com' -ApprovalPath $aPath } | Should -Throw
    }

    It 'throws when -TicketId is missing in NonInteractive mode' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        { Invoke-DecomBatchApproval -Batch $b -NonInteractive -OperatorUPN 'mgr@c.com' } | Should -Throw
    }

    It 'throws when approval file not found' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com') -TicketId 'CHG-12345'
        { Invoke-DecomBatchApproval -Batch $b -NonInteractive -TicketId 'CHG-12345' `
            -OperatorUPN 'mgr@c.com' -ApprovalPath 'C:\missing\approval.json' } | Should -Throw
    }

    It 'writes batch-approval.json to batch directory' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com') -TicketId 'CHG-99999'
        $batchDir = Join-Path $script:baseDir $b.BatchId
        $null = New-Item -ItemType Directory -Path $batchDir -Force
        $aPath = Join-Path $script:baseDir 'approval-write.json'
        @{
            SchemaVersion = '2.0'; RecordType = 'ApprovalRecord'
            BatchId = $b.BatchId; TicketId = 'CHG-99999'
            OperatorUPN = 'mgr@c.com'; Approved = $true
            ApprovedUtc = (Get-Date).ToUniversalTime().ToString('o')
        } | ConvertTo-Json | Set-Content $aPath -Encoding UTF8
        Invoke-DecomBatchApproval -Batch $b -NonInteractive -TicketId 'CHG-99999' `
            -OperatorUPN 'mgr@c.com' -ApprovalPath $aPath | Out-Null
        $recordPath = Join-Path $batchDir 'batch-approval.json'
        Test-Path $recordPath | Should -BeTrue
    }
}

Describe 'BatchApproval — Get-DecomApprovalStatus' {

    It 'returns null when no approval record exists' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com')
        $r = Get-DecomApprovalStatus -Batch $b
        $r | Should -BeNullOrEmpty
    }

    It 'returns approval record after approval' {
        $b = New-DecomBatchContext -OutputRoot $script:baseDir -UpnList @('u@c.com') -TicketId 'CHG-77777'
        $batchDir = Join-Path $script:baseDir $b.BatchId
        $null = New-Item -ItemType Directory -Path $batchDir -Force
        $aPath = Join-Path $script:baseDir 'approval-read.json'
        @{
            SchemaVersion = '2.0'; RecordType = 'ApprovalRecord'
            BatchId = $b.BatchId; TicketId = 'CHG-77777'
            OperatorUPN = 'mgr@c.com'; Approved = $true
            ApprovedUtc = (Get-Date).ToUniversalTime().ToString('o')
        } | ConvertTo-Json | Set-Content $aPath -Encoding UTF8
        Invoke-DecomBatchApproval -Batch $b -NonInteractive -TicketId 'CHG-77777' `
            -OperatorUPN 'mgr@c.com' -ApprovalPath $aPath | Out-Null
        $r = Get-DecomApprovalStatus -Batch $b
        $r          | Should -Not -BeNullOrEmpty
        $r.Approved | Should -Be $true
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'MailboxExtended — Get-DecomMailForwardingState' {

    It 'returns forwarding state object' {
        $ctx = New-TestContext
        $s = Get-DecomMailForwardingState -Context $ctx
        $s | Should -Not -BeNullOrEmpty
        $s.PSObject.Properties.Name | Should -Contain 'ForwardingSmtpAddress'
        $s.PSObject.Properties.Name | Should -Contain 'IsForwardingActive'
    }

    It 'IsForwardingActive is true when ForwardingSmtpAddress is set' {
        $ctx = New-TestContext
        $s = Get-DecomMailForwardingState -Context $ctx
        $s.IsForwardingActive | Should -Be $true
    }

    It 'IsForwardingActive is false when no forwarding configured' {
        function Global:Get-EXOMailbox {
            param([string]$Identity,[string[]]$Property,[string]$ErrorAction)
            [pscustomobject]@{
                ForwardingSmtpAddress      = $null
                ForwardingAddress          = $null
                DeliverToMailboxAndForward = $false
                RecipientTypeDetails       = 'SharedMailbox'
            }
        }
        $ctx = New-TestContext
        $s = Get-DecomMailForwardingState -Context $ctx
        $s.IsForwardingActive | Should -Be $false
        # Restore active-forwarding stub and module for subsequent tests
        function Global:Get-EXOMailbox {
            param([string]$Identity,[string[]]$Property,[string]$ErrorAction)
            [pscustomobject]@{
                ForwardingSmtpAddress      = 'manager@contoso.com'
                ForwardingAddress          = $null
                DeliverToMailboxAndForward = $false
                RecipientTypeDetails       = 'SharedMailbox'
            }
        }
        Import-Module (Join-Path $premiumMods 'MailboxExtended.psm1') -Force -DisableNameChecking
    }
}

Describe 'MailboxExtended — Set-DecomMailForwarding' {

    It 'returns Skipped when no forwarding target supplied' {
        $ctx = New-TestContext
        $r = Set-DecomMailForwarding -Context $ctx -Cmdlet $null
        $r.Status | Should -Be 'Skipped'
    }

    It 'returns Success in WhatIf mode' {
        $ctx = New-TestContext -WhatIf
        $r = Set-DecomMailForwarding -Context $ctx -ForwardToSmtp 'mgr@c.com' -Cmdlet $null
        $r.Status  | Should -Be 'Success'
        $r.Message | Should -Match '\[WhatIf\]'
    }

    It 'returns Success in live mode' {
        $ctx = New-TestContext
        $r = Set-DecomMailForwarding -Context $ctx -ForwardToSmtp 'mgr@c.com' -Cmdlet $null
        $r.Status | Should -Be 'Success'
    }

    It 'returns Failed when Set-Mailbox throws' {
        function Global:Set-Mailbox {
            param([string]$Identity,$ForwardingSmtpAddress,$ForwardingAddress,
                  [bool]$DeliverToMailboxAndForward,[string]$ErrorAction)
            throw 'EXO access denied'
        }
        $ctx = New-TestContext
        $r = Set-DecomMailForwarding -Context $ctx -ForwardToSmtp 'mgr@c.com' -Cmdlet $null
        $r.Status | Should -Be 'Failed'
        # Restore non-throwing stub
        function Global:Set-Mailbox {
            param([string]$Identity,$ForwardingSmtpAddress,$ForwardingAddress,
                  [bool]$DeliverToMailboxAndForward,[string]$ErrorAction)
        }
        Import-Module (Join-Path $premiumMods 'MailboxExtended.psm1') -Force -DisableNameChecking
    }
}

Describe 'MailboxExtended — Remove-DecomMailForwarding' {

    It 'returns Skipped when no forwarding is active' {
        function Global:Get-EXOMailbox {
            param([string]$Identity,[string[]]$Property,[string]$ErrorAction)
            [pscustomobject]@{
                ForwardingSmtpAddress = $null; ForwardingAddress = $null
                DeliverToMailboxAndForward = $false; RecipientTypeDetails = 'SharedMailbox'
            }
        }
        $ctx = New-TestContext
        $r = Remove-DecomMailForwarding -Context $ctx -Cmdlet $null
        $r.Status | Should -Be 'Skipped'
        Import-Module (Join-Path $premiumMods 'MailboxExtended.psm1') -Force -DisableNameChecking
    }

    BeforeEach {
        # Ensure active-forwarding stub is in place before every Remove test
        function Global:Get-EXOMailbox {
            param([string]$Identity,[string[]]$Property,[string]$ErrorAction)
            [pscustomobject]@{
                ForwardingSmtpAddress      = 'manager@contoso.com'
                ForwardingAddress          = $null
                DeliverToMailboxAndForward = $false
                RecipientTypeDetails       = 'SharedMailbox'
            }
        }
    }

    It 'returns Success when forwarding is cleared' {
        $ctx = New-TestContext
        $r = Remove-DecomMailForwarding -Context $ctx -Cmdlet $null
        $r.Status | Should -Be 'Success'
    }

    It 'returns Success in WhatIf mode' {
        $ctx = New-TestContext -WhatIf
        $r = Remove-DecomMailForwarding -Context $ctx -Cmdlet $null
        $r.Status  | Should -Be 'Success'
        $r.Message | Should -Match '\[WhatIf\]'
    }

    It 'AfterState shows null forwarding addresses' {
        $ctx = New-TestContext
        $r = Remove-DecomMailForwarding -Context $ctx -Cmdlet $null
        $r.AfterState.ForwardingSmtpAddress | Should -BeNullOrEmpty
        $r.AfterState.ForwardingAddress     | Should -BeNullOrEmpty
    }
}
