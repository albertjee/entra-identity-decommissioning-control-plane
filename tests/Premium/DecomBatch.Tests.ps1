# DecomBatch.Tests.ps1 — Pester v5 test suite for Premium v2.0 Phase 1
# Covers: BatchContext.psm1, BatchState.psm1, BatchOrchestrator.psm1
#
# Run from repo root:
#   Invoke-Pester .\tests\Premium\DecomBatch.Tests.ps1 -Output Detailed

BeforeAll {
    # ── Resolve paths ──────────────────────────────────────────────────────────
    $repoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $premiumMods = Join-Path $repoRoot 'src\Premium\Modules'
    $liteModules = Join-Path $repoRoot 'src\Modules'

    # ── Lite stubs required by BatchOrchestrator ───────────────────────────────
    # These mirror the pattern in Decom.Tests.ps1 — function stubs in BeforeAll
    # so no real Graph/EXO calls are made.

    function Global:New-DecomRunContext {
        param(
            [string]$TargetUPN, [string]$TicketId, [string]$OutputPath,
            [string]$EvidenceLevel = 'Forensic',
            [switch]$WhatIfMode, [switch]$NonInteractive, [switch]$Force,
            [switch]$ValidationOnly, [switch]$NoSeal,
            [string]$OperatorUPN, [string]$OperatorObjectId
        )
        [pscustomobject]@{
            TargetUPN        = $TargetUPN
            TicketId         = $TicketId
            OutputPath       = $OutputPath
            EvidenceLevel    = $EvidenceLevel
            WhatIf           = [bool]$WhatIfMode
            NonInteractive   = [bool]$NonInteractive
            Force            = [bool]$Force
            ValidationOnly   = [bool]$ValidationOnly
            SealEvidence     = -not [bool]$NoSeal
            OperatorUPN      = $OperatorUPN
            OperatorObjectId = $OperatorObjectId
            StartedUtc       = (Get-Date).ToUniversalTime().ToString('o')
            CorrelationId    = [guid]::NewGuid().Guid
        }
    }

    function Global:New-DecomState {
        param([string]$RunId)
        [pscustomobject]@{ RunId = $RunId; Phases = [ordered]@{} }
    }

    function Global:Initialize-DecomLog        { param([string]$Path) }
    function Global:Initialize-DecomEvidenceStore {
        param([pscustomobject]$Context, [string]$RunId, [string]$NdjsonPath)
        $Context | Add-Member -Force -NotePropertyName Evidence         -NotePropertyValue ([System.Collections.Generic.List[object]]::new())
        $Context | Add-Member -Force -NotePropertyName RunId            -NotePropertyValue $RunId
        $Context | Add-Member -Force -NotePropertyName EvidencePrevHash -NotePropertyValue 'GENESIS'
    }
    function Global:Write-DecomConsole         { param([string]$Level, [string]$Message) }
    function Global:Export-DecomJsonReport     { param([object]$WorkflowResult, [string]$Path) }
    function Global:Export-DecomHtmlReport     { param([object]$WorkflowResult, [string]$Path) }
    function Global:Write-DecomEvidenceManifest{ param([pscustomobject]$Context, [string]$OutputPath) }

    # ── Lite workflow stub — returns a minimal success result ──────────────────
    function Global:Invoke-DecomWorkflow {
        param(
            [pscustomobject]$Context,
            [pscustomobject]$State,
            [string]$OutOfOfficeMessage,
            [switch]$EnableLitigationHold,
            [switch]$RemoveLicenses,
            $Cmdlet
        )
        [pscustomobject]@{
            Context    = $Context
            State      = $State
            Results    = @()
            StopReason = $null
            Summary    = [pscustomobject]@{
                TargetUPN     = $Context.TargetUPN
                RunId         = $State.RunId
                CorrelationId = $Context.CorrelationId
                OperatorUPN   = $Context.OperatorUPN
                TicketId      = $Context.TicketId
                Status        = 'Completed'
                Version       = 'v2.0-Premium'
                EvidenceLevel = $Context.EvidenceLevel
                Sealed        = $Context.SealEvidence
            }
        }
    }

    # ── Lite workflow and access removal stubs ────────────────────────────────
    # Global scope so BatchOrchestrator's private wrappers can find them
    function Global:Invoke-DecomAccessRemoval {
        param([pscustomobject]$Context, $Cmdlet,
              [switch]$SkipGroups, [switch]$SkipRoles, [switch]$SkipAuthMethods)
        @()  # return empty results
    }

    # ── Premium remediation stubs — BatchOrchestrator now calls these ─────────
    # Stub all premium phase functions so BatchOrchestrator tests don't require
    # ComplianceRemediation, LicenseRemediation, DeviceRemediation, etc. loaded.
    function Global:Add-DecomEvidenceEvent {
        param([pscustomobject]$Context, [string]$Phase, [string]$ActionName,
              [string]$Status, [bool]$IsCritical, [string]$Message,
              [hashtable]$BeforeState, [hashtable]$AfterState,
              [hashtable]$Evidence, [string]$ControlObjective, [string]$RiskMitigated)
    }
    function Set-DecomLitigationHold {
        param([pscustomobject]$Context, [bool]$LitigationHold = $true,
              [int]$LitigationHoldDuration = 0, $Cmdlet)
        [pscustomobject]@{ ActionName = 'Set Litigation Hold'; Phase = 'Compliance'
            Status = 'Success'; IsCritical = $true; TargetUPN = $Context.TargetUPN
            Message = 'Stub'; BeforeState = @{}; AfterState = @{}; Evidence = @{}
            WarningMessages = @(); BlockerMessages = @(); ManualFollowUp = @()
            RecommendedNext = $null; ControlObjective = ''; RiskMitigated = ''
            FailureClass = $null; StepId = 'stub'; TimestampUtc = (Get-Date).ToString('o') }
    }
    function Remove-DecomLicenses {
        param([pscustomobject]$Context, $Cmdlet)
        [pscustomobject]@{ ActionName = 'Remove Licenses'; Phase = 'LicenseRemediation'
            Status = 'Skipped'; IsCritical = $false; TargetUPN = $Context.TargetUPN
            Message = 'Stub'; BeforeState = @{}; AfterState = @{}; Evidence = @{}
            WarningMessages = @(); BlockerMessages = @(); ManualFollowUp = @()
            RecommendedNext = $null; ControlObjective = ''; RiskMitigated = ''
            FailureClass = $null; StepId = 'stub'; TimestampUtc = (Get-Date).ToString('o') }
    }
    function Invoke-DecomDeviceRemediation {
        param([pscustomobject]$Context, [switch]$SkipWipe, $Cmdlet)
        @()
    }
    function Remove-DecomAppOwnership {
        param([pscustomobject]$Context, $AppOwnershipState, $Cmdlet)
        [pscustomobject]@{ ActionName = 'Remove App Ownership'; Phase = 'AppOwnership'
            Status = 'Skipped'; IsCritical = $false; TargetUPN = $Context.TargetUPN
            Message = 'Stub'; BeforeState = @{}; AfterState = @{}; Evidence = @{}
            WarningMessages = @(); BlockerMessages = @(); ManualFollowUp = @()
            RecommendedNext = $null; ControlObjective = ''; RiskMitigated = ''
            FailureClass = $null; StepId = 'stub'; TimestampUtc = (Get-Date).ToString('o') }
    }
    function Remove-DecomAzureRBAC {
        param([pscustomobject]$Context, $RBACState, $Cmdlet)
        [pscustomobject]@{ ActionName = 'Remove Azure RBAC'; Phase = 'AzureRBAC'
            Status = 'Skipped'; IsCritical = $false; TargetUPN = $Context.TargetUPN
            Message = 'Stub'; BeforeState = @{}; AfterState = @{}; Evidence = @{}
            WarningMessages = @(); BlockerMessages = @(); ManualFollowUp = @()
            RecommendedNext = $null; ControlObjective = ''; RiskMitigated = ''
            FailureClass = $null; StepId = 'stub'; TimestampUtc = (Get-Date).ToString('o') }
    }
    function Remove-DecomMailForwarding {
        param([pscustomobject]$Context, $Cmdlet)
        [pscustomobject]@{ ActionName = 'Remove Mail Forwarding'; Phase = 'MailboxRemediation'
            Status = 'Skipped'; IsCritical = $false; TargetUPN = $Context.TargetUPN
            Message = 'Stub'; BeforeState = @{}; AfterState = @{}; Evidence = @{}
            WarningMessages = @(); BlockerMessages = @(); ManualFollowUp = @()
            RecommendedNext = $null; ControlObjective = ''; RiskMitigated = ''
            FailureClass = $null; StepId = 'stub'; TimestampUtc = (Get-Date).ToString('o') }
    }
    function Get-DecomUpnPolicy {
        param([pscustomobject]$Policy, [string]$UPN)
        [pscustomobject]@{ LitigationHold = $null; EvidenceLevel = $null
            WhatIf = $null; RemoveLicenses = $null
            SkipGroups = $null; SkipRoles = $null; SkipAuthMethods = $null }
    }

    # ── Load Premium modules ───────────────────────────────────────────────────
    Import-Module (Join-Path $premiumMods 'BatchContext.psm1')     -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchState.psm1')       -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchOrchestrator.psm1')-Force -DisableNameChecking
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchContext — New-DecomBatchContext' {

    It 'creates a batch with required fields' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @()
        $b.BatchId        | Should -Not -BeNullOrEmpty
        $b.CreatedUtc     | Should -Not -BeNullOrEmpty
        $b.OutputRoot     | Should -Be 'C:\out'
        $b.EvidenceLevel  | Should -Be 'Forensic'
        $b.WhatIf         | Should -Be $false
        $b.NonInteractive | Should -Be $false
        $b.Force          | Should -Be $false
        $b.MaxParallel    | Should -Be 1
    }

    It 'generates a unique BatchId each call' {
        $b1 = New-DecomBatchContext -OutputRoot 'C:\out'
        $b2 = New-DecomBatchContext -OutputRoot 'C:\out'
        $b1.BatchId | Should -Not -Be $b2.BatchId
    }

    It 'pre-populates entries from UpnList' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @('a@c.com','b@c.com')
        $b.Entries.Count | Should -Be 2
        $b.Entries.Contains('a@c.com') | Should -BeTrue
        $b.Entries.Contains('b@c.com') | Should -BeTrue
    }

    It 'stores entries with Pending status' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @('u@c.com')
        $b.Entries['u@c.com'].Status | Should -Be 'Pending'
    }

    It 'normalises UPN keys to lowercase' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @('User@Contoso.COM')
        $b.Entries.Contains('user@contoso.com') | Should -BeTrue
    }

    It 'accepts WhatIfMode and NonInteractive flags' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -WhatIfMode -NonInteractive
        $b.WhatIf         | Should -Be $true
        $b.NonInteractive | Should -Be $true
    }

    It 'stores TicketId' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -TicketId 'CHG001'
        $b.TicketId | Should -Be 'CHG001'
    }

    It 'stores OperatorUPN and OperatorObjectId' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' `
            -OperatorUPN 'admin@c.com' -OperatorObjectId 'oid-123'
        $b.OperatorUPN      | Should -Be 'admin@c.com'
        $b.OperatorObjectId | Should -Be 'oid-123'
    }

    It 'ignores blank entries in UpnList' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @('a@c.com','','  ')
        $b.Entries.Count | Should -Be 1
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchContext — New-DecomBatchEntry' {

    BeforeEach {
        $script:batch = New-DecomBatchContext -OutputRoot 'C:\out'
    }

    It 'adds a new entry as Pending' {
        $e = New-DecomBatchEntry -Batch $script:batch -UPN 'u@c.com'
        $e.Status | Should -Be 'Pending'
        $e.UPN    | Should -Be 'u@c.com'
    }

    It 'is idempotent — second call returns existing entry' {
        $e1 = New-DecomBatchEntry -Batch $script:batch -UPN 'u@c.com'
        $e2 = New-DecomBatchEntry -Batch $script:batch -UPN 'u@c.com'
        $script:batch.Entries.Count | Should -Be 1
        $e1.UPN | Should -Be $e2.UPN
    }

    It 'second call does not reset status of existing entry' {
        New-DecomBatchEntry -Batch $script:batch -UPN 'u@c.com' | Out-Null
        Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'u@c.com' -Status 'Completed'
        New-DecomBatchEntry -Batch $script:batch -UPN 'u@c.com' | Out-Null
        $script:batch.Entries['u@c.com'].Status | Should -Be 'Completed'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchContext — Get-DecomBatchEntry' {

    BeforeEach {
        $script:batch = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @('a@c.com')
    }

    It 'returns the entry for a known UPN' {
        $e = Get-DecomBatchEntry -Batch $script:batch -UPN 'a@c.com'
        $e | Should -Not -BeNullOrEmpty
        $e.UPN | Should -Be 'a@c.com'
    }

    It 'returns null for an unknown UPN' {
        $e = Get-DecomBatchEntry -Batch $script:batch -UPN 'missing@c.com'
        $e | Should -BeNullOrEmpty
    }

    It 'is case-insensitive' {
        $e = Get-DecomBatchEntry -Batch $script:batch -UPN 'A@C.COM'
        $e | Should -Not -BeNullOrEmpty
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchContext — Set-DecomBatchEntryStatus' {

    BeforeEach {
        $script:batch = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @('u@c.com')
    }

    It 'updates status to Running' {
        Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'u@c.com' -Status 'Running'
        $script:batch.Entries['u@c.com'].Status | Should -Be 'Running'
    }

    It 'sets StartedUtc when transitioning to Running' {
        Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'u@c.com' -Status 'Running'
        $script:batch.Entries['u@c.com'].StartedUtc | Should -Not -BeNullOrEmpty
    }

    It 'does not overwrite StartedUtc on second Running call' {
        Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'u@c.com' -Status 'Running'
        $first = $script:batch.Entries['u@c.com'].StartedUtc
        Start-Sleep -Milliseconds 10
        Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'u@c.com' -Status 'Running'
        $script:batch.Entries['u@c.com'].StartedUtc | Should -Be $first
    }

    It 'sets CompletedUtc when transitioning to Completed' {
        Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'u@c.com' -Status 'Completed'
        $script:batch.Entries['u@c.com'].CompletedUtc | Should -Not -BeNullOrEmpty
    }

    It 'sets CompletedUtc when transitioning to Failed' {
        Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'u@c.com' -Status 'Failed'
        $script:batch.Entries['u@c.com'].CompletedUtc | Should -Not -BeNullOrEmpty
    }

    It 'stores RunId' {
        Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'u@c.com' -Status 'Running' -RunId 'run-abc'
        $script:batch.Entries['u@c.com'].RunId | Should -Be 'run-abc'
    }

    It 'stores ErrorMessage on failure' {
        Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'u@c.com' -Status 'Failed' -ErrorMessage 'Graph call failed'
        $script:batch.Entries['u@c.com'].ErrorMessage | Should -Be 'Graph call failed'
    }

    It 'throws for unknown UPN' {
        { Set-DecomBatchEntryStatus -Batch $script:batch -UPN 'nobody@c.com' -Status 'Running' } |
            Should -Throw
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchContext — Get-DecomBatchSummary' {

    It 'returns zero counts for empty batch' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out'
        $s = Get-DecomBatchSummary -Batch $b
        $s.TotalCount | Should -Be 0
        $s.AllDone    | Should -Be $false
        $s.AnyFailed  | Should -Be $false
    }

    It 'counts Pending correctly' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @('a@c.com','b@c.com')
        $s = Get-DecomBatchSummary -Batch $b
        $s.Pending    | Should -Be 2
        $s.TotalCount | Should -Be 2
        $s.AllDone    | Should -Be $false
    }

    It 'reports AllDone when all entries are terminal' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @('a@c.com','b@c.com')
        Set-DecomBatchEntryStatus -Batch $b -UPN 'a@c.com' -Status 'Completed'
        Set-DecomBatchEntryStatus -Batch $b -UPN 'b@c.com' -Status 'Skipped'
        $s = Get-DecomBatchSummary -Batch $b
        $s.AllDone   | Should -Be $true
        $s.AnyFailed | Should -Be $false
    }

    It 'reports AnyFailed correctly' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -UpnList @('a@c.com','b@c.com')
        Set-DecomBatchEntryStatus -Batch $b -UPN 'a@c.com' -Status 'Completed'
        Set-DecomBatchEntryStatus -Batch $b -UPN 'b@c.com' -Status 'Failed'
        $s = Get-DecomBatchSummary -Batch $b
        $s.AnyFailed  | Should -Be $true
        $s.Failed     | Should -Be 1
        $s.Completed  | Should -Be 1
    }

    It 'carries BatchId and TicketId through' {
        $b = New-DecomBatchContext -OutputRoot 'C:\out' -TicketId 'CHG999'
        $s = Get-DecomBatchSummary -Batch $b
        $s.BatchId  | Should -Be $b.BatchId
        $s.TicketId | Should -Be 'CHG999'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchState — Save and Restore' {

    BeforeAll {
        $script:tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DecomBatchTest-' + [guid]::NewGuid().Guid)
        $null = New-Item -ItemType Directory -Path $script:tmpDir -Force
    }

    AfterAll {
        if (Test-Path $script:tmpDir) {
            Remove-Item -Path $script:tmpDir -Recurse -Force
        }
    }

    It 'Get-DecomBatchStatePath returns expected path' {
        $b    = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @()
        $path = Get-DecomBatchStatePath -Batch $b
        $path | Should -Match 'batch-state\.json$'
        $path | Should -BeLike "*$($b.BatchId)*"
    }

    It 'Save-DecomBatchState creates the file' {
        $b    = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('u@c.com')
        $path = Save-DecomBatchState -Batch $b
        Test-Path $path | Should -BeTrue
    }

    It 'saved file is valid JSON' {
        $b    = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('u@c.com')
        $path = Save-DecomBatchState -Batch $b
        $raw  = Get-Content $path -Raw
        { $raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'Restore-DecomBatchState rehydrates BatchId' {
        $b    = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('a@c.com')
        $path = Save-DecomBatchState -Batch $b
        $r    = Restore-DecomBatchState -StatePath $path
        $r.BatchId | Should -Be $b.BatchId
    }

    It 'Restore-DecomBatchState rehydrates all scalar fields' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @() `
            -TicketId 'CHG42' -EvidenceLevel 'Detailed' `
            -WhatIfMode -NonInteractive -OperatorUPN 'op@c.com'
        $path = Save-DecomBatchState -Batch $b
        $r    = Restore-DecomBatchState -StatePath $path
        $r.TicketId         | Should -Be 'CHG42'
        $r.EvidenceLevel    | Should -Be 'Detailed'
        $r.WhatIf           | Should -Be $true
        $r.NonInteractive   | Should -Be $true
        $r.OperatorUPN      | Should -Be 'op@c.com'
    }

    It 'Restore-DecomBatchState rehydrates Entries as ordered dict' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('a@c.com','b@c.com')
        Set-DecomBatchEntryStatus -Batch $b -UPN 'a@c.com' -Status 'Completed'
        $path = Save-DecomBatchState -Batch $b
        $r    = Restore-DecomBatchState -StatePath $path
        $r.Entries.Count | Should -Be 2
        $r.Entries['a@c.com'].Status | Should -Be 'Completed'
        $r.Entries['b@c.com'].Status | Should -Be 'Pending'
    }

    It 'Restore-DecomBatchState rehydrates entry UPN string' {
        $b    = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('alice@contoso.com')
        $path = Save-DecomBatchState -Batch $b
        $r    = Restore-DecomBatchState -StatePath $path
        $r.Entries['alice@contoso.com'].UPN | Should -Be 'alice@contoso.com'
    }

    It 'Save overwrites cleanly on second call (no leftover .tmp)' {
        $b    = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('u@c.com')
        Save-DecomBatchState -Batch $b | Out-Null
        Set-DecomBatchEntryStatus -Batch $b -UPN 'u@c.com' -Status 'Completed'
        $path = Save-DecomBatchState -Batch $b
        $tmp  = $path + '.tmp'
        Test-Path $tmp | Should -Be $false
        $r = Restore-DecomBatchState -StatePath $path
        $r.Entries['u@c.com'].Status | Should -Be 'Completed'
    }

    It 'Restore-DecomBatchState throws for missing file' {
        { Restore-DecomBatchState -StatePath 'C:\does\not\exist\batch-state.json' } |
            Should -Throw
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchOrchestrator — Invoke-DecomBatch' {

    BeforeAll {
        $script:tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DecomBatchOrcTest-' + [guid]::NewGuid().Guid)
        $null = New-Item -ItemType Directory -Path $script:tmpDir -Force

        # Default success stub — mocked on the private wrapper inside the module
        # so PowerShell's module scope resolution finds it during Invoke-DecomBatch.
        Mock -ModuleName BatchOrchestrator _InvokeDecomWorkflow {
            param($Context, $State, $OutOfOfficeMessage, $EnableLitigationHold, $RemoveLicenses, $Cmdlet)
            [pscustomobject]@{
                Context    = $Context
                State      = $State
                Results    = [System.Collections.Generic.List[object]]::new()
                StopReason = $null
                Summary    = [pscustomobject]@{
                    TargetUPN     = $Context.TargetUPN
                    RunId         = $State.RunId
                    CorrelationId = $Context.CorrelationId
                    OperatorUPN   = $Context.OperatorUPN
                    TicketId      = $Context.TicketId
                    Status        = 'Completed'
                    Version       = 'v2.0-Premium'
                    EvidenceLevel = $Context.EvidenceLevel
                    Sealed        = $Context.SealEvidence
                }
            }
        }

        Mock -ModuleName BatchOrchestrator _InvokeDecomAccessRemoval { @() }
    }

    AfterAll {
        if (Test-Path $script:tmpDir) {
            Remove-Item -Path $script:tmpDir -Recurse -Force
        }
    }

    It 'returns a BatchResult with Summary' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('u@c.com') -Force -NonInteractive
        $r = Invoke-DecomBatch -Batch $b -Cmdlet $null
        $r.BatchId  | Should -Be $b.BatchId
        $r.Summary  | Should -Not -BeNullOrEmpty
        $r.Results  | Should -Not -BeNullOrEmpty
    }

    It 'marks entry Completed after successful workflow run' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('alice@c.com') -Force -NonInteractive
        Invoke-DecomBatch -Batch $b -Cmdlet $null | Out-Null
        $b.Entries['alice@c.com'].Status | Should -Be 'Completed'
    }

    It 'processes multiple UPNs sequentially' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir `
            -UpnList @('u1@c.com','u2@c.com','u3@c.com') -Force -NonInteractive
        $r = Invoke-DecomBatch -Batch $b -Cmdlet $null
        $r.Summary.Completed | Should -Be 3
        $r.Summary.Failed    | Should -Be 0
        $r.Results.Count     | Should -Be 3
    }

    It 'skips Completed entries on re-run (idempotency)' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir `
            -UpnList @('done@c.com','todo@c.com') -Force -NonInteractive
        Set-DecomBatchEntryStatus -Batch $b -UPN 'done@c.com' -Status 'Completed'
        $r = Invoke-DecomBatch -Batch $b -Cmdlet $null
        $r.Results.Count     | Should -Be 1   # only 'todo@c.com' ran
        $r.Summary.Completed | Should -Be 2   # both show as Completed in summary
    }

    It 'skips Skipped entries on re-run' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir `
            -UpnList @('skip@c.com') -Force -NonInteractive
        Set-DecomBatchEntryStatus -Batch $b -UPN 'skip@c.com' -Status 'Skipped'
        $r = Invoke-DecomBatch -Batch $b -Cmdlet $null
        $r.Results.Count | Should -Be 0
    }

    It 'marks interrupted Running entries as Resumed before re-running' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir `
            -UpnList @('interrupted@c.com') -Force -NonInteractive
        Set-DecomBatchEntryStatus -Batch $b -UPN 'interrupted@c.com' -Status 'Running'
        Invoke-DecomBatch -Batch $b -Cmdlet $null | Out-Null
        $b.Entries['interrupted@c.com'].Status | Should -Be 'Completed'
    }

    It 'handles workflow exceptions — marks entry Failed, continues batch' {
        # Override the default success mock with a conditional throw for bad@c.com only.
        Mock -ModuleName BatchOrchestrator _InvokeDecomWorkflow {
            param($Context, $State, $OutOfOfficeMessage, $EnableLitigationHold, $RemoveLicenses, $Cmdlet)
            if ($Context.TargetUPN -eq 'bad@c.com') { throw 'Simulated Graph failure' }
            [pscustomobject]@{
                Context    = $Context
                State      = $State
                Results    = [System.Collections.Generic.List[object]]::new()
                StopReason = $null
                Summary    = [pscustomobject]@{
                    TargetUPN = $Context.TargetUPN; RunId = $State.RunId
                    CorrelationId = $Context.CorrelationId; Status = 'Completed'
                    Version = 'v2.0-Premium'; EvidenceLevel = $Context.EvidenceLevel
                    Sealed = $Context.SealEvidence; OperatorUPN = ''; TicketId = ''
                }
            }
        }

        $b = New-DecomBatchContext -OutputRoot $script:tmpDir `
            -UpnList @('bad@c.com','good@c.com') -Force -NonInteractive
        $r = Invoke-DecomBatch -Batch $b -Cmdlet $null

        $b.Entries['bad@c.com'].Status  | Should -Be 'Failed'
        $b.Entries['good@c.com'].Status | Should -Be 'Completed'
        $r.Errors.Count                 | Should -Be 1
        $r.Errors[0].UPN                | Should -Be 'bad@c.com'
        $r.Summary.Failed               | Should -Be 1
        $r.Summary.Completed            | Should -Be 1

        # Restore default success mock for subsequent tests in this Describe
        Mock -ModuleName BatchOrchestrator _InvokeDecomWorkflow {
            param($Context, $State, $OutOfOfficeMessage, $EnableLitigationHold, $RemoveLicenses, $Cmdlet)
            [pscustomobject]@{
                Context    = $Context; State = $State
                Results    = [System.Collections.Generic.List[object]]::new()
                StopReason = $null
                Summary    = [pscustomobject]@{
                    TargetUPN = $Context.TargetUPN; RunId = $State.RunId
                    CorrelationId = $Context.CorrelationId; Status = 'Completed'
                    Version = 'v2.0-Premium'; EvidenceLevel = $Context.EvidenceLevel
                    Sealed = $Context.SealEvidence; OperatorUPN = $Context.OperatorUPN
                    TicketId = $Context.TicketId
                }
            }
        }
    }

    It 'checkpoints state file to disk after each UPN' {
        $b         = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('ckpt@c.com') -Force -NonInteractive
        $statePath = Get-DecomBatchStatePath -Batch $b
        Invoke-DecomBatch -Batch $b -Cmdlet $null | Out-Null
        Test-Path $statePath | Should -BeTrue
    }

    It 'respects -SkipFailed flag — does not retry Failed entries' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('f@c.com') -Force -NonInteractive
        Set-DecomBatchEntryStatus -Batch $b -UPN 'f@c.com' -Status 'Failed'
        $r = Invoke-DecomBatch -Batch $b -SkipFailed -Cmdlet $null
        $r.Results.Count             | Should -Be 0
        $b.Entries['f@c.com'].Status | Should -Be 'Failed'
    }

    It 'creates per-UPN output directory' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('dirtest@c.com') -Force -NonInteractive
        Invoke-DecomBatch -Batch $b -Cmdlet $null | Out-Null
        $upnDir = Join-Path (Join-Path $script:tmpDir $b.BatchId) 'dirtest@c.com'
        Test-Path $upnDir | Should -BeTrue
    }

    It 'stores RunId on the entry after completion' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('runid@c.com') -Force -NonInteractive
        Invoke-DecomBatch -Batch $b -Cmdlet $null | Out-Null
        $b.Entries['runid@c.com'].RunId | Should -Not -BeNullOrEmpty
    }

    It 'AllDone is true after full batch completes' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('x@c.com','y@c.com') -Force -NonInteractive
        $r = Invoke-DecomBatch -Batch $b -Cmdlet $null
        $r.Summary.AllDone | Should -Be $true
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'Resume flow — end-to-end' {

    BeforeAll {
        $script:tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DecomResumeTest-' + [guid]::NewGuid().Guid)
        $null = New-Item -ItemType Directory -Path $script:tmpDir -Force

        Mock -ModuleName BatchOrchestrator _InvokeDecomWorkflow {
            param($Context, $State, $OutOfOfficeMessage, $EnableLitigationHold, $RemoveLicenses, $Cmdlet)
            [pscustomobject]@{
                Context    = $Context; State = $State
                Results    = [System.Collections.Generic.List[object]]::new()
                StopReason = $null
                Summary    = [pscustomobject]@{
                    TargetUPN = $Context.TargetUPN; RunId = $State.RunId
                    CorrelationId = $Context.CorrelationId; Status = 'Completed'
                    Version = 'v2.0-Premium'; EvidenceLevel = $Context.EvidenceLevel
                    Sealed = $Context.SealEvidence; OperatorUPN = $Context.OperatorUPN
                    TicketId = $Context.TicketId
                }
            }
        }

        Mock -ModuleName BatchOrchestrator _InvokeDecomAccessRemoval { @() }
    }

    AfterAll {
        if (Test-Path $script:tmpDir) {
            Remove-Item -Path $script:tmpDir -Recurse -Force
        }
    }

    It 'resume skips completed entries and runs only remaining' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir `
            -UpnList @('done@c.com','pending@c.com') -Force -NonInteractive -TicketId 'CHG-RESUME'
        Set-DecomBatchEntryStatus -Batch $b -UPN 'done@c.com' -Status 'Completed' -RunId 'old-run-id'
        $statePath = Save-DecomBatchState -Batch $b

        $restored = Restore-DecomBatchState -StatePath $statePath
        $r = Invoke-DecomBatch -Batch $restored -Cmdlet $null

        $r.Results.Count                         | Should -Be 1
        $restored.Entries['done@c.com'].Status    | Should -Be 'Completed'
        $restored.Entries['pending@c.com'].Status | Should -Be 'Completed'
        $restored.Entries['done@c.com'].RunId     | Should -Be 'old-run-id'
    }

    It 'restored batch preserves TicketId through save/restore cycle' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @() -TicketId 'CHG-TICKET'
        $path = Save-DecomBatchState -Batch $b
        $r    = Restore-DecomBatchState -StatePath $path
        $r.TicketId | Should -Be 'CHG-TICKET'
    }

    It 'restored batch preserves entry statuses' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('a@c.com','b@c.com') -Force -NonInteractive
        Set-DecomBatchEntryStatus -Batch $b -UPN 'a@c.com' -Status 'Completed'
        $path = Save-DecomBatchState -Batch $b
        $r    = Restore-DecomBatchState -StatePath $path
        $r.Entries['a@c.com'].Status | Should -Be 'Completed'
        $r.Entries['b@c.com'].Status | Should -Be 'Pending'
    }
}
