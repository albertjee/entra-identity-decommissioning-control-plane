# DecomCoverageGap.Tests.ps1 — High-severity coverage gap tests
# Premium v2.0 — Reconciled from Claude + Copilot diff
# Covers: GAP-05, GAP-06, GAP-07, GAP-11, GAP-13, GAP-15, GAP-16
#
# NOTE: GAP-16 test will FAIL until BatchApproval.psm1 adds ExpiresUtc validation.
# That is intentional — the test drives the module fix.

BeforeAll {
    $repoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $premiumMods = Join-Path $repoRoot 'src\Premium\Modules'
    $liteModules = Join-Path $repoRoot 'src\Modules'

    Import-Module (Join-Path $premiumMods 'BatchContext.psm1')     -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchState.psm1')       -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchReporting.psm1')   -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchOrchestrator.psm1')-Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'BatchApproval.psm1')    -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'DeviceRemediation.psm1')-Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'AzureRBAC.psm1')        -Force -DisableNameChecking
    Import-Module (Join-Path $liteModules  'Models.psm1')          -Force -DisableNameChecking

    $script:tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('DecomGapTest-' + [guid]::NewGuid().Guid)
    $null = New-Item -ItemType Directory -Path $script:tmpDir -Force

    # ── Global stubs — visible to all imported modules ─────────────────────────

    function Global:New-DecomRunContext {
        param([string]$TargetUPN, [string]$TicketId, [string]$OutputPath,
              [string]$EvidenceLevel = 'Forensic',
              [switch]$WhatIfMode, [switch]$NonInteractive, [switch]$Force, [switch]$NoSeal,
              [string]$OperatorUPN, [string]$OperatorObjectId)
        [pscustomobject]@{
            TargetUPN        = $TargetUPN
            TicketId         = $TicketId
            OutputPath       = $OutputPath
            EvidenceLevel    = $EvidenceLevel
            WhatIf           = [bool]$WhatIfMode
            NonInteractive   = [bool]$NonInteractive
            Force            = [bool]$Force
            SealEvidence     = -not [bool]$NoSeal
            OperatorUPN      = $OperatorUPN
            OperatorObjectId = $OperatorObjectId
            CorrelationId    = [guid]::NewGuid().Guid
            Evidence         = [System.Collections.Generic.List[object]]::new()
            RunId            = $null
            EvidencePrevHash = 'GENESIS'
        }
    }

    function Global:New-DecomState {
        param([string]$RunId)
        [pscustomobject]@{ RunId = $RunId; Phases = [ordered]@{} }
    }

    function Global:Initialize-DecomLog { param([string]$Path) }

    # GAP-07: Initialize-DecomEvidenceStore is intercepted per-test to capture context.
    # Default stub does the minimum needed for the orchestrator to proceed.
    function Global:Initialize-DecomEvidenceStore {
        param([pscustomobject]$Context, [string]$RunId, [string]$NdjsonPath)
        $Context | Add-Member -Force -NotePropertyName RunId            -NotePropertyValue $RunId
        $Context | Add-Member -Force -NotePropertyName EvidencePrevHash -NotePropertyValue 'GENESIS'
        $Context | Add-Member -Force -NotePropertyName Evidence         -NotePropertyValue ([System.Collections.Generic.List[object]]::new())
    }

    function Global:Write-DecomConsole { param([string]$Level, [string]$Message) }

    function Global:Add-DecomEvidenceEvent {
        param([pscustomobject]$Context, [string]$Phase, [string]$ActionName,
              [string]$Status, [bool]$IsCritical, [string]$Message,
              [hashtable]$BeforeState, [hashtable]$AfterState, [hashtable]$Evidence,
              [string]$ControlObjective, [string]$RiskMitigated)
    }

    function Global:Invoke-DecomWorkflow {
        param([pscustomobject]$Context, [pscustomobject]$State,
              [string]$OutOfOfficeMessage, [switch]$EnableLitigationHold,
              [switch]$RemoveLicenses, $Cmdlet)
        [pscustomobject]@{
            Context    = $Context
            State      = $State
            Results    = @()
            StopReason = $null
            Summary    = [pscustomobject]@{
                TargetUPN     = $Context.TargetUPN
                RunId         = $State.RunId
                Status        = 'Completed'
                Version       = 'v2.0-Premium'
                EvidenceLevel = $Context.EvidenceLevel
                Sealed        = $Context.SealEvidence
                CorrelationId = $Context.CorrelationId
                OperatorUPN   = $Context.OperatorUPN
                TicketId      = $Context.TicketId
            }
        }
    }

    function Global:Invoke-DecomAccessRemoval {
        param([pscustomobject]$Context, $Cmdlet,
              [switch]$SkipGroups, [switch]$SkipRoles, [switch]$SkipAuthMethods)
        @()
    }

    function Global:Get-DecomUpnPolicy {
        param([pscustomobject]$Policy, [string]$UPN)
        if ($Policy.UpnPolicies -and $Policy.UpnPolicies.ContainsKey($UPN)) {
            return $Policy.UpnPolicies[$UPN]
        }
        return $Policy.DefaultPolicy
    }

    function Global:Export-DecomJsonReport      { param([object]$WorkflowResult, [string]$Path) }
    function Global:Export-DecomHtmlReport      { param([object]$WorkflowResult, [string]$Path) }
    function Global:Write-DecomEvidenceManifest { param([pscustomobject]$Context, [string]$OutputPath) }
}

AfterAll {
    if (Test-Path $script:tmpDir) { Remove-Item $script:tmpDir -Recurse -Force }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchState — GAP-05: stale .tmp file collision' {

    It 'overwrites pre-existing .tmp and leaves no leftover' {
        $b         = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('u@t.com')
        $statePath = Join-Path $script:tmpDir 'gap05-state.json'
        $tmpPath   = $statePath + '.tmp'

        # Pre-create stale .tmp to simulate a previous crashed write
        Set-Content -Path $tmpPath -Value 'stale content from crashed run' -Encoding UTF8

        $result = Save-DecomBatchState -Batch $b -StatePath $statePath

        $result                | Should -Be $statePath
        Test-Path $tmpPath     | Should -BeFalse        # no leftover
        Test-Path $statePath   | Should -BeTrue         # real file written
        { Get-Content $statePath -Raw | ConvertFrom-Json } | Should -Not -Throw
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchOrchestrator — GAP-06: per-UPN policy override' {

    BeforeEach {
        # Policy: batch default is Standard/Live. UPN override is Forensic/WhatIf.
        $script:policy = [pscustomobject]@{
            DefaultPolicy = [pscustomobject]@{
                EvidenceLevel = 'Standard'
                WhatIf        = $false
                RemoveLicenses = $null
                SkipGroups    = $null
                SkipRoles     = $null
                SkipAuthMethods = $null
            }
            UpnPolicies   = @{
                'upn@gap06.com' = [pscustomobject]@{
                    EvidenceLevel  = 'Forensic'
                    WhatIf         = $true
                    RemoveLicenses = $null
                    SkipGroups     = $null
                    SkipRoles      = $null
                    SkipAuthMethods = $null
                }
            }
        }

        $script:capturedEvidenceLevel = $null
        $script:capturedWhatIf        = $null

        # Override New-DecomRunContext to capture what the orchestrator passes
        function Global:New-DecomRunContext {
            param([string]$TargetUPN, [string]$TicketId, [string]$OutputPath,
                  [string]$EvidenceLevel = 'Forensic',
                  [switch]$WhatIfMode, [switch]$NonInteractive, [switch]$Force,
                  [switch]$NoSeal, [string]$OperatorUPN, [string]$OperatorObjectId)
            $script:capturedEvidenceLevel = $EvidenceLevel
            $script:capturedWhatIf        = [bool]$WhatIfMode
            [pscustomobject]@{
                TargetUPN        = $TargetUPN; TicketId = $TicketId; OutputPath = $OutputPath
                EvidenceLevel    = $EvidenceLevel; WhatIf = [bool]$WhatIfMode
                NonInteractive   = [bool]$NonInteractive; Force = [bool]$Force
                SealEvidence     = -not [bool]$NoSeal; OperatorUPN = $OperatorUPN
                OperatorObjectId = $OperatorObjectId; CorrelationId = [guid]::NewGuid().Guid
                Evidence         = [System.Collections.Generic.List[object]]::new()
                RunId            = $null; EvidencePrevHash = 'GENESIS'
            }
        }
    }

    AfterEach {
        # Restore default stub
        function Global:New-DecomRunContext {
            param([string]$TargetUPN, [string]$TicketId, [string]$OutputPath,
                  [string]$EvidenceLevel = 'Forensic', [switch]$WhatIfMode,
                  [switch]$NonInteractive, [switch]$Force, [switch]$NoSeal,
                  [string]$OperatorUPN, [string]$OperatorObjectId)
            [pscustomobject]@{
                TargetUPN=''; TicketId=''; OutputPath=''; EvidenceLevel=$EvidenceLevel
                WhatIf=[bool]$WhatIfMode; NonInteractive=[bool]$NonInteractive
                Force=[bool]$Force; SealEvidence=-not [bool]$NoSeal
                OperatorUPN=''; OperatorObjectId=''
                CorrelationId=[guid]::NewGuid().Guid
                Evidence=[System.Collections.Generic.List[object]]::new()
                RunId=$null; EvidencePrevHash='GENESIS'
            }
        }
    }

    It 'applies UPN-specific EvidenceLevel override from policy' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir `
             -UpnList @('upn@gap06.com') -EvidenceLevel 'Standard'
        Invoke-DecomBatch -Batch $b -Policy $script:policy | Out-Null
        $script:capturedEvidenceLevel | Should -Be 'Forensic'
    }

    It 'applies UPN-specific WhatIf override from policy' {
        $b = New-DecomBatchContext -OutputRoot $script:tmpDir `
             -UpnList @('upn@gap06.com') -EvidenceLevel 'Standard'
        Invoke-DecomBatch -Batch $b -Policy $script:policy | Out-Null
        $script:capturedWhatIf | Should -BeTrue
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchOrchestrator — GAP-07: NoSeal flag propagation' {

    It 'sets SealEvidence=false on per-UPN context when batch NoSeal=true' {
        $script:capturedSealEvidence = $null

        function Global:Initialize-DecomEvidenceStore {
            param([pscustomobject]$Context, [string]$RunId, [string]$NdjsonPath)
            $script:capturedSealEvidence = $Context.SealEvidence
            $Context | Add-Member -Force -NotePropertyName RunId            -NotePropertyValue $RunId
            $Context | Add-Member -Force -NotePropertyName EvidencePrevHash -NotePropertyValue 'GENESIS'
            $Context | Add-Member -Force -NotePropertyName Evidence         -NotePropertyValue ([System.Collections.Generic.List[object]]::new())
        }

        $b = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('u@gap07.com')
        # Set NoSeal directly since the param may not be exposed on New-DecomBatchContext
        $b.NoSeal = $true

        Invoke-DecomBatch -Batch $b | Out-Null

        $script:capturedSealEvidence | Should -BeFalse

        # Restore default stub
        function Global:Initialize-DecomEvidenceStore {
            param([pscustomobject]$Context, [string]$RunId, [string]$NdjsonPath)
            $Context | Add-Member -Force -NotePropertyName RunId            -NotePropertyValue $RunId
            $Context | Add-Member -Force -NotePropertyName EvidencePrevHash -NotePropertyValue 'GENESIS'
            $Context | Add-Member -Force -NotePropertyName Evidence         -NotePropertyValue ([System.Collections.Generic.List[object]]::new())
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchReporting — GAP-11: evidence hash correctness' {

    BeforeEach {
        $script:upnDir = Join-Path $script:tmpDir ('gap11-' + [guid]::NewGuid().Guid)
        $null = New-Item -ItemType Directory -Path $script:upnDir -Force
        $script:ndjsonPath = Join-Path $script:upnDir 'evidence.ndjson'

        $script:b11 = New-DecomBatchContext -OutputRoot $script:tmpDir -UpnList @('h@gap11.com')
        Set-DecomBatchEntryStatus -Batch $script:b11 -UPN 'h@gap11.com' -Status 'Completed' -RunId 'r11'
        $script:b11.Entries['h@gap11.com'].OutputPath = $script:upnDir
    }

    It 'hash changes when file content changes' {
        Set-Content -Path $script:ndjsonPath -Value '{"event":"A"}' -Encoding UTF8
        $path1 = Write-DecomBatchEvidenceManifest -Batch $script:b11
        $m1    = Get-Content $path1 -Raw | ConvertFrom-Json
        $hash1 = $m1.Entries[0].NdjsonFileHash

        Set-Content -Path $script:ndjsonPath -Value '{"event":"B"}' -Encoding UTF8
        $path2 = Write-DecomBatchEvidenceManifest -Batch $script:b11
        $m2    = Get-Content $path2 -Raw | ConvertFrom-Json
        $hash2 = $m2.Entries[0].NdjsonFileHash

        $hash1 | Should -Not -BeNullOrEmpty
        $hash2 | Should -Not -BeNullOrEmpty
        $hash1 | Should -Not -Be $hash2
    }

    It 'hash matches independently computed SHA-256 of file content' {
        $content = '{"event":"integrity-check"}'
        Set-Content -Path $script:ndjsonPath -Value $content -Encoding UTF8

        $path = Write-DecomBatchEvidenceManifest -Batch $script:b11
        $m    = Get-Content $path -Raw | ConvertFrom-Json
        $reportedHash = $m.Entries[0].NdjsonFileHash

        # Compute expected hash from actual file bytes (not string bytes —
        # Set-Content encoding matters, so read back the file bytes)
        $sha      = [System.Security.Cryptography.SHA256]::Create()
        $stream   = [System.IO.File]::OpenRead($script:ndjsonPath)
        $expected = ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join ''
        $stream.Dispose()
        $sha.Dispose()

        $reportedHash | Should -Be $expected
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'DeviceRemediation — GAP-13: corporate device full wipe path' {

    BeforeEach {
        $script:wipeCalled   = $false
        $script:retireCalled = $false

        # Corporate device: TrustType = AzureAD (Entra Joined)
        function Global:Get-MgUserRegisteredDevice {
            param($UserId, [switch]$All, $ErrorAction)
            @([pscustomobject]@{ Id = 'entra-dev-corp-01' })
        }

        function Global:Get-MgDevice {
            param($DeviceId, $Property, $ErrorAction)
            [pscustomobject]@{
                Id          = 'entra-dev-corp-01'
                DisplayName = 'CORP-LAPTOP-01'
                DeviceId    = 'entra-dev-corp-01'
                TrustType   = 'AzureAD'
                AccountEnabled = $true
                OperatingSystem = 'Windows'
                OperatingSystemVersion = '11'
                ApproximateLastSignInDateTime = $null
                IsCompliant = $true
                IsManaged   = $true
            }
        }

        function Global:Update-MgDevice { param($DeviceId, $BodyParameter, $ErrorAction) }

        # First call (filter) returns the managed device; second call (property fetch) returns details
        $script:mgdCallCount = 0
        function Global:Get-MgDeviceManagementManagedDevice {
            param($Filter, $All, $ManagedDeviceId, $Property, $ErrorAction)
            $script:mgdCallCount++
            if ($script:mgdCallCount -eq 1) {
                # Filter call — return matching Intune device
                @([pscustomobject]@{ Id = 'intune-dev-corp-01'; ManagedDeviceOwnerType = 'company' })
            } else {
                # Property fetch call — return ownership details
                [pscustomobject]@{ Id = 'intune-dev-corp-01'; ManagedDeviceOwnerType = 'company' }
            }
        }

        function Global:Clear-MgDeviceManagementManagedDevice {
            param($ManagedDeviceId, $ErrorAction)
            $script:wipeCalled = $true
        }

        function Global:Invoke-MgRetireDeviceManagementManagedDevice {
            param($ManagedDeviceId, $ErrorAction)
            $script:retireCalled = $true
        }

        $script:ctx13 = [pscustomobject]@{
            TargetUPN        = 'corp@gap13.com'
            WhatIf           = $false
            EvidenceLevel    = 'Forensic'
            Evidence         = [System.Collections.Generic.List[object]]::new()
            RunId            = 'r13'
            EvidencePrevHash = 'GENESIS'
            CorrelationId    = [guid]::NewGuid().Guid
        }
    }

    It 'issues full wipe for corporate device not retire' {
        $results = @(Invoke-DecomDeviceRemediation -Context $script:ctx13)
        # The wipe result message contains 'wiped (full)' for corporate devices
        $wipeResult = $results | Where-Object { $_.ActionName -like '*Wipe*' -or $_.Message -like '*wipe*' }
        $wipeResult      | Should -Not -BeNullOrEmpty
        $wipeResult.ActionName | Should -Match 'Wipe'
        # Retire result should not exist
        $retireResult = $results | Where-Object { $_.ActionName -like '*Retire*' }
        $retireResult | Should -BeNullOrEmpty
    }

    It 'result ActionName contains Wipe for corporate device' {
        $results = @(Invoke-DecomDeviceRemediation -Context $script:ctx13)
        $wipeResult = $results | Where-Object { $_.ActionName -like '*Wipe*' }
        $wipeResult | Should -Not -BeNullOrEmpty
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'AzureRBAC — GAP-15: partial failure returns Warning' {

    It 'returns Warning when first removal succeeds but second fails' {
        $assignments = @(
            [pscustomobject]@{
                RoleDefinitionName = 'Contributor'
                Scope              = '/subscriptions/sub-001/resourceGroups/rg-a'
                SubscriptionId     = 'sub-001'
                SubscriptionName   = 'Sub A'
            },
            [pscustomobject]@{
                RoleDefinitionName = 'Reader'
                Scope              = '/subscriptions/sub-001/resourceGroups/rg-b'
                SubscriptionId     = 'sub-001'
                SubscriptionName   = 'Sub A'
            }
        )

        $rbacState = [pscustomobject]@{
            DirectAssignments  = $assignments
            DirectCount        = 2
            InheritedCount     = 0
            InheritedAssignments = @()
            SubscriptionsScanned = 1
        }

        $callCount = 0
        function Global:Set-AzContext {
            param($SubscriptionId, $ErrorAction)
            [pscustomobject]@{ Subscription = $SubscriptionId }
        }
        function Global:Remove-AzRoleAssignment {
            param($SignInName, $RoleDefinitionName, $Scope, $ErrorAction)
            $script:callCount++
            if ($script:callCount -eq 2) { throw 'Authorization failed on second assignment' }
        }
        $script:callCount = 0

        $ctx15 = [pscustomobject]@{
            TargetUPN        = 'rbac@gap15.com'
            WhatIf           = $false
            EvidenceLevel    = 'Forensic'
            Evidence         = [System.Collections.Generic.List[object]]::new()
            RunId            = 'r15'
            EvidencePrevHash = 'GENESIS'
            CorrelationId    = [guid]::NewGuid().Guid
        }

        $result = Remove-DecomAzureRBAC -Context $ctx15 -RBACState $rbacState
        $result.Status | Should -Be 'Warning'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'BatchApproval — GAP-16: expired approval rejected' {
    # NOTE: This test will FAIL until BatchApproval.psm1 adds ExpiresUtc validation.
    # The test is intentionally written to drive that module fix.

    It 'throws when approval ExpiresUtc is in the past' {
        $b16 = New-DecomBatchContext -OutputRoot $script:tmpDir -TicketId 'CHG-99916'

        $approvalPath = Join-Path $script:tmpDir 'gap16-approval.json'
        [ordered]@{
            SchemaVersion = '2.0'
            RecordType    = 'ApprovalRecord'
            BatchId       = $b16.BatchId
            TicketId      = 'CHG-99916'
            OperatorUPN   = 'mgr@gap16.com'
            ApprovedUtc   = (Get-Date).AddDays(-2).ToUniversalTime().ToString('o')
            ExpiresUtc    = (Get-Date).AddDays(-1).ToUniversalTime().ToString('o')  # expired yesterday
            Approved      = $true
            Method        = 'NonInteractive'
        } | ConvertTo-Json | Set-Content -Path $approvalPath -Encoding UTF8

        {
            Invoke-DecomBatchApproval -Batch $b16 -ApprovalPath $approvalPath `
                -NonInteractive -TicketId 'CHG-99916' -OperatorUPN 'mgr@gap16.com'
        } | Should -Throw -ExpectedMessage '*expired*'
    }
}
