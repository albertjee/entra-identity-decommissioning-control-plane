# DecomPremiumRemediation.Tests.ps1 — Pester v5 tests for Premium v2.0 remediation modules
# Covers: ComplianceRemediation, LicenseRemediation, DeviceRemediation,
#         AppOwnership, AzureRBAC
#
# Run from repo root:
#   Invoke-Pester .\tests\Premium\DecomPremiumRemediation.Tests.ps1 -Output Detailed

BeforeAll {
    $repoRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $liteMods    = Join-Path $repoRoot 'src\Modules'
    $premiumMods = Join-Path $repoRoot 'src\Premium\Modules'

    Import-Module (Join-Path $liteMods 'Models.psm1') -Force -DisableNameChecking

    function Write-DecomConsole { param([string]$Level, [string]$Message) }

    # Add-DecomEvidenceEvent must be Global so module scope can resolve it
    function Global:Add-DecomEvidenceEvent {
        param([pscustomobject]$Context, [string]$Phase, [string]$ActionName,
              [string]$Status, [bool]$IsCritical, [string]$Message,
              [hashtable]$BeforeState, [hashtable]$AfterState,
              [hashtable]$Evidence, [string]$ControlObjective, [string]$RiskMitigated)
    }

    # ── Default stubs — restored in each Describe BeforeAll ───────────────────
    function script:Reset-EXOStubs {
        function Global:Get-EXOMailbox {
            param([string]$Identity, [string[]]$Property, [string]$ErrorAction)
            [pscustomobject]@{
                LitigationHoldEnabled  = $false
                LitigationHoldDuration = $null
                LitigationHoldOwner    = $null
                ForwardingSmtpAddress  = $null
                ForwardingAddress      = $null
                DeliverToMailboxAndForward = $false
            }
        }
        function Global:Set-Mailbox {
            param([string]$Identity, $LitigationHoldEnabled, $LitigationHoldDuration,
                  $ForwardingSmtpAddress, $ForwardingAddress,
                  [bool]$DeliverToMailboxAndForward, [string]$ErrorAction)
        }
    }

    function script:Reset-GraphStubs {
        function Global:Get-MgUser {
            param([string]$UserId, [string]$Property, [string]$ErrorAction)
            [pscustomobject]@{
                Id               = 'user-id-001'
                AssignedLicenses = @([pscustomobject]@{ SkuId = 'sku-e3-001' })
                LicenseAssignmentStates = @(
                    [pscustomobject]@{ SkuId = 'sku-e3-001'; AssignedByGroup = $null }
                )
            }
        }
        function Global:Set-MgUserLicense {
            param([string]$UserId, $RemoveLicenses, $AddLicenses, [string]$ErrorAction)
        }
        function Global:Get-MgUserRegisteredDevice {
            param([string]$UserId, [switch]$All, [string]$ErrorAction)
            @([pscustomobject]@{ Id = 'device-id-001' })
        }
        function Global:Get-MgDevice {
            param([string]$DeviceId, [string]$Property, [string]$ErrorAction)
            [pscustomobject]@{
                Id = 'device-id-001'; DisplayName = 'DESKTOP-CORP01'
                TrustType = 'AzureAD'; AccountEnabled = $true
                IsCompliant = $true; IsManaged = $true
                OperatingSystem = 'Windows'; OperatingSystemVersion = '11'
                ApproximateLastSignInDateTime = (Get-Date).AddDays(-5)
            }
        }
        function Global:Update-MgDevice {
            param([string]$DeviceId, [bool]$AccountEnabled, [string]$ErrorAction)
        }
        function Global:Get-MgDeviceManagementManagedDevice {
            param([string]$ManagedDeviceId, [string]$Filter, [switch]$All,
                  [string]$Property, [string]$ErrorAction)
            @([pscustomobject]@{ Id = 'intune-dev-001'; ManagedDeviceOwnerType = 'company' })
        }
        function Global:Invoke-MgRetireDeviceManagementManagedDevice {
            param([string]$ManagedDeviceId, [string]$ErrorAction)
        }
        function Global:Clear-MgDeviceManagementManagedDevice {
            param([string]$ManagedDeviceId, [string]$ErrorAction)
        }
        function Global:Get-MgUserOwnedObject {
            param([string]$UserId, [switch]$All, [string]$ErrorAction)
            @([pscustomobject]@{
                Id = 'app-id-001'
                AdditionalProperties = @{
                    '@odata.type' = '#microsoft.graph.application'
                    'displayName' = 'MyApp'
                    'appId'       = 'app-client-001'
                }
            })
        }
        function Global:Get-MgApplicationOwner {
            param([string]$ApplicationId, [switch]$All, [string]$ErrorAction)
            @([pscustomobject]@{ Id = 'user-id-001' },
              [pscustomobject]@{ Id = 'other-id-002' })
        }
        function Global:Get-MgServicePrincipalOwner {
            param([string]$ServicePrincipalId, [switch]$All, [string]$ErrorAction)
            @([pscustomobject]@{ Id = 'user-id-001' })
        }
        function Global:Remove-MgApplicationOwnerByRef {
            param([string]$ApplicationId, [string]$DirectoryObjectId, [string]$ErrorAction)
        }
        function Global:Remove-MgServicePrincipalOwnerByRef {
            param([string]$ServicePrincipalId, [string]$DirectoryObjectId, [string]$ErrorAction)
        }
    }

    function script:Reset-AzStubs {
        function Global:Get-AzSubscription {
            param([string]$ErrorAction)
            @([pscustomobject]@{ Id = 'sub-001'; Name = 'TestSub' })
        }
        function Global:Set-AzContext {
            param([string]$SubscriptionId, [string]$ErrorAction)
        }
        function Global:Get-AzRoleAssignment {
            param([string]$SignInName, [string]$ErrorAction)
            @([pscustomobject]@{
                RoleAssignmentId   = 'ra-001'
                RoleDefinitionName = 'Contributor'
                Scope              = '/subscriptions/sub-001/resourceGroups/rg-test'
                ObjectType         = 'User'
            })
        }
        function Global:Remove-AzRoleAssignment {
            param([string]$SignInName, [string]$RoleDefinitionName,
                  [string]$Scope, [string]$ErrorAction)
        }
    }

    # Run all resets at startup
    Reset-EXOStubs
    Reset-GraphStubs
    Reset-AzStubs

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

    # Load Premium modules
    Import-Module (Join-Path $premiumMods 'ComplianceRemediation.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'LicenseRemediation.psm1')   -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'DeviceRemediation.psm1')    -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'AppOwnership.psm1')         -Force -DisableNameChecking
    Import-Module (Join-Path $premiumMods 'AzureRBAC.psm1')            -Force -DisableNameChecking
}

AfterAll {
    # Remove Global stubs to prevent contamination of subsequent test files
    # when the full Premium suite runs together
    Remove-Item -Path Function:Global:Add-DecomEvidenceEvent   -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-EXOMailbox            -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Set-Mailbox               -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-MgUser                -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Set-MgUserLicense         -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-MgUserRegisteredDevice -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-MgDevice              -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Update-MgDevice           -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-MgDeviceManagementManagedDevice -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Invoke-MgRetireDeviceManagementManagedDevice -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Clear-MgDeviceManagementManagedDevice -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-MgUserOwnedObject     -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-MgApplicationOwner   -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-MgServicePrincipalOwner -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Remove-MgApplicationOwnerByRef -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Remove-MgServicePrincipalOwnerByRef -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-AzSubscription        -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Set-AzContext             -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Get-AzRoleAssignment      -ErrorAction SilentlyContinue
    Remove-Item -Path Function:Global:Remove-AzRoleAssignment   -ErrorAction SilentlyContinue
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'ComplianceRemediation - Set-DecomLitigationHold' {

    BeforeEach { Reset-EXOStubs }

    It 'returns Skipped when LH already enabled' {
        function Global:Get-EXOMailbox {
            param([string]$Identity, [string[]]$Property, [string]$ErrorAction)
            [pscustomobject]@{ LitigationHoldEnabled = $true; LitigationHoldDuration = $null; LitigationHoldOwner = $null }
        }
        $r = Set-DecomLitigationHold -Context (New-TestContext) -LitigationHold $true
        $r.Status  | Should -Be 'Skipped'
        $r.Message | Should -Match 'already enabled'
    }

    It 'returns Skipped when LH already disabled and opt-out requested' {
        $r = Set-DecomLitigationHold -Context (New-TestContext) -LitigationHold $false
        $r.Status  | Should -Be 'Skipped'
        $r.Message | Should -Match 'already disabled'
    }

    It 'returns Success in WhatIf mode without calling Set-Mailbox' {
        $script:setMailboxCalled = $false
        function Global:Set-Mailbox {
            param([string]$Identity, $LitigationHoldEnabled, $LitigationHoldDuration, [string]$ErrorAction)
            $script:setMailboxCalled = $true
        }
        $r = Set-DecomLitigationHold -Context (New-TestContext -WhatIf)
        $r.Status                | Should -Be 'Success'
        $r.Message               | Should -Match '\[WhatIf\]'
        $script:setMailboxCalled | Should -Be $false
    }

    It 'returns Warning when verification gate shows hold did not change' {
        # Default stub returns disabled before AND after — hold never changes
        $r = Set-DecomLitigationHold -Context (New-TestContext)
        $r.Status  | Should -Be 'Warning'
        $r.Message | Should -Match 'did not reach expected state'
    }

    It 'returns Warning when Get-EXOMailbox throws' {
        function Global:Get-EXOMailbox {
            param([string]$Identity, [string[]]$Property, [string]$ErrorAction)
            throw 'EXO connection failed'
        }
        $r = Set-DecomLitigationHold -Context (New-TestContext)
        $r.Status       | Should -Be 'Warning'
        $r.FailureClass | Should -Be 'ExchangeComplianceError'
    }

    It 'returns Success when before=false after=true' {
        $script:lhCount = 0
        function Global:Get-EXOMailbox {
            param([string]$Identity, [string[]]$Property, [string]$ErrorAction)
            $script:lhCount++
            if ($script:lhCount -eq 1) {
                [pscustomobject]@{ LitigationHoldEnabled = $false; LitigationHoldDuration = $null; LitigationHoldOwner = $null }
            } else {
                [pscustomobject]@{ LitigationHoldEnabled = $true; LitigationHoldDuration = $null }
            }
        }
        $r = Set-DecomLitigationHold -Context (New-TestContext)
        $r.Status | Should -Be 'Success'
        $r.Phase  | Should -Be 'Compliance'
    }

    It 'IsCritical is true on all results' {
        function Global:Get-EXOMailbox {
            param([string]$Identity, [string[]]$Property, [string]$ErrorAction)
            [pscustomobject]@{ LitigationHoldEnabled = $true; LitigationHoldDuration = $null; LitigationHoldOwner = $null }
        }
        $r = Set-DecomLitigationHold -Context (New-TestContext)
        $r.IsCritical | Should -Be $true
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'LicenseRemediation - Get-DecomLicenseState' {

    BeforeEach { Reset-GraphStubs }

    It 'returns correct counts for direct assignments' {
        $state = Get-DecomLicenseState -Context (New-TestContext)
        $state.DirectCount          | Should -Be 1
        $state.TotalCount           | Should -Be 1
        $state.DirectAssignedSkuIds | Should -Contain 'sku-e3-001'
    }

    It 'throws when Get-MgUser fails' {
        function Global:Get-MgUser {
            param([string]$UserId, [string]$Property, [string]$ErrorAction)
            throw 'Graph error'
        }
        { Get-DecomLicenseState -Context (New-TestContext) } | Should -Throw
    }
}

Describe 'LicenseRemediation - Remove-DecomLicenses' {

    BeforeEach { Reset-GraphStubs }

    It 'returns Skipped when no directly assigned licenses found' {
        function Global:Get-MgUser {
            param([string]$UserId, [string]$Property, [string]$ErrorAction)
            [pscustomobject]@{ AssignedLicenses = @(); LicenseAssignmentStates = @() }
        }
        $r = Remove-DecomLicenses -Context (New-TestContext)
        $r.Status  | Should -Be 'Skipped'
        $r.Message | Should -Match 'No directly assigned'
    }

    It 'returns Success in WhatIf mode without calling Set-MgUserLicense' {
        $script:licCalled = $false
        function Global:Set-MgUserLicense {
            param([string]$UserId, $RemoveLicenses, $AddLicenses, [string]$ErrorAction)
            $script:licCalled = $true
        }
        $r = Remove-DecomLicenses -Context (New-TestContext -WhatIf)
        $r.Status      | Should -Be 'Success'
        $r.Message     | Should -Match '\[WhatIf\]'
        $script:licCalled | Should -Be $false
    }

    It 'returns Failed when Set-MgUserLicense throws' {
        function Global:Set-MgUserLicense {
            param([string]$UserId, $RemoveLicenses, $AddLicenses, [string]$ErrorAction)
            throw 'Graph throttle'
        }
        $r = Remove-DecomLicenses -Context (New-TestContext)
        $r.Status       | Should -Be 'Failed'
        $r.FailureClass | Should -Be 'GraphError'
    }

    It 'notes group-based licenses in Skipped message' {
        function Global:Get-MgUser {
            param([string]$UserId, [string]$Property, [string]$ErrorAction)
            [pscustomobject]@{
                AssignedLicenses = @()
                LicenseAssignmentStates = @(
                    [pscustomobject]@{ SkuId = 'sku-grp-001'; AssignedByGroup = 'grp-001' }
                )
            }
        }
        $r = Remove-DecomLicenses -Context (New-TestContext)
        $r.Status  | Should -Be 'Skipped'
        $r.Message | Should -Match 'group'
    }

    It 'returns Success when licenses removed and post-state is empty' {
        $script:mgCount = 0
        function Global:Get-MgUser {
            param([string]$UserId, [string]$Property, [string]$ErrorAction)
            $script:mgCount++
            if ($script:mgCount -eq 1) {
                [pscustomobject]@{
                    AssignedLicenses = @([pscustomobject]@{ SkuId = 'sku-e3-001' })
                    LicenseAssignmentStates = @([pscustomobject]@{ SkuId = 'sku-e3-001'; AssignedByGroup = $null })
                }
            } else {
                [pscustomobject]@{ AssignedLicenses = @(); LicenseAssignmentStates = @() }
            }
        }
        $r = Remove-DecomLicenses -Context (New-TestContext)
        $r.Status | Should -Be 'Success'
        $r.Phase  | Should -Be 'LicenseRemediation'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'DeviceRemediation - Get-DecomDeviceState' {

    BeforeEach { Reset-GraphStubs }

    It 'returns device list with correct counts' {
        $state = Get-DecomDeviceState -Context (New-TestContext)
        $state.TotalCount     | Should -Be 1
        $state.CorporateCount | Should -Be 1
        $state.BYODCount      | Should -Be 0
    }

    It 'classifies Workplace TrustType as BYOD' {
        function Global:Get-MgDevice {
            param([string]$DeviceId, [string]$Property, [string]$ErrorAction)
            [pscustomobject]@{
                Id = 'dev-byod'; DisplayName = 'PHONE'; TrustType = 'Workplace'
                AccountEnabled = $true; IsCompliant = $false; IsManaged = $true
                OperatingSystem = 'iOS'; OperatingSystemVersion = '17'
                ApproximateLastSignInDateTime = (Get-Date)
            }
        }
        $state = Get-DecomDeviceState -Context (New-TestContext)
        $state.BYODCount      | Should -Be 1
        $state.CorporateCount | Should -Be 0
    }

    It 'keeps placeholder record when device detail fetch fails' {
        function Global:Get-MgDevice {
            param([string]$DeviceId, [string]$Property, [string]$ErrorAction)
            throw 'Not found'
        }
        $state = Get-DecomDeviceState -Context (New-TestContext)
        $state.TotalCount                 | Should -Be 1
        $state.Devices[0].DetailReadError | Should -Not -BeNullOrEmpty
        $state.Devices[0].IsBYOD         | Should -Be $true
    }

    It 'throws when Get-MgUserRegisteredDevice fails' {
        function Global:Get-MgUserRegisteredDevice {
            param([string]$UserId, [switch]$All, [string]$ErrorAction)
            throw 'Auth error'
        }
        { Get-DecomDeviceState -Context (New-TestContext) } | Should -Throw
    }
}

Describe 'DeviceRemediation - Disable-DecomEntraDevices' {

    BeforeEach { Reset-GraphStubs }

    It 'returns Skipped when no devices found' {
        function Global:Get-MgUserRegisteredDevice {
            param([string]$UserId, [switch]$All, [string]$ErrorAction)
            @()
        }
        $r = Disable-DecomEntraDevices -Context (New-TestContext)
        $r.Status | Should -Be 'Skipped'
    }

    It 'returns Success when device disabled successfully' {
        # Device is enabled — Update-MgDevice is called — result is Success
        $r = Disable-DecomEntraDevices -Context (New-TestContext)
        $r.Status | Should -Be 'Success'
        $r.Phase  | Should -Be 'DeviceRemediation'
    }

    It 'returns Success in WhatIf mode without calling Update-MgDevice' {
        $script:updateCalled = $false
        function Global:Update-MgDevice {
            param([string]$DeviceId, [bool]$AccountEnabled, [string]$ErrorAction)
            $script:updateCalled = $true
        }
        $r = Disable-DecomEntraDevices -Context (New-TestContext -WhatIf)
        $r.Status            | Should -Be 'Success'
        $r.Message           | Should -Match '\[WhatIf\]'
        $script:updateCalled | Should -Be $false
    }

    It 'reports Skipped status per-device when already disabled' {
        function Global:Get-MgDevice {
            param([string]$DeviceId, [string]$Property, [string]$ErrorAction)
            [pscustomobject]@{
                Id = 'dev-001'; DisplayName = 'DESKTOP'
                TrustType = 'AzureAD'; AccountEnabled = $false
                IsCompliant = $true; IsManaged = $true
                OperatingSystem = 'Windows'; OperatingSystemVersion = '11'
                ApproximateLastSignInDateTime = (Get-Date)
            }
        }
        $r = Disable-DecomEntraDevices -Context (New-TestContext)
        $r.Evidence.DeviceResults[0].Status | Should -Be 'Skipped'
    }

    It 'returns Failed when all devices fail to disable' {
        function Global:Update-MgDevice {
            param([string]$DeviceId, [bool]$AccountEnabled, [string]$ErrorAction)
            throw 'Permission denied'
        }
        $r = Disable-DecomEntraDevices -Context (New-TestContext)
        $r.Status               | Should -Be 'Failed'
        $r.Evidence.FailedCount | Should -Be 1
    }
}

Describe 'DeviceRemediation - Invoke-DecomDeviceRemediation' {

    BeforeEach { Reset-GraphStubs }

    It 'returns at least one result' {
        $results = Invoke-DecomDeviceRemediation -Context (New-TestContext)
        $results.Count | Should -BeGreaterThan 0
    }

    It 'skips Intune action when -SkipWipe is set' {
        $results = Invoke-DecomDeviceRemediation -Context (New-TestContext) -SkipWipe
        $results.Count         | Should -Be 1
        $results[0].ActionName | Should -Match 'Disable'
    }

    It 'issues retire for BYOD not full wipe' {
        function Global:Get-MgDevice {
            param([string]$DeviceId, [string]$Property, [string]$ErrorAction)
            [pscustomobject]@{
                Id = 'dev-byod'; DisplayName = 'PHONE'; TrustType = 'Workplace'
                AccountEnabled = $true; IsCompliant = $false; IsManaged = $true
                OperatingSystem = 'iOS'; OperatingSystemVersion = '17'
                ApproximateLastSignInDateTime = (Get-Date)
            }
        }
        function Global:Get-MgDeviceManagementManagedDevice {
            param([string]$ManagedDeviceId, [string]$Filter, [switch]$All,
                  [string]$Property, [string]$ErrorAction)
            @([pscustomobject]@{ Id = 'intune-byod-001'; ManagedDeviceOwnerType = 'personal' })
        }
        $script:wipeCalled   = $false
        $script:retireCalled = $false
        function Global:Clear-MgDeviceManagementManagedDevice {
            param([string]$ManagedDeviceId, [string]$ErrorAction)
            $script:wipeCalled = $true
        }
        function Global:Invoke-MgRetireDeviceManagementManagedDevice {
            param([string]$ManagedDeviceId, [string]$ErrorAction)
            $script:retireCalled = $true
        }
        Invoke-DecomDeviceRemediation -Context (New-TestContext) | Out-Null
        $script:retireCalled | Should -Be $true
        $script:wipeCalled   | Should -Be $false
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'AppOwnership - Get-DecomAppOwnershipState' {

    BeforeEach { Reset-GraphStubs }

    It 'returns app registrations with correct owner count' {
        $state = Get-DecomAppOwnershipState -Context (New-TestContext)
        $state.AppCount                        | Should -Be 1
        $state.AppRegistrations[0].DisplayName | Should -Be 'MyApp'
        $state.AppRegistrations[0].OwnerCount  | Should -Be 2
        $state.AppRegistrations[0].IsSoleOwner | Should -Be $false
    }

    It 'detects sole owner when only one owner returned' {
        function Global:Get-MgApplicationOwner {
            param([string]$ApplicationId, [switch]$All, [string]$ErrorAction)
            @([pscustomobject]@{ Id = 'user-id-001' })
        }
        $state = Get-DecomAppOwnershipState -Context (New-TestContext)
        $state.AppRegistrations[0].IsSoleOwner | Should -Be $true
        $state.SoleOwnerAppCount               | Should -Be 1
    }

    It 'returns placeholder with OwnerReadError when owner fetch fails' {
        function Global:Get-MgApplicationOwner {
            param([string]$ApplicationId, [switch]$All, [string]$ErrorAction)
            throw 'Graph permission denied'
        }
        $state = Get-DecomAppOwnershipState -Context (New-TestContext)
        $state.AppRegistrations[0].OwnerCount     | Should -Be -1
        $state.AppRegistrations[0].OwnerReadError | Should -Not -BeNullOrEmpty
    }

    It 'returns zero counts when user owns no objects' {
        function Global:Get-MgUserOwnedObject {
            param([string]$UserId, [switch]$All, [string]$ErrorAction)
            @()
        }
        $state = Get-DecomAppOwnershipState -Context (New-TestContext)
        $state.AppCount | Should -Be 0
        $state.SpnCount | Should -Be 0
    }
}

Describe 'AppOwnership - Remove-DecomAppOwnership' {

    BeforeEach { Reset-GraphStubs }

    It 'returns Skipped when no owned objects found' {
        function Global:Get-MgUserOwnedObject {
            param([string]$UserId, [switch]$All, [string]$ErrorAction)
            @()
        }
        $r = Remove-DecomAppOwnership -Context (New-TestContext)
        $r.Status | Should -Be 'Skipped'
    }

    It 'returns Success when ownership removed from non-sole-owner app' {
        $r = Remove-DecomAppOwnership -Context (New-TestContext)
        $r.Status | Should -Be 'Success'
        $r.Phase  | Should -Be 'AppOwnership'
    }

    It 'returns Warning when UPN is sole owner and does not remove' {
        function Global:Get-MgApplicationOwner {
            param([string]$ApplicationId, [switch]$All, [string]$ErrorAction)
            @([pscustomobject]@{ Id = 'user-id-001' })
        }
        $script:removeCalled = $false
        function Global:Remove-MgApplicationOwnerByRef {
            param([string]$ApplicationId, [string]$DirectoryObjectId, [string]$ErrorAction)
            $script:removeCalled = $true
        }
        $r = Remove-DecomAppOwnership -Context (New-TestContext)
        $r.Status                   | Should -Be 'Warning'
        $r.Evidence.Results[0].Note | Should -Match 'Sole owner'
        $script:removeCalled        | Should -Be $false
    }

    It 'returns Success in WhatIf mode' {
        $r = Remove-DecomAppOwnership -Context (New-TestContext -WhatIf)
        $r.Status  | Should -Be 'Success'
        $r.Message | Should -Match '\[WhatIf\]'
    }

    It 'returns Warning when owner enumeration failed' {
        function Global:Get-MgApplicationOwner {
            param([string]$ApplicationId, [switch]$All, [string]$ErrorAction)
            throw 'Graph error'
        }
        $r = Remove-DecomAppOwnership -Context (New-TestContext)
        $r.Status                   | Should -Be 'Warning'
        $r.Evidence.Results[0].Note | Should -Match 'Owner enumeration failed'
    }

    It 'records Failed per-object when Remove-MgApplicationOwnerByRef throws' {
        function Global:Remove-MgApplicationOwnerByRef {
            param([string]$ApplicationId, [string]$DirectoryObjectId, [string]$ErrorAction)
            throw 'Permission denied'
        }
        $r = Remove-DecomAppOwnership -Context (New-TestContext)
        $failedResult = @($r.Evidence.Results) | Where-Object { $_.Status -eq 'Failed' }
        $failedResult | Should -Not -BeNullOrEmpty
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
Describe 'AzureRBAC - Get-DecomAzureRBACState' {

    BeforeEach { Reset-AzStubs }

    It 'returns direct assignment at resource group scope' {
        $state = Get-DecomAzureRBACState -Context (New-TestContext)
        $state.DirectCount                             | Should -Be 1
        $state.SubscriptionsScanned                    | Should -Be 1
        $state.DirectAssignments[0].RoleDefinitionName | Should -Be 'Contributor'
    }

    It 'classifies subscription-exact scope as direct' {
        function Global:Get-AzRoleAssignment {
            param([string]$SignInName, [string]$ErrorAction)
            @([pscustomobject]@{
                RoleAssignmentId = 'ra-sub'; RoleDefinitionName = 'Reader'
                Scope = '/subscriptions/sub-001'; ObjectType = 'User'
            })
        }
        $state = Get-DecomAzureRBACState -Context (New-TestContext)
        $state.DirectCount    | Should -Be 1
        $state.InheritedCount | Should -Be 0
    }

    It 'classifies management group scope as inherited' {
        function Global:Get-AzRoleAssignment {
            param([string]$SignInName, [string]$ErrorAction)
            @([pscustomobject]@{
                RoleAssignmentId = 'ra-mg'; RoleDefinitionName = 'Owner'
                Scope = '/providers/Microsoft.Management/managementGroups/mg-root'
                ObjectType = 'User'
            })
        }
        $state = Get-DecomAzureRBACState -Context (New-TestContext)
        $state.InheritedCount | Should -Be 1
        $state.DirectCount    | Should -Be 0
    }

    It 'logs inaccessible subscriptions without aborting' {
        function Global:Set-AzContext {
            param([string]$SubscriptionId, [string]$ErrorAction)
            throw 'Authorization failed'
        }
        $state = Get-DecomAzureRBACState -Context (New-TestContext)
        $state.SkippedCount | Should -Be 1
        $state.DirectCount  | Should -Be 0
    }

    It 'logs enumeration failure as skipped when Get-AzRoleAssignment throws' {
        function Global:Get-AzRoleAssignment {
            param([string]$SignInName, [string]$ErrorAction)
            throw 'Throttled'
        }
        $state = Get-DecomAzureRBACState -Context (New-TestContext)
        $state.SkippedCount | Should -Be 1
    }
}

Describe 'AzureRBAC - Remove-DecomAzureRBAC' {

    BeforeEach { Reset-AzStubs }

    It 'returns Skipped when no direct assignments found' {
        function Global:Get-AzRoleAssignment {
            param([string]$SignInName, [string]$ErrorAction)
            @()
        }
        $r = Remove-DecomAzureRBAC -Context (New-TestContext)
        $r.Status | Should -Be 'Skipped'
    }

    It 'returns Success when direct assignment removed' {
        $r = Remove-DecomAzureRBAC -Context (New-TestContext)
        $r.Status | Should -Be 'Success'
        $r.Phase  | Should -Be 'AzureRBAC'
    }

    It 'returns Success in WhatIf mode without calling Remove-AzRoleAssignment' {
        $script:removeCalled = $false
        function Global:Remove-AzRoleAssignment {
            param([string]$SignInName, [string]$RoleDefinitionName,
                  [string]$Scope, [string]$ErrorAction)
            $script:removeCalled = $true
        }
        $r = Remove-DecomAzureRBAC -Context (New-TestContext -WhatIf)
        $r.Status         | Should -Be 'Success'
        $r.Message        | Should -Match '\[WhatIf\]'
        $script:removeCalled | Should -Be $false
    }

    It 'notes inherited assignments when no direct found' {
        function Global:Get-AzRoleAssignment {
            param([string]$SignInName, [string]$ErrorAction)
            @([pscustomobject]@{
                RoleAssignmentId = 'ra-mg'; RoleDefinitionName = 'Owner'
                Scope = '/providers/Microsoft.Management/managementGroups/mg-root'
                ObjectType = 'User'
            })
        }
        $r = Remove-DecomAzureRBAC -Context (New-TestContext)
        $r.Status  | Should -Be 'Skipped'
        $r.Message | Should -Match 'inherited'
    }

    It 'returns Failed when all Remove-AzRoleAssignment calls fail' {
        function Global:Remove-AzRoleAssignment {
            param([string]$SignInName, [string]$RoleDefinitionName,
                  [string]$Scope, [string]$ErrorAction)
            throw 'Permission denied'
        }
        $r = Remove-DecomAzureRBAC -Context (New-TestContext)
        $r.Status                     | Should -Be 'Failed'
        $r.Evidence.Results[0].Status | Should -Be 'Failed'
    }
}
