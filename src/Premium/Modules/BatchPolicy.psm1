# BatchPolicy.psm1 — Per-UPN policy file support
# Premium v2.1 — Feature 2
#
# Functions:
#   Read-DecomBatchPolicy     — loads a batch-level policy JSON file
#   Get-DecomUpnPolicy        — resolves effective policy for a single UPN
#                               (UPN-specific overrides batch defaults)
#   Test-DecomPolicyCompliance — validates a policy object before use
#
# Policy file format (JSON):
#   {
#     "DefaultPolicy": {
#       "EvidenceLevel":   "Forensic",
#       "RemoveLicenses":  true,
#       "SkipGroups":      false,
#       "SkipRoles":       false,
#       "SkipAuthMethods": false,
#       "WhatIf":          false,
#       "Notes":           "optional string"
#     },
#     "UpnPolicies": {
#       "alice@contoso.com": {
#         "EvidenceLevel": "Standard",
#         "SkipRoles":     true,
#         "Notes":         "VIP — role removal requires CAB approval"
#       },
#       "bob@contoso.com": {
#         "WhatIf": true,
#         "Notes":  "Under investigation — dry run only"
#       }
#     }
#   }
#
# Resolution order:
#   1. UPN-specific policy (UpnPolicies[upn]) overrides DefaultPolicy
#   2. DefaultPolicy fills in any missing fields
#   3. If no policy file is provided, batch-level context settings are used
#
# PS7 compatible (v2.1 baseline)

#Requires -Version 7.0

Set-StrictMode -Version Latest

# ── Policy schema defaults ─────────────────────────────────────────────────────

$script:PolicyDefaults = [ordered]@{
    EvidenceLevel   = 'Forensic'
    RemoveLicenses  = $false
    SkipGroups      = $false
    SkipRoles       = $false
    SkipAuthMethods = $false
    WhatIf          = $false
    Notes           = ''
}

$script:ValidEvidenceLevels = @('Standard','Detailed','Forensic')

# ── Public API ─────────────────────────────────────────────────────────────────

function Read-DecomBatchPolicy {
    <#
    .SYNOPSIS
        Loads and validates a batch policy JSON file from disk.

    .DESCRIPTION
        Returns a policy object with DefaultPolicy and UpnPolicies keys.
        Validates the file structure and all field values before returning.
        Throws a descriptive error if the file is missing, malformed, or
        contains invalid values.

    .PARAMETER Path
        Full path to the policy JSON file.

    .OUTPUTS
        [pscustomobject] with DefaultPolicy and UpnPolicies properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "Read-DecomBatchPolicy: policy file not found at '$Path'."
    }

    $raw = Get-Content -Path $Path -Raw -Encoding UTF8

    try {
        $policy = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Read-DecomBatchPolicy: policy file is not valid JSON. $($_.Exception.Message)"
    }

    # Validate structure
    $issues = Test-DecomPolicyCompliance -Policy $policy
    if ($issues.Count -gt 0) {
        throw "Read-DecomBatchPolicy: policy validation failed:`n  $($issues -join "`n  ")"
    }

    return $policy
}

function Get-DecomUpnPolicy {
    <#
    .SYNOPSIS
        Resolves the effective policy for a single UPN.

    .DESCRIPTION
        Merges the DefaultPolicy with any UPN-specific overrides from UpnPolicies.
        Fields not specified in the UPN override are inherited from DefaultPolicy.
        Fields not specified in DefaultPolicy fall back to built-in schema defaults.

        If no policy object is provided (null), returns built-in schema defaults.

    .PARAMETER Policy
        The policy object from Read-DecomBatchPolicy. Pass $null to get defaults.

    .PARAMETER UPN
        The user principal name to resolve policy for.

    .OUTPUTS
        [pscustomobject] effective policy for this UPN with all fields populated.
    #>
    [CmdletBinding()]
    param(
        $Policy,   # may be $null
        [Parameter(Mandatory)][string]$UPN
    )

    # Start from built-in defaults
    $effective = [ordered]@{}
    foreach ($k in $script:PolicyDefaults.Keys) {
        $effective[$k] = $script:PolicyDefaults[$k]
    }

    if ($null -eq $Policy) {
        return [pscustomobject]$effective
    }

    # Apply DefaultPolicy
    if ($Policy.DefaultPolicy) {
        foreach ($prop in $Policy.DefaultPolicy.PSObject.Properties) {
            if ($effective.Contains($prop.Name)) {
                $effective[$prop.Name] = $prop.Value
            }
        }
    }

    # Apply UPN-specific overrides
    $upnKey = $UPN.ToLower().Trim()
    $upnPolicies = $Policy.UpnPolicies

    if ($upnPolicies) {
        # PSObject property lookup is case-insensitive on name match
        $upnOverride = $upnPolicies.PSObject.Properties |
            Where-Object { $_.Name.ToLower() -eq $upnKey } |
            Select-Object -First 1

        if ($upnOverride) {
            foreach ($prop in $upnOverride.Value.PSObject.Properties) {
                if ($effective.Contains($prop.Name)) {
                    $effective[$prop.Name] = $prop.Value
                }
            }
        }
    }

    return [pscustomobject]$effective
}

function Test-DecomPolicyCompliance {
    <#
    .SYNOPSIS
        Validates a policy object. Returns an array of error strings (empty = valid).

    .DESCRIPTION
        Checks:
          - DefaultPolicy exists
          - EvidenceLevel values are in the allowed set
          - Boolean fields are actually boolean
          - UpnPolicies entries (if present) have valid fields

    .PARAMETER Policy
        The policy object to validate.

    .OUTPUTS
        [string[]] — validation errors. Empty array means valid.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Policy
    )

    $errors = [System.Collections.Generic.List[string]]::new()

    if (-not $Policy.DefaultPolicy) {
        $errors.Add("Missing required 'DefaultPolicy' section.")
        return $errors.ToArray()
    }

    # Validate DefaultPolicy fields
    _ValidatePolicyBlock -Block $Policy.DefaultPolicy -Label 'DefaultPolicy' -Errors $errors

    # Validate UPN-specific overrides
    if ($Policy.UpnPolicies) {
        foreach ($prop in $Policy.UpnPolicies.PSObject.Properties) {
            $upn   = $prop.Name
            $block = $prop.Value
            _ValidatePolicyBlock -Block $block -Label "UpnPolicies[$upn]" -Errors $errors
        }
    }

    return $errors.ToArray()
}

function New-DecomBatchPolicyTemplate {
    <#
    .SYNOPSIS
        Writes a documented policy template JSON file to disk.

    .DESCRIPTION
        Useful for operators who want to start from a complete template rather
        than writing the JSON from scratch. Includes all supported fields with
        comments as sibling _comment properties (JSON has no native comments).

    .PARAMETER Path
        Output path for the template file.

    .OUTPUTS
        [string] — path to the written file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $template = [ordered]@{
        '_comment'      = 'Entra Identity Decommissioning Control Plane — Batch Policy File v2.1'
        DefaultPolicy   = [ordered]@{
            '_comment'      = 'Applied to all UPNs unless overridden in UpnPolicies'
            EvidenceLevel   = 'Forensic'
            RemoveLicenses  = $false
            SkipGroups      = $false
            SkipRoles       = $false
            SkipAuthMethods = $false
            WhatIf          = $false
            Notes           = ''
        }
        UpnPolicies     = [ordered]@{
            '_comment'              = 'Optional per-UPN overrides. Only specify fields you want to override.'
            'alice@contoso.com'     = [ordered]@{
                EvidenceLevel = 'Standard'
                SkipRoles     = $true
                Notes         = 'VIP account — role removal requires CAB approval first'
            }
            'bob@contoso.com'       = [ordered]@{
                WhatIf = $true
                Notes  = 'Under legal hold investigation — dry run only'
            }
        }
    }

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }

    $template | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8
    return $Path
}

# ── Private helpers ────────────────────────────────────────────────────────────

function _ValidatePolicyBlock {
    param($Block, [string]$Label, [System.Collections.Generic.List[string]]$Errors)

    if ($null -eq $Block) { return }

    # EvidenceLevel
    if ($Block.PSObject.Properties.Name -contains 'EvidenceLevel') {
        if ($Block.EvidenceLevel -notin $script:ValidEvidenceLevels) {
            $Errors.Add("$Label.EvidenceLevel must be one of: $($script:ValidEvidenceLevels -join ', '). Got: '$($Block.EvidenceLevel)'")
        }
    }

    # Boolean fields
    $boolFields = @('RemoveLicenses','SkipGroups','SkipRoles','SkipAuthMethods','WhatIf')
    foreach ($f in $boolFields) {
        if ($Block.PSObject.Properties.Name -contains $f) {
            $v = $Block.$f
            if ($v -isnot [bool]) {
                $Errors.Add("$Label.$f must be a boolean (true/false). Got: '$v'")
            }
        }
    }
}

Export-ModuleMember -Function `
    Read-DecomBatchPolicy, `
    Get-DecomUpnPolicy, `
    Test-DecomPolicyCompliance, `
    New-DecomBatchPolicyTemplate
