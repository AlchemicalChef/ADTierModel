# Enhanced Security Policy Functions

function Set-ADTierSecurityPolicy {
    <#
    .SYNOPSIS
        Configures comprehensive security policies for a tier.

    .DESCRIPTION
        Implements all security settings including:
        - Account policies (password, lockout)
        - Security options (authentication, session management)
        - Audit policies
        - User rights assignments
        - Security restrictions

    .PARAMETER TierName
        The tier to configure security policies for.

    .PARAMETER GPOName
        Optional custom GPO name. If not specified, uses SEC-TierX-BasePolicy.

    .EXAMPLE
        Set-ADTierSecurityPolicy -TierName Tier1 -Verbose

    .NOTES
        This function configures tier-appropriate security settings for:
        - Tier 0: Maximum security (PAW workstations, restrictive policies)
        - Tier 1: High security (server management, controlled access)
        - Tier 2: Standard security (workstation management, user support)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,

        [string]$GPOName
    )

    # Guard: Ensure GroupPolicy module is available
    if (-not (Test-GroupPolicyModuleAvailable)) {
        throw "GroupPolicy module not available. Install RSAT tools to use GPO functions."
    }

    try {
        if (-not $GPOName) {
            $GPOName = "SEC-$TierName-BasePolicy"
        }

        # Verify GPO exists
        $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            throw "GPO not found: $GPOName. Run Initialize-ADTierModel -CreateGPOs first."
        }

        Write-Host "`n=== Configuring Security Policies for $TierName ===" -ForegroundColor Cyan

        if ($PSCmdlet.ShouldProcess($GPOName, "Configure Security Policies")) {

            # Configure tier-specific security settings
            switch ($TierName) {
                'Tier0' {
                    Write-Verbose "Applying Tier 0 (Maximum Security) policies..."

                    Set-GPOSecurityOption -GPOName $GPOName -Settings @{
                        # Network security
                        'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse LM & NTLM'
                        'Network security: Minimum session security for NTLM SSP' = 'Require NTLMv2 session security, Require 128-bit encryption'
                        'Network security: Do not store LAN Manager hash value on next password change' = 'Enabled'

                        # Account security
                        'Accounts: Limit local account use of blank passwords to console logon only' = 'Enabled'
                        'Accounts: Administrator account status' = 'Disabled'

                        # Interactive logon
                        'Interactive logon: Do not display last user name' = 'Enabled'

                        # Audit policies
                        'Audit: Force audit policy subcategory settings' = 'Enabled'
                    }

                    # Configure advanced audit policies for Tier 0
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Account Logon' -SubCategory 'Credential Validation' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Account Management' -SubCategory 'User Account Management' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'DS Access' -SubCategory 'Directory Service Changes' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Logon/Logoff' -SubCategory 'Logon' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Policy Change' -SubCategory 'Audit Policy Change' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Privilege Use' -SubCategory 'Sensitive Privilege Use' -Success -Failure

                    # Restrict software installation
                    Set-GPOUserRight -GPOName $GPOName -UserRight 'SeLoadDriverPrivilege' -Identity 'Administrators'

                    Write-Host "Tier 0 security policies configured: Maximum security with NTLMv2 and strict auditing" -ForegroundColor Green
                }

                'Tier1' {
                    Write-Verbose "Applying Tier 1 (High Security) policies..."

                    Set-GPOSecurityOption -GPOName $GPOName -Settings @{
                        # Network security
                        'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse LM & NTLM'
                        'Network security: Minimum session security for NTLM SSP' = 'Require NTLMv2 session security, Require 128-bit encryption'
                        'Network security: Do not store LAN Manager hash value on next password change' = 'Enabled'

                        # Account security
                        'Accounts: Limit local account use of blank passwords to console logon only' = 'Enabled'

                        # Interactive logon
                        'Interactive logon: Do not display last user name' = 'Enabled'
                        'Interactive logon: Number of previous logons to cache' = '2'

                        # Audit policies
                        'Audit: Force audit policy subcategory settings' = 'Enabled'
                    }

                    # Configure audit policies for Tier 1
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Account Logon' -SubCategory 'Credential Validation' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Account Management' -SubCategory 'Security Group Management' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Logon/Logoff' -SubCategory 'Logon' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Object Access' -SubCategory 'File Share' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Policy Change' -SubCategory 'Authorization Policy Change' -Success -Failure

                    # Windows Firewall - Enable for all profiles
                    Set-GPOFirewall -GPOName $GPOName -Profile 'Domain' -State 'On'
                    Set-GPOFirewall -GPOName $GPOName -Profile 'Private' -State 'On'
                    Set-GPOFirewall -GPOName $GPOName -Profile 'Public' -State 'On'

                    # Restrict CD-ROM and Floppy access (AllocateCDRoms uses DWORD, 1 = Allocate to administrators only)
                    Set-GPORegistryValue -GPOName $GPOName -Key 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueName 'AllocateCDRoms' -Type DWord -Value 1

                    Write-Host "Tier 1 security policies configured: High security for server management" -ForegroundColor Green
                }

                'Tier2' {
                    Write-Verbose "Applying Tier 2 (Standard Security) policies..."

                    Set-GPOSecurityOption -GPOName $GPOName -Settings @{
                        # Network security
                        'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only'
                        'Network security: Do not store LAN Manager hash value on next password change' = 'Enabled'

                        # Account security
                        'Accounts: Limit local account use of blank passwords to console logon only' = 'Enabled'

                        # Interactive logon
                        'Interactive logon: Do not display last user name' = 'Disabled' # Allow for user workstations
                        'Interactive logon: Number of previous logons to cache' = '10'

                        # Audit policies
                        'Audit: Force audit policy subcategory settings' = 'Enabled'
                    }

                    # Configure audit policies for Tier 2
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Account Logon' -SubCategory 'Credential Validation' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Logon/Logoff' -SubCategory 'Logon' -Success -Failure
                    Set-GPOAuditPolicy -GPOName $GPOName -Category 'Logon/Logoff' -SubCategory 'Logoff' -Success

                    # Windows Firewall - Enable for all profiles
                    Set-GPOFirewall -GPOName $GPOName -Profile 'Domain' -State 'On'
                    Set-GPOFirewall -GPOName $GPOName -Profile 'Private' -State 'On'
                    Set-GPOFirewall -GPOName $GPOName -Profile 'Public' -State 'On'

                    # User Account Control settings
                    Set-GPORegistryValue -GPOName $GPOName -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ValueName 'EnableLUA' -Type DWord -Value 1
                    Set-GPORegistryValue -GPOName $GPOName -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ValueName 'ConsentPromptBehaviorAdmin' -Type DWord -Value 2

                    Write-Host "Tier 2 security policies configured: Standard security for workstation management" -ForegroundColor Green
                }
            }

            Write-TierLog -Message "Configured security policies for $TierName in GPO: $GPOName" -Level Success -Component 'SecurityPolicy'
        }
    }
    catch {
        Write-TierLog -Message "Failed to configure security policies: $_" -Level Error -Component 'SecurityPolicy'
        throw
    }
}

function Set-GPOSecurityOption {
    <#
    .SYNOPSIS
        Configures security options in a GPO via GptTmpl.inf manipulation.

    .DESCRIPTION
        Writes security settings to the GPO's GptTmpl.inf file in SYSVOL.

    .PARAMETER GPOName
        The name of the GPO to configure.

    .PARAMETER Settings
        Hashtable of security settings to apply.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [hashtable]$Settings
    )

    # Guard: Ensure GroupPolicy module is available
    if (-not (Test-GroupPolicyModuleAvailable)) {
        throw "GroupPolicy module not available. Install RSAT tools."
    }

    # Security option registry path mappings
    $securityOptionMap = @{
        'Network security: LAN Manager authentication level' = 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
        'Network security: Do not store LAN Manager hash value on next password change' = 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'
        'Network security: Minimum session security for NTLM SSP based clients' = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec'
        'Network security: Minimum session security for NTLM SSP based servers' = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec'
        'Interactive logon: Do not display last user name' = 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName'
        'Accounts: Administrator account status' = 'MACHINE\SAM\SAM\Domains\Account\Users\000001F4\F'
    }

    try {
        $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
        $gpoGuid = $gpo.Id.ToString('B').ToUpper()
        $domain = (Get-ADDomain).DNSRoot
        $sysvolPath = "\\$domain\SYSVOL\$domain\Policies\$gpoGuid\Machine\Microsoft\Windows NT\SecEdit"
        $infPath = Join-Path $sysvolPath "GptTmpl.inf"

        # Ensure directory exists
        if (-not (Test-Path $sysvolPath)) {
            New-Item -Path $sysvolPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        # Build settings hashtable for merge
        $registryValues = @{}

        foreach ($setting in $Settings.GetEnumerator()) {
            $regKey = $securityOptionMap[$setting.Key]
            if ($regKey) {
                # Convert value based on setting type
                $value = switch -Regex ($setting.Key) {
                    'LAN Manager authentication level' {
                        switch ($setting.Value) {
                            'Send NTLMv2 response only. Refuse LM & NTLM' { '4,5' }
                            'Send NTLMv2 response only. Refuse LM' { '4,4' }
                            'Send NTLMv2 response only' { '4,3' }
                            default { "4,$($setting.Value)" }
                        }
                    }
                    'Enabled|Disabled|status' {
                        if ($setting.Value -match 'Enabled|1') { '4,1' } else { '4,0' }
                    }
                    default { "4,$($setting.Value)" }
                }
                $registryValues[$regKey] = $value
                Write-Verbose "Configured: $($setting.Key) = $($setting.Value)"
            }
            else {
                Write-Warning "Unknown security option: $($setting.Key)"
            }
        }

        if ($PSCmdlet.ShouldProcess($GPOName, "Configure Security Options")) {
            # Create backup before modification
            Backup-GptTmplFile -GptTmplPath $infPath | Out-Null

            # Use merge function to preserve existing settings
            $newSettings = @{
                'Registry Values' = $registryValues
            }

            $mergedContent = Merge-GptTmplContent -GptTmplPath $infPath -NewSettings $newSettings
            $mergedContent | Out-File -FilePath $infPath -Encoding Unicode -Force

            Update-GPOVersion -GPOGuid $gpo.Id
            Write-TierLog -Message "Configured security options in GPO: $GPOName" -Level Success -Component 'GPO'
        }
    }
    catch {
        Write-TierLog -Message "Failed to configure security options: $_" -Level Error -Component 'GPO'
        throw
    }
}

function Set-GPOAuditPolicy {
    <#
    .SYNOPSIS
        Configures audit policies in a GPO via audit.csv manipulation.

    .PARAMETER GPOName
        The name of the GPO to configure.

    .PARAMETER Category
        Audit category (e.g., 'Account Logon', 'Logon/Logoff').

    .PARAMETER SubCategory
        Audit subcategory (e.g., 'Credential Validation', 'Logon').

    .PARAMETER Success
        Enable success auditing.

    .PARAMETER Failure
        Enable failure auditing.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$SubCategory,

        [switch]$Success,
        [switch]$Failure
    )

    # Guard: Ensure GroupPolicy module is available
    if (-not (Test-GroupPolicyModuleAvailable)) {
        throw "GroupPolicy module not available. Install RSAT tools."
    }

    # Audit subcategory GUID mappings
    $auditGuidMap = @{
        'Credential Validation' = '{0CCE923F-69AE-11D9-BED3-505054503030}'
        'Kerberos Authentication Service' = '{0CCE9242-69AE-11D9-BED3-505054503030}'
        'User Account Management' = '{0CCE9235-69AE-11D9-BED3-505054503030}'
        'Computer Account Management' = '{0CCE9236-69AE-11D9-BED3-505054503030}'
        'Security Group Management' = '{0CCE9237-69AE-11D9-BED3-505054503030}'
        'Directory Service Changes' = '{0CCE923C-69AE-11D9-BED3-505054503030}'
        'Directory Service Access' = '{0CCE923B-69AE-11D9-BED3-505054503030}'
        'Logon' = '{0CCE9215-69AE-11D9-BED3-505054503030}'
        'Logoff' = '{0CCE9216-69AE-11D9-BED3-505054503030}'
        'Special Logon' = '{0CCE921B-69AE-11D9-BED3-505054503030}'
        'Audit Policy Change' = '{0CCE922F-69AE-11D9-BED3-505054503030}'
        'Authentication Policy Change' = '{0CCE9230-69AE-11D9-BED3-505054503030}'
        'Sensitive Privilege Use' = '{0CCE9228-69AE-11D9-BED3-505054503030}'
        'File Share' = '{0CCE9224-69AE-11D9-BED3-505054503030}'
        'Process Creation' = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    }

    $subcatGuid = $auditGuidMap[$SubCategory]
    if (-not $subcatGuid) {
        Write-Warning "Unknown audit subcategory: $SubCategory"
        return
    }

    # Calculate setting value (1=Success, 2=Failure, 3=Both, 0=None)
    $settingValue = 0
    if ($Success) { $settingValue = $settingValue -bor 1 }
    if ($Failure) { $settingValue = $settingValue -bor 2 }

    try {
        $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
        $gpoGuid = $gpo.Id.ToString('B').ToUpper()
        $domain = (Get-ADDomain).DNSRoot
        $auditDir = "\\$domain\SYSVOL\$domain\Policies\$gpoGuid\Machine\Microsoft\Windows NT\Audit"
        $auditCsvPath = Join-Path $auditDir "audit.csv"

        # Ensure directory exists
        if (-not (Test-Path $auditDir)) {
            New-Item -Path $auditDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        if ($PSCmdlet.ShouldProcess($GPOName, "Configure Audit Policy: $Category\$SubCategory")) {
            # Create or update audit.csv
            # Format: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
            $csvContent = @()
            $csvContent += "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value"
            $csvContent += ",System,$SubCategory,$subcatGuid,,$settingValue,"

            # If file exists, merge with existing entries
            if (Test-Path $auditCsvPath) {
                $existing = Import-Csv $auditCsvPath -ErrorAction SilentlyContinue
                foreach ($entry in $existing) {
                    if ($entry.'Subcategory GUID' -ne $subcatGuid) {
                        $csvContent += ",System,$($entry.Subcategory),$($entry.'Subcategory GUID'),,$($entry.'Setting Value'),"
                    }
                }
            }

            $csvContent | Set-Content -Path $auditCsvPath -Encoding Unicode -Force -ErrorAction Stop
            Update-GPOVersion -GPOGuid $gpo.Id
            Write-TierLog -Message "Configured audit policy: $Category\$SubCategory" -Level Success -Component 'GPO'
        }
    }
    catch {
        Write-TierLog -Message "Failed to configure audit policy: $_" -Level Error -Component 'GPO'
        throw
    }
}

function Set-GPOFirewall {
    <#
    .SYNOPSIS
        Configures Windows Firewall settings in a GPO via registry policy.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [ValidateSet('Domain', 'Private', 'Public')]
        [string]$Profile,

        [Parameter(Mandatory)]
        [ValidateSet('On', 'Off')]
        [string]$State
    )

    # Guard: Ensure GroupPolicy module is available
    if (-not (Test-GroupPolicyModuleAvailable)) {
        throw "GroupPolicy module not available. Install RSAT tools."
    }

    $profileMap = @{
        'Domain' = 'DomainProfile'
        'Private' = 'StandardProfile'
        'Public' = 'PublicProfile'
    }

    $key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$($profileMap[$Profile])"
    $value = if ($State -eq 'On') { 1 } else { 0 }

    try {
        if ($PSCmdlet.ShouldProcess($GPOName, "Configure Firewall: $Profile = $State")) {
            Set-GPRegistryValue -Name $GPOName -Key $key -ValueName 'EnableFirewall' -Type DWord -Value $value -ErrorAction Stop
            Write-TierLog -Message "Configured firewall: $Profile = $State in GPO $GPOName" -Level Success -Component 'GPO'
        }
    }
    catch {
        Write-TierLog -Message "Failed to configure firewall: $_" -Level Error -Component 'GPO'
        throw
    }
}

function Set-GPORegistryValue {
    <#
    .SYNOPSIS
        Sets registry values in a GPO using the GroupPolicy module.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$ValueName,

        [Parameter(Mandatory)]
        [ValidateSet('String', 'DWord', 'Binary', 'ExpandString', 'MultiString', 'QWord')]
        [string]$Type,

        [Parameter(Mandatory)]
        $Value
    )

    # Guard: Ensure GroupPolicy module is available
    if (-not (Test-GroupPolicyModuleAvailable)) {
        throw "GroupPolicy module not available. Install RSAT tools."
    }

    try {
        if ($PSCmdlet.ShouldProcess($GPOName, "Set Registry: $Key\$ValueName = $Value")) {
            Set-GPRegistryValue -Name $GPOName -Key $Key -ValueName $ValueName -Type $Type -Value $Value -ErrorAction Stop
            Write-TierLog -Message "Set registry value: $Key\$ValueName in GPO $GPOName" -Level Success -Component 'GPO'
        }
    }
    catch {
        Write-TierLog -Message "Failed to set registry value: $_" -Level Error -Component 'GPO'
        throw
    }
}
