#Requires -Modules ActiveDirectory
#Requires -Version 5.1

# Module-level variables

# Constants - Named values for clarity and maintainability
$script:GPO_USER_VERSION_INCREMENT = 65536   # High 16 bits: User configuration version
$script:GPO_COMPUTER_VERSION_INCREMENT = 1    # Low 16 bits: Computer configuration version
$script:AD_MAX_VALUES_RANGE = 1500            # Default MaxValRange for ranged retrieval
$script:MAX_LOG_MESSAGE_LENGTH = 4000         # Maximum log message length before truncation
$script:SAFETY_LIMIT_ITERATIONS = 1000000     # Safety limit for infinite loop prevention
$script:DC_PRIMARY_GROUP_ID = 516             # primaryGroupID for Domain Controllers

$script:TierConfiguration = @{
    Tier0 = @{
        Name = 'Tier 0 - Infrastructure'
        Description = 'Domain Controllers, core identity infrastructure, domain/enterprise admins'
        OUPath = 'OU=Tier0'
        Color = 'Red'
        RiskLevel = 'Critical'
    }
    Tier1 = @{
        Name = 'Tier 1 - Server Management'
        Description = 'Application servers, file servers, server administrators'
        OUPath = 'OU=Tier1'
        Color = 'Yellow'
        RiskLevel = 'High'
    }
    Tier2 = @{
        Name = 'Tier 2 - Workstation Management'
        Description = 'User workstations, etc'
        OUPath = 'OU=Tier2'
        Color = 'Green'
        RiskLevel = 'Medium'
    }
}

$script:Tier0CriticalRoles = @{
    DomainController = @{
        Name = 'Domain Controller'
        Detection = {
            # Use SearchBase for efficient query instead of -Filter * with client-side filtering
            try {
                $dcOU = "OU=Domain Controllers,$((Get-ADDomain -ErrorAction Stop).DistinguishedName)"
                (Get-ADComputer -SearchBase $dcOU -Filter * -Properties Name -ErrorAction SilentlyContinue).Name
            } catch {
                # Fallback: query by primaryGroupID (516 = Domain Controllers)
                (Get-ADComputer -Filter "primaryGroupID -eq $($script:DC_PRIMARY_GROUP_ID)" -Properties Name -ErrorAction SilentlyContinue).Name
            }
        }
        Description = 'Active Directory Domain Controllers'
    }
    ADFS = @{
        Name = 'AD FS Server'
        Detection = {
            # Filter by SPN server-side where possible, then client-side filter for specific patterns
            (Get-ADComputer -Filter "ServicePrincipalName -like '*http*'" -Properties ServicePrincipalName -ErrorAction SilentlyContinue |
                Where-Object { $_.ServicePrincipalName -like '*http/sts*' -or $_.ServicePrincipalName -like '*http/adfs*' }).Name
        }
        Description = 'Active Directory Federation Services servers'
    }
    EntraConnect = @{
        Name = 'Entra Connect (AAD Connect)'
        Detection = {
            # Use more specific filter to reduce result set
            (Get-ADComputer -Filter "Description -like '*Connect*'" -Properties Description -ErrorAction SilentlyContinue |
                Where-Object { $_.Description -like '*Azure AD Connect*' -or $_.Description -like '*AAD Connect*' -or $_.Description -like '*Entra Connect*' }).Name
        }
        Description = 'Microsoft Entra Connect (Azure AD Connect) synchronization servers'
    }
    CertificateAuthority = @{
        Name = 'Certificate Authority'
        Detection = {
            # Use more specific filter to reduce result set
            (Get-ADComputer -Filter "Description -like '*Certificate*' -or Description -like '*CA*'" -Properties Description -ErrorAction SilentlyContinue |
                Where-Object { $_.Description -like '*Certificate Authority*' -or $_.Description -like '*CA Server*' }).Name
        }
        Description = 'Enterprise Certificate Authority servers'
    }
    PAW = @{
        Name = 'Privileged Access Workstation'
        Detection = {
            try {
                # Use pipeline aggregation instead of array += for performance
                @(
                    Get-ADComputer -Filter "Name -like 'PAW-*'" -Properties Name -ErrorAction SilentlyContinue
                    Get-ADComputer -Filter "Name -like '*-PAW-*'" -Properties Name -ErrorAction SilentlyContinue
                    Get-ADComputer -Filter "Description -like '*PAW*'" -Properties Name, Description -ErrorAction SilentlyContinue
                    Get-ADComputer -Filter "Description -like '*Privileged Access*'" -Properties Name, Description -ErrorAction SilentlyContinue
                ) | Where-Object { $_ } | Select-Object -Unique -ExpandProperty Name
            }
            catch {
                @()
            }
        }
        Description = 'Privileged Access Workstations for Tier 0 administration'
    }
}

$script:StandardSubOUs = @('Computers', 'Users', 'Groups', 'ServiceAccounts', 'AdminWorkstations')

$script:ConfigPath = "$env:ProgramData\ADTierModel\config.json"

#region Core Helper Functions (Must be defined first)

function Initialize-TierDataDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $programDataRoot = [System.IO.Path]::GetFullPath($env:ProgramData)
    $fullPath = [System.IO.Path]::GetFullPath($Path)

    if (-not $programDataRoot -or ($fullPath -notlike "$programDataRoot*")) {
        throw "Invalid storage path specified: $fullPath"
    }

    if (-not (Test-Path $fullPath)) {
        New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
    }

    try {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $permissions = @(
            New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'),
            New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        )

        foreach ($rule in $permissions) {
            $acl.SetAccessRule($rule)
        }

        $acl.SetAccessRuleProtection($true, $false)
        Set-Acl -Path $fullPath -AclObject $acl
    }
    catch {
        Write-Warning "Unable to harden directory permissions for $fullPath: $_"
    }
}

function Test-GroupPolicyModuleAvailable {
    <#
    .SYNOPSIS
        Tests if the GroupPolicy module is available and can be loaded.
    .OUTPUTS
        Returns $true if available, $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
        return $false
    }
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-EscapedADFilterValue {
    <#
    .SYNOPSIS
        Escapes special characters in AD filter values to prevent LDAP injection.
    .DESCRIPTION
        Escapes single quotes, asterisks, parentheses, and backslashes that could
        be used for LDAP filter injection attacks.
        IMPORTANT: Backslash must be escaped FIRST to avoid double-escaping.
    .OUTPUTS
        Returns the escaped string safe for use in AD filters.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Value
    )

    process {
        if ([string]::IsNullOrEmpty($Value)) {
            return $Value
        }
        # CRITICAL: Escape backslashes FIRST to avoid double-escaping other escaped chars
        # Then escape NUL character and other special characters for PowerShell AD filter syntax
        # Per RFC 4515: Must escape *, (, ), \, NUL
        $Value -replace '\\', '\\\\' -replace '\x00', '\\00' -replace "'", "''" -replace '\*', '`*' -replace '\(', '`(' -replace '\)', '`)'
    }
}

function Test-ADGroupExists {
    <#
    .SYNOPSIS
        Validates that an AD group exists before attempting operations.
    .OUTPUTS
        Returns $true if group exists, $false otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName
    )

    try {
        $escapedName = Get-EscapedADFilterValue -Value $GroupName
        $group = Get-ADGroup -Filter "Name -eq '$escapedName'" -ErrorAction Stop
        return ($null -ne $group)
    }
    catch {
        return $false
    }
}

function Update-GPOVersion {
    <#
    .SYNOPSIS
        Increments the GPO version to trigger replication.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [guid]$GPOGuid
    )

    try {
        $domain = (Get-ADDomain).DNSRoot
        $gpoGuidStr = $GPOGuid.ToString('B').ToUpper()
        $gptIniPath = "\\$domain\SYSVOL\$domain\Policies\$gpoGuidStr\GPT.INI"

        if (Test-Path $gptIniPath) {
            $content = Get-Content $gptIniPath -Raw
            if ($content -match 'Version=(\d+)') {
                # GPO version: High 16 bits = User config, Low 16 bits = Computer config
                # Security settings are Computer Configuration, so increment low 16 bits
                # Also increment User config to ensure full propagation
                $newVersion = [int]$Matches[1] + $script:GPO_COMPUTER_VERSION_INCREMENT + $script:GPO_USER_VERSION_INCREMENT
                $newContent = $content -replace "Version=\d+", "Version=$newVersion"
                Set-Content -Path $gptIniPath -Value $newContent -Force
                Write-Verbose "Updated GPO version to $newVersion"
            }
        }
    }
    catch {
        Write-Warning "Failed to update GPO version: $_"
    }
}

function Merge-GptTmplContent {
    <#
    .SYNOPSIS
        Merges new settings into an existing GptTmpl.inf file instead of overwriting.
    .DESCRIPTION
        Parses an existing GptTmpl.inf file (if present), merges new settings into it,
        and returns the merged content. This prevents data loss when multiple functions
        configure different sections of the same GPO.
    .PARAMETER GptTmplPath
        Full path to the GptTmpl.inf file.
    .PARAMETER NewSettings
        Hashtable of settings to merge. Keys are section names, values are hashtables of key=value pairs.
        Example: @{ 'Event Audit' = @{ 'AuditSystemEvents' = '3' }; 'Privilege Rights' = @{ 'SeBackupPrivilege' = '*S-1-5-32-544' } }
    .OUTPUTS
        Returns the merged INF content as a string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$GptTmplPath,

        [Parameter(Mandatory)]
        [hashtable]$NewSettings
    )

    $existingContent = [ordered]@{}
    $currentSection = $null

    # Parse existing file if it exists
    if (Test-Path $GptTmplPath) {
        try {
            $lines = Get-Content $GptTmplPath -Encoding Unicode -ErrorAction Stop
            foreach ($line in $lines) {
                $trimmedLine = $line.Trim()
                if ($trimmedLine -match '^\[(.+)\]$') {
                    $currentSection = $Matches[1]
                    if (-not $existingContent.Contains($currentSection)) {
                        $existingContent[$currentSection] = [ordered]@{}
                    }
                }
                elseif ($trimmedLine -match '^([^=]+?)\s*=\s*(.*)$' -and $currentSection) {
                    $key = $Matches[1].Trim()
                    $value = $Matches[2].Trim()
                    $existingContent[$currentSection][$key] = $value
                }
            }
        }
        catch {
            Write-Verbose "Could not read existing GptTmpl.inf, creating new: $_"
        }
    }

    # Ensure required sections exist with proper values
    if (-not $existingContent.Contains('Unicode')) {
        $existingContent['Unicode'] = [ordered]@{ 'Unicode' = 'yes' }
    }
    if (-not $existingContent.Contains('Version')) {
        $existingContent['Version'] = [ordered]@{
            'signature' = '"$CHICAGO$"'
            'Revision' = '1'
        }
    }

    # Merge new settings into existing content
    foreach ($section in $NewSettings.Keys) {
        if (-not $existingContent.Contains($section)) {
            $existingContent[$section] = [ordered]@{}
        }
        foreach ($key in $NewSettings[$section].Keys) {
            $existingContent[$section][$key] = $NewSettings[$section][$key]
        }
    }

    # Build output string - Unicode and Version first, then others
    $output = [System.Text.StringBuilder]::new()

    # Write sections in order: Unicode, Version, then alphabetically
    $orderedSections = @('Unicode', 'Version') + ($existingContent.Keys | Where-Object { $_ -notin @('Unicode', 'Version') } | Sort-Object)

    foreach ($section in $orderedSections) {
        if ($existingContent.Contains($section) -and $existingContent[$section].Count -gt 0) {
            [void]$output.AppendLine("[$section]")
            foreach ($key in $existingContent[$section].Keys) {
                [void]$output.AppendLine("$key = $($existingContent[$section][$key])")
            }
        }
    }

    return $output.ToString()
}

function Backup-GptTmplFile {
    <#
    .SYNOPSIS
        Creates a timestamped backup of a GptTmpl.inf file before modification.
    .DESCRIPTION
        Creates a backup copy of the GptTmpl.inf file to enable recovery if needed.
    .PARAMETER GptTmplPath
        Full path to the GptTmpl.inf file to backup.
    .OUTPUTS
        Returns the backup file path if successful, $null if no backup needed or failed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$GptTmplPath
    )

    if (Test-Path $GptTmplPath) {
        try {
            $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
            $backupPath = "$GptTmplPath.$timestamp.bak"
            Copy-Item -Path $GptTmplPath -Destination $backupPath -Force
            Write-Verbose "Created backup: $backupPath"
            return $backupPath
        }
        catch {
            Write-Warning "Failed to create backup of GptTmpl.inf: $_"
            return $null
        }
    }
    return $null
}

#endregion

#region Helper Functions

function Write-TierLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info',

        [string]$Component = 'General'
    )

    $logPath = "$env:ProgramData\ADTierModel\Logs"
    Initialize-TierDataDirectory -Path $logPath

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logFile = Join-Path $logPath "ADTierModel_$(Get-Date -Format 'yyyyMMdd').log"
    $safeMessage = ($Message -replace '[\r\n]+', ' ').Trim()

    if ($safeMessage.Length -gt $script:MAX_LOG_MESSAGE_LENGTH) {
        $safeMessage = $safeMessage.Substring(0, $script:MAX_LOG_MESSAGE_LENGTH) + '...'
    }

    $logEntry = "$timestamp [$Level] [$Component] $safeMessage"

    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Level) {
        'Info'    { Write-Verbose $Message }
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Error $Message }
        'Success' { Write-Information $Message -InformationAction Continue }
    }
}

function Get-ADDomainRootDN {
    <#
    .SYNOPSIS
        Gets the distinguished name of the current AD domain root.
    .OUTPUTS
        Returns the domain's distinguished name string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        $domain = Get-ADDomain -ErrorAction Stop
        return $domain.DistinguishedName
    }
    catch {
        throw "Unable to retrieve AD Domain information. Ensure domain connectivity and proper permissions: $_"
    }
}

function Test-ADTierOUExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OUPath
    )
    
    try {
        Get-ADOrganizationalUnit -Identity $OUPath -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Test-ADTierPrerequisites {
    [CmdletBinding()]
    param()
    
    $issues = @()
    
    # Check ActiveDirectory module
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        $issues += "ActiveDirectory module not found. Install RSAT tools."
    }
    
    # Check domain connectivity
    try {
        $null = Get-ADDomain -ErrorAction Stop
    }
    catch {
        $issues += "Cannot connect to Active Directory domain: $_"
    }
    
    # Check permissions (basic check)
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $sidValue = $currentUser.User.Value
        $null = Get-ADUser -Identity $sidValue -ErrorAction Stop
    }
    catch {
        $issues += "Insufficient permissions to query Active Directory using the current identity"
    }
    
    if ($issues.Count -gt 0) {
        throw "Prerequisites not met:`n$($issues -join "`n")"
    }
    
    return $true
}

#endregion

#region Initialization Functions

function Initialize-ADTierModel {
    <#
    .SYNOPSIS
        Initializes the AD Tier Model infrastructure in the domain.
    
    .DESCRIPTION
        Creates the complete OU structure, security groups, and base configurations
        for a three-tier administrative model in Active Directory.
    
    .PARAMETER CreateOUStructure
        Creates the OU hierarchy for all tiers.
    
    .PARAMETER CreateGroups
        Creates administrative security groups for each tier.
    
    .PARAMETER SetPermissions
        Configures delegation of permissions for tier separation.
    
    .PARAMETER CreateGPOs
        Creates base Group Policy Objects for each tier.
    
    .EXAMPLE
        Initialize-ADTierModel -CreateOUStructure -CreateGroups -Verbose
        
    .NOTES
        Requires Domain Admin or equivalent permissions.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$CreateOUStructure,
        [switch]$CreateGroups,
        [switch]$SetPermissions,
        [switch]$CreateGPOs,
        [switch]$Force
    )
    
    begin {
        Write-TierLog -Message "Starting AD Tier Model initialization" -Level Info -Component 'Initialize'
        
        try {
            Test-ADTierPrerequisites
        }
        catch {
            Write-TierLog -Message $_ -Level Error -Component 'Initialize'
            throw
        }
        
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        Write-Verbose "Running as: $($currentUser.Name)"
    }
    
    process {
        $domainDN = Get-ADDomainRootDN
        $results = @{
            Success = $true
            OUsCreated = @()
            GroupsCreated = @()
            PermissionsSet = @()
            GPOsCreated = @()
            Errors = @()
            Warnings = @()
        }
        
        # Create OU Structure
        if ($CreateOUStructure) {
            Write-Host "`n=== Creating OU Structure ===" -ForegroundColor Cyan
            
            foreach ($tierKey in $script:TierConfiguration.Keys | Sort-Object) {
                $tier = $script:TierConfiguration[$tierKey]
                $ouPath = "$($tier.OUPath),$domainDN"
                
                if ($PSCmdlet.ShouldProcess($ouPath, "Create Tier OU")) {
                    try {
                        if (-not (Test-ADTierOUExists -OUPath $ouPath)) {
                            $ouParams = @{
                                Name = $tier.OUPath.Replace('OU=', '')
                                Path = $domainDN
                                Description = $tier.Description
                                ProtectedFromAccidentalDeletion = $true
                            }
                            
                            New-ADOrganizationalUnit @ouParams
                            $results.OUsCreated += $ouPath
                            Write-TierLog -Message "Created OU: $ouPath" -Level Success -Component 'Initialize'
                            
                            foreach ($subOU in $script:StandardSubOUs) {
                                $subOUPath = "OU=$subOU,$ouPath"
                                # Use try/catch instead of Test-then-Create to avoid TOCTOU race condition
                                try {
                                    New-ADOrganizationalUnit -Name $subOU -Path $ouPath -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
                                    $results.OUsCreated += $subOUPath
                                    Write-Verbose "Created sub-OU: $subOUPath"
                                }
                                catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                                    Write-Verbose "Sub-OU already exists: $subOUPath"
                                }
                            }
                        }
                        else {
                            Write-Warning "OU already exists: $ouPath"
                        }
                    }
                    catch {
                        $errorMsg = "Failed to create OU $ouPath : $_"
                        Write-TierLog -Message $errorMsg -Level Error -Component 'Initialize'
                        $results.Errors += $errorMsg
                        $results.Success = $false
                    }
                }
            }
        }
        
        # Create Security Groups
        if ($CreateGroups) {
            Write-Host "`n=== Creating Security Groups ===" -ForegroundColor Cyan
            
            $groupTemplates = @(
                @{ Suffix = 'Admins'; Description = 'Full administrative access'; Scope = 'Universal' }
                @{ Suffix = 'Operators'; Description = 'Operational access'; Scope = 'Universal' }
                @{ Suffix = 'Readers'; Description = 'Read-only access'; Scope = 'Universal' }
                @{ Suffix = 'ServiceAccounts'; Description = 'Service accounts'; Scope = 'Universal' }
                @{ Suffix = 'JumpServers'; Description = 'Privileged access workstations'; Scope = 'Universal' }
            )
            
            foreach ($tierKey in $script:TierConfiguration.Keys) {
                $tier = $script:TierConfiguration[$tierKey]
                $groupsOU = "OU=Groups,$($tier.OUPath),$domainDN"
                
                if (-not (Test-ADTierOUExists -OUPath $groupsOU)) {
                    Write-Warning "Groups OU does not exist: $groupsOU. Run with -CreateOUStructure first."
                    continue
                }
                
                foreach ($template in $groupTemplates) {
                    $groupName = "$tierKey-$($template.Suffix)"

                    if ($PSCmdlet.ShouldProcess($groupName, "Create Security Group")) {
                        try {
                            $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
                            $existingGroup = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction SilentlyContinue
                            
                            if (-not $existingGroup) {
                                $groupParams = @{
                                    Name = $groupName
                                    GroupScope = $template.Scope
                                    GroupCategory = 'Security'
                                    Path = $groupsOU
                                    Description = "$($tier.Name) - $($template.Description)"
                                }
                                
                                New-ADGroup @groupParams
                                $results.GroupsCreated += $groupName
                                Write-TierLog -Message "Created group: $groupName" -Level Success -Component 'Initialize'
                            }
                            else {
                                Write-Warning "Group already exists: $groupName"
                            }
                        }
                        catch {
                            $errorMsg = "Failed to create group $groupName : $_"
                            Write-TierLog -Message $errorMsg -Level Error -Component 'Initialize'
                            $results.Errors += $errorMsg
                            $results.Success = $false
                        }
                    }
                }
            }
        }
        
        # Set Permissions (Delegation)
        if ($SetPermissions) {
            Write-Host "`n=== Configuring Tier Permissions ===" -ForegroundColor Cyan
            Write-Warning "Permission delegation requires custom implementation based on your security requirements."
            Write-TierLog -Message "Permission configuration initiated" -Level Info -Component 'Initialize'
            
            # This would implement specific delegation rules
            # Example: Tier 1 admins should NOT have access to Tier 0
            $results.PermissionsSet += "Base permission structure configured"
        }
        
        # Create GPOs
        if ($CreateGPOs) {
            Write-Host "`n=== Creating Group Policy Objects ===" -ForegroundColor Cyan
            
            if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
                Write-Warning "GroupPolicy module not available. GPO creation skipped."
            }
            else {
                Import-Module GroupPolicy -ErrorAction SilentlyContinue
                
                foreach ($tierKey in $script:TierConfiguration.Keys) {
                    $tier = $script:TierConfiguration[$tierKey]
                    
                    # Create base security GPO
                    $baseGPOName = "SEC-$tierKey-BasePolicy"
                    $logonGPOName = "SEC-$tierKey-LogonRestrictions"
                    $ouPath = "$($tier.OUPath),$domainDN"
                    
                    if ($PSCmdlet.ShouldProcess($baseGPOName, "Create GPO")) {
                        try {
                            # Create base policy GPO
                            $existingGPO = Get-GPO -Name $baseGPOName -ErrorAction SilentlyContinue
                            
                            if (-not $existingGPO) {
                                $gpo = New-GPO -Name $baseGPOName -Comment "Base security policy for $($tier.Name)"
                                New-GPLink -Name $baseGPOName -Target $ouPath -LinkEnabled Yes
                                
                                $results.GPOsCreated += $baseGPOName
                                Write-TierLog -Message "Created and linked GPO: $baseGPOName" -Level Success -Component 'Initialize'
                            }
                            else {
                                Write-Warning "GPO already exists: $baseGPOName"
                            }
                            
                            # Create logon restrictions GPO
                            $existingLogonGPO = Get-GPO -Name $logonGPOName -ErrorAction SilentlyContinue
                            
                            if (-not $existingLogonGPO) {
                                $logonGPO = New-GPO -Name $logonGPOName -Comment "Enforces tier-based logon restrictions for $($tier.Name)"
                                $link = New-GPLink -Name $logonGPOName -Target $ouPath -LinkEnabled Yes -Order 1
                                
                                # Configure logon restrictions based on tier
                                Set-ADTierLogonRestrictions -TierName $tierKey -GPOName $logonGPOName
                                
                                $results.GPOsCreated += $logonGPOName
                                Write-TierLog -Message "Created and linked logon restrictions GPO: $logonGPOName" -Level Success -Component 'Initialize'
                            }
                            else {
                                Write-Warning "Logon restrictions GPO already exists: $logonGPOName"
                            }
                        }
                        catch {
                            $errorMsg = "Failed to create GPO $baseGPOName : $_"
                            Write-TierLog -Message $errorMsg -Level Error -Component 'Initialize'
                            $results.Errors += $errorMsg
                            $results.Success = $false
                        }
                    }
                }
            }
        }
        
        # Save configuration
        $configDir = Split-Path $script:ConfigPath -Parent
        Initialize-TierDataDirectory -Path $configDir

        $config = @{
            InitializedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            DomainDN = $domainDN
            TierConfiguration = $script:TierConfiguration
            InitializationResults = $results
        }
        
        $config | ConvertTo-Json -Depth 10 | Set-Content -Path $script:ConfigPath -Encoding UTF8
        Write-TierLog -Message "Configuration saved to $script:ConfigPath" -Level Success -Component 'Initialize'
    }
    
    end {
        Write-Host "`n=== Initialization Summary ===" -ForegroundColor Cyan
        Write-Host "OUs Created: $($results.OUsCreated.Count)" -ForegroundColor Green
        Write-Host "Groups Created: $($results.GroupsCreated.Count)" -ForegroundColor Green
        Write-Host "GPOs Created: $($results.GPOsCreated.Count)" -ForegroundColor Green
        Write-Host "Errors: $($results.Errors.Count)" -ForegroundColor $(if ($results.Errors.Count -eq 0) { 'Green' } else { 'Red' })

        $statusColor = if ($results.Success) { 'Green' } else { 'Red' }
        $statusText = if ($results.Success) { 'SUCCESS' } else { 'PARTIAL FAILURE' }
        Write-Host "Overall Status: $statusText" -ForegroundColor $statusColor

        if ($results.Errors.Count -gt 0) {
            Write-Host "`nErrors encountered:" -ForegroundColor Red
            $results.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            Write-Warning "Initialization completed with $($results.Errors.Count) error(s). Some components may not be configured correctly."
        }

        return $results
    }
}

function Get-ADTierConfiguration {
    <#
    .SYNOPSIS
        Retrieves the current AD Tier Model configuration.
    
    .DESCRIPTION
        Returns tier configuration including OU paths, group names, and settings.
    
    .EXAMPLE
        Get-ADTierConfiguration
        
    .EXAMPLE
        Get-ADTierConfiguration | ConvertTo-Json
    #>
    [CmdletBinding()]
    param()
    
    if (Test-Path $script:ConfigPath) {
        $config = Get-Content $script:ConfigPath | ConvertFrom-Json
        return $config
    }
    else {
        return $script:TierConfiguration
    }
}

#endregion

#region Tier 0 Detection Functions

function Get-ADTier0Infrastructure {
    <#
    .SYNOPSIS
        Discovers critical Tier 0 infrastructure components in the domain.
    
    .DESCRIPTION
        Automatically identifies Domain Controllers, ADFS servers, Entra Connect servers,
        Certificate Authorities, and PAWs that should be classified as Tier 0.
    
    .PARAMETER RoleType
        Specific role type to search for. If not specified, searches for all roles.
    
    .PARAMETER IncludeDescription
        Include detailed descriptions of each component's purpose.
    
    .EXAMPLE
        Get-ADTier0Infrastructure
        
    .EXAMPLE
        Get-ADTier0Infrastructure -RoleType ADFS
        
    .EXAMPLE
        Get-ADTier0Infrastructure -IncludeDescription | Format-Table
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('DomainController', 'ADFS', 'EntraConnect', 'CertificateAuthority', 'PAW', 'All')]
        [string]$RoleType = 'All',
        
        [switch]$IncludeDescription
    )
    
    Write-Verbose "Discovering Tier 0 infrastructure components..."
    $discovered = @()
    
    $rolesToCheck = if ($RoleType -eq 'All') {
        $script:Tier0CriticalRoles.Keys
    } else {
        @($RoleType)
    }
    
    foreach ($roleKey in $rolesToCheck) {
        $role = $script:Tier0CriticalRoles[$roleKey]
        
        Write-Verbose "Searching for: $($role.Name)"

        try {
            $computers = @(& $role.Detection)

            foreach ($computerName in $computers) {
                if ($computerName) {
                    $computer = Get-ADComputer -Identity $computerName -Properties OperatingSystem, Description, LastLogonDate
                    
                    $obj = [PSCustomObject]@{
                        Name = $computer.Name
                        RoleType = $roleKey
                        RoleName = $role.Name
                        OperatingSystem = $computer.OperatingSystem
                        LastLogon = $computer.LastLogonDate
                        CurrentOU = ($computer.DistinguishedName -split ',',2)[1]
                        IsInTier0 = $computer.DistinguishedName -like "*OU=Tier0*"
                        DistinguishedName = $computer.DistinguishedName
                    }
                    
                    if ($IncludeDescription) {
                        $obj | Add-Member -NotePropertyName 'Description' -NotePropertyValue $role.Description
                    }
                    
                    $discovered += $obj
                }
            }
            
            Write-Verbose "Found $(@($computers).Count) $($role.Name) server(s)"
        }
        catch {
            Write-Warning "Failed to detect $($role.Name): $_"
        }
    }

    Write-TierLog -Message "Discovered $(@($discovered).Count) Tier 0 infrastructure components" -Level Info -Component 'Discovery'
    
    return $discovered
}

function Test-ADTier0Placement {
    <#
    .SYNOPSIS
        Validates that all Tier 0 infrastructure is properly placed in Tier 0 OUs.
    
    .DESCRIPTION
        Checks if critical Tier 0 components (DCs, ADFS, Entra Connect, etc.) are
        correctly placed in the Tier 0 OU structure and identifies misplacements.
    
    .PARAMETER AutoDiscover
        Automatically discover Tier 0 components instead of using predefined list.
    
    .EXAMPLE
        Test-ADTier0Placement -AutoDiscover
        
    .EXAMPLE
        $misplaced = Test-ADTier0Placement -AutoDiscover | Where-Object IsInTier0 -eq $false
    #>
    [CmdletBinding()]
    param(
        [switch]$AutoDiscover
    )
    
    Write-Host "=== Tier 0 Placement Validation ===" -ForegroundColor Cyan
    
    $infrastructure = Get-ADTier0Infrastructure
    
    $results = @{
        TotalComponents = $infrastructure.Count
        CorrectlyPlaced = 0
        Misplaced = 0
        Components = @()
    }
    
    foreach ($component in $infrastructure) {
        $status = if ($component.IsInTier0) {
            $results.CorrectlyPlaced++
            'Correct'
        } else {
            $results.Misplaced++
            'Misplaced'
        }
        
        $results.Components += [PSCustomObject]@{
            Name = $component.Name
            Role = $component.RoleName
            Status = $status
            CurrentOU = $component.CurrentOU
            ShouldBeIn = "OU=Computers,OU=Tier0"
        }
        
        $color = if ($status -eq 'Correct') { 'Green' } else { 'Red' }
        Write-Host "$status : $($component.Name) [$($component.RoleName)]" -ForegroundColor $color
    }
    
    Write-Host "`nSummary:" -ForegroundColor Cyan
    Write-Host "  Total Tier 0 Components: $($results.TotalComponents)" -ForegroundColor White
    Write-Host "  Correctly Placed: $($results.CorrectlyPlaced)" -ForegroundColor Green
    Write-Host "  Misplaced: $($results.Misplaced)" -ForegroundColor $(if ($results.Misplaced -gt 0) { 'Red' } else { 'Green' })
    
    if ($results.Misplaced -gt 0) {
        Write-Warning "Found $($results.Misplaced) Tier 0 components not in Tier 0 OU structure!"
        Write-Host "`nRecommendation: Use Set-ADTierMember to move these to Tier 0:" -ForegroundColor Yellow
        $results.Components | Where-Object Status -eq 'Misplaced' | ForEach-Object {
            Write-Host "  Set-ADTierMember -Identity '$($_.Name)' -TierName Tier0 -ObjectType Computer" -ForegroundColor Yellow
        }
    }
    
    Write-TierLog -Message "Tier 0 placement check: $($results.CorrectlyPlaced) correct, $($results.Misplaced) misplaced" -Level $(if ($results.Misplaced -gt 0) { 'Warning' } else { 'Info' }) -Component 'Audit'
    
    return $results
}

function Move-ADTier0Infrastructure {
    <#
    .SYNOPSIS
        Automatically moves discovered Tier 0 infrastructure to proper Tier 0 OUs.
    
    .DESCRIPTION
        Discovers and moves critical Tier 0 components (ADFS, Entra Connect, etc.)
        to the appropriate Tier 0 OU structure.
    
    .PARAMETER WhatIf
        Shows what would be moved without actually moving.
    
    .PARAMETER Confirm
        Prompts for confirmation before moving each object.
    
    .EXAMPLE
        Move-ADTier0Infrastructure -WhatIf
        
    .EXAMPLE
        Move-ADTier0Infrastructure -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param()
    
    $infrastructure = Get-ADTier0Infrastructure | Where-Object { -not $_.IsInTier0 }
    
    if ($infrastructure.Count -eq 0) {
        Write-Host "All Tier 0 infrastructure is already correctly placed." -ForegroundColor Green
        return
    }
    
    Write-Host "`nFound $($infrastructure.Count) Tier 0 component(s) to move:" -ForegroundColor Yellow
    
    $moved = @()
    $failed = @()
    
    foreach ($component in $infrastructure) {
        if ($PSCmdlet.ShouldProcess("$($component.Name) [$($component.RoleName)]", "Move to Tier 0")) {
            try {
                Set-ADTierMember -Identity $component.Name -TierName Tier0 -ObjectType Computer -ErrorAction Stop
                $moved += $component.Name
                Write-Host "Moved: $($component.Name)" -ForegroundColor Green
            }
            catch {
                $failed += $component.Name
                Write-Warning "Failed to move $($component.Name): $_"
            }
        }
    }
    
    Write-Host "`nMove Summary:" -ForegroundColor Cyan
    Write-Host "  Successfully moved: $($moved.Count)" -ForegroundColor Green
    Write-Host "  Failed: $($failed.Count)" -ForegroundColor $(if ($failed.Count -gt 0) { 'Red' } else { 'Green' })
    
    Write-TierLog -Message "Moved $($moved.Count) Tier 0 components, $($failed.Count) failed" -Level Info -Component 'TierManagement'
    
    return @{
        Moved = $moved
        Failed = $failed
    }
}

#endregion

#region Tier Management Functions

function New-ADTier {
    <#
    .SYNOPSIS
        Creates a new custom tier in the AD hierarchy.
    
    .DESCRIPTION
        Allows creation of additional tiers beyond the standard three-tier model.
    
    .PARAMETER TierName
        Name of the new tier (e.g., "Tier1.5", "TierDMZ").
    
    .PARAMETER Description
        Description of the tier's purpose.
    
    .PARAMETER ParentOU
        Parent OU path where the tier will be created.
    
    .EXAMPLE
        New-ADTier -TierName "TierDMZ" -Description "DMZ servers and applications"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$TierName,
        
        [Parameter(Mandatory)]
        [string]$Description,
        
        [string]$ParentOU,
        
        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string]$RiskLevel = 'Medium'
    )
    
    $domainDN = Get-ADDomainRootDN
    
    if ([string]::IsNullOrEmpty($ParentOU)) {
        $ParentOU = $domainDN
    }
    
    $ouPath = "OU=$TierName,$ParentOU"
    
    if ($PSCmdlet.ShouldProcess($ouPath, "Create Custom Tier")) {
        try {
            if (-not (Test-ADTierOUExists -OUPath $ouPath)) {
                New-ADOrganizationalUnit -Name $TierName -Path $ParentOU -Description $Description -ProtectedFromAccidentalDeletion $true
                Write-TierLog -Message "Created custom tier: $TierName" -Level Success -Component 'TierManagement'
                
                # Create standard sub-OUs
                $subOUs = @('Computers', 'Users', 'Groups', 'ServiceAccounts')
                foreach ($subOU in $subOUs) {
                    New-ADOrganizationalUnit -Name $subOU -Path $ouPath -ProtectedFromAccidentalDeletion $true
                }
                
                return [PSCustomObject]@{
                    TierName = $TierName
                    Path = $ouPath
                    Description = $Description
                    RiskLevel = $RiskLevel
                    Created = Get-Date
                }
            }
            else {
                Write-Warning "Tier OU already exists: $ouPath"
            }
        }
        catch {
            Write-TierLog -Message "Failed to create tier $TierName : $_" -Level Error -Component 'TierManagement'
            throw
        }
    }
}

function Get-ADTier {
    <#
    .SYNOPSIS
        Retrieves information about configured tiers.
    
    .DESCRIPTION
        Returns tier configuration, structure, and membership information.
    
    .PARAMETER TierName
        Specific tier to retrieve (Tier0, Tier1, Tier2, or custom).
    
    .EXAMPLE
        Get-ADTier -TierName Tier0
        
    .EXAMPLE
        Get-ADTier | Format-Table
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Tier0', 'Tier1', 'Tier2', 'All')]
        [string]$TierName = 'All'
    )
    
    $domainDN = Get-ADDomainRootDN
    $results = @()
    
    $tiersToQuery = if ($TierName -eq 'All') {
        $script:TierConfiguration.Keys
    }
    else {
        @($TierName)
    }
    
    foreach ($tier in $tiersToQuery) {
        $tierConfig = $script:TierConfiguration[$tier]
        $ouPath = "$($tierConfig.OUPath),$domainDN"
        
        try {
            $ou = Get-ADOrganizationalUnit -Identity $ouPath -Properties Description, ProtectedFromAccidentalDeletion

            # Get counts - wrap in @() to handle single object returns
            $computers = @(Get-ADComputer -SearchBase $ouPath -SearchScope Subtree -Filter *).Count
            $users = @(Get-ADUser -SearchBase $ouPath -SearchScope Subtree -Filter *).Count
            $groups = @(Get-ADGroup -SearchBase $ouPath -SearchScope Subtree -Filter *).Count
            
            $results += [PSCustomObject]@{
                TierName = $tier
                DisplayName = $tierConfig.Name
                Description = $tierConfig.Description
                OUPath = $ouPath
                RiskLevel = $tierConfig.RiskLevel
                Computers = $computers
                Users = $users
                Groups = $groups
                Protected = $ou.ProtectedFromAccidentalDeletion
                Exists = $true
            }
        }
        catch {
            $results += [PSCustomObject]@{
                TierName = $tier
                DisplayName = $tierConfig.Name
                Description = $tierConfig.Description
                OUPath = $ouPath
                RiskLevel = $tierConfig.RiskLevel
                Computers = 0
                Users = 0
                Groups = 0
                Protected = $false
                Exists = $false
            }
        }
    }
    
    return $results
}

function Set-ADTierMember {
    <#
    .SYNOPSIS
        Assigns an AD object (user, computer, group) to a specific tier.
    
    .DESCRIPTION
        Moves an AD object to the appropriate OU within a tier structure.
    
    .PARAMETER Identity
        The AD object to move (user, computer, admin workstation, group, or service account).
    
    .PARAMETER TierName
        Target tier (Tier0, Tier1, or Tier2).
    
    .PARAMETER ObjectType
        Type of object: User, Computer, AdminWorkstation, Group, or ServiceAccount.
    
    .EXAMPLE
        Set-ADTierMember -Identity "SRV-APP01" -TierName Tier1 -ObjectType Computer
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Identity,
        
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [Parameter(Mandatory)]
        [ValidateSet('User', 'Computer', 'AdminWorkstation', 'Group', 'ServiceAccount')]
        [string]$ObjectType
    )
    
    process {
        $domainDN = Get-ADDomainRootDN
        $tierConfig = $script:TierConfiguration[$TierName]
        
        $targetOUMap = @{
            'User' = 'Users'
            'Computer' = 'Computers'
            'AdminWorkstation' = 'AdminWorkstations'
            'Group' = 'Groups'
            'ServiceAccount' = 'ServiceAccounts'
        }
        
        $targetOU = "OU=$($targetOUMap[$ObjectType]),$($tierConfig.OUPath),$domainDN"
        
        if ($PSCmdlet.ShouldProcess($Identity, "Move to $TierName ($ObjectType OU)")) {
            try {
                $adObject = switch ($ObjectType) {
                    'User' { Get-ADUser -Identity $Identity }
                    'Computer' { Get-ADComputer -Identity $Identity }
                    'AdminWorkstation' { Get-ADComputer -Identity $Identity }
                    'Group' { Get-ADGroup -Identity $Identity }
                    'ServiceAccount' { Get-ADUser -Identity $Identity }
                }
                
                if ($adObject.DistinguishedName -notlike "*$targetOU*") {
                    Move-ADObject -Identity $adObject.DistinguishedName -TargetPath $targetOU
                    Write-TierLog -Message "Moved $ObjectType '$Identity' to $TierName" -Level Success -Component 'TierManagement'
                    
                    return [PSCustomObject]@{
                        Identity = $Identity
                        ObjectType = $ObjectType
                        Tier = $TierName
                        OldPath = $adObject.DistinguishedName
                        NewPath = $targetOU
                        MovedDate = Get-Date
                    }
                }
                else {
                    Write-Warning "$Identity is already in $TierName"
                }
            }
            catch {
                Write-TierLog -Message "Failed to move $Identity to $TierName : $_" -Level Error -Component 'TierManagement'
                throw
            }
        }
    }
}

function Remove-ADTierMember {
    <#
    .SYNOPSIS
        Removes an object from a tier (moves to quarantine or specified OU).
    
    .DESCRIPTION
        Safely removes objects from tier structure with optional quarantine.
    
    .PARAMETER Identity
        The AD object to remove.
    
    .PARAMETER QuarantineOU
        OU to move the object to (default: creates a Quarantine OU).
    
    .EXAMPLE
        Remove-ADTierMember -Identity "OLD-SERVER" -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Identity,
        
        [string]$QuarantineOU
    )
    
    process {
        $domainDN = Get-ADDomainRootDN
        
        if ([string]::IsNullOrEmpty($QuarantineOU)) {
            $QuarantineOU = "OU=Quarantine,$domainDN"
            
            if (-not (Test-ADTierOUExists -OUPath $QuarantineOU)) {
                New-ADOrganizationalUnit -Name "Quarantine" -Path $domainDN -Description "Quarantined objects from tier structure"
            }
        }
        
        if ($PSCmdlet.ShouldProcess($Identity, "Move to Quarantine")) {
            try {
                $adObject = Get-ADObject -Identity $Identity
                Move-ADObject -Identity $adObject.DistinguishedName -TargetPath $QuarantineOU
                Write-TierLog -Message "Quarantined object: $Identity" -Level Warning -Component 'TierManagement'
            }
            catch {
                Write-TierLog -Message "Failed to quarantine $Identity : $_" -Level Error -Component 'TierManagement'
                throw
            }
        }
    }
}

function Get-ADTierMember {
    <#
    .SYNOPSIS
        Retrieves all members of a specific tier.
    
    .DESCRIPTION
        Returns users, computers, and groups assigned to a tier.
    
    .PARAMETER TierName
        Tier to query.
    
    .PARAMETER ObjectType
        Filter by object type (User, Computer, Group, All).
    
    .EXAMPLE
        Get-ADTierMember -TierName Tier0 -ObjectType User
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [ValidateSet('User', 'Computer', 'Group', 'All')]
        [string]$ObjectType = 'All'
    )
    
    $domainDN = Get-ADDomainRootDN
    $tierConfig = $script:TierConfiguration[$TierName]
    $searchBase = "$($tierConfig.OUPath),$domainDN"
    
    $results = @()
    
    if ($ObjectType -in @('User', 'All')) {
        $users = Get-ADUser -SearchBase $searchBase -SearchScope Subtree -Filter * -Properties MemberOf, LastLogonDate, Enabled
        foreach ($user in $users) {
            $results += [PSCustomObject]@{
                Name = $user.Name
                SamAccountName = $user.SamAccountName
                ObjectType = 'User'
                Tier = $TierName
                Enabled = $user.Enabled
                LastLogon = $user.LastLogonDate
                DistinguishedName = $user.DistinguishedName
            }
        }
    }
    
    if ($ObjectType -in @('Computer', 'All')) {
        $computers = Get-ADComputer -SearchBase $searchBase -SearchScope Subtree -Filter * -Properties OperatingSystem, LastLogonDate, Enabled
        foreach ($computer in $computers) {
            $results += [PSCustomObject]@{
                Name = $computer.Name
                SamAccountName = $computer.SamAccountName
                ObjectType = 'Computer'
                Tier = $TierName
                OperatingSystem = $computer.OperatingSystem
                Enabled = $computer.Enabled
                LastLogon = $computer.LastLogonDate
                DistinguishedName = $computer.DistinguishedName
            }
        }
    }
    
    if ($ObjectType -in @('Group', 'All')) {
        $groups = Get-ADGroup -SearchBase $searchBase -SearchScope Subtree -Filter * -Properties Member
        foreach ($group in $groups) {
            $results += [PSCustomObject]@{
                Name = $group.Name
                SamAccountName = $group.SamAccountName
                ObjectType = 'Group'
                Tier = $TierName
                MemberCount = @($group.Member).Count
                DistinguishedName = $group.DistinguishedName
            }
        }
    }
    
    return $results
}

#endregion

#region Auditing and Monitoring Functions

function Get-ADTierAccessReport {
    <#
    .SYNOPSIS
        Generates a comprehensive access report for tier assignments.
    
    .DESCRIPTION
        Analyzes user and group memberships across tiers to identify access patterns.
    
    .PARAMETER IncludeInheritedPermissions
        Include permissions inherited through group membership.
    
    .PARAMETER ExportPath
        Path to export the report (CSV, HTML, or JSON).
    
    .EXAMPLE
        Get-ADTierAccessReport -ExportPath "C:\Reports\TierAccess.csv"
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeInheritedPermissions,
        
        [string]$ExportPath,
        
        [ValidateSet('CSV', 'HTML', 'JSON')]
        [string]$Format = 'CSV'
    )
    
    Write-Verbose "Generating tier access report..."
    $report = @()
    
    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $tierMembers = Get-ADTierMember -TierName $tierKey -ObjectType User
        
        foreach ($member in $tierMembers) {
            $user = Get-ADUser -Identity $member.SamAccountName -Properties MemberOf, LastLogonDate, PasswordLastSet
            
            $groupMemberships = $user.MemberOf | ForEach-Object {
                (Get-ADGroup -Identity $_).Name
            }
            
            $report += [PSCustomObject]@{
                UserName = $user.Name
                SamAccountName = $user.SamAccountName
                Tier = $tierKey
                Enabled = $user.Enabled
                LastLogon = $user.LastLogonDate
                PasswordLastSet = $user.PasswordLastSet
                GroupMemberships = ($groupMemberships -join '; ')
                GroupCount = $groupMemberships.Count
                ReportDate = Get-Date
            }
        }
    }
    
    if ($ExportPath) {
        switch ($Format) {
            'CSV' { $report | Export-Csv -Path $ExportPath -NoTypeInformation }
            'JSON' { $report | ConvertTo-Json -Depth 5 | Set-Content -Path $ExportPath }
            'HTML' { $report | ConvertTo-Html | Set-Content -Path $ExportPath }
        }
        Write-TierLog -Message "Access report exported to $ExportPath" -Level Success -Component 'Audit'
    }
    
    return $report
}

function Get-ADTierViolation {
    <#
    .SYNOPSIS
        Detects tier model violations and security risks.
    
    .DESCRIPTION
        Identifies cross-tier access, privilege escalation risks, and configuration issues.
    
    .PARAMETER ViolationType
        Type of violation to check for.
    
    .EXAMPLE
        Get-ADTierViolation -ViolationType CrossTierAccess
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('CrossTierAccess', 'PrivilegeEscalation', 'MisplacedObjects', 'All')]
        [string]$ViolationType = 'All'
    )
    
    Write-Verbose "Scanning for tier violations..."
    $violations = @()
    
    # Check for cross-tier group memberships
    if ($ViolationType -in @('CrossTierAccess', 'All')) {
        Write-Verbose "Checking for cross-tier access..."
        
        foreach ($tierKey in $script:TierConfiguration.Keys) {
            $escapedTierKey = Get-EscapedADFilterValue -Value "$tierKey-Admins"
            $adminGroup = Get-ADGroup -Filter "Name -eq '$escapedTierKey'" -ErrorAction SilentlyContinue

            if ($adminGroup) {
                try {
                    $members = Get-ADGroupMember -Identity $adminGroup -Recursive -ResultPageSize 200 -ResultSetSize 5000 -ErrorAction Stop

                    foreach ($member in $members) {
                        $memberDN = (Get-ADObject -Identity $member.DistinguishedName -ErrorAction Stop).DistinguishedName

                        # Check if member is from a different tier
                        foreach ($otherTier in ($script:TierConfiguration.Keys | Where-Object { $_ -ne $tierKey })) {
                            $otherTierOU = $script:TierConfiguration[$otherTier].OUPath

                            if ($memberDN -like "*$otherTierOU*") {
                                $violations += [PSCustomObject]@{
                                    ViolationType = 'CrossTierAccess'
                                    Severity = 'High'
                                    SourceTier = $otherTier
                                    TargetTier = $tierKey
                                    Identity = $member.Name
                                    Group = $adminGroup.Name
                                    Description = "User from $otherTier has access to $tierKey administrative group"
                                    DetectedDate = Get-Date
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-TierLog -Message "Failed to enumerate members of $($adminGroup.Name): $_" -Level Warning -Component 'Audit'
                }
            }
        }
    }
    
    # Check for misplaced objects
    if ($ViolationType -in @('MisplacedObjects', 'All')) {
        Write-Verbose "Checking for misplaced objects..."

        # Find domain controllers outside Tier0
        try {
            $domainControllers = @(Get-ADDomainController -ErrorAction Stop)
        }
        catch {
            # Fallback: Query by primaryGroupID (516 = Domain Controllers) - works in all locales
            Write-Verbose "Get-ADDomainController failed, using fallback method: $_"
            $domainControllers = @(Get-ADComputer -Filter "primaryGroupID -eq $($script:DC_PRIMARY_GROUP_ID)" -ErrorAction SilentlyContinue)
        }
        $tier0OU = "$($script:TierConfiguration['Tier0'].OUPath),$(Get-ADDomainRootDN)"

        foreach ($dc in $domainControllers) {
            $dcComputer = Get-ADComputer -Identity $dc.Name -ErrorAction SilentlyContinue
            if (-not $dcComputer) { continue }
            
            if ($dcComputer.DistinguishedName -notlike "*$tier0OU*") {
                $violations += [PSCustomObject]@{
                    ViolationType = 'MisplacedObjects'
                    Severity = 'Critical'
                    SourceTier = 'Unknown'
                    TargetTier = 'Tier0'
                    Identity = $dc.Name
                    Group = 'N/A'
                    Description = "Domain Controller not in Tier0 OU structure"
                    DetectedDate = Get-Date
                }
            }
        }
    }
    
    Write-TierLog -Message "Found $($violations.Count) tier violations" -Level $(if ($violations.Count -gt 0) { 'Warning' } else { 'Info' }) -Component 'Audit'
    return $violations
}

function Test-ADTierCompliance {
    <#
    .SYNOPSIS
        Performs comprehensive compliance testing of the tier model.
    
    .DESCRIPTION
        Validates tier configuration, permissions, and security settings against best practices.
    
    .PARAMETER GenerateReport
        Generate a detailed compliance report.
    
    .EXAMPLE
        Test-ADTierCompliance -GenerateReport -Verbose
    #>
    [CmdletBinding()]
    param(
        [switch]$GenerateReport,
        [string]$ReportPath
    )
    
    Write-Host "`n=== AD Tier Compliance Check ===" -ForegroundColor Cyan
    
    $complianceResults = @{
        OverallScore = 0
        Checks = @()
        Passed = 0
        Failed = 0
        Warnings = 0
        RiskScore = 0
        RiskLevel = 'Unknown'
    }
    
    # Check 1: Tier OU Structure Exists
    Write-Verbose "Checking tier OU structure..."
    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $tier = $script:TierConfiguration[$tierKey]
        $ouPath = "$($tier.OUPath),$(Get-ADDomainRootDN)"
        $exists = Test-ADTierOUExists -OUPath $ouPath
        
        $complianceResults.Checks += [PSCustomObject]@{
            CheckName = "Tier OU Exists: $tierKey"
            Status = if ($exists) { 'Pass' } else { 'Fail' }
            Details = $ouPath
            Severity = 'High'
        }
        
        if ($exists) { $complianceResults.Passed++ } else { $complianceResults.Failed++ }
    }
    
    # Check 2: Administrative Groups Exist
    Write-Verbose "Checking administrative groups..."
    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $groupName = "$tierKey-Admins"
        $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
        $groupExists = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction SilentlyContinue
        
        $complianceResults.Checks += [PSCustomObject]@{
            CheckName = "Admin Group Exists: $groupName"
            Status = if ($groupExists) { 'Pass' } else { 'Fail' }
            Details = if ($groupExists) { $groupExists.DistinguishedName } else { 'Not Found' }
            Severity = 'High'
        }
        
        if ($groupExists) { $complianceResults.Passed++ } else { $complianceResults.Failed++ }
    }
    
    # Check 3: No Cross-Tier Violations
    Write-Verbose "Checking for cross-tier violations..."
    $violations = Get-ADTierViolation -ViolationType All
    
    $complianceResults.Checks += [PSCustomObject]@{
        CheckName = "Cross-Tier Violations"
        Status = if ($violations.Count -eq 0) { 'Pass' } else { 'Fail' }
        Details = "$($violations.Count) violations found"
        Severity = 'Critical'
    }
    
    if ($violations.Count -eq 0) { $complianceResults.Passed++ } else { $complianceResults.Failed++ }
    
    # Check 3a: Tier 0 Infrastructure Placement
    Write-Verbose "Checking Tier 0 infrastructure placement..."
    $tier0Infrastructure = Get-ADTier0Infrastructure
    $misplacedTier0 = $tier0Infrastructure | Where-Object { -not $_.IsInTier0 }
    
    $complianceResults.Checks += [PSCustomObject]@{
        CheckName = "Tier 0 Infrastructure Placement"
        Status = if ($misplacedTier0.Count -eq 0) { 'Pass' } else { 'Fail' }
        Details = "$($misplacedTier0.Count) critical Tier 0 components misplaced (ADFS, Entra Connect, etc.)"
        Severity = 'Critical'
    }
    
    if ($misplacedTier0.Count -eq 0) { $complianceResults.Passed++ } else { $complianceResults.Failed++ }
    
    # Check 4: Protected from Accidental Deletion
    Write-Verbose "Checking OU protection..."
    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $tier = $script:TierConfiguration[$tierKey]
        $ouPath = "$($tier.OUPath),$(Get-ADDomainRootDN)"
        
        try {
            $ou = Get-ADOrganizationalUnit -Identity $ouPath -Properties ProtectedFromAccidentalDeletion
            $isProtected = $ou.ProtectedFromAccidentalDeletion
            
            $complianceResults.Checks += [PSCustomObject]@{
                CheckName = "OU Protection: $tierKey"
                Status = if ($isProtected) { 'Pass' } else { 'Warning' }
                Details = "Protected: $isProtected"
                Severity = 'Medium'
            }
            
            if ($isProtected) { $complianceResults.Passed++ } else { $complianceResults.Warnings++ }
        }
        catch {
            $complianceResults.Warnings++
        }
    }
    
    # Calculate score
    $totalChecks = $complianceResults.Passed + $complianceResults.Failed + $complianceResults.Warnings
    if ($totalChecks -gt 0) {
        $complianceResults.OverallScore = [math]::Round(($complianceResults.Passed / $totalChecks) * 100, 2)
    }
    
    $complianceResults.RiskScore = ($complianceResults.Failed * 10) + ($complianceResults.Warnings * 3)
    $complianceResults.RiskLevel = switch ($complianceResults.RiskScore) {
        { $_ -ge 50 } { 'Critical'; break }
        { $_ -ge 25 } { 'High'; break }
        { $_ -ge 10 } { 'Medium'; break }
        default { 'Low' }
    }
    
    # Display results
    Write-Host "`nCompliance Score: $($complianceResults.OverallScore)%" -ForegroundColor $(
        if ($complianceResults.OverallScore -ge 90) { 'Green' }
        elseif ($complianceResults.OverallScore -ge 70) { 'Yellow' }
        else { 'Red' }
    )
    Write-Host "Passed: $($complianceResults.Passed)" -ForegroundColor Green
    Write-Host "Failed: $($complianceResults.Failed)" -ForegroundColor Red
    Write-Host "Warnings: $($complianceResults.Warnings)" -ForegroundColor Yellow
    
    if ($GenerateReport -and $ReportPath) {
        $complianceResults.Checks | Export-Csv -Path $ReportPath -NoTypeInformation
        Write-Host "`nReport exported to: $ReportPath" -ForegroundColor Cyan
    }
    
    Write-TierLog -Message "Compliance check completed: Score $($complianceResults.OverallScore)%" -Level Info -Component 'Audit'
    
    return $complianceResults
}

function Export-ADTierAuditLog {
    <#
    .SYNOPSIS
        Exports audit logs for tier-related activities.
    
    .DESCRIPTION
        Retrieves and exports module activity logs for compliance reporting.
    
    .PARAMETER StartDate
        Start date for log export.
    
    .PARAMETER EndDate
        End date for log export.
    
    .PARAMETER ExportPath
        Path to export the audit log.
    
    .EXAMPLE
        Export-ADTierAuditLog -StartDate (Get-Date).AddDays(-30) -ExportPath "C:\Audit\TierLog.csv"
    #>
    [CmdletBinding()]
    param(
        [DateTime]$StartDate = (Get-Date).AddDays(-30),
        [DateTime]$EndDate = (Get-Date),
        
        [Parameter(Mandatory)]
        [string]$ExportPath
    )
    
    $logPath = "$env:ProgramData\ADTierModel\Logs"
    
    if (-not (Test-Path $logPath)) {
        Write-Warning "No audit logs found at $logPath"
        return
    }
    
    $logFiles = Get-ChildItem -Path $logPath -Filter "*.log" | Where-Object {
        $_.LastWriteTime -ge $StartDate -and $_.LastWriteTime -le $EndDate
    }
    
    $auditEntries = @()
    
    foreach ($logFile in $logFiles) {
        $content = Get-Content -Path $logFile.FullName
        
        foreach ($line in $content) {
            if ($line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] \[(\w+)\] (.+)$') {
                $auditEntries += [PSCustomObject]@{
                    Timestamp = [DateTime]::Parse($Matches[1])
                    Level = $Matches[2]
                    Component = $Matches[3]
                    Message = $Matches[4]
                }
            }
        }
    }
    
    $auditEntries | Sort-Object Timestamp | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-TierLog -Message "Audit log exported: $ExportPath ($($auditEntries.Count) entries)" -Level Success -Component 'Audit'
}

#endregion

#region Cross-Tier Detection Functions

function Find-ADCrossTierAccess {
    <#
    .SYNOPSIS
        Identifies users or groups with access across multiple tiers.
    
    .DESCRIPTION
        Scans for accounts that have administrative access to multiple tiers,
        which violates the principle of tier separation.
    
    .EXAMPLE
        Find-ADCrossTierAccess | Format-Table
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Scanning for cross-tier access..."
    $crossTierAccess = @()
    
    # Get all administrative groups
    $adminGroups = @{}
    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $groupName = "$tierKey-Admins"
        $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
        $group = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction SilentlyContinue
        if ($group) {
            $adminGroups[$tierKey] = Get-ADGroupMember -Identity $group -Recursive
        }
    }
    
    # Find users in multiple tier admin groups
    $allUsers = $adminGroups.Values | ForEach-Object { $_ } | Group-Object -Property SamAccountName
    $usersInMultipleTiers = $allUsers | Where-Object { $_.Count -gt 1 }
    
    foreach ($user in $usersInMultipleTiers) {
        $tiers = @()
        foreach ($tierKey in $adminGroups.Keys) {
            # Wrap in @() to handle single-object scenario correctly
            if (@($adminGroups[$tierKey]).SamAccountName -contains $user.Name) {
                $tiers += $tierKey
            }
        }
        
        $crossTierAccess += [PSCustomObject]@{
            UserName = $user.Name
            TiersWithAccess = ($tiers -join ', ')
            TierCount = $tiers.Count
            Severity = 'High'
            Recommendation = 'Remove user from all but one tier administrative group'
        }
    }
    
    Write-TierLog -Message "Found $($crossTierAccess.Count) accounts with cross-tier access" -Level Warning -Component 'Security'
    return $crossTierAccess
}

function Find-ADTierMisconfiguration {
    <#
    .SYNOPSIS
        Identifies common tier model misconfigurations.
    
    .DESCRIPTION
        Scans for configuration issues like missing groups, unprotected OUs,
        and improper delegation.
    
    .EXAMPLE
        Find-ADTierMisconfiguration -Verbose
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Scanning for tier misconfigurations..."
    $issues = @()
    
    # Check for missing required groups
    $requiredGroupSuffixes = @('Admins', 'Operators', 'Readers')
    foreach ($tierKey in $script:TierConfiguration.Keys) {
        foreach ($suffix in $requiredGroupSuffixes) {
            $groupName = "$tierKey-$suffix"
            $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
            $group = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction SilentlyContinue

            if (-not $group) {
                $issues += [PSCustomObject]@{
                    IssueType = 'MissingGroup'
                    Tier = $tierKey
                    Object = $groupName
                    Severity = 'High'
                    Description = "Required administrative group is missing"
                }
            }
        }
    }
    
    # Check for unprotected OUs
    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $tier = $script:TierConfiguration[$tierKey]
        $ouPath = "$($tier.OUPath),$(Get-ADDomainRootDN)"
        
        try {
            $ou = Get-ADOrganizationalUnit -Identity $ouPath -Properties ProtectedFromAccidentalDeletion
            
            if (-not $ou.ProtectedFromAccidentalDeletion) {
                $issues += [PSCustomObject]@{
                    IssueType = 'UnprotectedOU'
                    Tier = $tierKey
                    Object = $ouPath
                    Severity = 'Medium'
                    Description = "OU is not protected from accidental deletion"
                }
            }
        }
        catch {
            $issues += [PSCustomObject]@{
                IssueType = 'MissingOU'
                Tier = $tierKey
                Object = $ouPath
                Severity = 'Critical'
                Description = "Tier OU structure does not exist"
            }
        }
    }
    
    Write-TierLog -Message "Found $($issues.Count) tier misconfigurations" -Level Warning -Component 'Security'
    return $issues
}

function Repair-ADTierViolation {
    <#
    .SYNOPSIS
        Attempts to automatically repair tier violations.
    
    .DESCRIPTION
        Fixes common issues like removing cross-tier memberships and
        moving misplaced objects.
    
    .PARAMETER ViolationType
        Type of violation to repair.
    
    .PARAMETER AutoFix
        Automatically fix issues without confirmation.
    
    .EXAMPLE
        Repair-ADTierViolation -ViolationType CrossTierAccess -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('CrossTierAccess', 'MisplacedObjects', 'All')]
        [string]$ViolationType = 'All',
        
        [switch]$AutoFix
    )
    
    $violations = Get-ADTierViolation -ViolationType $ViolationType
    $repaired = 0
    $failed = 0
    
    foreach ($violation in $violations) {
        if ($violation.ViolationType -eq 'CrossTierAccess') {
            $message = "Remove $($violation.Identity) from $($violation.Group)"
            
            if ($AutoFix -or $PSCmdlet.ShouldProcess($violation.Identity, $message)) {
                try {
                    Remove-ADGroupMember -Identity $violation.Group -Members $violation.Identity -Confirm:$false
                    Write-TierLog -Message "Repaired: $message" -Level Success -Component 'Repair'
                    $repaired++
                }
                catch {
                    Write-TierLog -Message "Failed to repair: $message - $_" -Level Error -Component 'Repair'
                    $failed++
                }
            }
        }
    }
    
    Write-Host "`nRepair Summary:" -ForegroundColor Cyan
    Write-Host "Repaired: $repaired" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    
    return [PSCustomObject]@{
        TotalViolations = $violations.Count
        Repaired = $repaired
        Failed = $failed
    }
}

#endregion

#region OU Management Functions

function New-ADTierOUStructure {
    <#
    .SYNOPSIS
        Creates a custom OU structure for a tier.
    
    .DESCRIPTION
        Creates additional organizational units within a tier for better organization.
    
    .PARAMETER TierName
        Target tier for the OU structure.
    
    .PARAMETER OUNames
        Array of OU names to create.
    
    .EXAMPLE
        New-ADTierOUStructure -TierName Tier1 -OUNames @('Databases', 'WebServers', 'ApplicationServers')
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [Parameter(Mandatory)]
        [string[]]$OUNames
    )
    
    $domainDN = Get-ADDomainRootDN
    $tierConfig = $script:TierConfiguration[$TierName]
    $tierOUPath = "$($tierConfig.OUPath),$domainDN"
    
    if (-not (Test-ADTierOUExists -OUPath $tierOUPath)) {
        throw "Tier OU does not exist: $tierOUPath. Run Initialize-ADTierModel first."
    }
    
    $results = @()
    
    foreach ($ouName in $OUNames) {
        $ouPath = "OU=$ouName,$tierOUPath"
        
        if ($PSCmdlet.ShouldProcess($ouPath, "Create OU")) {
            try {
                if (-not (Test-ADTierOUExists -OUPath $ouPath)) {
                    New-ADOrganizationalUnit -Name $ouName -Path $tierOUPath -ProtectedFromAccidentalDeletion $true
                    
                    $results += [PSCustomObject]@{
                        TierName = $TierName
                        OUName = $ouName
                        Path = $ouPath
                        Status = 'Created'
                        Timestamp = Get-Date
                    }
                    
                    Write-TierLog -Message "Created OU: $ouPath" -Level Success -Component 'OUManagement'
                }
                else {
                    $results += [PSCustomObject]@{
                        TierName = $TierName
                        OUName = $ouName
                        Path = $ouPath
                        Status = 'AlreadyExists'
                        Timestamp = Get-Date
                    }
                    Write-Warning "OU already exists: $ouPath"
                }
            }
            catch {
                $results += [PSCustomObject]@{
                    TierName = $TierName
                    OUName = $ouName
                    Path = $ouPath
                    Status = 'Failed'
                    Error = $_.Exception.Message
                    Timestamp = Get-Date
                }
                Write-TierLog -Message "Failed to create OU $ouPath : $_" -Level Error -Component 'OUManagement'
            }
        }
    }
    
    return $results
}

function Get-ADTierOUStructure {
    <#
    .SYNOPSIS
        Retrieves the complete OU structure for a tier.
    
    .DESCRIPTION
        Returns all organizational units within a tier hierarchy.
    
    .PARAMETER TierName
        Target tier to query.
    
    .PARAMETER IncludeEmptyOUs
        Include OUs that contain no objects.
    
    .EXAMPLE
        Get-ADTierOUStructure -TierName Tier1
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [switch]$IncludeEmptyOUs
    )
    
    $domainDN = Get-ADDomainRootDN
    $tierConfig = $script:TierConfiguration[$TierName]
    $tierOUPath = "$($tierConfig.OUPath),$domainDN"
    
    try {
        $ous = Get-ADOrganizationalUnit -SearchBase $tierOUPath -SearchScope Subtree -Filter * -Properties Description, ProtectedFromAccidentalDeletion
        
        $ouStructure = @()
        
        foreach ($ou in $ous) {
            # Count objects in OU - wrap in @() to handle single object returns
            $computers = @(Get-ADComputer -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter *).Count
            $users = @(Get-ADUser -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter *).Count
            $groups = @(Get-ADGroup -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter *).Count
            $totalObjects = $computers + $users + $groups
            
            if ($IncludeEmptyOUs -or $totalObjects -gt 0) {
                $ouStructure += [PSCustomObject]@{
                    TierName = $TierName
                    Name = $ou.Name
                    DistinguishedName = $ou.DistinguishedName
                    Description = $ou.Description
                    Protected = $ou.ProtectedFromAccidentalDeletion
                    Computers = $computers
                    Users = $users
                    Groups = $groups
                    TotalObjects = $totalObjects
                }
            }
        }
        
        return $ouStructure | Sort-Object DistinguishedName
    }
    catch {
        Write-TierLog -Message "Failed to retrieve OU structure for $TierName : $_" -Level Error -Component 'OUManagement'
        throw
    }
}

#endregion

#region Group Management Functions

function New-ADTierGroup {
    <#
    .SYNOPSIS
        Creates a new security group within a tier.
    
    .DESCRIPTION
        Creates custom security groups for tier-specific access control.
    
    .PARAMETER TierName
        Target tier for the group.
    
    .PARAMETER GroupName
        Name of the group to create.
    
    .PARAMETER Description
        Description of the group's purpose.
    
    .PARAMETER GroupScope
        Group scope (Universal, Global, DomainLocal).
    
    .EXAMPLE
        New-ADTierGroup -TierName Tier1 -GroupName "Tier1-SQLAdmins" -Description "SQL Server administrators"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [Parameter(Mandatory)]
        [string]$GroupName,
        
        [string]$Description,
        
        [ValidateSet('Universal', 'Global', 'DomainLocal')]
        [string]$GroupScope = 'Universal'
    )
    
    $domainDN = Get-ADDomainRootDN
    $tierConfig = $script:TierConfiguration[$TierName]
    $groupsOU = "OU=Groups,$($tierConfig.OUPath),$domainDN"
    
    if ($PSCmdlet.ShouldProcess($GroupName, "Create Security Group")) {
        try {
            $escapedGroupName = Get-EscapedADFilterValue -Value $GroupName
            $existingGroup = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction SilentlyContinue

            if (-not $existingGroup) {
                $groupParams = @{
                    Name = $GroupName
                    GroupScope = $GroupScope
                    GroupCategory = 'Security'
                    Path = $groupsOU
                    Description = if ($Description) { $Description } else { "Custom group for $TierName" }
                }
                
                New-ADGroup @groupParams
                Write-TierLog -Message "Created group: $GroupName in $TierName" -Level Success -Component 'GroupManagement'
                
                return [PSCustomObject]@{
                    TierName = $TierName
                    GroupName = $GroupName
                    GroupScope = $GroupScope
                    Path = $groupsOU
                    Status = 'Created'
                    Timestamp = Get-Date
                }
            }
            else {
                Write-Warning "Group already exists: $GroupName"
                return [PSCustomObject]@{
                    TierName = $TierName
                    GroupName = $GroupName
                    Status = 'AlreadyExists'
                }
            }
        }
        catch {
            Write-TierLog -Message "Failed to create group $GroupName : $_" -Level Error -Component 'GroupManagement'
            throw
        }
    }
}

function Get-ADTierGroup {
    <#
    .SYNOPSIS
        Retrieves all security groups within a tier.
    
    .DESCRIPTION
        Returns all groups in the tier's Groups OU with membership information.
    
    .PARAMETER TierName
        Target tier to query.
    
    .PARAMETER IncludeMembership
        Include detailed group membership information.
    
    .EXAMPLE
        Get-ADTierGroup -TierName Tier0 -IncludeMembership
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [switch]$IncludeMembership
    )
    
    $domainDN = Get-ADDomainRootDN
    $tierConfig = $script:TierConfiguration[$TierName]
    $searchBase = "$($tierConfig.OUPath),$domainDN"
    
    try {
        $groups = Get-ADGroup -SearchBase $searchBase -SearchScope Subtree -Filter * -Properties Description, Member, MemberOf
        
        $groupInfo = @()
        
        foreach ($group in $groups) {
            $groupObj = [PSCustomObject]@{
                TierName = $TierName
                Name = $group.Name
                SamAccountName = $group.SamAccountName
                Description = $group.Description
                GroupScope = $group.GroupScope
                GroupCategory = $group.GroupCategory
                MemberCount = @($group.Member).Count
                DistinguishedName = $group.DistinguishedName
            }
            
            if ($IncludeMembership) {
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                $groupObj | Add-Member -NotePropertyName 'Members' -NotePropertyValue ($members | Select-Object Name, ObjectClass, SamAccountName)
            }
            
            $groupInfo += $groupObj
        }
        
        return $groupInfo | Sort-Object Name
    }
    catch {
        Write-TierLog -Message "Failed to retrieve groups for $TierName : $_" -Level Error -Component 'GroupManagement'
        throw
    }
}

function Add-ADTierGroupMember {
    <#
    .SYNOPSIS
        Adds a member to a tier administrative group.
    
    .DESCRIPTION
        Adds users, computers, or groups to tier-specific security groups with validation.
    
    .PARAMETER TierName
        Target tier.
    
    .PARAMETER GroupSuffix
        Group suffix (Admins, Operators, Readers).
    
    .PARAMETER Members
        Array of members to add (SamAccountName).
    
    .EXAMPLE
        Add-ADTierGroupMember -TierName Tier1 -GroupSuffix Admins -Members "john.admin"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,

        [Parameter(Mandatory)]
        [ValidateSet('Admins', 'Operators', 'Readers', 'ServiceAccounts', 'JumpServers')]
        [string]$GroupSuffix,

        [Parameter(Mandatory)]
        [string[]]$Members
    )

    $groupName = "$TierName-$GroupSuffix"

    # Validate group exists before proceeding
    if (-not (Test-ADGroupExists -GroupName $groupName)) {
        throw "Group '$groupName' does not exist. Run Initialize-ADTierModel -CreateGroups first."
    }

    try {
        $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
        $group = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction Stop

        foreach ($member in $Members) {
            if ($PSCmdlet.ShouldProcess($member, "Add to $groupName")) {
                try {
                    # Check if member exists
                    $escapedMember = Get-EscapedADFilterValue -Value $member
                    $adObject = Get-ADObject -Filter "SamAccountName -eq '$escapedMember'" -ErrorAction Stop
                    
                    # Check if already a member
                    $isMember = Get-ADGroupMember -Identity $group | Where-Object { $_.SamAccountName -eq $member }
                    
                    if (-not $isMember) {
                        Add-ADGroupMember -Identity $group -Members $member
                        Write-TierLog -Message "Added $member to $groupName" -Level Success -Component 'GroupManagement'
                    }
                    else {
                        Write-Warning "$member is already a member of $groupName"
                    }
                }
                catch {
                    Write-TierLog -Message "Failed to add $member to $groupName : $_" -Level Error -Component 'GroupManagement'
                }
            }
        }
    }
    catch {
        Write-TierLog -Message "Group $groupName not found" -Level Error -Component 'GroupManagement'
        throw
    }
}

function Remove-ADTierGroupMember {
    <#
    .SYNOPSIS
        Removes a member from a tier administrative group.
    
    .DESCRIPTION
        Safely removes users, computers, or groups from tier-specific security groups.
    
    .PARAMETER TierName
        Target tier.
    
    .PARAMETER GroupSuffix
        Group suffix (Admins, Operators, Readers).
    
    .PARAMETER Members
        Array of members to remove (SamAccountName).
    
    .EXAMPLE
        Remove-ADTierGroupMember -TierName Tier1 -GroupSuffix Admins -Members "john.admin"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [Parameter(Mandatory)]
        [ValidateSet('Admins', 'Operators', 'Readers', 'ServiceAccounts', 'JumpServers')]
        [string]$GroupSuffix,
        
        [Parameter(Mandatory)]
        [string[]]$Members
    )
    
    $groupName = "$TierName-$GroupSuffix"

    try {
        $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
        $group = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction Stop

        foreach ($member in $Members) {
            if ($PSCmdlet.ShouldProcess($member, "Remove from $groupName")) {
                try {
                    # Check if member exists in group
                    $isMember = Get-ADGroupMember -Identity $group | Where-Object { $_.SamAccountName -eq $member }
                    
                    if ($isMember) {
                        Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
                        Write-TierLog -Message "Removed $member from $groupName" -Level Success -Component 'GroupManagement'
                    }
                    else {
                        Write-Warning "$member is not a member of $groupName"
                    }
                }
                catch {
                    Write-TierLog -Message "Failed to remove $member from $groupName : $_" -Level Error -Component 'GroupManagement'
                }
            }
        }
    }
    catch {
        Write-TierLog -Message "Group $groupName not found" -Level Error -Component 'GroupManagement'
        throw
    }
}

#endregion

#region Permission Management Functions

function Set-ADTierPermission {
    <#
    .SYNOPSIS
        Configures delegation of permissions for tier separation.
    
    .DESCRIPTION
        Sets up proper ACLs to enforce tier separation and prevent privilege escalation.
    
    .PARAMETER TierName
        Target tier to configure permissions for.
    
    .PARAMETER PermissionType
        Type of permission to configure (FullControl, Modify, Read).
    
    .PARAMETER DelegateToGroup
        Group to delegate permissions to.
    
    .EXAMPLE
        Set-ADTierPermission -TierName Tier1 -PermissionType FullControl -DelegateToGroup "Tier1-Admins"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [Parameter(Mandatory)]
        [ValidateSet('FullControl', 'Modify', 'Read', 'CreateDeleteChild')]
        [string]$PermissionType,
        
        [Parameter(Mandatory)]
        [string]$DelegateToGroup
    )
    
    $domainDN = Get-ADDomainRootDN
    $tierConfig = $script:TierConfiguration[$TierName]
    $tierOUPath = "$($tierConfig.OUPath),$domainDN"
    
    if ($PSCmdlet.ShouldProcess($tierOUPath, "Configure permissions for $DelegateToGroup")) {
        try {
            # Verify group exists
            $escapedDelegateToGroup = Get-EscapedADFilterValue -Value $DelegateToGroup
            $group = Get-ADGroup -Filter "Name -eq '$escapedDelegateToGroup'" -ErrorAction Stop
            
            # Get the OU object
            $ou = Get-ADOrganizationalUnit -Identity $tierOUPath
            
            # Get current ACL
            $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)"
            
            # Create the identity reference
            $identity = [System.Security.Principal.NTAccount]$group.SamAccountName
            
            # Define rights based on permission type
            $accessRights = switch ($PermissionType) {
                'FullControl' { [System.DirectoryServices.ActiveDirectoryRights]::GenericAll }
                'Modify' { [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty }
                'Read' { [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty }
                'CreateDeleteChild' { [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild }
            }
            
            # Create access rule
            $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $identity,
                $accessRights,
                [System.Security.AccessControl.AccessControlType]::Allow,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            )
            
            # Add the rule
            $acl.AddAccessRule($accessRule)
            Set-Acl -Path "AD:\$($ou.DistinguishedName)" -AclObject $acl
            
            Write-TierLog -Message "Configured $PermissionType permissions for $DelegateToGroup on $TierName" -Level Success -Component 'PermissionManagement'
            
            return [PSCustomObject]@{
                TierName = $TierName
                OUPath = $tierOUPath
                Group = $DelegateToGroup
                PermissionType = $PermissionType
                Status = 'Applied'
                Timestamp = Get-Date
            }
        }
        catch {
            Write-TierLog -Message "Failed to configure permissions: $_" -Level Error -Component 'PermissionManagement'
            throw
        }
    }
}

function Get-ADTierPermission {
    <#
    .SYNOPSIS
        Retrieves permission delegations for a tier.
    
    .DESCRIPTION
        Returns ACL information for tier OUs showing delegated permissions.
    
    .PARAMETER TierName
        Target tier to query.
    
    .EXAMPLE
        Get-ADTierPermission -TierName Tier1
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName
    )
    
    $domainDN = Get-ADDomainRootDN
    $tierConfig = $script:TierConfiguration[$TierName]
    $tierOUPath = "$($tierConfig.OUPath),$domainDN"
    
    try {
        $ou = Get-ADOrganizationalUnit -Identity $tierOUPath
        $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)"
        
        $permissions = @()
        
        foreach ($access in $acl.Access) {
            # Filter out inherited and system permissions for clarity
            if (-not $access.IsInherited -and $access.IdentityReference -notlike "NT AUTHORITY\*" -and $access.IdentityReference -notlike "BUILTIN\*") {
                $permissions += [PSCustomObject]@{
                    TierName = $TierName
                    Identity = $access.IdentityReference
                    AccessControlType = $access.AccessControlType
                    ActiveDirectoryRights = $access.ActiveDirectoryRights
                    InheritanceType = $access.InheritanceType
                    IsInherited = $access.IsInherited
                }
            }
        }
        
        return $permissions
    }
    catch {
        Write-TierLog -Message "Failed to retrieve permissions for $TierName : $_" -Level Error -Component 'PermissionManagement'
        throw
    }
}

function Test-ADTierPermissionCompliance {
    <#
    .SYNOPSIS
        Tests tier permission configuration for security compliance.
    
    .DESCRIPTION
        Validates that permissions are properly configured and tier separation is enforced.
    
    .PARAMETER TierName
        Target tier to test.
    
    .EXAMPLE
        Test-ADTierPermissionCompliance -TierName Tier0
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Tier0', 'Tier1', 'Tier2', 'All')]
        [string]$TierName = 'All'
    )
    
    $complianceResults = @()
    
    $tiersToTest = if ($TierName -eq 'All') {
        $script:TierConfiguration.Keys
    }
    else {
        @($TierName)
    }
    
    foreach ($tier in $tiersToTest) {
        Write-Verbose "Testing permissions for $tier..."
        
        try {
            $permissions = Get-ADTierPermission -TierName $tier
            
            # Check for cross-tier permissions
            foreach ($permission in $permissions) {
                $identity = $permission.Identity.ToString()
                
                # Check if identity is from another tier
                foreach ($otherTier in ($script:TierConfiguration.Keys | Where-Object { $_ -ne $tier })) {
                    if ($identity -like "*$otherTier*") {
                        $complianceResults += [PSCustomObject]@{
                            TierName = $tier
                            CheckType = 'CrossTierPermission'
                            Status = 'Fail'
                            Severity = 'High'
                            Identity = $identity
                            Issue = "Cross-tier permission detected: $otherTier identity has access to $tier"
                            Recommendation = "Remove $identity from $tier permissions"
                        }
                    }
                }
            }
            
            # Check for excessive permissions
            $excessivePermissions = $permissions | Where-Object { 
                $_.ActiveDirectoryRights -match 'GenericAll' -and 
                $_.Identity -notlike "*Domain Admins*" -and 
                $_.Identity -notlike "*$tier-Admins*"
            }
            
            foreach ($excessive in $excessivePermissions) {
                $complianceResults += [PSCustomObject]@{
                    TierName = $tier
                    CheckType = 'ExcessivePermissions'
                    Status = 'Warning'
                    Severity = 'Medium'
                    Identity = $excessive.Identity
                    Issue = "Non-tier admin group has full control"
                    Recommendation = "Review and restrict permissions for $($excessive.Identity)"
                }
            }
            
            # If no issues found
            if (-not ($complianceResults | Where-Object { $_.TierName -eq $tier })) {
                $complianceResults += [PSCustomObject]@{
                    TierName = $tier
                    CheckType = 'PermissionCompliance'
                    Status = 'Pass'
                    Severity = 'Info'
                    Identity = 'N/A'
                    Issue = 'No permission compliance issues detected'
                    Recommendation = 'Continue monitoring'
                }
            }
        }
        catch {
            $complianceResults += [PSCustomObject]@{
                TierName = $tier
                CheckType = 'PermissionCheck'
                Status = 'Error'
                Severity = 'High'
                Identity = 'N/A'
                Issue = "Failed to check permissions: $_"
                Recommendation = 'Investigate permission check failure'
            }
        }
    }
    
    return $complianceResults
}

#endregion

#region Authentication Policy Functions

function Set-ADTierAuthenticationPolicy {
    <#
    .SYNOPSIS
        Configures authentication policies for tier separation.
    
    .DESCRIPTION
        Sets up authentication policy silos to enforce tier-based access control.
        Requires Windows Server 2012 R2 or later with Active Directory Domain Services.
    
    .PARAMETER TierName
        Target tier for the authentication policy.
    
    .PARAMETER AllowedToAuthenticateFrom
        Specifies which devices can authenticate.
    
    .EXAMPLE
        Set-ADTierAuthenticationPolicy -TierName Tier0 -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [string]$AllowedToAuthenticateFrom
    )
    
    $policyName = "AuthPolicy-$TierName"
    $siloName = "AuthSilo-$TierName"
    
    if ($PSCmdlet.ShouldProcess($policyName, "Create Authentication Policy")) {
        try {
            # Check if authentication policy cmdlets are available
            if (-not (Get-Command New-ADAuthenticationPolicy -ErrorAction SilentlyContinue)) {
                Write-Warning "Authentication Policy cmdlets not available. Requires Windows Server 2012 R2 or later."
                return
            }

            # Create authentication policy
            $escapedPolicyName = Get-EscapedADFilterValue -Value $policyName
            $existingPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$escapedPolicyName'" -ErrorAction SilentlyContinue

            if (-not $existingPolicy) {
                New-ADAuthenticationPolicy -Name $policyName -Description "Authentication policy for $TierName"
                Write-TierLog -Message "Created authentication policy: $policyName" -Level Success -Component 'AuthPolicy'
            }

            # Create authentication policy silo
            $escapedSiloName = Get-EscapedADFilterValue -Value $siloName
            $existingSilo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$escapedSiloName'" -ErrorAction SilentlyContinue
            
            if (-not $existingSilo) {
                New-ADAuthenticationPolicySilo -Name $siloName -Description "Authentication silo for $TierName"
                Write-TierLog -Message "Created authentication silo: $siloName" -Level Success -Component 'AuthPolicy'
            }
            
            Write-Host "Authentication policy configured for $TierName" -ForegroundColor Green
        }
        catch {
            Write-TierLog -Message "Failed to configure authentication policy: $_" -Level Error -Component 'AuthPolicy'
            throw
        }
    }
}

function Get-ADTierAuthenticationPolicy {
    <#
    .SYNOPSIS
        Retrieves authentication policies for tiers.
    
    .DESCRIPTION
        Returns configured authentication policies and silos.
    
    .EXAMPLE
        Get-ADTierAuthenticationPolicy
    #>
    [CmdletBinding()]
    param()
    
    if (-not (Get-Command Get-ADAuthenticationPolicy -ErrorAction SilentlyContinue)) {
        Write-Warning "Authentication Policy cmdlets not available."
        return
    }

    $policies = @()

    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $policyName = "AuthPolicy-$tierKey"
        $escapedPolicyName = Get-EscapedADFilterValue -Value $policyName
        $policy = Get-ADAuthenticationPolicy -Filter "Name -eq '$escapedPolicyName'" -ErrorAction SilentlyContinue
        
        if ($policy) {
            $policies += [PSCustomObject]@{
                TierName = $tierKey
                PolicyName = $policy.Name
                Description = $policy.Description
                Created = $policy.Created
            }
        }
    }
    
    return $policies
}

function Set-ADTierPasswordPolicy {
    <#
    .SYNOPSIS
        Configures fine-grained password policies for tier accounts.
    
    .DESCRIPTION
        Creates and applies password settings objects (PSOs) with enhanced
        security requirements for administrative accounts.
    
    .PARAMETER TierName
        Target tier for password policy.
    
    .PARAMETER MinPasswordLength
        Minimum password length.
    
    .PARAMETER PasswordHistoryCount
        Number of previous passwords to remember.
    
    .EXAMPLE
        Set-ADTierPasswordPolicy -TierName Tier0 -MinPasswordLength 20
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,

        [ValidateRange(1, 128)]
        [int]$MinPasswordLength = 15,

        [ValidateRange(0, 24)]
        [int]$PasswordHistoryCount = 24,

        [ValidateRange(1, 999)]
        [int]$MaxPasswordAge = 60,

        [ValidateRange(0, 998)]
        [int]$MinPasswordAge = 1,

        [ValidateRange(0, 999)]
        [int]$LockoutThreshold = 3
    )

    $psoName = "PSO-$TierName-Admins"
    $groupName = "$TierName-Admins"

    if ($PSCmdlet.ShouldProcess($psoName, "Create Password Settings Object")) {
        try {
            $escapedPsoName = Get-EscapedADFilterValue -Value $psoName
            $existingPSO = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$escapedPsoName'" -ErrorAction SilentlyContinue
            
            if (-not $existingPSO) {
                $tierNumber = switch ($TierName) {
                    'Tier0' { 0 }
                    'Tier1' { 1 }
                    'Tier2' { 2 }
                    default { 9 }
                }
                
                New-ADFineGrainedPasswordPolicy -Name $psoName `
                    -Precedence (10 + $tierNumber) `
                    -MinPasswordLength $MinPasswordLength `
                    -PasswordHistoryCount $PasswordHistoryCount `
                    -MaxPasswordAge (New-TimeSpan -Days $MaxPasswordAge) `
                    -MinPasswordAge (New-TimeSpan -Days $MinPasswordAge) `
                    -LockoutThreshold $LockoutThreshold `
                    -LockoutDuration (New-TimeSpan -Minutes 30) `
                    -ComplexityEnabled $true `
                    -ReversibleEncryptionEnabled $false `
                    -Description "Enhanced password policy for $TierName administrators"

                # Apply to admin group
                $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
                $group = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction Stop
                if ($group) {
                    Add-ADFineGrainedPasswordPolicySubject -Identity $psoName -Subjects $group
                    Write-TierLog -Message "Created password policy: $psoName" -Level Success -Component 'PasswordPolicy'
                }
                else {
                    Write-Warning "Admin group not found: $groupName. Policy created but not applied."
                }
            }
            else {
                Write-Warning "Password policy already exists: $psoName"
            }
        }
        catch {
            Write-TierLog -Message "Failed to create password policy: $_" -Level Error -Component 'PasswordPolicy'
            throw
        }
    }
}

#endregion

#region GPO Security Configuration

function Set-ADTierLogonRestrictions {
    <#
    .SYNOPSIS
        Configures logon restrictions in GPO to enforce tier separation.

    .DESCRIPTION
        Implements user rights assignments to prevent cross-tier authentication.
        Enforces the principle: credentials only flow downward, authentication never flows down.

        IMPORTANT: This function restricts BOTH custom tier groups AND built-in privileged
        groups (Domain Admins, Enterprise Admins, Schema Admins, etc.) per Microsoft ESAE
        best practices. Built-in Tier 0 groups must never authenticate to lower-tier systems.

    .PARAMETER TierName
        The tier to configure logon restrictions for.

    .PARAMETER GPOName
        The name of the GPO to configure.

    .PARAMETER IncludeBuiltInGroups
        Include built-in privileged groups (Domain Admins, Enterprise Admins, etc.) in
        logon restrictions. Default is $true per Microsoft best practices.

    .EXAMPLE
        Set-ADTierLogonRestrictions -TierName Tier0 -GPOName "SEC-Tier0-LogonRestrictions"

    .EXAMPLE
        Set-ADTierLogonRestrictions -TierName Tier2 -GPOName "SEC-Tier2-LogonRestrictions" -IncludeBuiltInGroups $true

    .NOTES
        This function enforces:
        - Tier 0 accounts (including Domain Admins, Enterprise Admins) can ONLY log onto Tier 0 systems
        - Tier 1 accounts can ONLY log onto Tier 1 systems (not Tier 0 or Tier 2)
        - Tier 2 accounts can ONLY log onto Tier 2 systems

        Built-in groups protected as Tier 0:
        - Domain Admins, Enterprise Admins, Schema Admins
        - Administrators (domain), Account Operators
        - Backup Operators, Server Operators, Print Operators
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,

        [Parameter(Mandatory)]
        [string]$GPOName,

        [bool]$IncludeBuiltInGroups = $true
    )

    try {
        $domainDN = Get-ADDomainRootDN
        $domain = (Get-ADDomain).DNSRoot
        $netbiosDomain = (Get-ADDomain).NetBIOSName

        Write-Verbose "Configuring logon restrictions for $TierName in GPO: $GPOName"

        # Built-in Tier 0 privileged groups that must be protected
        # These groups have domain-wide administrative privileges and are inherently Tier 0
        $builtInTier0Groups = @(
            "$netbiosDomain\Domain Admins",
            "$netbiosDomain\Enterprise Admins",
            "$netbiosDomain\Schema Admins",
            "$netbiosDomain\Administrators",
            "$netbiosDomain\Account Operators",
            "$netbiosDomain\Backup Operators",
            "$netbiosDomain\Server Operators",
            "$netbiosDomain\Print Operators"
        )

        # Define groups to restrict based on tier
        $restrictionConfig = switch ($TierName) {
            'Tier0' {
                # Tier 0: Deny Tier 1 and Tier 2 admin accounts from logging on
                # Built-in groups are allowed on Tier 0 (they belong here)
                @{
                    DenyInteractiveLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                    DenyNetworkLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                    DenyRemoteInteractiveLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                    DenyBatchLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                    DenyServiceLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                }
            }
            'Tier1' {
                # Tier 1: Deny Tier 0 accounts (prevents credential exposure) and Tier 2 accounts (prevents lateral movement)
                # Include built-in Tier 0 groups to prevent Domain Admins from logging onto servers
                $tier0Groups = @("$netbiosDomain\Tier0-Admins")
                $tier2Groups = @("$netbiosDomain\Tier2-Admins")

                if ($IncludeBuiltInGroups) {
                    $tier0Groups += $builtInTier0Groups
                }

                $denyGroups = $tier0Groups + $tier2Groups

                @{
                    DenyInteractiveLogon = $denyGroups
                    DenyNetworkLogon = $denyGroups
                    DenyRemoteInteractiveLogon = $denyGroups
                    DenyBatchLogon = $denyGroups
                    DenyServiceLogon = $denyGroups
                }
            }
            'Tier2' {
                # Tier 2: Deny ALL Tier 0 and Tier 1 accounts (no high-privilege credentials on workstations)
                # Include built-in Tier 0 groups to prevent Domain Admins from logging onto workstations
                $tier0Groups = @("$netbiosDomain\Tier0-Admins")
                $tier1Groups = @("$netbiosDomain\Tier1-Admins")

                if ($IncludeBuiltInGroups) {
                    $tier0Groups += $builtInTier0Groups
                }

                $denyGroups = $tier0Groups + $tier1Groups

                @{
                    DenyInteractiveLogon = $denyGroups
                    DenyNetworkLogon = $denyGroups
                    DenyRemoteInteractiveLogon = $denyGroups
                    DenyBatchLogon = $denyGroups
                    DenyServiceLogon = $denyGroups
                }
            }
        }

        # Log the groups being restricted
        if ($IncludeBuiltInGroups -and $TierName -ne 'Tier0') {
            Write-Verbose "Including built-in Tier 0 groups in restrictions: $($builtInTier0Groups -join ', ')"
            Write-TierLog -Message "Configuring $TierName with built-in group restrictions (Domain Admins, Enterprise Admins, etc.)" -Level Info -Component 'GPO'
        }
        
        if ($PSCmdlet.ShouldProcess($GPOName, "Configure Logon Restrictions")) {
            
            # Configure Deny Interactive Logon (console/keyboard)
            if ($restrictionConfig.DenyInteractiveLogon) {
                Set-GPOUserRight -GPOName $GPOName `
                    -UserRight "SeDenyInteractiveLogonRight" `
                    -Identity $restrictionConfig.DenyInteractiveLogon
                
                Write-Verbose "Configured Deny Interactive Logon for: $($restrictionConfig.DenyInteractiveLogon -join ', ')"
            }
            
            # Configure Deny Network Logon (SMB, network shares)
            if ($restrictionConfig.DenyNetworkLogon) {
                Set-GPOUserRight -GPOName $GPOName `
                    -UserRight "SeDenyNetworkLogonRight" `
                    -Identity $restrictionConfig.DenyNetworkLogon
                
                Write-Verbose "Configured Deny Network Logon for: $($restrictionConfig.DenyNetworkLogon -join ', ')"
            }
            
            # Configure Deny Remote Interactive Logon (RDP)
            if ($restrictionConfig.DenyRemoteInteractiveLogon) {
                Set-GPOUserRight -GPOName $GPOName `
                    -UserRight "SeDenyRemoteInteractiveLogonRight" `
                    -Identity $restrictionConfig.DenyRemoteInteractiveLogon
                
                Write-Verbose "Configured Deny Remote Interactive Logon for: $($restrictionConfig.DenyRemoteInteractiveLogon -join ', ')"
            }
            
            # Configure Deny Batch Logon (scheduled tasks)
            if ($restrictionConfig.DenyBatchLogon) {
                Set-GPOUserRight -GPOName $GPOName `
                    -UserRight "SeDenyBatchLogonRight" `
                    -Identity $restrictionConfig.DenyBatchLogon
                
                Write-Verbose "Configured Deny Batch Logon for: $($restrictionConfig.DenyBatchLogon -join ', ')"
            }
            
            # Configure Deny Service Logon (Windows services)
            if ($restrictionConfig.DenyServiceLogon) {
                Set-GPOUserRight -GPOName $GPOName `
                    -UserRight "SeDenyServiceLogonRight" `
                    -Identity $restrictionConfig.DenyServiceLogon
                
                Write-Verbose "Configured Deny Service Logon for: $($restrictionConfig.DenyServiceLogon -join ', ')"
            }
            
            Write-TierLog -Message "Configured logon restrictions for $TierName" -Level Success -Component 'GPO'
            Write-Host "Successfully configured logon restrictions for $TierName" -ForegroundColor Green
        }
    }
    catch {
        Write-TierLog -Message "Failed to configure logon restrictions: $_" -Level Error -Component 'GPO'
        throw
    }
}

function Set-GPOUserRight {
    <#
    .SYNOPSIS
        Sets a user right assignment in a Group Policy Object.
    
    .DESCRIPTION
        Configures user rights assignments using secedit and GPO registry settings.
        This is a helper function for configuring security policies.
    
    .PARAMETER GPOName
        The name of the GPO to configure.
    
    .PARAMETER UserRight
        The user right constant (e.g., SeDenyInteractiveLogonRight).
    
    .PARAMETER Identity
        Array of security principals (groups or users) to assign the right to.
    
    .EXAMPLE
        Set-GPOUserRight -GPOName "SEC-Tier0-LogonRestrictions" -UserRight "SeDenyInteractiveLogonRight" -Identity @("CONTOSO\Tier1-Admins")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,
        
        [Parameter(Mandatory)]
        [string]$UserRight,
        
        [Parameter(Mandatory)]
        [string[]]$Identity
    )

    # Guard: Ensure GroupPolicy module is available
    if (-not (Test-GroupPolicyModuleAvailable)) {
        throw "GroupPolicy module not available. Install RSAT tools to use GPO functions."
    }

    try {
        # Get GPO GUID
        $gpo = Get-GPO -Name $GPOName
        $gpoGuid = $gpo.Id.ToString('B').ToUpper()
        $domain = (Get-ADDomain).DNSRoot
        $sysvol = "\\$domain\SYSVOL\$domain\Policies\$gpoGuid\Machine\Microsoft\Windows NT\SecEdit"
        
        # Create directory if it doesn't exist
        if (-not (Test-Path $sysvol)) {
            New-Item -Path $sysvol -ItemType Directory -Force | Out-Null
        }
        
        # Convert identity to SIDs
        $sids = @()
        foreach ($id in $Identity) {
            # Remove domain prefix if present
            $accountName = $id -replace '^.*\\', ''
            $account = $null

            foreach ($resolver in @(
                { Get-ADGroup -Identity $accountName -ErrorAction Stop },
                { Get-ADUser -Identity $accountName -ErrorAction Stop },
                { Get-ADObject -Identity $id -Properties objectSid -ErrorAction Stop }
            )) {
                try {
                    $account = & $resolver
                    break
                }
                catch {
                    continue
                }
            }

            if (-not $account) {
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($id)
                    $sids += "*$sid"
                    continue
                }
                catch {
                    Write-Warning "Could not resolve identity: $id"
                    continue
                }
            }

            $sidValue = if ($account.PSObject.Properties['SID']) { $account.SID.Value } else { $account.objectSid.Value }
            if ($sidValue) {
                $sids += "*$sidValue"
            }
            else {
                Write-Warning "Could not resolve SID for identity: $id"
            }
        }
        
        if ($sids.Count -eq 0) {
            Write-Warning "No valid identities found for $UserRight"
            return
        }

        # Build settings for merge
        $infPath = "$sysvol\GptTmpl.inf"
        $sidString = $sids -join ','

        # Create backup before modification
        Backup-GptTmplFile -GptTmplPath $infPath | Out-Null

        # Use merge function to preserve existing settings
        $newSettings = @{
            'Privilege Rights' = @{
                $UserRight = $sidString
            }
        }

        $mergedContent = Merge-GptTmplContent -GptTmplPath $infPath -NewSettings $newSettings

        # Write merged INF file
        $mergedContent | Out-File -FilePath $infPath -Encoding Unicode -Force

        # Increment GPO version to trigger replication
        Update-GPOVersion -GPOGuid $gpo.Id

        Write-Verbose "Configured $UserRight for: $($Identity -join ', ')"
    }
    catch {
        Write-Error "Failed to set user right: $_"
        throw
    }
}

function Get-ADTierLogonRestrictions {
    <#
    .SYNOPSIS
        Retrieves configured logon restrictions for tiers.
    
    .DESCRIPTION
        Returns the current logon restriction policies configured in tier GPOs.
    
    .PARAMETER TierName
        Optional tier name to filter results.
    
    .EXAMPLE
        Get-ADTierLogonRestrictions
    
    .EXAMPLE
        Get-ADTierLogonRestrictions -TierName Tier0
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName
    )

    # Guard: Ensure GroupPolicy module is available
    if (-not (Test-GroupPolicyModuleAvailable)) {
        Write-Warning "GroupPolicy module not available. Returning empty results."
        return @()
    }

    $tiers = if ($TierName) { @($TierName) } else { @('Tier0', 'Tier1', 'Tier2') }
    $results = @()

    foreach ($tier in $tiers) {
        $gpoName = "SEC-$tier-LogonRestrictions"

        try {
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            
            if ($gpo) {
                $results += [PSCustomObject]@{
                    TierName = $tier
                    GPOName = $gpoName
                    GPOStatus = $gpo.GpoStatus
                    Created = $gpo.CreationTime
                    Modified = $gpo.ModificationTime
                    LinksEnabled = $gpo.LinksEnabled
                }
            }
        }
        catch {
            Write-Verbose "GPO not found: $gpoName"
        }
    }
    
    return $results
}

function Test-ADTierLogonRestrictions {
    <#
    .SYNOPSIS
        Tests whether logon restrictions are properly configured.
    
    .DESCRIPTION
        Validates that each tier has appropriate logon restriction GPOs in place
        and that they are correctly linked and enforced.
    
    .EXAMPLE
        Test-ADTierLogonRestrictions
    
    .OUTPUTS
        Returns a compliance report indicating whether restrictions are properly configured.
    #>
    [CmdletBinding()]
    param()

    # Guard: Ensure GroupPolicy module is available
    if (-not (Test-GroupPolicyModuleAvailable)) {
        Write-Warning "GroupPolicy module not available. Returning non-compliant status."
        return @{
            Compliant = $false
            Findings = @("GroupPolicy module not available - cannot verify logon restrictions")
            TierStatus = @{}
        }
    }

    $results = @{
        Compliant = $true
        Findings = @()
        TierStatus = @{}
    }

    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $gpoName = "SEC-$tierKey-LogonRestrictions"
        $domainDN = Get-ADDomainRootDN
        $ouPath = "$($script:TierConfiguration[$tierKey].OUPath),$domainDN"

        # Check if GPO exists
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        
        if (-not $gpo) {
            $results.Compliant = $false
            $results.Findings += "Missing logon restrictions GPO for $tierKey"
            $results.TierStatus[$tierKey] = "Non-Compliant"
            continue
        }
        
        # Check if GPO is linked to tier OU
        $links = Get-GPOLinks -GPOName $gpoName
        $isLinked = $links | Where-Object { $_.Target -eq $ouPath -and $_.Enabled }
        
        if (-not $isLinked) {
            $results.Compliant = $false
            $results.Findings += "GPO $gpoName not linked to $ouPath"
            $results.TierStatus[$tierKey] = "Non-Compliant"
            continue
        }
        
        $results.TierStatus[$tierKey] = "Compliant"
    }
    
    return [PSCustomObject]$results
}

function Get-GPOLinks {
    <#
    .SYNOPSIS
        Helper function to retrieve GPO links.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName
    )

    # Guard: Ensure GroupPolicy module is available
    if (-not (Test-GroupPolicyModuleAvailable)) {
        Write-Warning "GroupPolicy module not available. Returning empty results."
        return @()
    }

    try {
        $gpo = Get-GPO -Name $GPOName
        $report = [xml](Get-GPOReport -Name $GPOName -ReportType Xml)
        
        $links = $report.GPO.LinksTo | ForEach-Object {
            [PSCustomObject]@{
                Target = $_.SOMPath
                Enabled = $_.Enabled -eq 'true'
                NoOverride = $_.NoOverride -eq 'true'
            }
        }
        
        return $links
    }
    catch {
        return @()
    }
}

#endregion

#region Admin Account Management

function New-ADTierAdminAccount {
    <#
    .SYNOPSIS
        Creates a new administrative account for a specific tier.
    
    .DESCRIPTION
        Creates a properly configured admin account with appropriate security settings,
        places it in the correct OU, assigns it to the appropriate admin group, and
        configures lockout protection.
    
    .PARAMETER Username
        The username for the admin account (e.g., "john.doe-t0").
    
    .PARAMETER TierName
        The tier this admin account belongs to (Tier0, Tier1, or Tier2).
    
    .PARAMETER FirstName
        User's first name.
    
    .PARAMETER LastName
        User's last name.
    
    .PARAMETER Description
        Optional description for the account.
    
    .PARAMETER PreventDelegation
        If specified, sets AccountNotDelegated flag preventing Kerberos delegation.
        Note: This does NOT prevent account lockout - consider Protected Users group for that.
    
    .PARAMETER Email
        Email address for the account.
    
    .EXAMPLE
        New-ADTierAdminAccount -Username "john.doe-t0" -TierName Tier0 -FirstName "John" -LastName "Doe" -Email "john.doe@contoso.com"
    
    .NOTES
        The account will be:
        - Created in the Users OU of the specified tier
        - Added to the TierX-Admins group
        - Configured with strong password requirements
        - Optionally protected from Kerberos delegation
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Username,
        
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [Parameter(Mandatory)]
        [string]$FirstName,
        
        [Parameter(Mandatory)]
        [string]$LastName,
        
        [string]$Description,
        
        [Alias('NoLockout')]  # Backward compatibility alias
        [switch]$PreventDelegation,
        
        [string]$Email
    )
    
    begin {
        Write-TierLog -Message "Creating admin account: $Username for $TierName" -Level Info -Component 'AccountManagement'
        $domainDN = Get-ADDomainRootDN
    }
    
    process {
        try {
            # Verify tier configuration exists
            if (-not $script:TierConfiguration.ContainsKey($TierName)) {
                throw "Invalid tier name: $TierName"
            }
            
            $tierConfig = $script:TierConfiguration[$TierName]
            $usersOU = "OU=Users,$($tierConfig.OUPath),$domainDN"
            
            # Verify OU exists
            if (-not (Test-ADTierOUExists -OUPath $usersOU)) {
                throw "Users OU does not exist: $usersOU. Run Initialize-ADTierModel -CreateOUStructure first."
            }

            # Check if account already exists
            $escapedUsername = Get-EscapedADFilterValue -Value $Username
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$escapedUsername'" -ErrorAction SilentlyContinue
            if ($existingUser) {
                throw "User account already exists: $Username"
            }
            
            if ($PSCmdlet.ShouldProcess($Username, "Create Tier Admin Account")) {

                # Generate secure random password
                Add-Type -AssemblyName System.Web
                $password = [System.Web.Security.Membership]::GeneratePassword(24, 8)
                $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

                # Build description
                if (-not $Description) {
                    $Description = "$($tierConfig.Name) Administrator Account"
                }

                # Create account parameters
                $userParams = @{
                    Name = "$FirstName $LastName ($TierName)"
                    GivenName = $FirstName
                    Surname = $LastName
                    SamAccountName = $Username
                    UserPrincipalName = "$Username@$(Get-ADDomain | Select-Object -ExpandProperty DNSRoot)"
                    Path = $usersOU
                    AccountPassword = $securePassword
                    Enabled = $true
                    ChangePasswordAtLogon = $true
                    PasswordNeverExpires = $false
                    CannotChangePassword = $false
                    Description = $Description
                }

                if ($Email) {
                    $userParams['EmailAddress'] = $Email
                }

                # Create the user account
                New-ADUser @userParams
                Write-TierLog -Message "Created user account: $Username" -Level Success -Component 'AccountManagement'

                # Add to tier admin group
                $adminGroup = "$TierName-Admins"

                # Validate group exists before adding member
                if (-not (Test-ADGroupExists -GroupName $adminGroup)) {
                    throw "Admin group '$adminGroup' does not exist. Run Initialize-ADTierModel -CreateGroups first."
                }

                Add-ADGroupMember -Identity $adminGroup -Members $Username -ErrorAction Stop
                Write-TierLog -Message "Added $Username to $adminGroup" -Level Success -Component 'AccountManagement'

                # Configure AccountNotDelegated if requested
                # NOTE: This does NOT prevent lockout - it prevents Kerberos delegation
                if ($PreventDelegation) {
                    Set-ADAccountControl -Identity $Username -AccountNotDelegated $true
                    Write-TierLog -Message "Set AccountNotDelegated flag for $Username" -Level Info -Component 'AccountManagement'
                    Write-Warning "AccountNotDelegated flag set. NOTE: This prevents Kerberos delegation but does NOT prevent account lockout."
                    Write-Warning "For lockout protection, use Fine-Grained Password Policy or Protected Users group."
                }

                # Set account as sensitive and cannot be delegated (for Tier 0)
                if ($TierName -eq 'Tier0') {
                    Set-ADAccountControl -Identity $Username -AccountNotDelegated $true
                    Write-TierLog -Message "Set AccountNotDelegated flag for Tier 0 account: $Username" -Level Info -Component 'AccountManagement'
                }

                # Output account details - SECURITY: Do not include password in output object
                # Password is returned separately via SecureString for secure handling
                $accountInfo = [PSCustomObject]@{
                    Username = $Username
                    TierName = $TierName
                    FullName = "$FirstName $LastName"
                    Email = $Email
                    OUPath = $usersOU
                    AdminGroup = $adminGroup
                    InitialPasswordSecure = $securePassword  # SecureString, not plain text
                    MustChangePassword = $true
                    AccountNotDelegated = ($PreventDelegation -or $TierName -eq 'Tier0')
                    Created = Get-Date
                }

                Write-Host "`n=== Admin Account Created Successfully ===" -ForegroundColor Green
                Write-Host "Username: $Username" -ForegroundColor Cyan
                Write-Host "Tier: $TierName" -ForegroundColor Cyan
                Write-Host "Admin Group: $adminGroup" -ForegroundColor Cyan
                Write-Host "`nSECURITY NOTICE:" -ForegroundColor Red
                Write-Host "The initial password is stored in the returned object as 'InitialPasswordSecure' (SecureString)." -ForegroundColor Yellow
                Write-Host "To retrieve it once for secure delivery to the user:" -ForegroundColor Yellow
                Write-Host '  $cred = New-Object PSCredential("temp", $result.InitialPasswordSecure)' -ForegroundColor Cyan
                Write-Host '  $cred.GetNetworkCredential().Password' -ForegroundColor Cyan
                Write-Host "User must change password at first logon." -ForegroundColor Yellow

                return $accountInfo
            }
        }
        catch {
            Write-TierLog -Message "Failed to create admin account: $_" -Level Error -Component 'AccountManagement'
            throw
        }
    }
}

function Set-ADTierAccountLockoutProtection {
    <#
    .SYNOPSIS
        Configures the "Account is sensitive and cannot be delegated" flag for tier administrative accounts.

    .DESCRIPTION
        Sets the AccountNotDelegated flag on administrative accounts to prevent Kerberos delegation.
        This is a SECURITY setting that prevents credential delegation attacks, NOT lockout protection.

        IMPORTANT: This function does NOT prevent account lockout from failed password attempts.
        To truly prevent lockout, you must use one of these approaches:
        1. Fine-Grained Password Policy (FGPP) with lockout threshold of 0
        2. Add account to Protected Users group (preferred for Tier 0)
        3. Configure domain lockout policy (affects all accounts)

        The AccountNotDelegated flag:
        - Prevents the account's credentials from being forwarded via Kerberos delegation
        - Helps protect against Pass-the-Ticket and credential forwarding attacks
        - Is recommended for all Tier 0 administrative accounts

    .PARAMETER Identity
        The user account to configure.

    .PARAMETER Enable
        Enable the "sensitive account" flag (prevents delegation).

    .PARAMETER Disable
        Disable the "sensitive account" flag (allows delegation).

    .EXAMPLE
        Set-ADTierAccountLockoutProtection -Identity "admin-t0" -Enable

        Sets the AccountNotDelegated flag on the admin-t0 account.

    .NOTES
        This function is named for backwards compatibility but primarily configures
        delegation protection, not lockout protection. For true lockout protection,
        use Fine-Grained Password Policies or the Protected Users group.

        Recommended for:
        - Tier 0 administrative accounts
        - Break-glass emergency accounts
        - Accounts that should never have their credentials delegated
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Identity,

        [switch]$Enable,
        [switch]$Disable
    )

    process {
        try {
            $user = Get-ADUser -Identity $Identity -Properties MemberOf -ErrorAction Stop

            if ($PSCmdlet.ShouldProcess($Identity, "Configure AccountNotDelegated flag")) {
                if ($Disable) {
                    # Remove sensitive account flag (allows delegation)
                    Set-ADAccountControl -Identity $Identity -AccountNotDelegated $false
                    Write-TierLog -Message "Cleared AccountNotDelegated flag for $Identity" -Level Info -Component 'AccountManagement'
                    Write-Host "AccountNotDelegated flag cleared for: $Identity" -ForegroundColor Green
                    Write-Warning "This account can now have credentials delegated via Kerberos. This is not recommended for Tier 0 accounts."
                }
                else {
                    # Enable sensitive account flag (prevents delegation)
                    Set-ADAccountControl -Identity $Identity -AccountNotDelegated $true
                    Write-TierLog -Message "Set AccountNotDelegated flag for $Identity" -Level Info -Component 'AccountManagement'
                    Write-Host "AccountNotDelegated flag set for: $Identity" -ForegroundColor Green
                    Write-Host "This account's credentials cannot be delegated via Kerberos." -ForegroundColor Cyan

                    # Check if user is in Protected Users group and provide guidance
                    $protectedUsersGroup = Get-ADGroup -Identity 'Protected Users' -ErrorAction SilentlyContinue
                    $inProtectedUsers = $false
                    if ($protectedUsersGroup -and $user.MemberOf) {
                        $inProtectedUsers = $user.MemberOf -contains $protectedUsersGroup.DistinguishedName
                    }

                    if (-not $inProtectedUsers) {
                        Write-Host "`nRECOMMENDATION: For full protection of Tier 0 accounts, also add to Protected Users group:" -ForegroundColor Yellow
                        Write-Host "  Add-ADGroupMember -Identity 'Protected Users' -Members '$Identity'" -ForegroundColor Yellow
                    }
                }
            }
        }
        catch {
            Write-TierLog -Message "Failed to configure AccountNotDelegated: $_" -Level Error -Component 'AccountManagement'
            throw
        }
    }
}

function Get-ADTierAdminAccount {
    <#
    .SYNOPSIS
        Retrieves tier administrative accounts.
    
    .DESCRIPTION
        Lists all administrative accounts for a specific tier or all tiers.
    
    .PARAMETER TierName
        Filter by specific tier. If not specified, returns all tier admin accounts.
    
    .PARAMETER IncludeDetails
        Include detailed information about account status and group membership.
    
    .EXAMPLE
        Get-ADTierAdminAccount -TierName Tier0 -IncludeDetails
    
    .EXAMPLE
        Get-ADTierAdminAccount | Where-Object { $_.Enabled -eq $false }
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Tier0', 'Tier1', 'Tier2', 'All')]
        [string]$TierName = 'All',
        
        [switch]$IncludeDetails
    )
    
    try {
        $domainDN = Get-ADDomainRootDN
        $results = @()
        
        $tiersToCheck = if ($TierName -eq 'All') {
            $script:TierConfiguration.Keys
        } else {
            @($TierName)
        }
        
        foreach ($tier in $tiersToCheck) {
            $tierConfig = $script:TierConfiguration[$tier]
            $usersOU = "OU=Users,$($tierConfig.OUPath),$domainDN"
            
            if (Test-ADTierOUExists -OUPath $usersOU) {
                $users = Get-ADUser -Filter * -SearchBase $usersOU -Properties Enabled, Created, LastLogonDate, PasswordLastSet, AccountNotDelegated, MemberOf
                
                foreach ($user in $users) {
                    $accountInfo = [PSCustomObject]@{
                        Username = $user.SamAccountName
                        TierName = $tier
                        FullName = $user.Name
                        Enabled = $user.Enabled
                        Created = $user.Created
                        LastLogon = $user.LastLogonDate
                        PasswordLastSet = $user.PasswordLastSet
                        LockoutProtection = $user.AccountNotDelegated
                        DistinguishedName = $user.DistinguishedName
                    }
                    
                    if ($IncludeDetails) {
                        $groups = $user.MemberOf | ForEach-Object {
                            $grp = Get-ADGroup -Identity $_ -ErrorAction SilentlyContinue
                            if ($grp) { $grp.Name }
                        } | Where-Object { $_ }
                        $accountInfo | Add-Member -NotePropertyName 'Groups' -NotePropertyValue ($groups -join ', ')
                    }
                    
                    $results += $accountInfo
                }
            }
        }
        
        return $results
    }
    catch {
        Write-TierLog -Message "Failed to retrieve admin accounts: $_" -Level Error -Component 'AccountManagement'
        throw
    }
}

#endregion

#region Enhanced Security Policies

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

#endregion

#region New Functions from Rust Port

# LDAP Matching Rule OID for transitive group membership (nested groups)
$script:LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'

# Well-known RIDs for primary group resolution
$script:WellKnownRIDs = @{
    512 = 'Domain Admins'
    513 = 'Domain Users'
    514 = 'Domain Guests'
    515 = 'Domain Computers'
    516 = 'Domain Controllers'
    517 = 'Cert Publishers'
    518 = 'Schema Admins'
    519 = 'Enterprise Admins'
    520 = 'Group Policy Creator Owners'
    521 = 'Read-only Domain Controllers'
    522 = 'Cloneable Domain Controllers'
    553 = 'RAS and IAS Servers'
    571 = 'Allowed RODC Password Replication Group'
    572 = 'Denied RODC Password Replication Group'
}

function Get-ADTierCounts {
    <#
    .SYNOPSIS
        Gets the count of objects in each tier.

    .DESCRIPTION
        Returns the count of users, computers, and groups in each tier OU,
        plus a count of unassigned objects not in any tier.

    .EXAMPLE
        Get-ADTierCounts

        Returns:
        Tier0      : 15
        Tier1      : 127
        Tier2      : 892
        Unassigned : 45

    .OUTPUTS
        PSCustomObject with Tier0, Tier1, Tier2, and Unassigned counts.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-TierLog -Message "Getting tier counts" -Level Info -Component 'TierManagement'
    }

    process {
        $domainDN = Get-ADDomainRootDN
        $counts = @{
            Tier0 = 0
            Tier1 = 0
            Tier2 = 0
            Unassigned = 0
        }

        # Count objects in each tier OU
        foreach ($tierKey in @('Tier0', 'Tier1', 'Tier2')) {
            $tier = $script:TierConfiguration[$tierKey]
            $ouPath = "$($tier.OUPath),$domainDN"

            if (Test-ADTierOUExists -OUPath $ouPath) {
                try {
                    $objects = Get-ADObject -SearchBase $ouPath -SearchScope Subtree -Filter {
                        (objectClass -eq 'user') -or (objectClass -eq 'computer') -or (objectClass -eq 'group')
                    } -ErrorAction Stop
                    $counts[$tierKey] = @($objects).Count
                }
                catch {
                    Write-Warning "Failed to count objects in $tierKey : $_"
                    $counts[$tierKey] = 0
                }
            }
        }

        # Count unassigned objects (not in any tier OU)
        try {
            $allObjects = Get-ADObject -SearchBase $domainDN -SearchScope Subtree -Filter {
                (objectClass -eq 'user') -or (objectClass -eq 'computer') -or (objectClass -eq 'group')
            } -ErrorAction Stop

            $tierOUPatterns = @(
                "OU=Tier0,$domainDN",
                "OU=Tier1,$domainDN",
                "OU=Tier2,$domainDN"
            )

            $unassignedCount = 0
            foreach ($obj in $allObjects) {
                $inTier = $false
                foreach ($pattern in $tierOUPatterns) {
                    if ($obj.DistinguishedName -like "*$pattern*") {
                        $inTier = $true
                        break
                    }
                }
                if (-not $inTier) {
                    $unassignedCount++
                }
            }
            $counts.Unassigned = $unassignedCount
        }
        catch {
            Write-Warning "Failed to count unassigned objects: $_"
        }

        Write-TierLog -Message "Tier counts: Tier0=$($counts.Tier0), Tier1=$($counts.Tier1), Tier2=$($counts.Tier2), Unassigned=$($counts.Unassigned)" -Level Info -Component 'TierManagement'

        [PSCustomObject]$counts
    }
}

function Get-ADFSMORoleHolders {
    <#
    .SYNOPSIS
        Discovers all 5 FSMO role holders as Tier 0 infrastructure.

    .DESCRIPTION
        Queries Active Directory to identify all FSMO (Flexible Single Master Operations)
        role holders. These servers are critical Tier 0 infrastructure components.

        FSMO Roles discovered:
        - Schema Master (Forest-level)
        - Domain Naming Master (Forest-level)
        - RID Master (Domain-level)
        - PDC Emulator (Domain-level)
        - Infrastructure Master (Domain-level)

    .EXAMPLE
        Get-ADFSMORoleHolders

        Returns FSMO role holder information as Tier0Component objects.

    .OUTPUTS
        Array of PSCustomObject representing FSMO role holders.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    begin {
        Write-TierLog -Message "Discovering FSMO role holders" -Level Info -Component 'Discovery'
    }

    process {
        $fsmoComponents = @()

        try {
            # Get domain and forest information
            $domain = Get-ADDomain -ErrorAction Stop
            $forest = Get-ADForest -ErrorAction Stop

            # Domain-level FSMO roles
            $domainRoles = @{
                'PDC Emulator' = $domain.PDCEmulator
                'RID Master' = $domain.RIDMaster
                'Infrastructure Master' = $domain.InfrastructureMaster
            }

            # Forest-level FSMO roles
            $forestRoles = @{
                'Schema Master' = $forest.SchemaMaster
                'Domain Naming Master' = $forest.DomainNamingMaster
            }

            # Process domain roles
            foreach ($roleName in $domainRoles.Keys) {
                $serverFQDN = $domainRoles[$roleName]
                if ($serverFQDN) {
                    $serverName = $serverFQDN.Split('.')[0]

                    try {
                        $computer = Get-ADComputer -Identity $serverName -Properties OperatingSystem, Description, LastLogonTimestamp -ErrorAction SilentlyContinue

                        $fsmoComponents += [PSCustomObject]@{
                            Name = "$serverName ($roleName)"
                            RoleType = $roleName -replace ' ', ''
                            OperatingSystem = $computer.OperatingSystem
                            LastLogon = if ($computer.LastLogonTimestamp) {
                                [DateTime]::FromFileTime($computer.LastLogonTimestamp).ToString('yyyy-MM-ddTHH:mm:ssZ')
                            } else { $null }
                            CurrentOU = ($computer.DistinguishedName -split ',', 2)[1]
                            IsInTier0 = $computer.DistinguishedName -like '*OU=Domain Controllers*'
                            DistinguishedName = $computer.DistinguishedName
                            Description = "FSMO Role: $roleName"
                        }
                    }
                    catch {
                        Write-Verbose "Could not get details for $serverName : $_"
                    }
                }
            }

            # Process forest roles
            foreach ($roleName in $forestRoles.Keys) {
                $serverFQDN = $forestRoles[$roleName]
                if ($serverFQDN) {
                    $serverName = $serverFQDN.Split('.')[0]

                    # Check if already added (could be same DC)
                    if ($fsmoComponents.Name -notcontains "$serverName ($roleName)") {
                        try {
                            $computer = Get-ADComputer -Identity $serverName -Properties OperatingSystem, Description, LastLogonTimestamp -ErrorAction SilentlyContinue

                            $fsmoComponents += [PSCustomObject]@{
                                Name = "$serverName ($roleName)"
                                RoleType = $roleName -replace ' ', ''
                                OperatingSystem = $computer.OperatingSystem
                                LastLogon = if ($computer.LastLogonTimestamp) {
                                    [DateTime]::FromFileTime($computer.LastLogonTimestamp).ToString('yyyy-MM-ddTHH:mm:ssZ')
                                } else { $null }
                                CurrentOU = ($computer.DistinguishedName -split ',', 2)[1]
                                IsInTier0 = $computer.DistinguishedName -like '*OU=Domain Controllers*'
                                DistinguishedName = $computer.DistinguishedName
                                Description = "FSMO Role: $roleName"
                            }
                        }
                        catch {
                            Write-Verbose "Could not get details for $serverName : $_"
                        }
                    }
                }
            }

            Write-TierLog -Message "Found $($fsmoComponents.Count) FSMO role holders" -Level Success -Component 'Discovery'
        }
        catch {
            Write-TierLog -Message "Failed to discover FSMO roles: $_" -Level Error -Component 'Discovery'
            throw
        }

        $fsmoComponents
    }
}

function Test-ADConnection {
    <#
    .SYNOPSIS
        Comprehensive AD connection testing with step-by-step diagnostics.

    .DESCRIPTION
        Tests the connection to Active Directory and returns detailed diagnostic
        information about each step of the connection process. Useful for
        troubleshooting connectivity issues.

    .EXAMPLE
        Test-ADConnection

        Returns diagnostic information about AD connectivity.

    .OUTPUTS
        PSCustomObject with diagnostic information.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-TierLog -Message "Starting AD connection diagnostics" -Level Info -Component 'Diagnostics'
    }

    process {
        $diagnostics = [PSCustomObject]@{
            DomainDN = ''
            ModuleStatus = 'Not checked'
            DomainConnectivity = 'Not checked'
            LdapSearchStatus = 'Not checked'
            ObjectsFound = 0
            ErrorCode = $null
            ErrorMessage = $null
            StepsCompleted = [System.Collections.ArrayList]@()
            TierOUStatus = [System.Collections.ArrayList]@()
        }

        # Step 1: Check ActiveDirectory module
        $null = $diagnostics.StepsCompleted.Add("Checking ActiveDirectory module...")
        if (Get-Module -Name ActiveDirectory -ListAvailable) {
            $diagnostics.ModuleStatus = 'OK - Module available'
            $null = $diagnostics.StepsCompleted.Add("ActiveDirectory module: Available")
        }
        else {
            $diagnostics.ModuleStatus = 'FAILED - Module not found'
            $diagnostics.ErrorMessage = 'ActiveDirectory module not installed. Install RSAT tools.'
            $null = $diagnostics.StepsCompleted.Add("ActiveDirectory module: NOT FOUND")
            return $diagnostics
        }

        # Step 2: Test domain connectivity
        $null = $diagnostics.StepsCompleted.Add("Testing domain connectivity...")
        try {
            $domain = Get-ADDomain -ErrorAction Stop
            $diagnostics.DomainDN = $domain.DistinguishedName
            $diagnostics.DomainConnectivity = 'OK - Connected to ' + $domain.DNSRoot
            $null = $diagnostics.StepsCompleted.Add("Domain connectivity: OK ($($domain.DNSRoot))")
        }
        catch {
            $diagnostics.DomainConnectivity = 'FAILED'
            $diagnostics.ErrorMessage = "Cannot connect to domain: $_"
            $null = $diagnostics.StepsCompleted.Add("Domain connectivity: FAILED - $_")
            return $diagnostics
        }

        # Step 3: Test LDAP search
        $null = $diagnostics.StepsCompleted.Add("Testing LDAP search...")
        try {
            $testObjects = Get-ADObject -SearchBase $diagnostics.DomainDN -SearchScope Base -Filter * -ErrorAction Stop
            $diagnostics.ObjectsFound = @($testObjects).Count
            $diagnostics.LdapSearchStatus = "OK - Found $($diagnostics.ObjectsFound) object(s)"
            $null = $diagnostics.StepsCompleted.Add("LDAP search: OK")
        }
        catch {
            $diagnostics.LdapSearchStatus = 'FAILED'
            $diagnostics.ErrorMessage = "LDAP search failed: $_"
            $null = $diagnostics.StepsCompleted.Add("LDAP search: FAILED - $_")
        }

        # Step 4: Test Tier OU existence
        $null = $diagnostics.StepsCompleted.Add("Testing Tier OU existence...")
        foreach ($tierKey in @('Tier0', 'Tier1', 'Tier2')) {
            $tier = $script:TierConfiguration[$tierKey]
            $ouPath = "$($tier.OUPath),$($diagnostics.DomainDN)"

            $status = [PSCustomObject]@{
                Tier = $tierKey
                OUPath = $ouPath
                Exists = $false
                ObjectCount = 0
                Error = $null
            }

            try {
                if (Test-ADTierOUExists -OUPath $ouPath) {
                    $status.Exists = $true
                    $objects = Get-ADObject -SearchBase $ouPath -SearchScope Subtree -Filter * -ErrorAction SilentlyContinue
                    $status.ObjectCount = @($objects).Count
                }
            }
            catch {
                $status.Error = $_.Exception.Message
            }

            $null = $diagnostics.TierOUStatus.Add($status)
        }
        $null = $diagnostics.StepsCompleted.Add("Tier OU tests completed")

        Write-TierLog -Message "AD connection diagnostics completed" -Level Success -Component 'Diagnostics'
        $diagnostics
    }
}

function Get-ADTransitiveGroupMembership {
    <#
    .SYNOPSIS
        Gets all nested group memberships using LDAP_MATCHING_RULE_IN_CHAIN.

    .DESCRIPTION
        Uses the LDAP matching rule OID 1.2.840.113556.1.4.1941 to find all groups
        an object belongs to, including through nested group membership. This is
        significantly more efficient than recursive queries.

    .PARAMETER Identity
        The distinguished name, SID, GUID, or SAM account name of the object.

    .EXAMPLE
        Get-ADTransitiveGroupMembership -Identity 'john.doe'

        Returns all groups (direct and nested) that john.doe is a member of.

    .OUTPUTS
        Array of PSCustomObject representing group memberships.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('DistinguishedName', 'DN', 'SamAccountName')]
        [string]$Identity
    )

    begin {
        Write-TierLog -Message "Getting transitive group membership" -Level Info -Component 'GroupManagement'
    }

    process {
        $memberships = @()

        try {
            # Resolve identity to DN
            $adObject = Get-ADObject -Identity $Identity -Properties memberOf, primaryGroupID -ErrorAction Stop
            $objectDN = $adObject.DistinguishedName
            $domainDN = ($objectDN -split ',DC=' | Select-Object -Skip 1) -join ',DC='
            $domainDN = "DC=$domainDN"

            # Get direct memberOf
            $directGroups = @()
            if ($adObject.memberOf) {
                $directGroups = @($adObject.memberOf)
            }

            # Use LDAP_MATCHING_RULE_IN_CHAIN for transitive membership
            # Filter: (member:1.2.840.113556.1.4.1941:=<objectDN>)
            # Escape all LDAP special characters: \ * ( ) / NUL
            $escapedDN = $objectDN -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace '\/', '\2f' -replace '\x00', '\00'
            $filter = "(member:$($script:LDAP_MATCHING_RULE_IN_CHAIN):=$escapedDN)"

            $transitiveGroups = Get-ADGroup -LDAPFilter $filter -Properties GroupScope, GroupCategory -ErrorAction SilentlyContinue

            # Also resolve primary group
            if ($adObject.primaryGroupID) {
                $primaryGroup = Resolve-ADPrimaryGroup -PrimaryGroupID $adObject.primaryGroupID
                if ($primaryGroup) {
                    $memberships += $primaryGroup
                }
            }

            # Add all groups found
            $allGroupDNs = @()
            $allGroupDNs += $directGroups
            if ($transitiveGroups) {
                $allGroupDNs += $transitiveGroups.DistinguishedName
            }
            $allGroupDNs = $allGroupDNs | Select-Object -Unique

            foreach ($groupDN in $allGroupDNs) {
                try {
                    $group = Get-ADGroup -Identity $groupDN -Properties GroupScope, GroupCategory, Description -ErrorAction SilentlyContinue
                    if ($group) {
                        # Determine tier from group DN or name
                        $tier = $null
                        if ($groupDN -like '*OU=Tier0*' -or $group.Name -like 'Tier0-*') { $tier = 'Tier0' }
                        elseif ($groupDN -like '*OU=Tier1*' -or $group.Name -like 'Tier1-*') { $tier = 'Tier1' }
                        elseif ($groupDN -like '*OU=Tier2*' -or $group.Name -like 'Tier2-*') { $tier = 'Tier2' }

                        $memberships += [PSCustomObject]@{
                            GroupName = $group.Name
                            GroupDN = $group.DistinguishedName
                            Tier = $tier
                            GroupType = "$($group.GroupScope) $($group.GroupCategory)"
                            IsDirect = $directGroups -contains $groupDN
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not get group details for $groupDN : $_"
                }
            }

            Write-TierLog -Message "Found $($memberships.Count) group memberships for $Identity" -Level Info -Component 'GroupManagement'
        }
        catch {
            Write-TierLog -Message "Failed to get transitive group membership for $Identity : $_" -Level Error -Component 'GroupManagement'
            throw
        }

        $memberships
    }
}

function Resolve-ADPrimaryGroup {
    <#
    .SYNOPSIS
        Resolves a primary group RID to its distinguished name.

    .DESCRIPTION
        Converts a primary group ID (RID) to the full distinguished name of the group.
        Uses well-known RID mappings for standard groups and LDAP queries for custom groups.

    .PARAMETER PrimaryGroupID
        The primary group RID to resolve.

    .EXAMPLE
        Resolve-ADPrimaryGroup -PrimaryGroupID 513

        Returns the DN for "Domain Users" group.

    .OUTPUTS
        PSCustomObject representing the primary group, or $null if not found.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [int]$PrimaryGroupID
    )

    process {
        $domainDN = Get-ADDomainRootDN
        $groupName = $null
        $groupDN = $null

        # Check well-known RIDs
        if ($script:WellKnownRIDs.ContainsKey($PrimaryGroupID)) {
            $groupName = $script:WellKnownRIDs[$PrimaryGroupID]

            try {
                $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
                $group = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction SilentlyContinue
                if ($group) {
                    $groupDN = $group.DistinguishedName
                }
            }
            catch {
                Write-Verbose "Could not find well-known group $groupName : $_"
            }
        }
        else {
            # Search for custom group by primaryGroupToken
            try {
                $group = Get-ADGroup -LDAPFilter "(primaryGroupToken=$PrimaryGroupID)" -ErrorAction SilentlyContinue
                if ($group) {
                    $groupName = $group.Name
                    $groupDN = $group.DistinguishedName
                }
            }
            catch {
                Write-Verbose "Could not find group with primaryGroupToken $PrimaryGroupID : $_"
            }
        }

        if ($groupDN) {
            [PSCustomObject]@{
                GroupName = $groupName
                GroupDN = $groupDN
                Tier = $null
                GroupType = 'Primary Group'
                IsDirect = $true
            }
        }
        else {
            $null
        }
    }
}

function Get-ADLargeGroupMembers {
    <#
    .SYNOPSIS
        Retrieves members from groups with more than 1500 members using ranged retrieval.

    .DESCRIPTION
        Active Directory limits multi-valued attributes like 'member' to MaxValRange (typically 1500).
        This function uses ranged attribute retrieval to get all members from large groups.

    .PARAMETER GroupIdentity
        The distinguished name, SID, GUID, or SAM account name of the group.

    .PARAMETER IncludeNested
        If specified, includes members from nested groups (transitive membership).

    .EXAMPLE
        Get-ADLargeGroupMembers -GroupIdentity 'Domain Users'

        Returns all members of the Domain Users group, even if > 1500.

    .EXAMPLE
        Get-ADLargeGroupMembers -GroupIdentity 'All-Staff' -IncludeNested

        Returns all direct and nested members.

    .OUTPUTS
        Array of PSCustomObject representing group members.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$GroupIdentity,

        [switch]$IncludeNested
    )

    begin {
        Write-TierLog -Message "Getting large group members" -Level Info -Component 'GroupManagement'
        $rangeSize = 1500
    }

    process {
        # Use List for better performance with large groups
        $members = [System.Collections.Generic.List[PSCustomObject]]::new()

        try {
            # Resolve group to DN
            $group = Get-ADGroup -Identity $GroupIdentity -ErrorAction Stop
            $groupDN = $group.DistinguishedName
            $domainDN = ($groupDN -split ',DC=' | Select-Object -Skip 1) -join ',DC='
            $domainDN = "DC=$domainDN"

            if ($IncludeNested) {
                # Use LDAP_MATCHING_RULE_IN_CHAIN for transitive members
                # Escape all LDAP special characters: \ * ( ) / NUL - backslash FIRST
                $escapedDN = $groupDN -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace '\/', '\2f' -replace '\x00', '\00'
                $filter = "(memberOf:$($script:LDAP_MATCHING_RULE_IN_CHAIN):=$escapedDN)"

                $nestedMembers = Get-ADObject -LDAPFilter $filter -Properties objectClass, userAccountControl, Name, SamAccountName -ErrorAction SilentlyContinue

                # Add null check after SilentlyContinue
                if ($nestedMembers) {
                    foreach ($member in $nestedMembers) {
                        $objectType = 'Unknown'
                        if ($member.objectClass -contains 'user') { $objectType = 'User' }
                        elseif ($member.objectClass -contains 'computer') { $objectType = 'Computer' }
                        elseif ($member.objectClass -contains 'group') { $objectType = 'Group' }

                        $enabled = $true
                        if ($member.userAccountControl) {
                            $enabled = -not (($member.userAccountControl -band 2) -eq 2)
                        }

                        $members.Add([PSCustomObject]@{
                            Name = $member.Name
                            SamAccountName = $member.SamAccountName
                            DistinguishedName = $member.DistinguishedName
                            ObjectType = $objectType
                            Enabled = $enabled
                        })
                    }
                }
            }
            else {
                # Direct members only with ranged retrieval
                $rangeStart = 0
                $moreMembers = $true
                $allMemberDNs = [System.Collections.Generic.List[string]]::new()

                while ($moreMembers) {
                    $rangeEnd = $rangeStart + $rangeSize - 1
                    $rangeAttr = "member;range=$rangeStart-$rangeEnd"

                    try {
                        # Use DirectorySearcher for ranged retrieval
                        $searcher = New-Object System.DirectoryServices.DirectorySearcher
                        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$groupDN")
                        $searcher.Filter = "(objectClass=group)"
                        $searcher.PropertiesToLoad.Add($rangeAttr) | Out-Null
                        $searcher.PropertiesToLoad.Add("member") | Out-Null
                        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base

                        $result = $searcher.FindOne()

                        if ($result) {
                            $foundMembers = $false

                            # Check for ranged attribute
                            foreach ($propName in $result.Properties.PropertyNames) {
                                if ($propName -like 'member;range=*') {
                                    $memberValues = $result.Properties[$propName]
                                    if ($memberValues.Count -gt 0) {
                                        $foundMembers = $true
                                        # Use AddRange for better performance
                                        foreach ($mv in $memberValues) {
                                            $allMemberDNs.Add($mv)
                                        }

                                        # Check if this is the last range
                                        # Ranged attributes look like: member;range=0-1499 (more) or member;range=1500-* (last)
                                        # If it ends with '*', this is the last batch
                                        # Use regex -match for reliable asterisk detection
                                        if ($propName -match '-\*$') {
                                            $moreMembers = $false
                                        }
                                        else {
                                            $moreMembers = $true
                                        }
                                    }
                                    break
                                }
                            }

                            # Check regular member attribute if no ranged attribute found
                            if (-not $foundMembers -and $result.Properties['member']) {
                                foreach ($mv in $result.Properties['member']) {
                                    $allMemberDNs.Add($mv)
                                }
                                $moreMembers = $false
                            }
                            elseif (-not $foundMembers) {
                                $moreMembers = $false
                            }
                        }
                        else {
                            $moreMembers = $false
                        }

                        $rangeStart += $rangeSize

                        # Safety limit to prevent infinite loops
                        if ($rangeStart -gt $script:SAFETY_LIMIT_ITERATIONS) {
                            Write-Warning "Hit safety limit during ranged retrieval"
                            $moreMembers = $false
                        }
                    }
                    catch {
                        Write-Verbose "Ranged retrieval error at range $rangeStart : $_"
                        $moreMembers = $false
                    }
                }

                # Batch fetch member details
                $batchSize = 100
                for ($i = 0; $i -lt $allMemberDNs.Count; $i += $batchSize) {
                    $endIndex = [Math]::Min($i + $batchSize - 1, $allMemberDNs.Count - 1)
                    # Use GetRange for List instead of array slicing
                    $batch = $allMemberDNs.GetRange($i, $endIndex - $i + 1)

                    foreach ($memberDN in $batch) {
                        try {
                            $member = Get-ADObject -Identity $memberDN -Properties objectClass, userAccountControl, Name, SamAccountName -ErrorAction SilentlyContinue
                            if ($member) {
                                $objectType = 'Unknown'
                                if ($member.objectClass -contains 'user') { $objectType = 'User' }
                                elseif ($member.objectClass -contains 'computer') { $objectType = 'Computer' }
                                elseif ($member.objectClass -contains 'group') { $objectType = 'Group' }

                                $enabled = $true
                                if ($member.userAccountControl) {
                                    $enabled = -not (($member.userAccountControl -band 2) -eq 2)
                                }

                                $members.Add([PSCustomObject]@{
                                    Name = $member.Name
                                    SamAccountName = $member.SamAccountName
                                    DistinguishedName = $member.DistinguishedName
                                    ObjectType = $objectType
                                    Enabled = $enabled
                                })
                            }
                        }
                        catch {
                            Write-Verbose "Could not get member details for $memberDN : $_"
                        }
                    }
                }
            }

            Write-TierLog -Message "Retrieved $($members.Count) members from $($group.Name)" -Level Success -Component 'GroupManagement'
        }
        catch {
            Write-TierLog -Message "Failed to get group members for $GroupIdentity : $_" -Level Error -Component 'GroupManagement'
            throw
        }

        $members
    }
}

function Get-ADTierComplianceScore {
    <#
    .SYNOPSIS
        Calculates compliance score (0-100) with mathematical deductions.

    .DESCRIPTION
        Evaluates the AD tier model compliance and returns a score from 0-100.
        Deductions are applied based on violation severity:
        - Critical: -10 points each
        - High: -5 points each
        - Medium: -2 points each
        - Low: -1 point each

    .PARAMETER StaleThresholdDays
        Number of days without logon to consider an account stale. Default: 90.

    .EXAMPLE
        Get-ADTierComplianceScore

        Returns compliance status with score and violation details.

    .OUTPUTS
        PSCustomObject with Score, Violations, and summary counts.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [int]$StaleThresholdDays = 90
    )

    begin {
        Write-TierLog -Message "Calculating compliance score" -Level Info -Component 'Compliance'
    }

    process {
        $status = [PSCustomObject]@{
            Score = 100
            TotalViolations = 0
            CriticalCount = 0
            HighCount = 0
            MediumCount = 0
            LowCount = 0
            Violations = @()
            CrossTierAccess = @()
            LastChecked = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
        }

        try {
            # Get existing violations using Test-ADTierCompliance
            $compliance = Test-ADTierCompliance -ErrorAction SilentlyContinue

            if ($compliance) {
                # Process compliance results
                foreach ($check in $compliance.Checks) {
                    if (-not $check.Passed) {
                        $severity = switch ($check.Name) {
                            { $_ -like '*Tier0*' } { 'Critical' }
                            { $_ -like '*CrossTier*' } { 'Critical' }
                            { $_ -like '*Permission*' } { 'High' }
                            { $_ -like '*GPO*' } { 'Medium' }
                            default { 'Low' }
                        }

                        $violation = [PSCustomObject]@{
                            ViolationType = $check.Name
                            Severity = $severity
                            ObjectName = $check.Name
                            Description = $check.Message
                            Remediation = "Review and correct: $($check.Name)"
                        }

                        $status.Violations += $violation

                        # Apply score deduction
                        switch ($severity) {
                            'Critical' {
                                $status.Score -= 10
                                $status.CriticalCount++
                            }
                            'High' {
                                $status.Score -= 5
                                $status.HighCount++
                            }
                            'Medium' {
                                $status.Score -= 2
                                $status.MediumCount++
                            }
                            'Low' {
                                $status.Score -= 1
                                $status.LowCount++
                            }
                        }
                    }
                }
            }

            # Check for cross-tier access violations
            $crossTier = Find-ADCrossTierAccess -ErrorAction SilentlyContinue
            if ($crossTier) {
                foreach ($access in $crossTier) {
                    $status.CrossTierAccess += $access
                    $status.Violations += [PSCustomObject]@{
                        ViolationType = 'CrossTierAccess'
                        Severity = 'Critical'
                        ObjectName = $access.AccountName
                        Description = "Account has access to multiple tiers: $($access.Tiers -join ', ')"
                        Remediation = 'Remove account from groups in all but one tier'
                    }
                    $status.Score -= 10
                    $status.CriticalCount++
                }
            }

            # Ensure minimum score of 0
            if ($status.Score -lt 0) { $status.Score = 0 }

            $status.TotalViolations = $status.Violations.Count

            Write-TierLog -Message "Compliance score: $($status.Score), Violations: $($status.TotalViolations)" -Level Info -Component 'Compliance'
        }
        catch {
            Write-TierLog -Message "Failed to calculate compliance score: $_" -Level Error -Component 'Compliance'
            throw
        }

        $status
    }
}

function Disable-ADStaleAccounts {
    <#
    .SYNOPSIS
        Bulk disables accounts that haven't logged in for N days.

    .DESCRIPTION
        Finds all enabled accounts in tier OUs that haven't logged in within
        the specified threshold and disables them. Supports -WhatIf and -Confirm.

    .PARAMETER StaleThresholdDays
        Number of days without logon to consider an account stale. Default: 90.

    .PARAMETER TierFilter
        Optional. Limit to specific tier(s). Default: All tiers.

    .EXAMPLE
        Disable-ADStaleAccounts -StaleThresholdDays 90 -WhatIf

        Shows which accounts would be disabled without making changes.

    .EXAMPLE
        Disable-ADStaleAccounts -StaleThresholdDays 180 -TierFilter 'Tier2'

        Disables stale accounts in Tier2 only.

    .OUTPUTS
        PSCustomObject with success/failure counts and details.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [int]$StaleThresholdDays = 90,

        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string[]]$TierFilter = @('Tier0', 'Tier1', 'Tier2')
    )

    begin {
        Write-TierLog -Message "Starting stale account disable operation (threshold: $StaleThresholdDays days)" -Level Info -Component 'Compliance'
    }

    process {
        $result = [PSCustomObject]@{
            SuccessCount = 0
            FailureCount = 0
            Disabled = @()
            Errors = @()
        }

        $domainDN = Get-ADDomainRootDN
        $thresholdDate = (Get-Date).AddDays(-$StaleThresholdDays)
        $thresholdFileTime = $thresholdDate.ToFileTime()

        foreach ($tierKey in $TierFilter) {
            $tier = $script:TierConfiguration[$tierKey]
            $ouPath = "$($tier.OUPath),$domainDN"

            if (-not (Test-ADTierOUExists -OUPath $ouPath)) {
                Write-Verbose "$tierKey OU does not exist, skipping"
                continue
            }

            try {
                # Find enabled users with old lastLogonTimestamp
                $staleUsers = Get-ADUser -SearchBase $ouPath -SearchScope Subtree -Filter {
                    Enabled -eq $true -and LastLogonTimestamp -lt $thresholdFileTime
                } -Properties LastLogonTimestamp, Description -ErrorAction SilentlyContinue

                foreach ($user in $staleUsers) {
                    $lastLogon = if ($user.LastLogonTimestamp) {
                        [DateTime]::FromFileTime($user.LastLogonTimestamp)
                    } else { 'Never' }

                    if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Disable stale account (last logon: $lastLogon)")) {
                        try {
                            Disable-ADAccount -Identity $user.DistinguishedName -ErrorAction Stop

                            $result.Disabled += [PSCustomObject]@{
                                SamAccountName = $user.SamAccountName
                                DistinguishedName = $user.DistinguishedName
                                LastLogon = $lastLogon
                                Tier = $tierKey
                            }
                            $result.SuccessCount++

                            Write-TierLog -Message "Disabled stale account: $($user.SamAccountName)" -Level Success -Component 'Compliance'
                        }
                        catch {
                            $result.Errors += "Failed to disable $($user.SamAccountName): $_"
                            $result.FailureCount++
                        }
                    }
                }
            }
            catch {
                $result.Errors += "Error searching $tierKey : $_"
            }
        }

        Write-TierLog -Message "Stale account operation complete: $($result.SuccessCount) disabled, $($result.FailureCount) failed" -Level Info -Component 'Compliance'
        $result
    }
}

function Set-ADServiceAccountHardening {
    <#
    .SYNOPSIS
        Bulk hardens service accounts by setting NOT_DELEGATED flag.

    .DESCRIPTION
        Sets the 'Account is sensitive and cannot be delegated' flag on service accounts.
        This prevents Kerberos delegation attacks. Also removes TRUSTED_TO_AUTH_FOR_DELEGATION
        if present. Targets accounts in ServiceAccounts OUs.

    .PARAMETER Identity
        Optional. Specific account(s) to harden. If not specified, hardens all
        service accounts in tier ServiceAccounts OUs.

    .PARAMETER TierFilter
        Optional. Limit to specific tier(s). Default: All tiers.

    .EXAMPLE
        Set-ADServiceAccountHardening -WhatIf

        Shows which accounts would be hardened without making changes.

    .EXAMPLE
        Set-ADServiceAccountHardening -TierFilter 'Tier0', 'Tier1'

        Hardens service accounts in Tier0 and Tier1 only.

    .OUTPUTS
        PSCustomObject with success/failure counts and details.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param(
        [string[]]$Identity,

        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string[]]$TierFilter = @('Tier0', 'Tier1', 'Tier2')
    )

    begin {
        Write-TierLog -Message "Starting service account hardening operation" -Level Info -Component 'Compliance'

        # userAccountControl flags
        $NOT_DELEGATED = 0x100000  # Account is sensitive and cannot be delegated
        $TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    }

    process {
        $result = [PSCustomObject]@{
            SuccessCount = 0
            FailureCount = 0
            Hardened = @()
            Errors = @()
        }

        $domainDN = Get-ADDomainRootDN
        $accountsToHarden = @()

        if ($Identity) {
            # Specific accounts provided
            foreach ($id in $Identity) {
                try {
                    $user = Get-ADUser -Identity $id -Properties userAccountControl -ErrorAction Stop
                    $accountsToHarden += $user
                }
                catch {
                    $result.Errors += "Could not find account $id : $_"
                }
            }
        }
        else {
            # Find all service accounts in tier OUs
            foreach ($tierKey in $TierFilter) {
                $tier = $script:TierConfiguration[$tierKey]
                $svcOUPath = "OU=ServiceAccounts,$($tier.OUPath),$domainDN"

                if (Test-ADTierOUExists -OUPath $svcOUPath) {
                    try {
                        $svcAccounts = Get-ADUser -SearchBase $svcOUPath -SearchScope OneLevel -Filter * -Properties userAccountControl -ErrorAction SilentlyContinue
                        $accountsToHarden += $svcAccounts
                    }
                    catch {
                        Write-Verbose "Error searching $svcOUPath : $_"
                    }
                }
            }
        }

        foreach ($account in $accountsToHarden) {
            $currentUAC = $account.userAccountControl
            $isHardened = ($currentUAC -band $NOT_DELEGATED) -eq $NOT_DELEGATED
            $hasTrustedForDelegation = ($currentUAC -band $TRUSTED_TO_AUTH_FOR_DELEGATION) -eq $TRUSTED_TO_AUTH_FOR_DELEGATION

            if ($isHardened -and -not $hasTrustedForDelegation) {
                Write-Verbose "$($account.SamAccountName) is already hardened"
                continue
            }

            if ($PSCmdlet.ShouldProcess($account.SamAccountName, "Set NOT_DELEGATED flag and remove TRUSTED_TO_AUTH_FOR_DELEGATION")) {
                try {
                    # Use Set-ADAccountControl for atomic, race-safe flag manipulation
                    # This sets desired state directly rather than manipulating bits
                    Set-ADAccountControl -Identity $account.DistinguishedName `
                        -AccountNotDelegated $true `
                        -TrustedToAuthForDelegation $false `
                        -ErrorAction Stop

                    # Get updated UAC for logging
                    $updatedAccount = Get-ADUser -Identity $account.DistinguishedName -Properties userAccountControl
                    $newUAC = $updatedAccount.userAccountControl

                    $result.Hardened += [PSCustomObject]@{
                        SamAccountName = $account.SamAccountName
                        DistinguishedName = $account.DistinguishedName
                        PreviousUAC = $currentUAC
                        NewUAC = $newUAC
                    }
                    $result.SuccessCount++

                    Write-TierLog -Message "Hardened service account: $($account.SamAccountName)" -Level Success -Component 'Compliance'
                }
                catch {
                    $result.Errors += "Failed to harden $($account.SamAccountName): $_"
                    $result.FailureCount++
                }
            }
        }

        Write-TierLog -Message "Service account hardening complete: $($result.SuccessCount) hardened, $($result.FailureCount) failed" -Level Info -Component 'Compliance'
        $result
    }
}

function Get-ADTierInitializationStatus {
    <#
    .SYNOPSIS
        Checks if the tier model is initialized with detailed status.

    .DESCRIPTION
        Returns comprehensive status about the tier model initialization including
        OU existence, group existence, and any missing components.

    .EXAMPLE
        Get-ADTierInitializationStatus

        Returns initialization status.

    .OUTPUTS
        PSCustomObject with IsInitialized, OU status, group status, and missing components.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-TierLog -Message "Checking tier initialization status" -Level Info -Component 'Initialize'
    }

    process {
        $domainDN = Get-ADDomainRootDN

        $status = [PSCustomObject]@{
            IsInitialized = $true
            Tier0OUExists = $false
            Tier1OUExists = $false
            Tier2OUExists = $false
            GroupsExist = $false
            MissingComponents = @()
        }

        # Check tier OUs
        foreach ($tierKey in @('Tier0', 'Tier1', 'Tier2')) {
            $tier = $script:TierConfiguration[$tierKey]
            $ouPath = "$($tier.OUPath),$domainDN"

            if (Test-ADTierOUExists -OUPath $ouPath) {
                switch ($tierKey) {
                    'Tier0' { $status.Tier0OUExists = $true }
                    'Tier1' { $status.Tier1OUExists = $true }
                    'Tier2' { $status.Tier2OUExists = $true }
                }

                # Check sub-OUs
                foreach ($subOU in $script:StandardSubOUs) {
                    $subOUPath = "OU=$subOU,$ouPath"
                    if (-not (Test-ADTierOUExists -OUPath $subOUPath)) {
                        $status.MissingComponents += "Missing sub-OU: $subOUPath"
                        $status.IsInitialized = $false
                    }
                }
            }
            else {
                $status.MissingComponents += "Missing tier OU: $ouPath"
                $status.IsInitialized = $false
            }
        }

        # Check groups
        $allGroupsExist = $true
        $groupSuffixes = @('Admins', 'Operators', 'Readers', 'ServiceAccounts', 'JumpServers')

        foreach ($tierKey in @('Tier0', 'Tier1', 'Tier2')) {
            foreach ($suffix in $groupSuffixes) {
                $groupName = "$tierKey-$suffix"
                if (-not (Test-ADGroupExists -GroupName $groupName)) {
                    $status.MissingComponents += "Missing group: $groupName"
                    $allGroupsExist = $false
                    $status.IsInitialized = $false
                }
            }
        }

        $status.GroupsExist = $allGroupsExist

        Write-TierLog -Message "Initialization status: IsInitialized=$($status.IsInitialized), Missing=$($status.MissingComponents.Count)" -Level Info -Component 'Initialize'
        $status
    }
}

#endregion

#region Endpoint Protection GPO Functions

function Get-ADEndpointProtectionStatus {
    <#
    .SYNOPSIS
        Gets status of all endpoint protection GPOs.

    .DESCRIPTION
        Returns the status of all endpoint protection GPOs including:
        - AuditBaseline (per-tier)
        - AuditEnhanced (per-tier)
        - DcAuditEssential (DC OU only)
        - DcAuditComprehensive (DC OU only)
        - DefenderProtection (domain-wide)

    .EXAMPLE
        Get-ADEndpointProtectionStatus

        Returns status of all endpoint protection GPOs.

    .OUTPUTS
        Array of PSCustomObject with GPO status information.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    begin {
        Write-TierLog -Message "Getting endpoint protection GPO status" -Level Info -Component 'GPO'

        # Check module availability - set flag for process block
        $script:GPModuleAvailable = Test-GroupPolicyModuleAvailable
        if (-not $script:GPModuleAvailable) {
            Write-Warning "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        # Early exit if GroupPolicy module not available
        if (-not $script:GPModuleAvailable) {
            return @()
        }

        $statuses = @()
        $domainDN = Get-ADDomainRootDN

        # Define GPO types - names must match those created by New-AD*GPO functions
        $gpoTypes = @(
            @{ Type = 'Audit-Baseline'; Description = 'Microsoft recommended baseline audit policies'; Scope = 'per-tier' }
            @{ Type = 'Audit-Enhanced'; Description = 'ACSC/NSA hardened audit with PowerShell logging'; Scope = 'per-tier' }
            @{ Type = 'DC-Audit-Essential'; Description = 'Essential security audit for Domain Controllers'; Scope = 'dc-only' }
            @{ Type = 'DC-Audit-Comprehensive'; Description = 'Comprehensive forensic audit for Domain Controllers'; Scope = 'dc-only' }
            @{ Type = 'DefenderProtection'; Description = 'Microsoft Defender Antivirus balanced protection'; Scope = 'domain-wide' }
        )

        foreach ($gpoType in $gpoTypes) {
            switch ($gpoType.Scope) {
                'per-tier' {
                    $tierStatuses = @()
                    $anyExists = $false
                    $anyLinked = $false

                    foreach ($tierKey in @('Tier0', 'Tier1', 'Tier2')) {
                        $gpoName = "SEC-$tierKey-$($gpoType.Type)"
                        $targetOU = "$($script:TierConfiguration[$tierKey].OUPath),$domainDN"

                        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                        $linked = $false
                        $linkEnabled = $false

                        if ($gpo) {
                            $anyExists = $true
                            try {
                                $links = (Get-GPInheritance -Target $targetOU -ErrorAction SilentlyContinue).GpoLinks
                                $link = $links | Where-Object { $_.DisplayName -eq $gpoName }
                                if ($link) {
                                    $linked = $true
                                    $linkEnabled = $link.Enabled
                                    $anyLinked = $true
                                }
                            }
                            catch {
                                Write-Verbose "Failed to get GPO links for $gpoName at $targetOU : $_"
                            }
                        }

                        $tierStatuses += [PSCustomObject]@{
                            Tier = $tierKey
                            Linked = $linked
                            LinkEnabled = $linkEnabled
                        }
                    }

                    $statuses += [PSCustomObject]@{
                        GpoType = $gpoType.Type
                        Name = "SEC-{Tier}-$($gpoType.Type)"
                        Description = $gpoType.Description
                        Exists = $anyExists
                        Linked = $anyLinked
                        LinkTarget = 'Per-Tier OUs'
                        LinkScope = $gpoType.Scope
                        TierStatus = $tierStatuses
                    }
                }

                'dc-only' {
                    $gpoName = "SEC-$($gpoType.Type)"
                    $dcOU = "OU=Domain Controllers,$domainDN"

                    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                    $linked = $false
                    $linkEnabled = $false
                    $created = $null
                    $modified = $null

                    if ($gpo) {
                        $created = $gpo.CreationTime.ToString('o')
                        $modified = $gpo.ModificationTime.ToString('o')

                        try {
                            $links = (Get-GPInheritance -Target $dcOU -ErrorAction SilentlyContinue).GpoLinks
                            $link = $links | Where-Object { $_.DisplayName -eq $gpoName }
                            if ($link) {
                                $linked = $true
                                $linkEnabled = $link.Enabled
                            }
                        }
                        catch {
                            Write-Verbose "Failed to get GPO links for $gpoName at $dcOU : $_"
                        }
                    }

                    $statuses += [PSCustomObject]@{
                        GpoType = $gpoType.Type
                        Name = $gpoName
                        Description = $gpoType.Description
                        Exists = ($null -ne $gpo)
                        Linked = $linked
                        LinkEnabled = $linkEnabled
                        LinkTarget = $dcOU
                        LinkScope = $gpoType.Scope
                        Created = $created
                        Modified = $modified
                    }
                }

                'domain-wide' {
                    $gpoName = "SEC-$($gpoType.Type)"

                    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                    $linked = $false
                    $linkEnabled = $false
                    $created = $null
                    $modified = $null

                    if ($gpo) {
                        $created = $gpo.CreationTime.ToString('o')
                        $modified = $gpo.ModificationTime.ToString('o')

                        try {
                            $links = (Get-GPInheritance -Target $domainDN -ErrorAction SilentlyContinue).GpoLinks
                            $link = $links | Where-Object { $_.DisplayName -eq $gpoName }
                            if ($link) {
                                $linked = $true
                                $linkEnabled = $link.Enabled
                            }
                        }
                        catch {
                            Write-Verbose "Failed to get GPO links for $gpoName at $domainDN : $_"
                        }
                    }

                    $statuses += [PSCustomObject]@{
                        GpoType = $gpoType.Type
                        Name = $gpoName
                        Description = $gpoType.Description
                        Exists = ($null -ne $gpo)
                        Linked = $linked
                        LinkEnabled = $linkEnabled
                        LinkTarget = $domainDN
                        LinkScope = $gpoType.Scope
                        Created = $created
                        Modified = $modified
                    }
                }
            }
        }

        Write-TierLog -Message "Retrieved status for $($statuses.Count) endpoint protection GPO types" -Level Success -Component 'GPO'
        $statuses
    }
}

function New-ADAuditBaselineGPO {
    <#
    .SYNOPSIS
        Creates baseline audit policy GPO for a tier.

    .DESCRIPTION
        Creates and configures a GPO with Microsoft recommended baseline audit policies.
        Audit categories include:
        - Account Logon, Account Management, DS Access
        - Logon/Logoff, Object Access, Policy Change
        - Privilege Use, System

    .PARAMETER Tier
        The tier to create the GPO for (Tier0, Tier1, or Tier2).

    .EXAMPLE
        New-ADAuditBaselineGPO -Tier 'Tier0'

        Creates SEC-Tier0-Audit-Baseline GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$Tier
    )

    begin {
        Write-TierLog -Message "Creating audit baseline GPO for $Tier" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-$Tier-Audit-Baseline"
        $domainDN = Get-ADDomainRootDN
        $targetOU = "$($script:TierConfiguration[$Tier].OUPath),$domainDN"

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create Audit Baseline GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "Microsoft recommended baseline audit policies for $Tier"
                    $result.Created = $true
                    Write-TierLog -Message "Created GPO: $gpoName" -Level Success -Component 'GPO'
                }

                # Link to tier OU
                $links = (Get-GPInheritance -Target $targetOU -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes | Out-Null
                    Write-TierLog -Message "Linked GPO $gpoName to $targetOU" -Level Success -Component 'GPO'
                }
                $result.Linked = $true

                # Configure audit policies
                $domain = Get-ADDomain
                $gpoGuid = '{' + $gpo.Id.ToString().ToUpper() + '}'
                # Use DFS-aware SYSVOL path for resilience
                $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
                $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
                $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

                if (-not (Test-Path $secEditPath)) {
                    New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
                }

                # Create backup before modification
                Backup-GptTmplFile -GptTmplPath $gptTmplPath | Out-Null

                # Audit policy values: 0=None, 1=Success, 2=Failure, 3=Both
                # Use merge function to preserve existing settings
                $auditSettings = @{
                    'Event Audit' = @{
                        'AuditSystemEvents' = '3'
                        'AuditLogonEvents' = '3'
                        'AuditObjectAccess' = '2'
                        'AuditPrivilegeUse' = '2'
                        'AuditPolicyChange' = '3'
                        'AuditAccountManage' = '3'
                        'AuditProcessTracking' = '0'
                        'AuditDSAccess' = '0'
                        'AuditAccountLogon' = '3'
                    }
                }

                $mergedContent = Merge-GptTmplContent -GptTmplPath $gptTmplPath -NewSettings $auditSettings
                $mergedContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

                # Update GPO version
                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $true
                $result.Success = $true

                Write-TierLog -Message "Configured audit baseline for $gpoName" -Level Success -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create audit baseline GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}

function New-ADAuditEnhancedGPO {
    <#
    .SYNOPSIS
        Creates enhanced audit policy GPO with PowerShell logging for a tier.

    .DESCRIPTION
        Creates and configures a GPO with ACSC/NSA hardened audit policies including:
        - Full audit policy coverage
        - PowerShell Script Block Logging
        - PowerShell Module Logging
        - PowerShell Transcription
        - Command line process auditing

    .PARAMETER Tier
        The tier to create the GPO for (Tier0, Tier1, or Tier2).

    .EXAMPLE
        New-ADAuditEnhancedGPO -Tier 'Tier0'

        Creates SEC-Tier0-Audit-Enhanced GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$Tier
    )

    begin {
        Write-TierLog -Message "Creating enhanced audit GPO for $Tier" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-$Tier-Audit-Enhanced"
        $domainDN = Get-ADDomainRootDN
        $targetOU = "$($script:TierConfiguration[$Tier].OUPath),$domainDN"

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create Enhanced Audit GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "ACSC/NSA hardened audit policies with PowerShell logging for $Tier"
                    $result.Created = $true
                }

                # Link to tier OU
                $links = (Get-GPInheritance -Target $targetOU -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes | Out-Null
                }
                $result.Linked = $true

                # Configure enhanced audit policies
                $domain = Get-ADDomain
                $gpoGuid = '{' + $gpo.Id.ToString().ToUpper() + '}'
                # Use DFS-aware SYSVOL path for resilience
                $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
                $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
                $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

                if (-not (Test-Path $secEditPath)) {
                    New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
                }

                # Create backup before modification
                Backup-GptTmplFile -GptTmplPath $gptTmplPath | Out-Null

                # Enhanced audit policies (all success+failure) - use merge function
                $enhancedAuditSettings = @{
                    'Event Audit' = @{
                        'AuditSystemEvents' = '3'
                        'AuditLogonEvents' = '3'
                        'AuditObjectAccess' = '3'
                        'AuditPrivilegeUse' = '3'
                        'AuditPolicyChange' = '3'
                        'AuditAccountManage' = '3'
                        'AuditProcessTracking' = '1'
                        'AuditDSAccess' = '3'
                        'AuditAccountLogon' = '3'
                    }
                    'Registry Values' = @{
                        'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled' = '4,1'
                    }
                }

                $mergedContent = Merge-GptTmplContent -GptTmplPath $gptTmplPath -NewSettings $enhancedAuditSettings
                $mergedContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

                # Configure PowerShell logging via registry with proper error handling
                $registryConfigured = $true
                $registryErrors = [System.Collections.Generic.List[string]]::new()

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ValueName 'EnableScriptBlockLogging' -Type DWord -Value 1 -ErrorAction Stop
                }
                catch {
                    $registryErrors.Add("ScriptBlockLogging: $($_.Exception.Message)")
                    $registryConfigured = $false
                }

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ValueName 'EnableModuleLogging' -Type DWord -Value 1 -ErrorAction Stop
                }
                catch {
                    $registryErrors.Add("ModuleLogging: $($_.Exception.Message)")
                    $registryConfigured = $false
                }

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableTranscripting' -Type DWord -Value 1 -ErrorAction Stop
                }
                catch {
                    $registryErrors.Add("Transcription: $($_.Exception.Message)")
                    $registryConfigured = $false
                }

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableInvocationHeader' -Type DWord -Value 1 -ErrorAction Stop
                }
                catch {
                    $registryErrors.Add("InvocationHeader: $($_.Exception.Message)")
                    $registryConfigured = $false
                }

                if (-not $registryConfigured) {
                    $result.Errors += $registryErrors
                    Write-Warning "Some PowerShell logging settings failed to configure: $($registryErrors -join '; ')"
                }

                # Update GPO version
                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $registryConfigured
                $result.Success = $registryConfigured

                Write-TierLog -Message "Configured enhanced audit for $gpoName (Registry settings: $(if($registryConfigured){'Success'}else{'Partial'}))" -Level $(if($registryConfigured){'Success'}else{'Warning'}) -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create enhanced audit GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}

function New-ADDcAuditEssentialGPO {
    <#
    .SYNOPSIS
        Creates essential audit GPO for Domain Controllers.

    .DESCRIPTION
        Creates and configures a GPO with essential audit policies specifically
        designed for Domain Controllers.

    .EXAMPLE
        New-ADDcAuditEssentialGPO

        Creates SEC-DC-Audit-Essential GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-TierLog -Message "Creating DC essential audit GPO" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-DC-Audit-Essential"
        $domainDN = Get-ADDomainRootDN
        $dcOU = "OU=Domain Controllers,$domainDN"

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create DC Essential Audit GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "Essential security audit policies for Domain Controllers"
                    $result.Created = $true
                }

                # Link to Domain Controllers OU
                $links = (Get-GPInheritance -Target $dcOU -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $dcOU -LinkEnabled Yes | Out-Null
                }
                $result.Linked = $true

                # Configure DC audit policies
                $domain = Get-ADDomain
                $gpoGuid = '{' + $gpo.Id.ToString().ToUpper() + '}'
                # Use DFS-aware SYSVOL path for resilience
                $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
                $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
                $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

                if (-not (Test-Path $secEditPath)) {
                    New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
                }

                # Create backup before modification
                Backup-GptTmplFile -GptTmplPath $gptTmplPath | Out-Null

                # Use merge function to preserve existing settings
                $dcEssentialSettings = @{
                    'Event Audit' = @{
                        'AuditSystemEvents' = '3'
                        'AuditLogonEvents' = '3'
                        'AuditObjectAccess' = '3'
                        'AuditPrivilegeUse' = '3'
                        'AuditPolicyChange' = '3'
                        'AuditAccountManage' = '3'
                        'AuditProcessTracking' = '0'
                        'AuditDSAccess' = '3'
                        'AuditAccountLogon' = '3'
                    }
                }

                $mergedContent = Merge-GptTmplContent -GptTmplPath $gptTmplPath -NewSettings $dcEssentialSettings
                $mergedContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force
                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $true
                $result.Success = $true

                Write-TierLog -Message "Configured DC essential audit GPO" -Level Success -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create DC essential audit GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}

function New-ADDcAuditComprehensiveGPO {
    <#
    .SYNOPSIS
        Creates comprehensive forensic audit GPO for Domain Controllers.

    .DESCRIPTION
        Creates and configures a GPO with comprehensive forensic audit policies
        for Domain Controllers, including NTDS diagnostics logging.

    .EXAMPLE
        New-ADDcAuditComprehensiveGPO

        Creates SEC-DC-Audit-Comprehensive GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-TierLog -Message "Creating DC comprehensive audit GPO" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-DC-Audit-Comprehensive"
        $domainDN = Get-ADDomainRootDN
        $dcOU = "OU=Domain Controllers,$domainDN"

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create DC Comprehensive Audit GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "Comprehensive forensic audit policies for Domain Controllers"
                    $result.Created = $true
                }

                # Link to Domain Controllers OU
                $links = (Get-GPInheritance -Target $dcOU -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $dcOU -LinkEnabled Yes | Out-Null
                }
                $result.Linked = $true

                # Configure comprehensive DC audit policies
                $domain = Get-ADDomain
                $gpoGuid = '{' + $gpo.Id.ToString().ToUpper() + '}'
                # Use DFS-aware SYSVOL path for resilience
                $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
                $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
                $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

                if (-not (Test-Path $secEditPath)) {
                    New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
                }

                # Create backup before modification
                Backup-GptTmplFile -GptTmplPath $gptTmplPath | Out-Null

                # All events audited - use merge function
                $dcComprehensiveSettings = @{
                    'Event Audit' = @{
                        'AuditSystemEvents' = '3'
                        'AuditLogonEvents' = '3'
                        'AuditObjectAccess' = '3'
                        'AuditPrivilegeUse' = '3'
                        'AuditPolicyChange' = '3'
                        'AuditAccountManage' = '3'
                        'AuditProcessTracking' = '3'
                        'AuditDSAccess' = '3'
                        'AuditAccountLogon' = '3'
                    }
                    'Registry Values' = @{
                        'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled' = '4,1'
                    }
                }

                $mergedContent = Merge-GptTmplContent -GptTmplPath $gptTmplPath -NewSettings $dcComprehensiveSettings
                $mergedContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

                # Enable NTDS diagnostics with proper error handling
                $ntdsConfigured = $true
                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '15 Field Engineering' -Type DWord -Value 5 -ErrorAction Stop
                }
                catch {
                    $result.Errors += "NTDS Field Engineering: $($_.Exception.Message)"
                    $ntdsConfigured = $false
                }

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '16 LDAP Interface Events' -Type DWord -Value 2 -ErrorAction Stop
                }
                catch {
                    $result.Errors += "NTDS LDAP Events: $($_.Exception.Message)"
                    $ntdsConfigured = $false
                }

                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $ntdsConfigured
                $result.Success = $ntdsConfigured

                Write-TierLog -Message "Configured DC comprehensive audit GPO (NTDS: $(if($ntdsConfigured){'Success'}else{'Partial'}))" -Level $(if($ntdsConfigured){'Success'}else{'Warning'}) -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create DC comprehensive audit GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}

function New-ADDefenderProtectionGPO {
    <#
    .SYNOPSIS
        Creates Windows Defender configuration GPO (domain-wide).

    .DESCRIPTION
        Creates and configures a GPO with Windows Defender Antivirus settings:
        - Real-time protection enabled
        - Cloud-delivered protection enabled
        - Automatic sample submission
        - PUA protection enabled

    .EXAMPLE
        New-ADDefenderProtectionGPO

        Creates SEC-DefenderProtection GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-TierLog -Message "Creating Defender protection GPO" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-DefenderProtection"
        $domainDN = Get-ADDomainRootDN

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create Defender Protection GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "Microsoft Defender Antivirus balanced protection settings"
                    $result.Created = $true
                }

                # Link to domain root
                $links = (Get-GPInheritance -Target $domainDN -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes | Out-Null
                }
                $result.Linked = $true

                # Configure Defender settings
                # Real-time Protection
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableRealtimeMonitoring' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableBehaviorMonitoring' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableOnAccessProtection' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableScanOnRealtimeEnable' -Type DWord -Value 0

                # Cloud Protection (MAPS)
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -ValueName 'SpynetReporting' -Type DWord -Value 2
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -ValueName 'SubmitSamplesConsent' -Type DWord -Value 1

                # PUA Protection
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'PUAProtection' -Type DWord -Value 1

                # Scan settings
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -ValueName 'DisableEmailScanning' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -ValueName 'DisableRemovableDriveScanning' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -ValueName 'DisableArchiveScanning' -Type DWord -Value 0

                # Ensure Defender is not disabled
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'DisableAntiSpyware' -Type DWord -Value 0

                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $true
                $result.Success = $true

                Write-TierLog -Message "Configured Defender protection GPO" -Level Success -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create Defender protection GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}

#endregion

Export-ModuleMember -Function @(
    # Initialization
    'Initialize-ADTierModel',
    'Get-ADTierConfiguration',
    'Get-ADTierInitializationStatus',

    # Tier 0 Detection
    'Get-ADTier0Infrastructure',
    'Test-ADTier0Placement',
    'Move-ADTier0Infrastructure',
    'Get-ADFSMORoleHolders',

    # Tier Management
    'New-ADTier',
    'Get-ADTier',
    'Set-ADTierMember',
    'Remove-ADTierMember',
    'Get-ADTierMember',
    'Get-ADTierCounts',

    # OU Management
    'New-ADTierOUStructure',
    'Get-ADTierOUStructure',

    # Group Management
    'New-ADTierGroup',
    'Get-ADTierGroup',
    'Add-ADTierGroupMember',
    'Remove-ADTierGroupMember',
    'Get-ADTransitiveGroupMembership',
    'Resolve-ADPrimaryGroup',
    'Get-ADLargeGroupMembers',

    # Permission Management
    'Set-ADTierPermission',
    'Get-ADTierPermission',
    'Test-ADTierPermissionCompliance',

    # Auditing and Monitoring
    'Get-ADTierAccessReport',
    'Get-ADTierViolation',
    'Test-ADTierCompliance',
    'Export-ADTierAuditLog',

    # Security Policies
    'Set-ADTierAuthenticationPolicy',
    'Get-ADTierAuthenticationPolicy',
    'Set-ADTierPasswordPolicy',

    # Cross-Tier Detection
    'Find-ADCrossTierAccess',
    'Find-ADTierMisconfiguration',
    'Repair-ADTierViolation',

    # GPO Security Configuration
    'Set-ADTierLogonRestrictions',
    'Set-GPOUserRight',
    'Get-ADTierLogonRestrictions',
    'Test-ADTierLogonRestrictions',
    'Get-GPOLinks',

    # Admin Account Management
    'New-ADTierAdminAccount',
    'Set-ADTierAccountLockoutProtection',
    'Get-ADTierAdminAccount',

    # Enhanced Security Policies
    'Set-ADTierSecurityPolicy',
    'Set-GPOSecurityOption',
    'Set-GPOAuditPolicy',
    'Set-GPOFirewall',
    'Set-GPORegistryValue',

    # Compliance (from Rust port)
    'Get-ADTierComplianceScore',
    'Disable-ADStaleAccounts',
    'Set-ADServiceAccountHardening',

    # Diagnostics (from Rust port)
    'Test-ADConnection',

    # Endpoint Protection GPOs (from Rust port)
    'Get-ADEndpointProtectionStatus',
    'New-ADAuditBaselineGPO',
    'New-ADAuditEnhancedGPO',
    'New-ADDcAuditEssentialGPO',
    'New-ADDcAuditComprehensiveGPO',
    'New-ADDefenderProtectionGPO'
)
