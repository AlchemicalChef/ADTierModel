#Requires -Version 5.1

# Core Helper Functions - Must be loaded first
# These are internal functions used by other module functions

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
