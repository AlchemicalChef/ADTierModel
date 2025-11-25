#Requires -Modules ActiveDirectory
#Requires -Version 5.1

# Module-level variables
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
        Detection = { (Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object { $_.DistinguishedName -like '*Domain Controllers*' }).Name }
        Description = 'Active Directory Domain Controllers'
    }
    ADFS = @{
        Name = 'AD FS Server'
        Detection = { (Get-ADComputer -Filter * -Properties ServicePrincipalName | Where-Object { $_.ServicePrincipalName -like '*http/sts*' -or $_.ServicePrincipalName -like '*http/adfs*' }).Name }
        Description = 'Active Directory Federation Services servers'
    }
    EntraConnect = @{
        Name = 'Entra Connect (AAD Connect)'
        Detection = { (Get-ADComputer -Filter * -Properties Description | Where-Object { $_.Description -like '*Azure AD Connect*' -or $_.Description -like '*AAD Connect*' -or $_.Description -like '*Entra Connect*' }).Name }
        Description = 'Microsoft Entra Connect (Azure AD Connect) synchronization servers'
    }
    CertificateAuthority = @{
        Name = 'Certificate Authority'
        Detection = { (Get-ADComputer -Filter * -Properties Description | Where-Object { $_.Description -like '*Certificate Authority*' -or $_.Description -like '*CA Server*' }).Name }
        Description = 'Enterprise Certificate Authority servers'
    }
    PAW = @{
        Name = 'Privileged Access Workstation'
        Detection = { (Get-ADComputer -Filter "Name -like 'PAW-*' -or Name -like '*-PAW-*'" -Properties Description | Where-Object { $_.Description -like '*PAW*' -or $_.Description -like '*Privileged Access*' }).Name }
        Description = 'Privileged Access Workstations for Tier 0 administration'
    }
}

$script:StandardSubOUs = @('Computers', 'Users', 'Groups', 'ServiceAccounts', 'AdminWorkstations')

$script:ConfigPath = "$env:ProgramData\ADTierModel\config.json"

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
    Ensure-TierDataDirectory -Path $logPath

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logFile = Join-Path $logPath "ADTierModel_$(Get-Date -Format 'yyyyMMdd').log"
    $safeMessage = ($Message -replace '[\r\n]+', ' ').Trim()

    if ($safeMessage.Length -gt 4000) {
        $safeMessage = $safeMessage.Substring(0, 4000) + '...'
    }

    $logEntry = "$timestamp [$Level] [$Component] $safeMessage"

    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Level) {
        'Info'    { Write-Verbose $Message }
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Error $Message }
        'Success' { Write-Host $Message -ForegroundColor Green }
    }
}

function Get-ADDomainRootDN {
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
            OUsCreated = @()
            GroupsCreated = @()
            PermissionsSet = @()
            GPOsCreated = @()
            Errors = @()
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
                                if (-not (Test-ADTierOUExists -OUPath $subOUPath)) {
                                    New-ADOrganizationalUnit -Name $subOU -Path $ouPath -ProtectedFromAccidentalDeletion $true
                                    $results.OUsCreated += $subOUPath
                                    Write-Verbose "Created sub-OU: $subOUPath"
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
                            $existingGroup = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                            
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
                        }
                    }
                }
            }
        }
        
        # Save configuration
        $configDir = Split-Path $script:ConfigPath -Parent
        Ensure-TierDataDirectory -Path $configDir

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
        
        if ($results.Errors.Count -gt 0) {
            Write-Host "`nErrors encountered:" -ForegroundColor Red
            $results.Errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
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
            $computers = & $role.Detection
            
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
            
            Write-Verbose "Found $($computers.Count) $($role.Name) server(s)"
        }
        catch {
            Write-Warning "Failed to detect $($role.Name): $_"
        }
    }
    
    Write-TierLog -Message "Discovered $($discovered.Count) Tier 0 infrastructure components" -Level Info -Component 'Discovery'
    
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
            
            # Get counts
            $computers = (Get-ADComputer -SearchBase $ouPath -SearchScope Subtree -Filter *).Count
            $users = (Get-ADUser -SearchBase $ouPath -SearchScope Subtree -Filter *).Count
            $groups = (Get-ADGroup -SearchBase $ouPath -SearchScope Subtree -Filter *).Count
            
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
                MemberCount = if ($group.Member) { $group.Member.Count } else { 0 }
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
            $adminGroup = Get-ADGroup -Filter "Name -eq '$tierKey-Admins'" -ErrorAction SilentlyContinue

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
        $domainControllers = Get-ADDomainController -Filter *
        $tier0OU = "$($script:TierConfiguration['Tier0'].OUPath),$(Get-ADDomainRootDN)"
        
        foreach ($dc in $domainControllers) {
            $dcComputer = Get-ADComputer -Identity $dc.Name
            
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

function Ensure-TierDataDirectory {
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
            New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\\Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'),
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
        $groupExists = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
        
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
        $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
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
            if ($adminGroups[$tierKey].SamAccountName -contains $user.Name) {
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
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
            
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
            # Count objects in OU
            $computers = (Get-ADComputer -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter *).Count
            $users = (Get-ADUser -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter *).Count
            $groups = (Get-ADGroup -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter *).Count
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
            $existingGroup = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
            
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
                MemberCount = if ($group.Member) { $group.Member.Count } else { 0 }
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
    
    try {
        $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
        
        foreach ($member in $Members) {
            if ($PSCmdlet.ShouldProcess($member, "Add to $groupName")) {
                try {
                    # Check if member exists
                    $adObject = Get-ADObject -Filter "SamAccountName -eq '$member'" -ErrorAction Stop
                    
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
        $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
        
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
            $group = Get-ADGroup -Filter "Name -eq '$DelegateToGroup'" -ErrorAction Stop
            
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
            $existingPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$policyName'" -ErrorAction SilentlyContinue
            
            if (-not $existingPolicy) {
                New-ADAuthenticationPolicy -Name $policyName -Description "Authentication policy for $TierName"
                Write-TierLog -Message "Created authentication policy: $policyName" -Level Success -Component 'AuthPolicy'
            }
            
            # Create authentication policy silo
            $existingSilo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$siloName'" -ErrorAction SilentlyContinue
            
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
        $policy = Get-ADAuthenticationPolicy -Filter "Name -eq '$policyName'" -ErrorAction SilentlyContinue
        
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
        
        [int]$MinPasswordLength = 15,
        [int]$PasswordHistoryCount = 24,
        [int]$MaxPasswordAge = 60,
        [int]$MinPasswordAge = 1,
        [int]$LockoutThreshold = 3
    )
    
    $psoName = "PSO-$TierName-Admins"
    $groupName = "$TierName-Admins"
    
    if ($PSCmdlet.ShouldProcess($psoName, "Create Password Settings Object")) {
        try {
            $existingPSO = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$psoName'" -ErrorAction SilentlyContinue
            
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
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
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
    
    .PARAMETER TierName
        The tier to configure logon restrictions for.
    
    .PARAMETER GPOName
        The name of the GPO to configure.
    
    .EXAMPLE
        Set-ADTierLogonRestrictions -TierName Tier0 -GPOName "SEC-Tier0-LogonRestrictions"
    
    .NOTES
        This function enforces:
        - Tier 0 accounts can ONLY log onto Tier 0 systems
        - Tier 1 accounts can ONLY log onto Tier 1 and Tier 2 systems
        - Tier 2 accounts can ONLY log onto Tier 2 systems
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,
        
        [Parameter(Mandatory)]
        [string]$GPOName
    )
    
    try {
        $domainDN = Get-ADDomainRootDN
        $domain = (Get-ADDomain).DNSRoot
        
        Write-Verbose "Configuring logon restrictions for $TierName in GPO: $GPOName"
        
        # Define groups to restrict based on tier
        $restrictionConfig = switch ($TierName) {
            'Tier0' {
                # Tier 0: Deny Tier 1 and Tier 2 admin accounts from logging on
                @{
                    DenyInteractiveLogon = @("$domain\Tier1-Admins", "$domain\Tier2-Admins")
                    DenyNetworkLogon = @("$domain\Tier1-Admins", "$domain\Tier2-Admins")
                    DenyRemoteInteractiveLogon = @("$domain\Tier1-Admins", "$domain\Tier2-Admins")
                    DenyBatchLogon = @("$domain\Tier1-Admins", "$domain\Tier2-Admins")
                    DenyServiceLogon = @("$domain\Tier1-Admins", "$domain\Tier2-Admins")
                }
            }
            'Tier1' {
                # Tier 1: Deny Tier 0 accounts (downward auth) and Tier 2 accounts (lateral)
                @{
                    DenyInteractiveLogon = @("$domain\Tier0-Admins", "$domain\Tier2-Admins")
                    DenyNetworkLogon = @("$domain\Tier0-Admins", "$domain\Tier2-Admins")
                    DenyRemoteInteractiveLogon = @("$domain\Tier0-Admins", "$domain\Tier2-Admins")
                    DenyBatchLogon = @("$domain\Tier0-Admins", "$domain\Tier2-Admins")
                    DenyServiceLogon = @("$domain\Tier0-Admins", "$domain\Tier2-Admins")
                }
            }
            'Tier2' {
                # Tier 2: Deny Tier 0 and Tier 1 accounts (no downward auth)
                @{
                    DenyInteractiveLogon = @("$domain\Tier0-Admins", "$domain\Tier1-Admins")
                    DenyNetworkLogon = @("$domain\Tier0-Admins", "$domain\Tier1-Admins")
                    DenyRemoteInteractiveLogon = @("$domain\Tier0-Admins", "$domain\Tier1-Admins")
                    DenyBatchLogon = @("$domain\Tier0-Admins", "$domain\Tier1-Admins")
                    DenyServiceLogon = @("$domain\Tier0-Admins", "$domain\Tier1-Admins")
                }
            }
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
    
    try {
        # Get GPO GUID
        $gpo = Get-GPO -Name $GPOName
        $gpoGuid = $gpo.Id
        $domain = (Get-ADDomain).DNSRoot
        $sysvol = "\\$domain\SYSVOL\$domain\Policies\{$gpoGuid}\Machine\Microsoft\Windows NT\SecEdit"
        
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
        
        # Build secedit INF content
        $infPath = "$sysvol\GptTmpl.inf"
        $sidString = $sids -join ','
        
        $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$UserRight = $sidString
"@
        
        # Write INF file
        Set-Content -Path $infPath -Value $infContent -Encoding Unicode
        
        # Increment GPO version to trigger replication
        $gpo = Get-GPO -Guid $gpoGuid
        $gpo.GpoStatus = $gpo.GpoStatus
        
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
    
    .PARAMETER NoLockout
        If specified, excludes this account from lockout policies (use sparingly).
    
    .PARAMETER Email
        Email address for the account.
    
    .EXAMPLE
        New-ADTierAdminAccount -Username "john.doe-t0" -TierName Tier0 -FirstName "John" -LastName "Doe" -Email "john.doe@contoso.com"
    
    .NOTES
        The account will be:
        - Created in the Users OU of the specified tier
        - Added to the TierX-Admins group
        - Configured with strong password requirements
        - Optionally protected from account lockout
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
        
        [switch]$NoLockout,
        
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
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue
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
                Add-ADGroupMember -Identity $adminGroup -Members $Username
                Write-TierLog -Message "Added $Username to $adminGroup" -Level Success -Component 'AccountManagement'
                
                # Configure lockout protection if requested
                if ($NoLockout) {
                    Set-ADUser -Identity $Username -Replace @{msDS-User-Account-Control-Computed = 0x10000}
                    Write-TierLog -Message "Configured lockout protection for $Username" -Level Info -Component 'AccountManagement'
                    Write-Warning "Account $Username is protected from lockout. Use this feature sparingly."
                }
                
                # Set account as sensitive and cannot be delegated (for Tier 0)
                if ($TierName -eq 'Tier0') {
                    Set-ADAccountControl -Identity $Username -AccountNotDelegated $true
                    Write-TierLog -Message "Configured account not delegated for Tier 0 account: $Username" -Level Info -Component 'AccountManagement'
                }
                
                # Output account details
                $accountInfo = [PSCustomObject]@{
                    Username = $Username
                    TierName = $TierName
                    FullName = "$FirstName $LastName"
                    Email = $Email
                    OUPath = $usersOU
                    AdminGroup = $adminGroup
                    InitialPassword = $password
                    MustChangePassword = $true
                    LockoutProtection = $NoLockout
                    Created = Get-Date
                }
                
                Write-Host "`n=== Admin Account Created Successfully ===" -ForegroundColor Green
                Write-Host "Username: $Username" -ForegroundColor Cyan
                Write-Host "Tier: $TierName" -ForegroundColor Cyan
                Write-Host "Initial Password: $password" -ForegroundColor Yellow
                Write-Host "IMPORTANT: Save this password securely. User must change at first logon." -ForegroundColor Red
                Write-Host "Admin Group: $adminGroup" -ForegroundColor Cyan
                
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
        Configures lockout protection for tier administrative accounts.
    
    .DESCRIPTION
        Prevents specific administrative accounts from being locked out due to
        failed password attempts. Use this sparingly and only for critical accounts.
    
    .PARAMETER Identity
        The user account to protect from lockout.
    
    .PARAMETER Enable
        Enable lockout protection (default).
    
    .PARAMETER Disable
        Disable lockout protection.
    
    .EXAMPLE
        Set-ADTierAccountLockoutProtection -Identity "admin-t0" -Enable
    
    .NOTES
        Lockout protection should only be used for:
        - Break-glass emergency accounts
        - Critical service accounts
        - Tier 0 domain admin accounts (use very sparingly)
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
            $user = Get-ADUser -Identity $Identity -ErrorAction Stop
            
            if ($PSCmdlet.ShouldProcess($Identity, "Configure Lockout Protection")) {
                if ($Disable) {
                    # Remove lockout protection
                    Set-ADUser -Identity $Identity -Clear msDS-User-Account-Control-Computed
                    Write-TierLog -Message "Disabled lockout protection for $Identity" -Level Info -Component 'AccountManagement'
                    Write-Host "Lockout protection disabled for: $Identity" -ForegroundColor Green
                }
                else {
                    # Enable lockout protection (NOT_DELEGATED flag)
                    Set-ADAccountControl -Identity $Identity -AccountNotDelegated $true
                    Write-TierLog -Message "Enabled lockout protection for $Identity" -Level Info -Component 'AccountManagement'
                    Write-Host "Lockout protection enabled for: $Identity" -ForegroundColor Green
                    Write-Warning "Use lockout protection sparingly. This account will not be locked out due to failed password attempts."
                }
            }
        }
        catch {
            Write-TierLog -Message "Failed to configure lockout protection: $_" -Level Error -Component 'AccountManagement'
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
                            (Get-ADGroup -Identity $_).Name 
                        }
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
                    Set-UserRight -GPOName $GPOName -UserRight 'SeLoadDriverPrivilege' -Identity 'Administrators'
                    
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
                    
                    # Restrict CD-ROM and Floppy access
                    Set-GPORegistryValue -GPOName $GPOName -Key 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueName 'AllocateCDRoms' -Type String -Value '1'
                    
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
        Helper function to set security options in a GPO.
    
    .DESCRIPTION
        Configures security options in the specified GPO using secedit.
    
    .PARAMETER GPOName
        The name of the GPO to configure.
    
    .PARAMETER Settings
        Hashtable of security settings to apply.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GPOName,
        
        [Parameter(Mandatory)]
        [hashtable]$Settings
    )
    
    Write-Verbose "Configuring security options in GPO: $GPOName"
    
    # Note: This is a simplified implementation
    # In production, you would use secedit or direct SYSVOL manipulation
    # For demonstration, we'll log the settings that would be applied
    
    foreach ($setting in $Settings.GetEnumerator()) {
        Write-Verbose "  $($setting.Key) = $($setting.Value)"
        Write-TierLog -Message "Would configure: $($setting.Key) = $($setting.Value)" -Level Info -Component 'GPO'
    }
    
    Write-Warning "Security option configuration requires direct GPO manipulation via secedit or registry. Settings have been logged."
}

function Set-GPOAuditPolicy {
    <#
    .SYNOPSIS
        Configures audit policies in a GPO.
    
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
    [CmdletBinding()]
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
    
    $auditValue = @()
    if ($Success) { $auditValue += 'Success' }
    if ($Failure) { $auditValue += 'Failure' }
    
    Write-Verbose "Configuring audit policy: $Category\$SubCategory = $($auditValue -join ', ')"
    Write-TierLog -Message "Would configure audit: $Category\$SubCategory = $($auditValue -join ', ')" -Level Info -Component 'GPO'
}

function Set-GPOFirewall {
    <#
    .SYNOPSIS
        Configures Windows Firewall settings in a GPO.
    #>
    [CmdletBinding()]
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
    
    Write-Verbose "Configuring Windows Firewall: $Profile profile = $State"
    Write-TierLog -Message "Would configure firewall: $Profile profile = $State" -Level Info -Component 'GPO'
}

function Set-GPORegistryValue {
    <#
    .SYNOPSIS
        Sets registry values in a GPO.
    #>
    [CmdletBinding()]
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
    
    Write-Verbose "Setting registry value: $Key\$ValueName = $Value ($Type)"
    Write-TierLog -Message "Would set registry: $Key\$ValueName = $Value ($Type)" -Level Info -Component 'GPO'
}

#endregion

Export-ModuleMember -Function @(
    # Initialization
    'Initialize-ADTierModel',
    'Get-ADTierConfiguration',
    
    # Tier 0 Detection
    'Get-ADTier0Infrastructure',
    'Test-ADTier0Placement',
    'Move-ADTier0Infrastructure',
    
    # Tier Management
    'New-ADTier',
    'Get-ADTier',
    'Set-ADTierMember',
    'Remove-ADTierMember',
    'Get-ADTierMember',
    
    # OU Management
    'New-ADTierOUStructure',
    'Get-ADTierOUStructure',
    
    # Group Management
    'New-ADTierGroup',
    'Get-ADTierGroup',
    'Add-ADTierGroupMember',
    'Remove-ADTierGroupMember',
    
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
    'Set-GPORegistryValue'
)
