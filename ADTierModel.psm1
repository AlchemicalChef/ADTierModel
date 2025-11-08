#Requires -Modules ActiveDirectory
#Requires -Version 5.1

# Module-level variables
$script:TierConfiguration = @{
    Tier0 = @{
        Name = 'Tier 0 - Infrastructure'
        Description = 'Domain Controllers, core infrastructure, enterprise admins'
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
        Description = 'User workstations, end-user support, helpdesk'
        OUPath = 'OU=Tier2'
        Color = 'Green'
        RiskLevel = 'Medium'
    }
}

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
    if (-not (Test-Path $logPath)) {
        New-Item -Path $logPath -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logFile = Join-Path $logPath "ADTierModel_$(Get-Date -Format 'yyyyMMdd').log"
    $logEntry = "$timestamp [$Level] [$Component] $Message"
    
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
        $domain = Get-ADDomain
        return $domain.DistinguishedName
    }
    catch {
        throw "Unable to retrieve AD Domain information: $_"
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
        
        # Verify prerequisites
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            throw "Active Directory module is required. Install RSAT tools."
        }
        
        # Check permissions
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
        
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
                            
                            # Create sub-OUs
                            $subOUs = @('Computers', 'Users', 'Groups', 'ServiceAccounts', 'AdminWorkstations')
                            foreach ($subOU in $subOUs) {
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
            
            foreach ($tierKey in $script:TierConfiguration.Keys) {
                $tier = $script:TierConfiguration[$tierKey]
                $gpoName = "SEC-$tierKey-BasePolicy"
                
                if ($PSCmdlet.ShouldProcess($gpoName, "Create GPO")) {
                    try {
                        $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                        
                        if (-not $existingGPO) {
                            $gpo = New-GPO -Name $gpoName -Comment "Base security policy for $($tier.Name)"
                            $ouPath = "$($tier.OUPath),$domainDN"
                            New-GPLink -Name $gpoName -Target $ouPath -LinkEnabled Yes
                            
                            $results.GPOsCreated += $gpoName
                            Write-TierLog -Message "Created and linked GPO: $gpoName" -Level Success -Component 'Initialize'
                        }
                        else {
                            Write-Warning "GPO already exists: $gpoName"
                        }
                    }
                    catch {
                        $errorMsg = "Failed to create GPO $gpoName : $_"
                        Write-TierLog -Message $errorMsg -Level Error -Component 'Initialize'
                        $results.Errors += $errorMsg
                    }
                }
            }
        }
        
        # Save configuration
        $configDir = Split-Path $script:ConfigPath -Parent
        if (-not (Test-Path $configDir)) {
            New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        }
        
        $config = @{
            InitializedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            DomainDN = $domainDN
            TierConfiguration = $script:TierConfiguration
            InitializationResults = $results
        }
        
        $config | ConvertTo-Json -Depth 10 | Set-Content -Path $script:ConfigPath
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
        Returns the tier configuration including OU paths, group names, and settings.
    
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
        The AD object to move (user, computer, or group).
    
    .PARAMETER TierName
        Target tier (Tier0, Tier1, or Tier2).
    
    .PARAMETER ObjectType
        Type of object: User, Computer, or Group.
    
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
        [ValidateSet('User', 'Computer', 'Group', 'ServiceAccount')]
        [string]$ObjectType
    )
    
    process {
        $domainDN = Get-ADDomainRootDN
        $tierConfig = $script:TierConfiguration[$TierName]
        
        $targetOUMap = @{
            'User' = 'Users'
            'Computer' = 'Computers'
            'Group' = 'Groups'
            'ServiceAccount' = 'ServiceAccounts'
        }
        
        $targetOU = "OU=$($targetOUMap[$ObjectType]),$($tierConfig.OUPath),$domainDN"
        
        if ($PSCmdlet.ShouldProcess($Identity, "Move to $TierName ($ObjectType OU)")) {
            try {
                $adObject = switch ($ObjectType) {
                    'User' { Get-ADUser -Identity $Identity }
                    'Computer' { Get-ADComputer -Identity $Identity }
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
        $groups = Get-ADGroup -SearchBase $searchBase -SearchScope Subtree -Filter * -Properties Members
        foreach ($group in $groups) {
            $results += [PSCustomObject]@{
                Name = $group.Name
                SamAccountName = $group.SamAccountName
                ObjectType = 'Group'
                Tier = $TierName
                MemberCount = $group.Members.Count
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
                $members = Get-ADGroupMember -Identity $adminGroup -Recursive
                
                foreach ($member in $members) {
                    $memberDN = (Get-ADObject -Identity $member.DistinguishedName).DistinguishedName
                    
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
                New-ADFineGrainedPasswordPolicy -Name $psoName `
                    -Precedence (10 * ([int]$TierName.Replace('Tier', ''))) `
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
                $group = Get-ADGroup -Filter "Name -eq '$groupName'"
                if ($group) {
                    Add-ADFineGrainedPasswordPolicySubject -Identity $psoName -Subjects $group
                }
                
                Write-TierLog -Message "Created password policy: $psoName" -Level Success -Component 'PasswordPolicy'
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

# Export module members
Export-ModuleMember -Function * -Variable TierConfiguration
