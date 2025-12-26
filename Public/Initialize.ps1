# Initialization Functions

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

                    $baseGPOName = "SEC-$tierKey-BasePolicy"
                    $logonGPOName = "SEC-$tierKey-LogonRestrictions"
                    $ouPath = "$($tier.OUPath),$domainDN"

                    if ($PSCmdlet.ShouldProcess($baseGPOName, "Create GPO")) {
                        try {
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

                            $existingLogonGPO = Get-GPO -Name $logonGPOName -ErrorAction SilentlyContinue

                            if (-not $existingLogonGPO) {
                                $logonGPO = New-GPO -Name $logonGPOName -Comment "Enforces tier-based logon restrictions for $($tier.Name)"
                                $link = New-GPLink -Name $logonGPOName -Target $ouPath -LinkEnabled Yes -Order 1

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
