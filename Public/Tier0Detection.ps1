# Tier 0 Detection Functions

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
