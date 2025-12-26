# Tier Management Functions

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

function Get-ADTierCounts {
    <#
    .SYNOPSIS
        Gets the count of objects in each tier.

    .DESCRIPTION
        Returns the count of users, computers, and groups in each tier OU,
        plus a count of unassigned objects not in any tier.

    .EXAMPLE
        Get-ADTierCounts

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

function Get-ADTierInitializationStatus {
    <#
    .SYNOPSIS
        Checks if the tier model is initialized with detailed status.

    .DESCRIPTION
        Returns comprehensive status about the tier model initialization including
        OU existence, group existence, and any missing components.

    .EXAMPLE
        Get-ADTierInitializationStatus

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
