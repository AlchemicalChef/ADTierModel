# OU and Group Management Functions

#region OU Management

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

#region Group Management

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

    if (-not (Test-ADGroupExists -GroupName $groupName)) {
        throw "Group '$groupName' does not exist. Run Initialize-ADTierModel -CreateGroups first."
    }

    try {
        $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
        $group = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction Stop

        foreach ($member in $Members) {
            if ($PSCmdlet.ShouldProcess($member, "Add to $groupName")) {
                try {
                    $escapedMember = Get-EscapedADFilterValue -Value $member
                    $adObject = Get-ADObject -Filter "SamAccountName -eq '$escapedMember'" -ErrorAction Stop

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
