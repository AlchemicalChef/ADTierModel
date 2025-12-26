# Rust Port Functions - Advanced AD Operations

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
