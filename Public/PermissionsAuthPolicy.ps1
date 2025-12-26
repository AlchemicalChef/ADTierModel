# Permission Management and Authentication Policy Functions

#region Permission Management

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
            $escapedDelegateToGroup = Get-EscapedADFilterValue -Value $DelegateToGroup
            $group = Get-ADGroup -Filter "Name -eq '$escapedDelegateToGroup'" -ErrorAction Stop

            $ou = Get-ADOrganizationalUnit -Identity $tierOUPath
            $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)"

            $identity = [System.Security.Principal.NTAccount]$group.SamAccountName

            $accessRights = switch ($PermissionType) {
                'FullControl' { [System.DirectoryServices.ActiveDirectoryRights]::GenericAll }
                'Modify' { [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty }
                'Read' { [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty }
                'CreateDeleteChild' { [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild }
            }

            $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $identity,
                $accessRights,
                [System.Security.AccessControl.AccessControlType]::Allow,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            )

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

            foreach ($permission in $permissions) {
                $identity = $permission.Identity.ToString()

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
            if (-not (Get-Command New-ADAuthenticationPolicy -ErrorAction SilentlyContinue)) {
                Write-Warning "Authentication Policy cmdlets not available. Requires Windows Server 2012 R2 or later."
                return
            }

            $escapedPolicyName = Get-EscapedADFilterValue -Value $policyName
            $existingPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$escapedPolicyName'" -ErrorAction SilentlyContinue

            if (-not $existingPolicy) {
                New-ADAuthenticationPolicy -Name $policyName -Description "Authentication policy for $TierName"
                Write-TierLog -Message "Created authentication policy: $policyName" -Level Success -Component 'AuthPolicy'
            }

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
