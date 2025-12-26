# Admin Account Management Functions

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

        [Alias('NoLockout')]
        [switch]$PreventDelegation,

        [string]$Email
    )

    begin {
        Write-TierLog -Message "Creating admin account: $Username for $TierName" -Level Info -Component 'AccountManagement'
        $domainDN = Get-ADDomainRootDN
    }

    process {
        try {
            if (-not $script:TierConfiguration.ContainsKey($TierName)) {
                throw "Invalid tier name: $TierName"
            }

            $tierConfig = $script:TierConfiguration[$TierName]
            $usersOU = "OU=Users,$($tierConfig.OUPath),$domainDN"

            if (-not (Test-ADTierOUExists -OUPath $usersOU)) {
                throw "Users OU does not exist: $usersOU. Run Initialize-ADTierModel -CreateOUStructure first."
            }

            $escapedUsername = Get-EscapedADFilterValue -Value $Username
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$escapedUsername'" -ErrorAction SilentlyContinue
            if ($existingUser) {
                throw "User account already exists: $Username"
            }

            if ($PSCmdlet.ShouldProcess($Username, "Create Tier Admin Account")) {

                Add-Type -AssemblyName System.Web
                $password = [System.Web.Security.Membership]::GeneratePassword(24, 8)
                $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

                if (-not $Description) {
                    $Description = "$($tierConfig.Name) Administrator Account"
                }

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

                New-ADUser @userParams
                Write-TierLog -Message "Created user account: $Username" -Level Success -Component 'AccountManagement'

                $adminGroup = "$TierName-Admins"

                if (-not (Test-ADGroupExists -GroupName $adminGroup)) {
                    throw "Admin group '$adminGroup' does not exist. Run Initialize-ADTierModel -CreateGroups first."
                }

                Add-ADGroupMember -Identity $adminGroup -Members $Username -ErrorAction Stop
                Write-TierLog -Message "Added $Username to $adminGroup" -Level Success -Component 'AccountManagement'

                if ($PreventDelegation) {
                    Set-ADAccountControl -Identity $Username -AccountNotDelegated $true
                    Write-TierLog -Message "Set AccountNotDelegated flag for $Username" -Level Info -Component 'AccountManagement'
                    Write-Warning "AccountNotDelegated flag set. NOTE: This prevents Kerberos delegation but does NOT prevent account lockout."
                }

                if ($TierName -eq 'Tier0') {
                    Set-ADAccountControl -Identity $Username -AccountNotDelegated $true
                    Write-TierLog -Message "Set AccountNotDelegated flag for Tier 0 account: $Username" -Level Info -Component 'AccountManagement'
                }

                $accountInfo = [PSCustomObject]@{
                    Username = $Username
                    TierName = $TierName
                    FullName = "$FirstName $LastName"
                    Email = $Email
                    OUPath = $usersOU
                    AdminGroup = $adminGroup
                    InitialPasswordSecure = $securePassword
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

    .PARAMETER Identity
        The user account to configure.

    .PARAMETER Enable
        Enable the "sensitive account" flag (prevents delegation).

    .PARAMETER Disable
        Disable the "sensitive account" flag (allows delegation).

    .EXAMPLE
        Set-ADTierAccountLockoutProtection -Identity "admin-t0" -Enable

    .NOTES
        For true lockout protection, use Fine-Grained Password Policies or the Protected Users group.
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
                    Set-ADAccountControl -Identity $Identity -AccountNotDelegated $false
                    Write-TierLog -Message "Cleared AccountNotDelegated flag for $Identity" -Level Info -Component 'AccountManagement'
                    Write-Host "AccountNotDelegated flag cleared for: $Identity" -ForegroundColor Green
                    Write-Warning "This account can now have credentials delegated via Kerberos. This is not recommended for Tier 0 accounts."
                }
                else {
                    Set-ADAccountControl -Identity $Identity -AccountNotDelegated $true
                    Write-TierLog -Message "Set AccountNotDelegated flag for $Identity" -Level Info -Component 'AccountManagement'
                    Write-Host "AccountNotDelegated flag set for: $Identity" -ForegroundColor Green
                    Write-Host "This account's credentials cannot be delegated via Kerberos." -ForegroundColor Cyan

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
