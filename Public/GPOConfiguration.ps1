# GPO Security Configuration Functions

function Set-ADTierLogonRestrictions {
    <#
    .SYNOPSIS
        Configures logon restrictions in GPO to enforce tier separation.

    .DESCRIPTION
        Implements user rights assignments to prevent cross-tier authentication.
        Enforces the principle: credentials only flow downward, authentication never flows down.

        IMPORTANT: This function restricts BOTH custom tier groups AND built-in privileged
        groups (Domain Admins, Enterprise Admins, Schema Admins, etc.) per Microsoft ESAE
        best practices. Built-in Tier 0 groups must never authenticate to lower-tier systems.

    .PARAMETER TierName
        The tier to configure logon restrictions for.

    .PARAMETER GPOName
        The name of the GPO to configure.

    .PARAMETER IncludeBuiltInGroups
        Include built-in privileged groups (Domain Admins, Enterprise Admins, etc.) in
        logon restrictions. Default is $true per Microsoft best practices.

    .EXAMPLE
        Set-ADTierLogonRestrictions -TierName Tier0 -GPOName "SEC-Tier0-LogonRestrictions"

    .EXAMPLE
        Set-ADTierLogonRestrictions -TierName Tier2 -GPOName "SEC-Tier2-LogonRestrictions" -IncludeBuiltInGroups $true

    .NOTES
        This function enforces:
        - Tier 0 accounts (including Domain Admins, Enterprise Admins) can ONLY log onto Tier 0 systems
        - Tier 1 accounts can ONLY log onto Tier 1 systems (not Tier 0 or Tier 2)
        - Tier 2 accounts can ONLY log onto Tier 2 systems

        Built-in groups protected as Tier 0:
        - Domain Admins, Enterprise Admins, Schema Admins
        - Administrators (domain), Account Operators
        - Backup Operators, Server Operators, Print Operators
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName,

        [Parameter(Mandatory)]
        [string]$GPOName,

        [bool]$IncludeBuiltInGroups = $true
    )

    try {
        $domainDN = Get-ADDomainRootDN
        $domain = (Get-ADDomain).DNSRoot
        $netbiosDomain = (Get-ADDomain).NetBIOSName

        Write-Verbose "Configuring logon restrictions for $TierName in GPO: $GPOName"

        # Built-in Tier 0 privileged groups that must be protected
        $builtInTier0Groups = @(
            "$netbiosDomain\Domain Admins",
            "$netbiosDomain\Enterprise Admins",
            "$netbiosDomain\Schema Admins",
            "$netbiosDomain\Administrators",
            "$netbiosDomain\Account Operators",
            "$netbiosDomain\Backup Operators",
            "$netbiosDomain\Server Operators",
            "$netbiosDomain\Print Operators"
        )

        # Define groups to restrict based on tier
        $restrictionConfig = switch ($TierName) {
            'Tier0' {
                @{
                    DenyInteractiveLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                    DenyNetworkLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                    DenyRemoteInteractiveLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                    DenyBatchLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                    DenyServiceLogon = @("$netbiosDomain\Tier1-Admins", "$netbiosDomain\Tier2-Admins")
                }
            }
            'Tier1' {
                $tier0Groups = @("$netbiosDomain\Tier0-Admins")
                $tier2Groups = @("$netbiosDomain\Tier2-Admins")

                if ($IncludeBuiltInGroups) {
                    $tier0Groups += $builtInTier0Groups
                }

                $denyGroups = $tier0Groups + $tier2Groups

                @{
                    DenyInteractiveLogon = $denyGroups
                    DenyNetworkLogon = $denyGroups
                    DenyRemoteInteractiveLogon = $denyGroups
                    DenyBatchLogon = $denyGroups
                    DenyServiceLogon = $denyGroups
                }
            }
            'Tier2' {
                $tier0Groups = @("$netbiosDomain\Tier0-Admins")
                $tier1Groups = @("$netbiosDomain\Tier1-Admins")

                if ($IncludeBuiltInGroups) {
                    $tier0Groups += $builtInTier0Groups
                }

                $denyGroups = $tier0Groups + $tier1Groups

                @{
                    DenyInteractiveLogon = $denyGroups
                    DenyNetworkLogon = $denyGroups
                    DenyRemoteInteractiveLogon = $denyGroups
                    DenyBatchLogon = $denyGroups
                    DenyServiceLogon = $denyGroups
                }
            }
        }

        if ($IncludeBuiltInGroups -and $TierName -ne 'Tier0') {
            Write-Verbose "Including built-in Tier 0 groups in restrictions: $($builtInTier0Groups -join ', ')"
            Write-TierLog -Message "Configuring $TierName with built-in group restrictions (Domain Admins, Enterprise Admins, etc.)" -Level Info -Component 'GPO'
        }

        if ($PSCmdlet.ShouldProcess($GPOName, "Configure Logon Restrictions")) {

            if ($restrictionConfig.DenyInteractiveLogon) {
                Set-GPOUserRight -GPOName $GPOName -UserRight "SeDenyInteractiveLogonRight" -Identity $restrictionConfig.DenyInteractiveLogon
                Write-Verbose "Configured Deny Interactive Logon for: $($restrictionConfig.DenyInteractiveLogon -join ', ')"
            }

            if ($restrictionConfig.DenyNetworkLogon) {
                Set-GPOUserRight -GPOName $GPOName -UserRight "SeDenyNetworkLogonRight" -Identity $restrictionConfig.DenyNetworkLogon
                Write-Verbose "Configured Deny Network Logon for: $($restrictionConfig.DenyNetworkLogon -join ', ')"
            }

            if ($restrictionConfig.DenyRemoteInteractiveLogon) {
                Set-GPOUserRight -GPOName $GPOName -UserRight "SeDenyRemoteInteractiveLogonRight" -Identity $restrictionConfig.DenyRemoteInteractiveLogon
                Write-Verbose "Configured Deny Remote Interactive Logon for: $($restrictionConfig.DenyRemoteInteractiveLogon -join ', ')"
            }

            if ($restrictionConfig.DenyBatchLogon) {
                Set-GPOUserRight -GPOName $GPOName -UserRight "SeDenyBatchLogonRight" -Identity $restrictionConfig.DenyBatchLogon
                Write-Verbose "Configured Deny Batch Logon for: $($restrictionConfig.DenyBatchLogon -join ', ')"
            }

            if ($restrictionConfig.DenyServiceLogon) {
                Set-GPOUserRight -GPOName $GPOName -UserRight "SeDenyServiceLogonRight" -Identity $restrictionConfig.DenyServiceLogon
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

    if (-not (Test-GroupPolicyModuleAvailable)) {
        throw "GroupPolicy module not available. Install RSAT tools to use GPO functions."
    }

    try {
        $gpo = Get-GPO -Name $GPOName
        $gpoGuid = $gpo.Id.ToString('B').ToUpper()
        $domain = (Get-ADDomain).DNSRoot
        $sysvol = "\\$domain\SYSVOL\$domain\Policies\$gpoGuid\Machine\Microsoft\Windows NT\SecEdit"

        if (-not (Test-Path $sysvol)) {
            New-Item -Path $sysvol -ItemType Directory -Force | Out-Null
        }

        $sids = @()
        foreach ($id in $Identity) {
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

        $infPath = "$sysvol\GptTmpl.inf"
        $sidString = $sids -join ','

        Backup-GptTmplFile -GptTmplPath $infPath | Out-Null

        $newSettings = @{
            'Privilege Rights' = @{
                $UserRight = $sidString
            }
        }

        $mergedContent = Merge-GptTmplContent -GptTmplPath $infPath -NewSettings $newSettings
        $mergedContent | Out-File -FilePath $infPath -Encoding Unicode -Force

        Update-GPOVersion -GPOGuid $gpo.Id

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
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$TierName
    )

    if (-not (Test-GroupPolicyModuleAvailable)) {
        Write-Warning "GroupPolicy module not available. Returning empty results."
        return @()
    }

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
        Validates that each tier has appropriate logon restriction GPOs in place.

    .EXAMPLE
        Test-ADTierLogonRestrictions
    #>
    [CmdletBinding()]
    param()

    if (-not (Test-GroupPolicyModuleAvailable)) {
        Write-Warning "GroupPolicy module not available. Returning non-compliant status."
        return @{
            Compliant = $false
            Findings = @("GroupPolicy module not available - cannot verify logon restrictions")
            TierStatus = @{}
        }
    }

    $results = @{
        Compliant = $true
        Findings = @()
        TierStatus = @{}
    }

    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $gpoName = "SEC-$tierKey-LogonRestrictions"
        $domainDN = Get-ADDomainRootDN
        $ouPath = "$($script:TierConfiguration[$tierKey].OUPath),$domainDN"

        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

        if (-not $gpo) {
            $results.Compliant = $false
            $results.Findings += "Missing logon restrictions GPO for $tierKey"
            $results.TierStatus[$tierKey] = "Non-Compliant"
            continue
        }

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

    if (-not (Test-GroupPolicyModuleAvailable)) {
        Write-Warning "GroupPolicy module not available. Returning empty results."
        return @()
    }

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
