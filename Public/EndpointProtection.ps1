# Endpoint Protection GPO Functions

function Get-ADEndpointProtectionStatus {
    <#
    .SYNOPSIS
        Gets status of all endpoint protection GPOs.

    .DESCRIPTION
        Returns the status of all endpoint protection GPOs including:
        - AuditBaseline (per-tier)
        - AuditEnhanced (per-tier)
        - DcAuditEssential (DC OU only)
        - DcAuditComprehensive (DC OU only)
        - DefenderProtection (domain-wide)

    .EXAMPLE
        Get-ADEndpointProtectionStatus

        Returns status of all endpoint protection GPOs.

    .OUTPUTS
        Array of PSCustomObject with GPO status information.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param()

    begin {
        Write-TierLog -Message "Getting endpoint protection GPO status" -Level Info -Component 'GPO'

        # Check module availability - set flag for process block
        $script:GPModuleAvailable = Test-GroupPolicyModuleAvailable
        if (-not $script:GPModuleAvailable) {
            Write-Warning "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        # Early exit if GroupPolicy module not available
        if (-not $script:GPModuleAvailable) {
            return @()
        }

        $statuses = @()
        $domainDN = Get-ADDomainRootDN

        # Define GPO types - names must match those created by New-AD*GPO functions
        $gpoTypes = @(
            @{ Type = 'Audit-Baseline'; Description = 'Microsoft recommended baseline audit policies'; Scope = 'per-tier' }
            @{ Type = 'Audit-Enhanced'; Description = 'ACSC/NSA hardened audit with PowerShell logging'; Scope = 'per-tier' }
            @{ Type = 'DC-Audit-Essential'; Description = 'Essential security audit for Domain Controllers'; Scope = 'dc-only' }
            @{ Type = 'DC-Audit-Comprehensive'; Description = 'Comprehensive forensic audit for Domain Controllers'; Scope = 'dc-only' }
            @{ Type = 'DefenderProtection'; Description = 'Microsoft Defender Antivirus balanced protection'; Scope = 'domain-wide' }
        )

        foreach ($gpoType in $gpoTypes) {
            switch ($gpoType.Scope) {
                'per-tier' {
                    $tierStatuses = @()
                    $anyExists = $false
                    $anyLinked = $false

                    foreach ($tierKey in @('Tier0', 'Tier1', 'Tier2')) {
                        $gpoName = "SEC-$tierKey-$($gpoType.Type)"
                        $targetOU = "$($script:TierConfiguration[$tierKey].OUPath),$domainDN"

                        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                        $linked = $false
                        $linkEnabled = $false

                        if ($gpo) {
                            $anyExists = $true
                            try {
                                $links = (Get-GPInheritance -Target $targetOU -ErrorAction SilentlyContinue).GpoLinks
                                $link = $links | Where-Object { $_.DisplayName -eq $gpoName }
                                if ($link) {
                                    $linked = $true
                                    $linkEnabled = $link.Enabled
                                    $anyLinked = $true
                                }
                            }
                            catch {
                                Write-Verbose "Failed to get GPO links for $gpoName at $targetOU : $_"
                            }
                        }

                        $tierStatuses += [PSCustomObject]@{
                            Tier = $tierKey
                            Linked = $linked
                            LinkEnabled = $linkEnabled
                        }
                    }

                    $statuses += [PSCustomObject]@{
                        GpoType = $gpoType.Type
                        Name = "SEC-{Tier}-$($gpoType.Type)"
                        Description = $gpoType.Description
                        Exists = $anyExists
                        Linked = $anyLinked
                        LinkTarget = 'Per-Tier OUs'
                        LinkScope = $gpoType.Scope
                        TierStatus = $tierStatuses
                    }
                }

                'dc-only' {
                    $gpoName = "SEC-$($gpoType.Type)"
                    $dcOU = "OU=Domain Controllers,$domainDN"

                    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                    $linked = $false
                    $linkEnabled = $false
                    $created = $null
                    $modified = $null

                    if ($gpo) {
                        $created = $gpo.CreationTime.ToString('o')
                        $modified = $gpo.ModificationTime.ToString('o')

                        try {
                            $links = (Get-GPInheritance -Target $dcOU -ErrorAction SilentlyContinue).GpoLinks
                            $link = $links | Where-Object { $_.DisplayName -eq $gpoName }
                            if ($link) {
                                $linked = $true
                                $linkEnabled = $link.Enabled
                            }
                        }
                        catch {
                            Write-Verbose "Failed to get GPO links for $gpoName at $dcOU : $_"
                        }
                    }

                    $statuses += [PSCustomObject]@{
                        GpoType = $gpoType.Type
                        Name = $gpoName
                        Description = $gpoType.Description
                        Exists = ($null -ne $gpo)
                        Linked = $linked
                        LinkEnabled = $linkEnabled
                        LinkTarget = $dcOU
                        LinkScope = $gpoType.Scope
                        Created = $created
                        Modified = $modified
                    }
                }

                'domain-wide' {
                    $gpoName = "SEC-$($gpoType.Type)"

                    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                    $linked = $false
                    $linkEnabled = $false
                    $created = $null
                    $modified = $null

                    if ($gpo) {
                        $created = $gpo.CreationTime.ToString('o')
                        $modified = $gpo.ModificationTime.ToString('o')

                        try {
                            $links = (Get-GPInheritance -Target $domainDN -ErrorAction SilentlyContinue).GpoLinks
                            $link = $links | Where-Object { $_.DisplayName -eq $gpoName }
                            if ($link) {
                                $linked = $true
                                $linkEnabled = $link.Enabled
                            }
                        }
                        catch {
                            Write-Verbose "Failed to get GPO links for $gpoName at $domainDN : $_"
                        }
                    }

                    $statuses += [PSCustomObject]@{
                        GpoType = $gpoType.Type
                        Name = $gpoName
                        Description = $gpoType.Description
                        Exists = ($null -ne $gpo)
                        Linked = $linked
                        LinkEnabled = $linkEnabled
                        LinkTarget = $domainDN
                        LinkScope = $gpoType.Scope
                        Created = $created
                        Modified = $modified
                    }
                }
            }
        }

        Write-TierLog -Message "Retrieved status for $($statuses.Count) endpoint protection GPO types" -Level Success -Component 'GPO'
        $statuses
    }
}

function New-ADAuditBaselineGPO {
    <#
    .SYNOPSIS
        Creates baseline audit policy GPO for a tier.

    .DESCRIPTION
        Creates and configures a GPO with Microsoft recommended baseline audit policies.
        Audit categories include:
        - Account Logon, Account Management, DS Access
        - Logon/Logoff, Object Access, Policy Change
        - Privilege Use, System

    .PARAMETER Tier
        The tier to create the GPO for (Tier0, Tier1, or Tier2).

    .EXAMPLE
        New-ADAuditBaselineGPO -Tier 'Tier0'

        Creates SEC-Tier0-Audit-Baseline GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$Tier
    )

    begin {
        Write-TierLog -Message "Creating audit baseline GPO for $Tier" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-$Tier-Audit-Baseline"
        $domainDN = Get-ADDomainRootDN
        $targetOU = "$($script:TierConfiguration[$Tier].OUPath),$domainDN"

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create Audit Baseline GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "Microsoft recommended baseline audit policies for $Tier"
                    $result.Created = $true
                    Write-TierLog -Message "Created GPO: $gpoName" -Level Success -Component 'GPO'
                }

                # Link to tier OU
                $links = (Get-GPInheritance -Target $targetOU -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes | Out-Null
                    Write-TierLog -Message "Linked GPO $gpoName to $targetOU" -Level Success -Component 'GPO'
                }
                $result.Linked = $true

                # Configure audit policies
                $domain = Get-ADDomain
                $gpoGuid = '{' + $gpo.Id.ToString().ToUpper() + '}'
                # Use DFS-aware SYSVOL path for resilience
                $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
                $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
                $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

                if (-not (Test-Path $secEditPath)) {
                    New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
                }

                # Create backup before modification
                Backup-GptTmplFile -GptTmplPath $gptTmplPath | Out-Null

                # Audit policy values: 0=None, 1=Success, 2=Failure, 3=Both
                # Use merge function to preserve existing settings
                $auditSettings = @{
                    'Event Audit' = @{
                        'AuditSystemEvents' = '3'
                        'AuditLogonEvents' = '3'
                        'AuditObjectAccess' = '2'
                        'AuditPrivilegeUse' = '2'
                        'AuditPolicyChange' = '3'
                        'AuditAccountManage' = '3'
                        'AuditProcessTracking' = '0'
                        'AuditDSAccess' = '0'
                        'AuditAccountLogon' = '3'
                    }
                }

                $mergedContent = Merge-GptTmplContent -GptTmplPath $gptTmplPath -NewSettings $auditSettings
                $mergedContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

                # Update GPO version
                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $true
                $result.Success = $true

                Write-TierLog -Message "Configured audit baseline for $gpoName" -Level Success -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create audit baseline GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}

function New-ADAuditEnhancedGPO {
    <#
    .SYNOPSIS
        Creates enhanced audit policy GPO with PowerShell logging for a tier.

    .DESCRIPTION
        Creates and configures a GPO with ACSC/NSA hardened audit policies including:
        - Full audit policy coverage
        - PowerShell Script Block Logging
        - PowerShell Module Logging
        - PowerShell Transcription
        - Command line process auditing

    .PARAMETER Tier
        The tier to create the GPO for (Tier0, Tier1, or Tier2).

    .EXAMPLE
        New-ADAuditEnhancedGPO -Tier 'Tier0'

        Creates SEC-Tier0-Audit-Enhanced GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Tier0', 'Tier1', 'Tier2')]
        [string]$Tier
    )

    begin {
        Write-TierLog -Message "Creating enhanced audit GPO for $Tier" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-$Tier-Audit-Enhanced"
        $domainDN = Get-ADDomainRootDN
        $targetOU = "$($script:TierConfiguration[$Tier].OUPath),$domainDN"

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create Enhanced Audit GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "ACSC/NSA hardened audit policies with PowerShell logging for $Tier"
                    $result.Created = $true
                }

                # Link to tier OU
                $links = (Get-GPInheritance -Target $targetOU -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes | Out-Null
                }
                $result.Linked = $true

                # Configure enhanced audit policies
                $domain = Get-ADDomain
                $gpoGuid = '{' + $gpo.Id.ToString().ToUpper() + '}'
                # Use DFS-aware SYSVOL path for resilience
                $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
                $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
                $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

                if (-not (Test-Path $secEditPath)) {
                    New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
                }

                # Create backup before modification
                Backup-GptTmplFile -GptTmplPath $gptTmplPath | Out-Null

                # Enhanced audit policies (all success+failure) - use merge function
                $enhancedAuditSettings = @{
                    'Event Audit' = @{
                        'AuditSystemEvents' = '3'
                        'AuditLogonEvents' = '3'
                        'AuditObjectAccess' = '3'
                        'AuditPrivilegeUse' = '3'
                        'AuditPolicyChange' = '3'
                        'AuditAccountManage' = '3'
                        'AuditProcessTracking' = '1'
                        'AuditDSAccess' = '3'
                        'AuditAccountLogon' = '3'
                    }
                    'Registry Values' = @{
                        'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled' = '4,1'
                    }
                }

                $mergedContent = Merge-GptTmplContent -GptTmplPath $gptTmplPath -NewSettings $enhancedAuditSettings
                $mergedContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

                # Configure PowerShell logging via registry with proper error handling
                $registryConfigured = $true
                $registryErrors = [System.Collections.Generic.List[string]]::new()

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ValueName 'EnableScriptBlockLogging' -Type DWord -Value 1 -ErrorAction Stop
                }
                catch {
                    $registryErrors.Add("ScriptBlockLogging: $($_.Exception.Message)")
                    $registryConfigured = $false
                }

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ValueName 'EnableModuleLogging' -Type DWord -Value 1 -ErrorAction Stop
                }
                catch {
                    $registryErrors.Add("ModuleLogging: $($_.Exception.Message)")
                    $registryConfigured = $false
                }

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableTranscripting' -Type DWord -Value 1 -ErrorAction Stop
                }
                catch {
                    $registryErrors.Add("Transcription: $($_.Exception.Message)")
                    $registryConfigured = $false
                }

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableInvocationHeader' -Type DWord -Value 1 -ErrorAction Stop
                }
                catch {
                    $registryErrors.Add("InvocationHeader: $($_.Exception.Message)")
                    $registryConfigured = $false
                }

                if (-not $registryConfigured) {
                    $result.Errors += $registryErrors
                    Write-Warning "Some PowerShell logging settings failed to configure: $($registryErrors -join '; ')"
                }

                # Update GPO version
                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $registryConfigured
                $result.Success = $registryConfigured

                Write-TierLog -Message "Configured enhanced audit for $gpoName (Registry settings: $(if($registryConfigured){'Success'}else{'Partial'}))" -Level $(if($registryConfigured){'Success'}else{'Warning'}) -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create enhanced audit GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}

function New-ADDcAuditEssentialGPO {
    <#
    .SYNOPSIS
        Creates essential audit GPO for Domain Controllers.

    .DESCRIPTION
        Creates and configures a GPO with essential audit policies specifically
        designed for Domain Controllers.

    .EXAMPLE
        New-ADDcAuditEssentialGPO

        Creates SEC-DC-Audit-Essential GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-TierLog -Message "Creating DC essential audit GPO" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-DC-Audit-Essential"
        $domainDN = Get-ADDomainRootDN
        $dcOU = "OU=Domain Controllers,$domainDN"

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create DC Essential Audit GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "Essential security audit policies for Domain Controllers"
                    $result.Created = $true
                }

                # Link to Domain Controllers OU
                $links = (Get-GPInheritance -Target $dcOU -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $dcOU -LinkEnabled Yes | Out-Null
                }
                $result.Linked = $true

                # Configure DC audit policies
                $domain = Get-ADDomain
                $gpoGuid = '{' + $gpo.Id.ToString().ToUpper() + '}'
                # Use DFS-aware SYSVOL path for resilience
                $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
                $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
                $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

                if (-not (Test-Path $secEditPath)) {
                    New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
                }

                # Create backup before modification
                Backup-GptTmplFile -GptTmplPath $gptTmplPath | Out-Null

                # Use merge function to preserve existing settings
                $dcEssentialSettings = @{
                    'Event Audit' = @{
                        'AuditSystemEvents' = '3'
                        'AuditLogonEvents' = '3'
                        'AuditObjectAccess' = '3'
                        'AuditPrivilegeUse' = '3'
                        'AuditPolicyChange' = '3'
                        'AuditAccountManage' = '3'
                        'AuditProcessTracking' = '0'
                        'AuditDSAccess' = '3'
                        'AuditAccountLogon' = '3'
                    }
                }

                $mergedContent = Merge-GptTmplContent -GptTmplPath $gptTmplPath -NewSettings $dcEssentialSettings
                $mergedContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force
                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $true
                $result.Success = $true

                Write-TierLog -Message "Configured DC essential audit GPO" -Level Success -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create DC essential audit GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}

function New-ADDcAuditComprehensiveGPO {
    <#
    .SYNOPSIS
        Creates comprehensive forensic audit GPO for Domain Controllers.

    .DESCRIPTION
        Creates and configures a GPO with comprehensive forensic audit policies
        for Domain Controllers, including NTDS diagnostics logging.

    .EXAMPLE
        New-ADDcAuditComprehensiveGPO

        Creates SEC-DC-Audit-Comprehensive GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-TierLog -Message "Creating DC comprehensive audit GPO" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-DC-Audit-Comprehensive"
        $domainDN = Get-ADDomainRootDN
        $dcOU = "OU=Domain Controllers,$domainDN"

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create DC Comprehensive Audit GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "Comprehensive forensic audit policies for Domain Controllers"
                    $result.Created = $true
                }

                # Link to Domain Controllers OU
                $links = (Get-GPInheritance -Target $dcOU -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $dcOU -LinkEnabled Yes | Out-Null
                }
                $result.Linked = $true

                # Configure comprehensive DC audit policies
                $domain = Get-ADDomain
                $gpoGuid = '{' + $gpo.Id.ToString().ToUpper() + '}'
                # Use DFS-aware SYSVOL path for resilience
                $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
                $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
                $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

                if (-not (Test-Path $secEditPath)) {
                    New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
                }

                # Create backup before modification
                Backup-GptTmplFile -GptTmplPath $gptTmplPath | Out-Null

                # All events audited - use merge function
                $dcComprehensiveSettings = @{
                    'Event Audit' = @{
                        'AuditSystemEvents' = '3'
                        'AuditLogonEvents' = '3'
                        'AuditObjectAccess' = '3'
                        'AuditPrivilegeUse' = '3'
                        'AuditPolicyChange' = '3'
                        'AuditAccountManage' = '3'
                        'AuditProcessTracking' = '3'
                        'AuditDSAccess' = '3'
                        'AuditAccountLogon' = '3'
                    }
                    'Registry Values' = @{
                        'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled' = '4,1'
                    }
                }

                $mergedContent = Merge-GptTmplContent -GptTmplPath $gptTmplPath -NewSettings $dcComprehensiveSettings
                $mergedContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

                # Enable NTDS diagnostics with proper error handling
                $ntdsConfigured = $true
                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '15 Field Engineering' -Type DWord -Value 5 -ErrorAction Stop
                }
                catch {
                    $result.Errors += "NTDS Field Engineering: $($_.Exception.Message)"
                    $ntdsConfigured = $false
                }

                try {
                    Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '16 LDAP Interface Events' -Type DWord -Value 2 -ErrorAction Stop
                }
                catch {
                    $result.Errors += "NTDS LDAP Events: $($_.Exception.Message)"
                    $ntdsConfigured = $false
                }

                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $ntdsConfigured
                $result.Success = $ntdsConfigured

                Write-TierLog -Message "Configured DC comprehensive audit GPO (NTDS: $(if($ntdsConfigured){'Success'}else{'Partial'}))" -Level $(if($ntdsConfigured){'Success'}else{'Warning'}) -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create DC comprehensive audit GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}

function New-ADDefenderProtectionGPO {
    <#
    .SYNOPSIS
        Creates Windows Defender configuration GPO (domain-wide).

    .DESCRIPTION
        Creates and configures a GPO with Windows Defender Antivirus settings:
        - Real-time protection enabled
        - Cloud-delivered protection enabled
        - Automatic sample submission
        - PUA protection enabled

    .EXAMPLE
        New-ADDefenderProtectionGPO

        Creates SEC-DefenderProtection GPO.

    .OUTPUTS
        PSCustomObject with creation result.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-TierLog -Message "Creating Defender protection GPO" -Level Info -Component 'GPO'

        if (-not (Test-GroupPolicyModuleAvailable)) {
            throw "GroupPolicy module not available. Install RSAT tools."
        }
    }

    process {
        $gpoName = "SEC-DefenderProtection"
        $domainDN = Get-ADDomainRootDN

        $result = [PSCustomObject]@{
            Success = $false
            GpoName = $gpoName
            Created = $false
            Linked = $false
            Configured = $false
            Errors = @()
        }

        if ($PSCmdlet.ShouldProcess($gpoName, "Create Defender Protection GPO")) {
            try {
                # Create GPO if needed
                $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                if (-not $gpo) {
                    $gpo = New-GPO -Name $gpoName -Comment "Microsoft Defender Antivirus balanced protection settings"
                    $result.Created = $true
                }

                # Link to domain root
                $links = (Get-GPInheritance -Target $domainDN -ErrorAction SilentlyContinue).GpoLinks
                if (-not ($links | Where-Object { $_.DisplayName -eq $gpoName })) {
                    New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes | Out-Null
                }
                $result.Linked = $true

                # Configure Defender settings
                # Real-time Protection
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableRealtimeMonitoring' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableBehaviorMonitoring' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableOnAccessProtection' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableScanOnRealtimeEnable' -Type DWord -Value 0

                # Cloud Protection (MAPS)
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -ValueName 'SpynetReporting' -Type DWord -Value 2
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -ValueName 'SubmitSamplesConsent' -Type DWord -Value 1

                # PUA Protection
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'PUAProtection' -Type DWord -Value 1

                # Scan settings
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -ValueName 'DisableEmailScanning' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -ValueName 'DisableRemovableDriveScanning' -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -ValueName 'DisableArchiveScanning' -Type DWord -Value 0

                # Ensure Defender is not disabled
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'DisableAntiSpyware' -Type DWord -Value 0

                Update-GPOVersion -GPOGuid $gpo.Id

                $result.Configured = $true
                $result.Success = $true

                Write-TierLog -Message "Configured Defender protection GPO" -Level Success -Component 'GPO'
            }
            catch {
                $result.Errors += $_.Exception.Message
                Write-TierLog -Message "Failed to create Defender protection GPO: $_" -Level Error -Component 'GPO'
            }
        }

        $result
    }
}
