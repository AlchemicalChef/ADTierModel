# Auditing, Monitoring, and Compliance Functions

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
            $escapedTierKey = Get-EscapedADFilterValue -Value "$tierKey-Admins"
            $adminGroup = Get-ADGroup -Filter "Name -eq '$escapedTierKey'" -ErrorAction SilentlyContinue

            if ($adminGroup) {
                try {
                    $members = Get-ADGroupMember -Identity $adminGroup -Recursive -ResultPageSize 200 -ResultSetSize 5000 -ErrorAction Stop

                    foreach ($member in $members) {
                        $memberDN = (Get-ADObject -Identity $member.DistinguishedName -ErrorAction Stop).DistinguishedName

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
                catch {
                    Write-TierLog -Message "Failed to enumerate members of $($adminGroup.Name): $_" -Level Warning -Component 'Audit'
                }
            }
        }
    }

    # Check for misplaced objects
    if ($ViolationType -in @('MisplacedObjects', 'All')) {
        Write-Verbose "Checking for misplaced objects..."

        try {
            $domainControllers = @(Get-ADDomainController -ErrorAction Stop)
        }
        catch {
            Write-Verbose "Get-ADDomainController failed, using fallback method: $_"
            $domainControllers = @(Get-ADComputer -Filter "primaryGroupID -eq $($script:DC_PRIMARY_GROUP_ID)" -ErrorAction SilentlyContinue)
        }
        $tier0OU = "$($script:TierConfiguration['Tier0'].OUPath),$(Get-ADDomainRootDN)"

        foreach ($dc in $domainControllers) {
            $dcComputer = Get-ADComputer -Identity $dc.Name -ErrorAction SilentlyContinue
            if (-not $dcComputer) { continue }

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
        RiskScore = 0
        RiskLevel = 'Unknown'
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
        $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
        $groupExists = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction SilentlyContinue

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

    # Check 3a: Tier 0 Infrastructure Placement
    Write-Verbose "Checking Tier 0 infrastructure placement..."
    $tier0Infrastructure = Get-ADTier0Infrastructure
    $misplacedTier0 = $tier0Infrastructure | Where-Object { -not $_.IsInTier0 }

    $complianceResults.Checks += [PSCustomObject]@{
        CheckName = "Tier 0 Infrastructure Placement"
        Status = if ($misplacedTier0.Count -eq 0) { 'Pass' } else { 'Fail' }
        Details = "$($misplacedTier0.Count) critical Tier 0 components misplaced"
        Severity = 'Critical'
    }

    if ($misplacedTier0.Count -eq 0) { $complianceResults.Passed++ } else { $complianceResults.Failed++ }

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

    $complianceResults.RiskScore = ($complianceResults.Failed * 10) + ($complianceResults.Warnings * 3)
    $complianceResults.RiskLevel = switch ($complianceResults.RiskScore) {
        { $_ -ge 50 } { 'Critical'; break }
        { $_ -ge 25 } { 'High'; break }
        { $_ -ge 10 } { 'Medium'; break }
        default { 'Low' }
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

    $adminGroups = @{}
    foreach ($tierKey in $script:TierConfiguration.Keys) {
        $groupName = "$tierKey-Admins"
        $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
        $group = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction SilentlyContinue
        if ($group) {
            $adminGroups[$tierKey] = Get-ADGroupMember -Identity $group -Recursive
        }
    }

    $allUsers = $adminGroups.Values | ForEach-Object { $_ } | Group-Object -Property SamAccountName
    $usersInMultipleTiers = $allUsers | Where-Object { $_.Count -gt 1 }

    foreach ($user in $usersInMultipleTiers) {
        $tiers = @()
        foreach ($tierKey in $adminGroups.Keys) {
            if (@($adminGroups[$tierKey]).SamAccountName -contains $user.Name) {
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

    $requiredGroupSuffixes = @('Admins', 'Operators', 'Readers')
    foreach ($tierKey in $script:TierConfiguration.Keys) {
        foreach ($suffix in $requiredGroupSuffixes) {
            $groupName = "$tierKey-$suffix"
            $escapedGroupName = Get-EscapedADFilterValue -Value $groupName
            $group = Get-ADGroup -Filter "Name -eq '$escapedGroupName'" -ErrorAction SilentlyContinue

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

function Get-ADTierComplianceScore {
    <#
    .SYNOPSIS
        Calculates compliance score (0-100) with mathematical deductions.

    .DESCRIPTION
        Evaluates the AD tier model compliance and returns a score from 0-100.
        Deductions are applied based on violation severity.

    .PARAMETER StaleThresholdDays
        Number of days without logon to consider an account stale. Default: 90.

    .EXAMPLE
        Get-ADTierComplianceScore

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
            $compliance = Test-ADTierCompliance -ErrorAction SilentlyContinue

            if ($compliance) {
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

                        switch ($severity) {
                            'Critical' { $status.Score -= 10; $status.CriticalCount++ }
                            'High' { $status.Score -= 5; $status.HighCount++ }
                            'Medium' { $status.Score -= 2; $status.MediumCount++ }
                            'Low' { $status.Score -= 1; $status.LowCount++ }
                        }
                    }
                }
            }

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
        the specified threshold and disables them.

    .PARAMETER StaleThresholdDays
        Number of days without logon to consider an account stale. Default: 90.

    .PARAMETER TierFilter
        Optional. Limit to specific tier(s). Default: All tiers.

    .EXAMPLE
        Disable-ADStaleAccounts -StaleThresholdDays 90 -WhatIf

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

function Test-ADConnection {
    <#
    .SYNOPSIS
        Comprehensive AD connection testing with step-by-step diagnostics.

    .DESCRIPTION
        Tests the connection to Active Directory and returns detailed diagnostic
        information about each step of the connection process.

    .EXAMPLE
        Test-ADConnection

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
