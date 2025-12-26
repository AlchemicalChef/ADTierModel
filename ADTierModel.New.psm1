#Requires -Modules ActiveDirectory
#Requires -Version 5.1

<#
.SYNOPSIS
    AD Tier Model PowerShell Module

.DESCRIPTION
    Implements Microsoft's three-tier administrative model (ESAE) for Active Directory.
    This module provides functions for:
    - Creating and managing tier OU structures
    - Enforcing logon restrictions between tiers
    - Managing tier membership and permissions
    - Auditing and compliance checking
    - GPO configuration for tier security

.NOTES
    Version: 2.0.0
    Author: AD Tier Model Team
    Requires: ActiveDirectory module, GroupPolicy module (for GPO functions)
#>

# Module-level variables

# Constants - Named values for clarity and maintainability
$script:GPO_USER_VERSION_INCREMENT = 65536   # High 16 bits: User configuration version
$script:GPO_COMPUTER_VERSION_INCREMENT = 1    # Low 16 bits: Computer configuration version
$script:AD_MAX_VALUES_RANGE = 1500            # Default MaxValRange for ranged retrieval
$script:MAX_LOG_MESSAGE_LENGTH = 4000         # Maximum log message length before truncation
$script:SAFETY_LIMIT_ITERATIONS = 1000000     # Safety limit for infinite loop prevention
$script:DC_PRIMARY_GROUP_ID = 516             # primaryGroupID for Domain Controllers

$script:TierConfiguration = @{
    Tier0 = @{
        Name = 'Tier 0 - Infrastructure'
        Description = 'Domain Controllers, core identity infrastructure, domain/enterprise admins'
        OUPath = 'OU=Tier0'
        Color = 'Red'
        RiskLevel = 'Critical'
    }
    Tier1 = @{
        Name = 'Tier 1 - Server Management'
        Description = 'Application servers, file servers, server administrators'
        OUPath = 'OU=Tier1'
        Color = 'Yellow'
        RiskLevel = 'High'
    }
    Tier2 = @{
        Name = 'Tier 2 - Workstation Management'
        Description = 'User workstations, etc'
        OUPath = 'OU=Tier2'
        Color = 'Green'
        RiskLevel = 'Medium'
    }
}

$script:Tier0CriticalRoles = @{
    DomainController = @{
        Name = 'Domain Controller'
        Detection = {
            try {
                $dcOU = "OU=Domain Controllers,$((Get-ADDomain -ErrorAction Stop).DistinguishedName)"
                (Get-ADComputer -SearchBase $dcOU -Filter * -Properties Name -ErrorAction SilentlyContinue).Name
            } catch {
                (Get-ADComputer -Filter "primaryGroupID -eq $($script:DC_PRIMARY_GROUP_ID)" -Properties Name -ErrorAction SilentlyContinue).Name
            }
        }
        Description = 'Active Directory Domain Controllers'
    }
    ADFS = @{
        Name = 'AD FS Server'
        Detection = {
            (Get-ADComputer -Filter "ServicePrincipalName -like '*http*'" -Properties ServicePrincipalName -ErrorAction SilentlyContinue |
                Where-Object { $_.ServicePrincipalName -like '*http/sts*' -or $_.ServicePrincipalName -like '*http/adfs*' }).Name
        }
        Description = 'Active Directory Federation Services servers'
    }
    EntraConnect = @{
        Name = 'Entra Connect (AAD Connect)'
        Detection = {
            (Get-ADComputer -Filter "Description -like '*Connect*'" -Properties Description -ErrorAction SilentlyContinue |
                Where-Object { $_.Description -like '*Azure AD Connect*' -or $_.Description -like '*AAD Connect*' -or $_.Description -like '*Entra Connect*' }).Name
        }
        Description = 'Microsoft Entra Connect (Azure AD Connect) synchronization servers'
    }
    CertificateAuthority = @{
        Name = 'Certificate Authority'
        Detection = {
            (Get-ADComputer -Filter "Description -like '*Certificate*' -or Description -like '*CA*'" -Properties Description -ErrorAction SilentlyContinue |
                Where-Object { $_.Description -like '*Certificate Authority*' -or $_.Description -like '*CA Server*' }).Name
        }
        Description = 'Enterprise Certificate Authority servers'
    }
    PAW = @{
        Name = 'Privileged Access Workstation'
        Detection = {
            try {
                @(
                    Get-ADComputer -Filter "Name -like 'PAW-*'" -Properties Name -ErrorAction SilentlyContinue
                    Get-ADComputer -Filter "Name -like '*-PAW-*'" -Properties Name -ErrorAction SilentlyContinue
                    Get-ADComputer -Filter "Description -like '*PAW*'" -Properties Name, Description -ErrorAction SilentlyContinue
                    Get-ADComputer -Filter "Description -like '*Privileged Access*'" -Properties Name, Description -ErrorAction SilentlyContinue
                ) | Where-Object { $_ } | Select-Object -Unique -ExpandProperty Name
            }
            catch {
                @()
            }
        }
        Description = 'Privileged Access Workstations for Tier 0 administration'
    }
}

$script:StandardSubOUs = @('Computers', 'Users', 'Groups', 'ServiceAccounts', 'AdminWorkstations')

$script:ConfigPath = "$env:ProgramData\ADTierModel\config.json"

# Get module root path
$ModuleRoot = $PSScriptRoot

# Dot-source private functions (internal helpers)
$PrivateFunctions = @(
    'Core.ps1'
)

foreach ($function in $PrivateFunctions) {
    $path = Join-Path -Path $ModuleRoot -ChildPath "Private\$function"
    if (Test-Path $path) {
        . $path
        Write-Verbose "Loaded private functions from: $function"
    }
    else {
        Write-Warning "Private function file not found: $path"
    }
}

# Dot-source public functions
$PublicFunctions = @(
    'Initialize.ps1',
    'Tier0Detection.ps1',
    'TierManagement.ps1',
    'AuditingCompliance.ps1',
    'GPOConfiguration.ps1',
    'OUGroupManagement.ps1',
    'PermissionsAuthPolicy.ps1',
    'AdminAccountManagement.ps1',
    'SecurityPolicies.ps1',
    'RemainingFunctions.ps1',
    'EndpointProtection.ps1'
)

foreach ($function in $PublicFunctions) {
    $path = Join-Path -Path $ModuleRoot -ChildPath "Public\$function"
    if (Test-Path $path) {
        . $path
        Write-Verbose "Loaded public functions from: $function"
    }
    else {
        Write-Warning "Public function file not found: $path"
    }
}

# Export public functions
Export-ModuleMember -Function @(
    # Initialization
    'Initialize-ADTierModel',
    'Get-ADTierConfiguration',
    'Get-ADTierInitializationStatus',

    # Tier 0 Detection
    'Get-ADTier0Infrastructure',
    'Test-ADTier0Placement',
    'Move-ADTier0Infrastructure',
    'Get-ADFSMORoleHolders',

    # Tier Management
    'New-ADTier',
    'Get-ADTier',
    'Set-ADTierMember',
    'Remove-ADTierMember',
    'Get-ADTierMember',
    'Get-ADTierCounts',

    # OU Management
    'New-ADTierOUStructure',
    'Get-ADTierOUStructure',

    # Group Management
    'New-ADTierGroup',
    'Get-ADTierGroup',
    'Add-ADTierGroupMember',
    'Remove-ADTierGroupMember',
    'Get-ADTransitiveGroupMembership',
    'Resolve-ADPrimaryGroup',
    'Get-ADLargeGroupMembers',

    # Permission Management
    'Set-ADTierPermission',
    'Get-ADTierPermission',
    'Test-ADTierPermissionCompliance',

    # Auditing and Monitoring
    'Get-ADTierAccessReport',
    'Get-ADTierViolation',
    'Test-ADTierCompliance',
    'Export-ADTierAuditLog',

    # Security Policies
    'Set-ADTierAuthenticationPolicy',
    'Get-ADTierAuthenticationPolicy',
    'Set-ADTierPasswordPolicy',

    # Cross-Tier Detection
    'Find-ADCrossTierAccess',
    'Find-ADTierMisconfiguration',
    'Repair-ADTierViolation',

    # GPO Security Configuration
    'Set-ADTierLogonRestrictions',
    'Set-GPOUserRight',
    'Get-ADTierLogonRestrictions',
    'Test-ADTierLogonRestrictions',
    'Get-GPOLinks',

    # Admin Account Management
    'New-ADTierAdminAccount',
    'Set-ADTierAccountLockoutProtection',
    'Get-ADTierAdminAccount',

    # Enhanced Security Policies
    'Set-ADTierSecurityPolicy',
    'Set-GPOSecurityOption',
    'Set-GPOAuditPolicy',
    'Set-GPOFirewall',
    'Set-GPORegistryValue',

    # Compliance (from Rust port)
    'Get-ADTierComplianceScore',
    'Disable-ADStaleAccounts',
    'Set-ADServiceAccountHardening',

    # Diagnostics (from Rust port)
    'Test-ADConnection',

    # Endpoint Protection GPOs (from Rust port)
    'Get-ADEndpointProtectionStatus',
    'New-ADAuditBaselineGPO',
    'New-ADAuditEnhancedGPO',
    'New-ADDcAuditEssentialGPO',
    'New-ADDcAuditComprehensiveGPO',
    'New-ADDefenderProtectionGPO'
)
