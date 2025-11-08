@{
    RootModule = 'ADTierModel.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d'
    Author = 'Enterprise Security Team'
    CompanyName = 'Your Organization'
    Copyright = '(c) 2025. All rights reserved.'
    Description = 'Implements a comprehensive tiered administrative model for Active Directory environments with Tier 0 (Infrastructure), Tier 1 (Servers), and Tier 2 (Workstations) separation.'
    
    PowerShellVersion = '5.1'
    
    RequiredModules = @('ActiveDirectory')
    
    FunctionsToExport = @(
        # Initialization
        'Initialize-ADTierModel',
        'Get-ADTierConfiguration',
        
        # Tier Management
        'New-ADTier',
        'Get-ADTier',
        'Set-ADTierMember',
        'Remove-ADTierMember',
        'Get-ADTierMember',
        
        # OU Management
        'New-ADTierOUStructure',
        'Get-ADTierOUStructure',
        
        # Group Management
        'New-ADTierGroup',
        'Get-ADTierGroup',
        'Add-ADTierGroupMember',
        'Remove-ADTierGroupMember',
        
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
        'Repair-ADTierViolation'
    )
    
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'Security', 'TierModel', 'Administration', 'ESAE')
            ProjectUri = 'https://github.com/yourorg/ADTierModel'
            LicenseUri = 'https://github.com/yourorg/ADTierModel/LICENSE'
            ReleaseNotes = 'Initial release of AD Tier Model implementation'
        }
    }
}
