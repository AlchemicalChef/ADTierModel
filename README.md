# Active Directory Tier Model PowerShell Module

## Overview

The **ADTierModel** module implements a comprehensive tiered administrative model for Active Directory environments, following the Microsoft's Enhanced Security Administrative Environment (ESAE) best practices, while also being maintainable. This module enforces separation of duties and reduces the risk of privilege escalation by logically separating administrative access into three tiers.


## Architecture

### Tier Structure

- **Tier 0 (Identity Infrastructure)**: Domain controllers, core infrastructure, Enterprise/Domain Admins, ADConnect/EntraConnect, ADFS
- **Tier 1 (Server Management)**: Application servers, database servers, file servers
- **Tier 2 (Workstation Management)**: User workstations, end-user devices

### Key Principles

1. **Separation of Duties**: Administrators operate within their assigned tier
2. **No Downward Authentication**: Higher tier credentials never used on lower tiers
3. **Protected Administration**: Administrative actions logged and audited
4. **Minimal Privileged Accounts**: Least privilege access model

## Installation

```powershell
# Import the module
Import-Module .\ADTierModel.psd1

# Verify installation
Get-Module ADTierModel

# View available commands
Get-Command -Module ADTierModel
