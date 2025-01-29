param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("Users", "Computers", "Groups")]
    [string]$SourceType,

    [Parameter(Mandatory=$false)]
    [string]$SourceObject,

    [Parameter(Mandatory=$false)]
    [switch]$ExtraGPOEnumeration,  # New Optional Parameter for Extra GPO Enumeration

    [Parameter(Mandatory=$false)]
    [switch]$ASREPRoasting,  # Optional parameter for ASREP Roasting analysis

    [Parameter(Mandatory=$false)]
    [switch]$LogonScripts,  # Optional parameter for logon script analysis

    [Parameter(Mandatory=$false)]
    [switch]$Kerberoastable,  # Optional parameter for finding kerberoastable accounts.

    [Parameter(Mandatory=$false)]
    [switch]$TrustedForUnConstrainedDelegation,  # Optional parameter for Trusted to Authenticate Objects

    [Parameter(Mandatory=$false)]
    [switch]$TrustedForConstrainedDelegation,  # Optional parameter for Constrained Delegation

    [Parameter(Mandatory=$false)]
    [switch]$AllAssignedSPNs,  # Optional parameter for fiding all assigned SPNs

    [Parameter(Mandatory=$false)]
    [switch]$DomainTrust,  #Optional for getting Domain Trust Information

    [Parameter(Mandatory=$false)]
    [switch]$DomainTrustMapping,  #Optional for Mapping Domain Trusts Accross Domains if possibile

    [Parameter(Mandatory=$false)]
    [switch]$NamingContextPermissions, #Optional for enumeration Permissions over Naming Contex.

    [Parameter(Mandatory=$false)]
    [switch]$ForeignUsers,

    [Parameter(Mandatory=$false)]
    [switch]$ForeignAcls,

    [switch]$Help
)

# Introductory Banner
Write-Host "#############################################" -ForegroundColor Cyan
Write-Host "#           AnalyzePermissions.ps1          #" -ForegroundColor Cyan
Write-Host "#       Created by m3ta | Version 1.3     #" -ForegroundColor Cyan
Write-Host "#############################################" -ForegroundColor Cyan
Write-Host "`nDescription:" -ForegroundColor Yellow
Write-Host "  This script analyzes Active Directory permissions for a specified domain object (User, Computer, or Group)."
Write-Host "  It provides categorized permissions and optional checks for ASREP Roasting, Kerberoastable users, logon scripts,"
Write-Host "  users trusted for constrationed and unconstrained delegation, objects with assigned SPNs, domain trust information,"
Write-Host "  information about foreing users and possibility to enumerate acls from current users on a target domain."
Write-Host "  Additionally, it performs GPO enumeration for Create, Link, and Modify actions and naming context permissions." -ForegroundColor Yellow
Write-Host "`nUse the -Help parameter for detailed usage instructions." -ForegroundColor Green
Write-Host "#############################################`n" -ForegroundColor Cyan


# Show help menu if -Help is specified
if ($Help) {
    Write-Host "Usage: AnalyzePermissions.ps1 -SourceType <Users|Computers|Groups> -SourceObject <SamAccountName> [-ExtraGPOEnumeration] [-ASREPRoasting] [-LogonScripts] [-Kerberoastable] [-TrustedForDelegation] [-AllAssignedSPNs]"
    Write-Host "`nParameters:"
    Write-Host "  -SourceType            The type of the source object. Must be one of: Users, Computers, or Groups."
    Write-Host "  -SourceObject          The SAMAccountName of the object to analyze permissions for."
    Write-Host "  -ExtraGPOEnumeration   An optional switch to include extra GPO enumeration."
    Write-Host "  -ASREPRoasting         An optional switch to list users vulnerable to ASREP Roasting."
    Write-Host "  -LogonScripts          An optional switch to list users with assigned logon scripts."
    Write-Host "  -Kerberoastable        An optional switch to list users with service principal names (SPNs) set."
    Write-Host "  -TrustedForUnConstrainedDelegation  An optional switch to list Objects with Unconstrained Delegation."
    Write-Host "  -TrustedForConstrainedDelegation  An optional switch to list Objects with Constrained Delegation."
    Write-Host "  -AllAssignedSPNs       An optional switch to list all objects with assigned Service Principal Names (SPNs)."
    Write-Host "  -DomainTrust		 An optional switch to list domain trusts."	
    Write-Host "  -DomainTrustMapping    An option switch to attemp the domain trust mapping across domains."
    Write-Host "  -NamingContextPermissions An optional switch to list Naming Context Permissions."
    Write-Host "  -ForeignUsers          An optional switch to list foreign users to remote domains."
    Write-Host "  -ForeignAcls           An optional switch to list acls from current domain users to remote objects."
    Write-Host "  -Help                  Display this help menu."
    Write-Host "`nDescription:"
    Write-Host "  This script analyzes Active Directory permissions for a specified domain object (User, Computer, or Group) using PowerView."
    Write-Host "  It retrieves all permissions granted to the specified object and categorizes them by Users, Computers, and Groups."
    Write-Host "  Additionally, it performs optional checks such as ASREP Roasting, Kerberoastable users, logon scripts,"
    Write-Host "  users trusted for delegation, and lists objects with assigned SPNs. It can also perform GPO enumeration for Create,"
    Write-Host "  Link, and Modify actions."
    Write-Host "`nExamples:"
    Write-Host "  .\AnalyzePermissions.ps1 -SourceType Users -SourceObject john.doe"
    Write-Host "  .\AnalyzePermissions.ps1 -SourceType Users -SourceObject john.doe -AllAssignedSPNs"
    Write-Host "  .\AnalyzePermissions.ps1 -SourceType Users -SourceObject john.doe -ASREPRoasting"
    Write-Host "  .\AnalyzePermissions.ps1 -SourceType Users -SourceObject john.doe -ExtraGPOEnumeration"
    Write-Host "`n"
    exit
}

# Ensure we are working in the correct directory
Set-Location -Path (Get-Location)

# Function to remove a module safely with error handling
function Remove-ModuleSafely {
    param (
        [string]$ModuleName
    )
    try {
        Remove-Module -Name $ModuleName -ErrorAction Stop
        Write-Host "Successfully cleared $ModuleName from memory." -ForegroundColor Green
    } catch {
        Write-Host "Error: Unable to remove $ModuleName from memory. Probably not there or already removed. $_" -ForegroundColor Red
    }
}

# Check if PowerView.ps1 is available and import it if not already loaded
$PowerViewPath = ".\PowerView.ps1"
Remove-ModuleSafely -ModuleName "PowerView"
if (-not (Get-Module -Name PowerView)) {
    if (Test-Path $PowerViewPath) {
        try {
            Import-Module $PowerViewPath -ErrorAction Stop
            Write-Host "Successfully imported PowerView.ps1." -ForegroundColor Green
        } catch {
            Write-Host "Error: Unable to import PowerView.ps1. $_" -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "Error: PowerView.ps1 is missing or cannot be imported. Enumeration for permissions cannot be done." -ForegroundColor Red
        exit
    }
} else {
    Write-Host "PowerView.ps1 is already loaded." -ForegroundColor Green
}

# Import Get-GPOEnumeration.ps1 only if -ExtraGPOEnumeration is specified
if ($ExtraGPOEnumeration) {
    $GPOEnumPath = ".\Get-GPOEnumeration.ps1"
    Remove-ModuleSafely -ModuleName "Get-GPOEnumeration"
    if (-not (Get-Module -Name Get-GPOEnumeration)) {
        if (Test-Path $GPOEnumPath) {
            try {
                Import-Module $GPOEnumPath -ErrorAction Stop
                Write-Host "Successfully imported Get-GPOEnumeration.ps1." -ForegroundColor Green
            } catch {
                Write-Host "Error: Unable to import Get-GPOEnumeration.ps1. $_" -ForegroundColor Red
                exit
            }
        } else {
            Write-Host "Error: Get-GPOEnumeration.ps1 is missing or cannot be imported. Enumeration for GPOs cannot be done." -ForegroundColor Red
            exit
        }
    } else {
        Write-Host "Get-GPOEnumeration.ps1 is already loaded." -ForegroundColor Green
    }
}

# ASREP Roasting Analysis
if ($ASREPRoasting) {
    try {
        $asrepUsers = @(Get-DomainObject -UACFilter DONT_REQ_PREAUTH | Select-Object SamAccountName, UserAccountControl)
        Write-Host "`nUsers Vulnerable to ASREP Roasting:" -ForegroundColor Yellow
        if ($asrepUsers.Count -gt 0) {
            $asrepUsers | Format-Table -Property SamAccountName, UserAccountControl -AutoSize
        } else {
            Write-Host "No users and/or vulnerable to ASREP Roasting found." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to fetch ASREP Roasting data. $_" -ForegroundColor Red
    }

}

# Logon Script Analysis
if ($LogonScripts) {
    try {
        $logonScriptUsers = @(Get-DomainUser | Where-Object { $_.scriptpath -ne $null -and $_.scriptpath -ne "" } | Select-Object SamAccountName, ScriptPath)
        if ($logonScriptUsers.Count -gt 0) {
            $logonScriptUsers | Format-Table -Property SamAccountName, ScriptPath -AutoSize
        } else {
            Write-Host "No logon scripts found for the current domain users." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to fetch logon script data. $_" -ForegroundColor Red
    }
}

# Check for Kerberoastable accounts if -Kerberoastable is specified
if ($Kerberoastable) {
    try {
        $kerberoastableUsers = @(Get-DomainUser -SPN | Select-Object SamAccountName, ServicePrincipalName)
        Write-Host "`nUsers Vulnerable to Kerberoasting:" -ForegroundColor Yellow
        if ($kerberoastableUsers.Count -gt 0) {
            $kerberoastableUsers | Format-Table -Property SamAccountName, ServicePrincipalName -AutoSize
        } else {
            Write-Host "No users vulnerable to Kerberoasting found." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to fetch Kerberoastable user data. $_" -ForegroundColor Red
    }
}

if ($TrustedForUnConstrainedDelegation) {
    Write-Host "`nUsers and/or Computers with the 'Trusted for Delegation' attribute set indicatingr Unconstrained Delegatio:" -ForegroundColor Cyan
    try {
        $trustedUsers = @(Get-DomainObject -UACFilter TRUSTED_FOR_DELEGATION | Select-Object SamAccountName, UserAccountControl)
        if ($trustedUsers.Count -gt 0) {
            $trustedUsers | Format-Table -Property SamAccountName, UserAccountControl -AutoSize
        } else {
            Write-Host "No users and/or Computers with 'Trusted for Delegation' found in the current domain." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to fetch 'Trusted for Delegation' data. $_" -ForegroundColor Red
    }
}

if ($TrustedForConstrainedDelegation) {
    Write-Host "`nUsers and/or Computers with the 'Trusted to Auth for Delegation' attribute set indicating Constrained Delegation:" -ForegroundColor Cyan
    try {
        $trustedUsers = @(Get-DomainObject -UACFilter TRUSTED_TO_AUTH_FOR_DELEGATION | Select-Object SamAccountName, UserAccountControl, msds-AllowedToDelegateto)
        if ($trustedUsers.Count -gt 0) {
            $trustedUsers | Format-Table -Property SamAccountName, UserAccountControl, msds-AllowedToDelegateto  -AutoSize
        } else {
            Write-Host "No users and/or Computers with 'Trusted to Auth for Delegation' found in the current domain." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to fetch 'Trusted to Auth for Delegation' data. $_" -ForegroundColor Red
    }
}

if ($AllAssignedSPNs) {
    Write-Host "`nObjects with assigned Service Principal Names (SPNs):" -ForegroundColor Cyan
    try {
        $spnObjects = @(Get-DomainObject | Where-Object { $_.serviceprincipalname -ne $null -and $_.serviceprincipalname -ne "" } | Select-Object SamAccountName, ServicePrincipalName)
        if ($spnObjects.Count -gt 0) {
            $spnObjects | Format-Table -Property SamAccountName, ServicePrincipalName -AutoSize
        } else {
            Write-Host "No objects with assigned SPNs found in the current domain." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to fetch assigned SPN data. $_" -ForegroundColor Red
    }
}

if ($DomainTrust) {
    Write-Host "`nAnalyzing domain trust relationships..." -ForegroundColor Cyan
    try {
        $domainTrusts = Get-DomainTrust | Select-Object SourceName, TargetName, TrustDirection, TrustAttributes
        if ($domainTrusts) {
            $domainTrusts | Format-Table -Property SourceName, TargetName, TrustDirection, TrustAttributes -AutoSize
        } else {
            Write-Host "No domain trust relationships found." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to analyze domain trust relationships. $_" -ForegroundColor Red
    }
}

# DomainTrustMapping Analysis
if ($DomainTrustMapping) {
    Write-Host "`nMapping domain trust relationships..." -ForegroundColor Cyan
    try {
        $trustMapping = Get-DomainTrustMapping | Select-Object SourceName, TargetName, TrustDirection, TrustAttributes
        if ($trustMapping) {
            $trustMapping | Format-Table -Property SourceName, TargetName, TrustDirection, TrustAttributes -AutoSize
        } else {
            Write-Host "No domain trust mappings found." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to map domain trust relationships. $_" -ForegroundColor Red
    }
}

if ($NamingContextPermissions) {
    Write-Host "`nAnalyzing permissions on the Configuration naming context with ActiveDirectory module..." -ForegroundColor Cyan

    try {
        # Import the ActiveDirectory module if not already imported
        Write-Host "Loading ActiveDirectory module..." -ForegroundColor Yellow
        Import-Module ActiveDirectory

        # Ensure the 'AD:' drive is available
        if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
            Write-Host "Creating AD: drive..." -ForegroundColor Yellow
            New-PSDrive -Name AD -PSProvider ActiveDirectory -Root "//RootDSE"
        }

        # Retrieve the Configuration naming context dynamically
        $configurationDN = ([ADSI]"LDAP://RootDSE").configurationNamingContext

        # Get ACLs for the Configuration naming context
        $acl = Get-Acl -Path "AD:$configurationDN"

        # Filter for specific permissions (GenericAll or Write)
        $filteredAcl = $acl.Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|Write" } | 
Select-Object IdentityReference, ActiveDirectoryRights

        if ($filteredAcl) {
            # Display results
            $filteredAcl | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType | 
                Format-Table -AutoSize
        } else {
            Write-Host "No permissions with 'GenericAll' or 'Write' found on the Configuration naming context." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to analyze permissions on the Configuration naming context. $_" -ForegroundColor Red
    }
}

# Foreign Users Enumeration
# Enumerate foreign users if the -ForeignUsers switch is used
if ($ForeignUsers) {
    Write-Host "`nEnumerating foreign users in the domain..." -ForegroundColor Cyan
    try {
        $ForeignUsersList = Get-DomainForeignUser | Select-Object UserName, UserDomain, GroupDomain, GroupName
        if ($ForeignUsersList.Count -gt 0) {
            $ForeignUsersList | Format-Table -AutoSize
        } else {
            Write-Host "No foreign users found in the domain." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to enumerate foreign users. $_" -ForegroundColor Red
    }
}

# Enumerate foreign ACLs if the -ForeignAcls switch is used
if ($ForeignAcls) {
    Write-Host "`nEnumerating foreign ACLs in the domain..." -ForegroundColor Cyan
    try {
        $Domain = Read-Host "Enter the target domain name"
        $DomainSid = Get-DomainSid $Domain

        $ForeignAclList = Get-DomainObjectAcl -Domain $Domain -ResolveGUIDs -Identity * | Where-Object { 
            ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and 
            ($_.AceType -match 'AccessAllowed') -and 
            ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and 
            ($_.SecurityIdentifier -notmatch $DomainSid)
        } | ForEach-Object {
            [PSCustomObject]@{
                SecurityIdentifier     = $_.SecurityIdentifier
                ResolvedName           = ConvertFrom-SID $_.SecurityIdentifier
                ActiveDirectoryRights  = $_.ActiveDirectoryRights
                ObjectDN               = $_.ObjectDN
            }
        }

        if ($ForeignAclList.Count -gt 0) {
            $ForeignAclList | Format-Table -AutoSize -Wrap
        } else {
            Write-Host "No foreign ACLs found in the domain." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to enumerate foreign ACLs. $_" -ForegroundColor Red
    }
}

function Analyze-Permissions {
    param (
        [array]$ObjectsToCheck,
        [string]$SelectedSID
    )

    $resultsUsers = @()
    $resultsComputers = @()
    $resultsGroups = @()

    # Loop through each object and check permissions
    foreach ($object in $ObjectsToCheck) {
        try {
            # Get the ACL for the object
            $acl = Get-DomainObjectAcl -Identity $object.SID

            # Check for any permissions granted to the selected SID
            $permissions = $acl | Where-Object { $_.SecurityIdentifier -eq $SelectedSID }

            # If there are permissions, process them
            if ($permissions) {
                foreach ($perm in $permissions) {
                    # Get the DistinguishedName of the object
                    $objectDN = (Get-DomainObject -Identity $object.SID).DistinguishedName

                    # Resolve the security principal name (user, computer, or group name)
                    $principalName = try {
                        (Get-DomainObject -Identity $perm.SecurityIdentifier).SamAccountName
                    } catch {
                        "Unknown"
                    }

                    # Store the results in the appropriate category
                    $entry = [PSCustomObject]@{
                        ObjectDN              = $objectDN
                        PermissionHolderName  = $principalName
                        ActiveDirectoryRights = $perm.ActiveDirectoryRights
                        SID                   = $perm.SecurityIdentifier
                    }

                    switch ($object.Type) {
                        "User" { $resultsUsers += $entry }
                        "Computer" { $resultsComputers += $entry }
                        "Group" { $resultsGroups += $entry }
                    }
                }
            }
        } catch {
            Write-Host "Error processing SID: $($object.SID)"
        }
    }

    return @{
        Users    = $resultsUsers
        Computers = $resultsComputers
        Groups   = $resultsGroups
    }
}

# Fetch the selected object based on SourceType
switch ($SourceType) {
    "Users" {
        $selectedObject = Get-DomainUser | Where-Object { $_.SamAccountName -eq $SourceObject }
    }
    "Computers" {
        $selectedObject = Get-DomainComputer | Where-Object { $_.SamAccountName -eq $SourceObject }
    }
    "Groups" {
        $selectedObject = Get-DomainGroup | Where-Object { $_.SamAccountName -eq $SourceObject }
    }
}

if (-not $selectedObject) {
    Write-Host "Error: Object '$SourceObject' not found in '$SourceType'." -ForegroundColor Red
    exit
}

$selectedSID = $selectedObject.ObjectSID

# Get all domain objects to analyze permissions
$domainObjects = @()
$userObjects = (Get-DomainUser).ForEach({ [PSCustomObject]@{ SID = $_.ObjectSID; Type = "User" } })
$computerObjects = (Get-DomainComputer).ForEach({ [PSCustomObject]@{ SID = $_.ObjectSID; Type = "Computer" } })
$groupObjects = (Get-DomainGroup).ForEach({ [PSCustomObject]@{ SID = $_.ObjectSID; Type = "Group" } })

$domainObjects += $userObjects
$domainObjects += $computerObjects
$domainObjects += $groupObjects

# Analyze permissions
$results = Analyze-Permissions -ObjectsToCheck $domainObjects -SelectedSID $selectedSID

# Output results
Write-Host "`nPermissions for Domain Users:"
if ($results.Users.Count -gt 0) {
    $results.Users | Format-Table -Property ObjectDN, PermissionHolderName, ActiveDirectoryRights, SID
} else {
    Write-Host "No permissions found for Domain Users."
}

Write-Host "`nPermissions for Domain Computers:"
if ($results.Computers.Count -gt 0) {
    $results.Computers | Format-Table -Property ObjectDN, PermissionHolderName, ActiveDirectoryRights, SID
} else {
    Write-Host "No permissions found for Domain Computers."
}

Write-Host "`nPermissions for Domain Groups:"
if ($results.Groups.Count -gt 0) {
    $results.Groups | Format-Table -Property ObjectDN, PermissionHolderName, ActiveDirectoryRights, SID
} else {
    Write-Host "No permissions found for Domain Groups."
}

# Perform GPO enumeration (only if the module is available and -ExtraGPOEnumeration is used)
if ($ExtraGPOEnumeration) {
    Write-Host "`nGPO Enumeration Results:`n"

    Write-Host "- GPOs Modified:"
    Get-GPOEnumeration -ModifyGPOs | Format-Table -AutoSize

    Write-Host "`n- GPOs Created:"
    Get-GPOEnumeration -CreateGPO | Format-Table -AutoSize

    Write-Host "`n- GPOs Linked:"
    Get-GPOEnumeration -LinkGPOs | Format-Table -AutoSize
}
