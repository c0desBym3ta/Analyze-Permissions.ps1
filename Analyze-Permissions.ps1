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

    [switch]$Help
)

# Introductory Banner
Write-Host "#############################################" -ForegroundColor Cyan
Write-Host "#           AnalyzePermissions.ps1          #" -ForegroundColor Cyan
Write-Host "#       Created by m3ta | Version 1.1       #" -ForegroundColor Cyan
Write-Host "#############################################" -ForegroundColor Cyan
Write-Host "`nDescription:" -ForegroundColor Yellow
Write-Host "  This script analyzes Active Directory permissions for a specified domain object (User, Computer, or Group)."
Write-Host "  It provides categorized permissions and optional analyses, including:"
Write-Host "    - Enumeration of Group Policy Objects (GPOs) for Create, Link, and Modify actions."
Write-Host "    - Detection of users vulnerable to ASREP Roasting (accounts with DONT_REQ_PREAUTH)."
Write-Host "    - Listing of users with assigned logon scripts."
Write-Host "`nUse the -Help parameter for detailed usage instructions." -ForegroundColor Green
Write-Host "#############################################`n" -ForegroundColor Cyan


# Show help menu if -Help is specified
if ($Help) {
    Write-Host "Usage: AnalyzePermissions.ps1 -SourceType <Users|Computers|Groups> -SourceObject <SamAccountName> [-ExtraGPOEnumeration] [-ASREPRoasting] [-LogonScripts]"
    Write-Host "`nParameters:"
    Write-Host "  -SourceType        The type of the source object. Must be one of: Users, Computers, or Groups."
    Write-Host "  -SourceObject      The SAMAccountName of the object to analyze permissions for."
    Write-Host "  -ExtraGPOEnumeration  An optional switch to include extra GPO enumeration."
    Write-Host "  -ASREPRoasting     An optional switch to identify users vulnerable to ASREP Roasting."
    Write-Host "  -LogonScripts      An optional switch to list users with assigned logon scripts."
    Write-Host "  -Help              Display this help menu."
    Write-Host "`nDescription:"
    Write-Host "  This script analyzes Active Directory permissions for a specified domain object (User, Computer, or Group) using PowerView."
    Write-Host "  It retrieves all permissions granted to the specified object and categorizes them by Users, Computers, and Groups."
    Write-Host "  Additionally:"
    Write-Host "    - Performs optional GPO enumeration for Create, Link, and Modify actions."
    Write-Host "    - Identifies users vulnerable to ASREP Roasting (accounts with DONT_REQ_PREAUTH)."
    Write-Host "    - Lists users with assigned logon scripts."
    Write-Host "`nExample:"
    Write-Host "  .\AnalyzePermissions.ps1 -SourceType Users -SourceObject john.doe"
    Write-Host "  .\AnalyzePermissions.ps1 -SourceType Users -SourceObject john.doe -ExtraGPOEnumeration -ASREPRoasting -LogonScripts"
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
    Write-Host "`nUsers Vulnerable to ASREP Roasting:" -ForegroundColor Yellow
    try {
        $asrepUsers = Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select-Object SamAccountName, UserAccountControl
        if ($asrepUsers.Count -gt 0) {
            $asrepUsers | Format-Table -Property SamAccountName, UserAccountControl -AutoSize
        } else {
            Write-Host "No users vulnerable to ASREP Roasting found." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to fetch ASREP Roasting data. $_" -ForegroundColor Red
    }
}

# Logon Script Analysis
if ($LogonScripts) {
    Write-Host "`nUsers with Logon Scripts:" -ForegroundColor Yellow
    try {
        $logonScriptUsers = Get-DomainUser | Where-Object { $_.scriptpath -ne $null -and $_.scriptpath -ne "" } | Select-Object SamAccountName, ScriptPath
        if ($logonScriptUsers.Count -gt 0) {
            $logonScriptUsers | Format-Table -Property SamAccountName, ScriptPath -AutoSize
        } else {
            Write-Host "No logon scripts found for the current domain users." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error: Unable to fetch logon script data. $_" -ForegroundColor Red
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
