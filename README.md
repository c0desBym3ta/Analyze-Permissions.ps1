# AnalyzePermissions.ps1

## Overview

`AnalyzePermissions.ps1` is a PowerShell script to analyze Active Directory permissions for a specified domain object (User, Computer, or Group). It categorizes permissions and includes optional advanced analyses, such as Group Policy Object (GPO) enumeration, detection of users vulnerable to ASREP Roasting, and listing of users with assigned logon scripts.

## Features

- **Active Directory Permissions Analysis**: Analyze permissions for Users, Computers, or Groups.
- **Categorized Output**: Results are grouped into Users, Computers, and Groups.
- **Optional GPO Enumeration**: Lists created, linked, or modified GPOs.
- **PowerView Integration**: Utilizes PowerView for Active Directory enumeration.
- **Active Directory Permissions Analysis**: Analyze permissions for Users, Computers, or Groups.
- **Categorized Output**: Results are grouped into Users, Computers, and Groups.
- **Optional GPO Enumeration**: Lists created, linked, or modified GPOs.
- **ASREP Roasting Analysis**: Detects accounts with DONT_REQ_PREAUTH, indicating ASREP Roasting vulnerability.
- **Kerberoastable Accounts**: Detects user accounts with SPN assigned.
- **Logon Script Analysis**: Lists users with assigned logon scripts for enhanced visibility into login processes.
- **All Assigned SPNs**: Getting List of All Assigned SPNs.
- **DomainTrust**: Getting List of All Domain Trusts.
- **DomainTrustMapping**: Getting List Domain Trust Mappings across domains..
- **NamingContextPermissions**: Getting List of Naming Context permissions.
- **ForeignUsers**: Getting List of foreign users to remote domains.
- **ForeignAcls**: Getting List acls from current domain users to remote objects.
- **Delegation Analysis**: Getting list of objects with Constrained and Unconstrained delegation.
- **PowerView Integration**: Utilizes PowerView for Active Directory enumeration.

## Prerequisites

- **PowerShell 5.1 or later.**
- **[`PowerView.ps1`](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script must be available in the same directory as `AnalyzePermissions.ps1`.**
- **(Optional) `Get-GPOEnumeration.ps1` for extended GPO analysis.**

## Usage

Run the script using the following syntax:

![image](https://github.com/user-attachments/assets/8daab02b-90c1-4d59-b225-f029dee897ae)

```powershell
.\AnalyzePermissions.ps1 -SourceType <Users|Computers|Groups> -SourceObject <SamAccountName> [-ExtraGPOEnumeration] [-ASREPRoasting] [-LogonScripts] [-Kerberoastable] [-TrustedForUnConstrainedDelegation] [-TrustedForConstrainedDelegation] [-AllAssignedSPNs]

## What's New in Version 1.1
- **Added optional -ASREPRoasting parameter to identify vulnerable accounts.**
- **Added optional -LogonScripts parameter to list users with logon scripts.**
- **Updated introductory banner and help menu with the latest features.**

## What's New in Version 1.1.1
- **Fixing small bug on logon scripts not showing.**

## What's New in Version 1.2
- **Fixing small bug on printing results.**
- **Trusted for Delegation Check (-TrustedForDelegation).**
- **All Assigned SPNs Check (-AllAssignedSPNs).**
- **Finding Kerberoastable Accounts (-Kerberoastable).**
- **Enhanced Help Menu and Banner.**

## What's New in Version 1.2.1
- **Separating Constrained from Unconstrained delegation.**

## What's New in Version 1.2.2
- **Printing msds-AllowToDelegateTo value.**

## What's New in Version 1.3
- **Domain Trust and Mapping Information.**
- **Foreing ACLs and Foreign users memberships.**
- **Naming Context Permissions.**



