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
- **Logon Script Analysis**: Lists users with assigned logon scripts for enhanced visibility into login processes.
- **PowerView Integration**: Utilizes PowerView for Active Directory enumeration.

## What's New in Version 1.1
- **Added optional -ASREPRoasting parameter to identify vulnerable accounts.**
- **Added optional -LogonScripts parameter to list users with logon scripts.**
- **Updated introductory banner and help menu with the latest features.**

## Prerequisites

- **PowerShell 5.1 or later.**
- **[`PowerView.ps1`](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script must be available in the same directory as `AnalyzePermissions.ps1`.**
- **(Optional) `Get-GPOEnumeration.ps1` for extended GPO analysis.**

## Usage

Run the script using the following syntax:

![image](https://github.com/user-attachments/assets/8daab02b-90c1-4d59-b225-f029dee897ae)

```powershell
.\AnalyzePermissions.ps1 -SourceType <Users|Computers|Groups> -SourceObject <SamAccountName> [-ExtraGPOEnumeration] [-ASREPRoasting] [-LogonScripts]



