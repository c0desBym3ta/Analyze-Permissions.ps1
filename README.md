# AnalyzePermissions.ps1

## Overview

`AnalyzePermissions.ps1` is a PowerShell script to analyze Active Directory permissions for a specified domain object (User, Computer, or Group). It categorizes permissions and optionally performs Group Policy Object (GPO) enumeration for Create, Link, and Modify actions.

## Features

- **Active Directory Permissions Analysis**: Analyze permissions for Users, Computers, or Groups.
- **Categorized Output**: Results are grouped into Users, Computers, and Groups.
- **Optional GPO Enumeration**: Lists created, linked, or modified GPOs.
- **PowerView Integration**: Utilizes PowerView for Active Directory enumeration.

## Prerequisites

- PowerShell 5.1 or later.
- [`PowerView.ps1`](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script must be available in the same directory as `AnalyzePermissions.ps1`.
- (Optional) `Get-GPOEnumeration.ps1` for extended GPO analysis.

## Usage

Run the script using the following syntax:

```powershell
.\AnalyzePermissions.ps1 -SourceType <Users|Computers|Groups> -SourceObject <SamAccountName> [-ExtraGPOEnumeration]

