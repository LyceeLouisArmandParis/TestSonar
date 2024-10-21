
<#PSScriptInfo

.VERSION 1.1.20240204.1930

.GUID 09c7caf4-4d36-434d-94c4-6cc8e797f51f

.AUTHOR Administrateur

.COMPANYNAME Lycée des Sciences et du Numérique Louis ARMAND

.COPYRIGHT (CC-BY-NC-SA) 2024 Administrateur. All rights reserved.

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
This script now supports the following features:
No New Features

.PRIVATEDATA

#> 







<# 

.DESCRIPTION 
 Script de création d'identifiants sécurisés

#> 

# Parameters
Param(
    [Parameter(Mandatory = $true)][string] $File,
    [Parameter(Mandatory = $false)] [switch] $Default,
    [Parameter(Mandatory = $false)][string] $Username = "admin",
    [Parameter(Mandatory = $false)][string] $Passwd = "admin"
    
)

<# Lecture sécurisée des identifiants #>
if ($Default) {
    <# Création de crédentials par défaut (admin/admin) #>
    $secureStringPwd = $passwd | ConvertTo-SecureString -AsPlainText -Force 
    $Credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureStringPwd
}
else {
    <# Lecture des crédentials #>
    $Credentials = Get-Credential -ErrorAction Stop
}

Export-Clixml -Path $File -InputObject $Credentials
