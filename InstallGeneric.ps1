
<#PSScriptInfo

.VERSION 2.2.20240922.1713

.GUID 20749aa6-cda9-4d7d-91b6-769c3cc63c7c

.AUTHOR Pascal MOUSSIER

.COMPANYNAME Lycée des Sciences et du Numérique Louis ARMAND

.COPYRIGHT (CC-BY-NC-SA) Pascal MOUSSIER. All rights reserved.

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
This script now supports the following features:
Add Complementary script, executed at the end of the standard script.

.PRIVATEDATA

#> 









<#
.SYNOPSIS

Installation Générique d'application

.DESCRIPTION

Installation d'application à partir de l'executable.

Met à jour la configuration. La configuration est identique pour tous les types de postes.

L'installeur DOIT comporter le nom de l'executable et le numéro de version pour assurer correctement les fonction de suivi du versionning.

Par exemple pour 7zip l'executable téléchargé est 7z-2203.exe qui ne permet pas l'execution correcte du script. 
Le nom correct doit être 7z-22.03.exe ou 7-zip-22.03-win64.exe out une combinaison utilisant [-._] comme séparateur et faisant apparaitre la version au format 22.03 


.INPUTS 

-Force         : force la rénstallation, même si la version est déjà installée
-Uninstall     : désinstall uniquement le logiciel
-Latest        : Installe la dernière version (exclusif avec Version/Build)
-AppName       : préfixe/Element du nom de fichier d'installation (obligatoire, pas de défaut), 
-package       : Préfixe du nom du package si différent du nom de l'installer (pas de défaut)
-Version       : numéro de version du fichier (exclusif avec Latest, obligatoire, pas de défaut)
-Build         : numéro du build du fichier (exclusif avec Latest, pas de défaut)
-SuffixAMD64   : suffixe du nom de fichier pour AMD64 (défaut : "-win.exe", 
-InstallerPath : Chemin d'accès à l'installer (défaut : \\louisarmand.local\logiciels$\netlogon\$AppName)
-Postes        : Type de postes All, Prof, Eleve
-Complement    : Script complémentaire à executer à la fin

.OUTPUTS

None

.NOTES

    Author : Pascal MOUSSIER 
    Purpose : PowerShell script to deploy any application

#>

# Parameters
Param(
    [Parameter(Mandatory = $false)][switch] $Force = $false,  
    [Parameter(ParameterSetName = "Uninstall", Mandatory = $false)][switch] $Uninstall = $false,
    [Parameter(Mandatory = $true)][string] $AppName,
    [Parameter(Mandatory = $false)][string] $Package,
    [Parameter(ParameterSetName = "Uninstall", Mandatory = $false)]
    [Parameter(ParameterSetName = "Latest", Mandatory = $false)]
    [Parameter(ParameterSetName = "Version", Mandatory = $false)]
    [ValidateSet("All", "Prof", "Eleve")][string] $Poste,
    [Parameter(ParameterSetName = "Latest", Mandatory = $true)][switch]   $Latest = $false,
    [Parameter(ParameterSetName = "Version", Mandatory = $true)][string]  $Version,
    #    [Parameter(ParameterSetName = "Version", Mandatory = $false)][string]  $Build,
    [Parameter(Mandatory = $false)][string] $SuffixAMD64 = ".exe",
    [Parameter(Mandatory = $false)][string] $InstallerPath = "$($Configuration.Config.BasePath)\$AppName",
    [Parameter(Mandatory = $false)][string] $InstallerOptions = "/SILENT",
    [Parameter(Mandatory = $false)][string] $InstallerOptionsProf,
    [Parameter(Mandatory = $false)][string] $InstallerOptionsEleve,
    [Parameter(Mandatory = $false)][string] $Complement
)

# Functions to test if application is already installed
# x86 or AMD64 version
$libPath = "$(Split-Path -Path $PSScriptRoot -Parent)\lib"
. $libPath\psFunctions.ps1

# To check if Application is already installed
$InstallerFile = "" <# pour detecter si un fichier existe #>

if (($Latest) -or ($Uninstall)) {
    $LatestVersion = Get-LatestVersion -AppName $AppName -Path $InstallerPath 
    $Version = $LatestVersion.Version
    #    $Version = $LatestVersion.Version[0]
    #    $Build = $LatestVersion['Version'][1]
    $InstallerFile = $LatestVersion.FileName

    if (!$LatestVersion.Version) {
        <# Le fichier n'est pas trouvé, on log et on sort #>
        WriteLog -message "Executable non trouvé pour $AppName/$Package : $InstallerFile" -Severity Error -ErrorCode 128 
        exit 128 
    }
} 

[Version]$Version = $Version

#WriteLog -Message "Paramètres du Script Nom : $AppName ($Package), Version : $Version$(& { if ($build) {"-$Build"}})$(& { If ($Latest) { ", Latest" } })$(& { If ($Force) { ', Force' } })"
WriteLog -Message "Paramètres du Script Installer : $AppName $(& { if ($Package) {"($Package)"} }), Version : $Version$(& { If ($Latest) { ", Latest" } })$(& { If ($Force) { ', Force' } })"

# Si aucun package indiqué on reprend le nom de l'installer
if (!$Package) {$Package = $AppName}

$Installed = Get-AlreadyInstalled $Package $Version

if ($Uninstall) {
    # Uninstall Application
    If ($Installed) {
#        $ReturnCode = Uninstall-Package (Get-Package "*$Package*") -AllVersions -Force -ErrorAction SilentlyContinue
        $Uninstaller = (Get-Package "*$Package*").Meta.Attributes["QuietUninstallString"] -split " "
        $ReturnCode = Start-Process $uninstaller[0] -ArgumentList $uninstaller[1] -Wait -NoNewWindow

        WriteLog -Message "Uninstall $Package" -ErrorCode $ReturnCode.ExitCode
        Exit 0
    }
    else {
        WriteLog -Message "Not Exist $Package" -ErrorCode 120 -Severity Notice
        Exit 120
    }
}

if (!($Force) -and ($Installed)) {
    <# L'app est déjà installée, on log et on sort #>
    WriteLog -Message "Application : $Package OK"  
    exit 0 
}

$MSIInstaller = $InstallerFile -match "\.msi$"

if ($MSIInstaller) {
    <# On passe par msiexec et on adapte les options à passer :
        - l'executable devient un paramètre
        - on ajoute les options de MSIExec 
    #>
    if (($InstallerOptions -match "/silent") -or 
        ($InstallerOptions -match "/s")) {
        $InstallerOptions = $InstallerOptions.Replace("/silent", "/qn /norestart")
    }
    else {
        $InstallerOptions = "/qn /norestart $InstallerOptions"
    }
    $InstallerOptions = "/i $InstallerPath\$InstallerFile $InstallerOptions"
    $InstallerExecStr = "msiexec" 
}
else {
    <# On execute directement #>
    $InstallerExecStr = "$InstallerPath\$InstallerFile"
}

# Get computer type by name
$strComputerName = $env:COMPUTERNAME
if (-Not $Poste) {
    # Pas d'option en ligne de commande, on récupère le ficier de configuration
    $Poste = $Configuration.Config.Poste
}

$isPosteEleve = (($strComputerName -notmatch "mgmt") -and ($strComputerName -notmatch "prof"))

if (($isPosteEleve) -or ($Poste -eq "Eleve")) {
    # On est sur un poste élève, on applique les paramètres spécifiques
    if (-Not $InstallerOptionsEleve) {
        # Pas d'option en ligne de commande, on récupère le ficier de configuration
        $InstallerOptionsEleve = $Configuration.Config.ConfigEleve
    }
    
    $InstallerOptions += $InstallerOptionsEleve
}
else {
    # Sinon c'est un poste prof, on applique les paramètres spécifiques
    if (-Not $InstallerOptionsProf) {
        $InstallerOptionsProf = $Configuration.Config.ConfigProf
    }
    
    $InstallerOptions += $InstallerOptionsProf
}

# If exist
$Installed = Get-AlreadyInstalled $Package

if (($Installed) -or   ((($Poste -eq "Eleve") -and !$isPosteEleve) -or # Poste Elève, mais config Prof
    (($Poste -eq "Prof") -and $isPosteEleve)      # Poste Prof, mais config Elève
        )
    ) {
        # first uninstall Application
        $ReturnCode = Uninstall-Package (Get-Package "*$Package*") -AllVersions -Force -ErrorAction SilentlyContinue
        WriteLog -Message "Uninstall $Package before reinstall" -ErrorCode $ReturnCode.ExitCode
    
}        
#Install Application
$ReturnCode = Start-Process $InstallerExecStr -ArgumentList $InstallerOptions -NoNewWindow -PassThru -Wait -ErrorAction SilentlyContinue
#            WriteLog -Message "Install New Nom : $AppName, Version : $Version-$Build$(& { If ($Force) { ', Force' } })" -ErrorCode $ReturnCode.ExitCode
WriteLog -Message "Install $(& { If ($Installed) { 'Update' } else { 'New' } }) Nom : $AppName, Version : $Version$(& { If ($Force) { ', Force' } })" -ErrorCode $ReturnCode.ExitCode
        
# Si script complémentaire, on l'execute
if ($Complement) {
    <# On lance le script complémentaire après avoir déterminé le chemin absolu #>

    if (!(Split-Path -IsAbsolute -Path $Complement)) {
        <# Le chamin indiqué est relatif, on crée un chemin absolu #>
        $Complement = "$InstallerPath\$Complement"
    }

    $ComplementExt = [System.IO.Path]::GetExtension("$Complement")

    if ($ComplementExt.Equals("")) {
        <# pas d'extension, on complète par .ps1 #>
        $Complement += ".ps1"
        $ComplementExt = ".ps1"
    }

    if (Test-Path -Path $Complement) {
        <# si le fichier existe, on l'execute #>
        WriteLog -Message "Script complémentaire : $Complement"
        . $Complement
    }

}


# SIG # Begin signature block
# MIIl5wYJKoZIhvcNAQcCoIIl2DCCJdQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBEukWfAaWf/4C5
# y+Ge7idM7nMWeq58udJ15vhJLXkvaqCCH/EwggVKMIIEMqADAgECAhNwAAAAD1uv
# s42YS7ULAAEAAAAPMA0GCSqGSIb3DQEBCwUAMFwxFTATBgoJkiaJk/IsZAEZFgVs
# b2NhbDEbMBkGCgmSJomT8ixkARkWC2xvdWlzYXJtYW5kMSYwJAYDVQQDEx1BQyBM
# eWNlZSBMb3VpcyBBUk1BTkQgLSBQQVJJUzAeFw0yMTA5MTAxNTE3MjRaFw0yNjA5
# MTAxNTI3MjRaMF0xFTATBgoJkiaJk/IsZAEZFgVsb2NhbDEbMBkGCgmSJomT8ixk
# ARkWC2xvdWlzYXJtYW5kMScwJQYDVQQDEx5DQTEgTHljZWUgTG91aXMgQVJNQU5E
# IC0gUEFSSVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwJJM4Ytz0
# l3PXzSdhHyhWWRgkgBxjslQrkIXh7QN0Z13aRfzH/bJLgEKi0Bo9mPmrqQsxPMlt
# +dGJIKmm3zXb+jlUs5WMyHTZNE/FNjLvNczxdc6jt4kh5c30loTRfmRLWCUzyJ52
# 09xmQX1lr0cxZvodIaWRMl/SixUBNCpwTKy8SF2ujp/51fWyjuulUiTRiObauBSh
# WjKBmzQZpG95e9+mP2hJX950jxtgTuouTjUwOonu3UupRJErSIkFm5A+uhBzhTSC
# 4tK23atTr4UeMoa47V2f+j5fuP3RSyvq0Vq2EegfrS54tFpLXGAjeHipBsvvlekf
# EV/80hlPymztAgMBAAGjggICMIIB/jAQBgkrBgEEAYI3FQEEAwIBBDAjBgkrBgEE
# AYI3FQIEFgQU16i6+Ag0iOid8T16RDq5XxRlIy8wHQYDVR0OBBYEFACzLrnXeRqq
# 1LvAWrXcprUvhioFMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFOOP2KidwOtotSayZ1rr
# r5wTX2diMGQGA1UdHwRdMFswWaBXoFWGU2h0dHA6Ly9jcmwubG91aXNhcm1hbmQu
# bG9jYWwvQ2VydEVucm9sbC9BQyUyMEx5Y2VlJTIwTG91aXMlMjBBUk1BTkQlMjAt
# JTIwUEFSSVMuY3JsMIHlBggrBgEFBQcBAQSB2DCB1TBpBggrBgEFBQcwAYZdaHR0
# cDovL2NybC5sb3Vpc2FybWFuZC5sb2NhbC9DZXJ0RW5yb2xsLyUzQ05vbUROU1Nl
# cnZldXIlM0VfJTNDTm9tQXV0b3JpdCVDMyVBOUNlcnQlM0UoMSkuY3J0MGgGCCsG
# AQUFBzAChlxmaWxlOi8vLy9jcmwubG91aXNhcm1hbmQubG9jYWwvQ2VydEVucm9s
# bC8lM0NOb21TZXJ2ZXVyJTNFXyUzQ05vbUF1dG9yaXQlQzMlQTlDZXJ0JTNFKDEp
# LmNydDANBgkqhkiG9w0BAQsFAAOCAQEA3XuTFihN4RaI2EhpEoW1fua7g6wofpUc
# WUQzuLFA/FJXwBcpsQgMW4UCGenjq6bPstAxsEDpT1KTw7OeIzxMShyrDnCT71Zg
# 9QLnXoyYRBg/PHHqpuX7C0sFVpRoARWeKM0K0PZGrNZ17snD5kUKAWzX1U504JnK
# h1P6tNKVW8cj7nQmKN+qE2NoDSw0p2tF2gamEBOxVXsdPhGzU8pqyDab8mgLPeQ5
# t9e2mhdi/H6GO43ju9c1oOjO4h5DW1JG3EtiMdjb/WvQn8YQv/DDml0gWDhPwQ5n
# VHESh+c7XGsgJAHffZU+GbCAmPRDnKulRaFMilnvliq/TObYY5glmTCCBhQwggP8
# oAMCAQICEHojrtpTaZYPkcg+XPTH4z8wDQYJKoZIhvcNAQEMBQAwVzELMAkGA1UE
# BhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEuMCwGA1UEAxMlU2VjdGln
# byBQdWJsaWMgVGltZSBTdGFtcGluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBa
# Fw0zNjAzMjEyMzU5NTlaMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdv
# IExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcg
# Q0EgUjM2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzZjYQ0GrboIr
# 7PYzfiY05ImM0+8iEoBUPu8mr4wOgYPjoiIz5vzf7d5wu8GFK1JWN5hciN9rdqOh
# bdxLcSVwnOTJmUGfAMQm4eXOls3iQwfapEFWuOsYmBKXPNSpwZAFoLGl5y1EaGGc
# 5LByM8wjcbSF52/Z42YaJRsPXY545E3QAPN2mxDh0OLozhiGgYT1xtjXVfEzYBVm
# fQaI5QL35cTTAjsJAp85R+KAsOfuL9Z7LFnjdcuPkZWjssMETFIueH69rxbFOUD6
# 4G+rUo7xFIdRAuDNvWBsv0iGDPGaR2nZlY24tz5fISYk1sPY4gir99aXAGnoo0vX
# 3Okew4MsiyBn5ZnUDMKzUcQrpVavGacrIkmDYu/bcOUR1mVBIZ0X7P4bKf38JF7M
# p7tY3LFF/h7hvBS2tgTYXlD7TnIMPrxyXCfB5yQq3FFoXRXM3/DvqQ4shoVWF/mw
# wz9xoRku05iphp22fTfjKRIVpm4gFT24JKspEpM8mFa9eTgKWWCvAgMBAAGjggFc
# MIIBWDAfBgNVHSMEGDAWgBT2d2rdP/0BE/8WoWyCAi/QCj0UJTAdBgNVHQ4EFgQU
# X1jtTDF6omFCjVKAurNhlxmiMpswDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwEQYDVR0gBAowCDAGBgRVHSAA
# MEwGA1UdHwRFMEMwQaA/oD2GO2h0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGln
# b1B1YmxpY1RpbWVTdGFtcGluZ1Jvb3RSNDYuY3JsMHwGCCsGAQUFBwEBBHAwbjBH
# BggrBgEFBQcwAoY7aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# VGltZVN0YW1waW5nUm9vdFI0Ni5wN2MwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3Nw
# LnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQAS13sgrQ41WAyegR0lWP1M
# LWd0r8diJiH2VVRpxqFGhnZbaF+IQ7JATGceTWOS+kgnMAzGYRzpm8jIcjlSQ8Jt
# cqymKhgx1s6cFZBSfvfeoyigF8iCGlH+SVSo3HHr98NepjSFJTU5KSRKK+3nVSWY
# kSVQgJlgGh3MPcz9IWN4I/n1qfDGzqHCPWZ+/Mb5vVyhgaeqxLPbBIqv6cM74Nvy
# o1xNsllECJJrOvsrJQkajVz4xJwZ8blAdX5umzwFfk7K/0K3fpjgiXpqNOpXaJ+K
# SRW0HdE0FSDC7+ZKJJSJx78mn+rwEyT+A3z7Ss0gT5CpTrcmhUwIw9jbvnYuYRKx
# FVWjKklW3z83epDVzoWJttxFpujdrNmRwh1YZVIB2guAAjEQoF42H0BA7WBCueHV
# MDyV1e4nM9K4As7PVSNvQ8LI1WRaTuGSFUd9y8F8jw22BZC6mJoB40d7SlZIYfai
# ldlgpgbgtu6SDsek2L8qomG57Yp5qTqof0DwJ4Q4HsShvRl/59T4IJBovRwmqWaf
# H0cIPEX7cEttS5+tXrgRtMjjTOp6A9l0D6xcKZtxnLqiTH9KPCy6xZEi0UDcMTww
# 5Fl4VvoGbMG2oonuX3f1tsoHLaO/Fwkj3xVr3lDkmeUqivebQTvGkx5hGuJaSVQ+
# x60xJ/Y29RBr8Tm9XJ59AjCCBl0wggTFoAMCAQICEDpSaiyEzlXmHWX8zBLY6Ykw
# DQYJKoZIhvcNAQEMBQAwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBD
# QSBSMzYwHhcNMjQwMTE1MDAwMDAwWhcNMzUwNDE0MjM1OTU5WjBuMQswCQYDVQQG
# EwJHQjETMBEGA1UECBMKTWFuY2hlc3RlcjEYMBYGA1UEChMPU2VjdGlnbyBMaW1p
# dGVkMTAwLgYDVQQDEydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFNpZ25l
# ciBSMzUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCN0Wf0wUibvf04
# STpNYYGbw9jcRaVhBDaNBp7jmJaA9dQZW5ighrXGNMYjK7Dey5RIHMqLIbT9z9if
# 753mYbojJrKWO4ZP0N5dBT2TwZZaPb8E+hqaDZ8Vy2c+x1NiEwbEzTrPX4W3QFq/
# zJvDDbWKL99qLL42GJQzX3n5wWo60KklfFn+Wb22mOZWYSqkCVGl8aYuE12SqIS4
# MVO4PUaxXeO+4+48YpQlNqbc/ndTgszRQLF4MjxDPjRDD1M9qvpLTZcTGVzxfViy
# IToRNxPP6DUiZDU6oXARrGwyP9aglPXwYbkqI2dLuf9fiIzBugCDciOly8TPDgBk
# JmjAfILNiGcVEzg+40xUdhxNcaC+6r0juPiR7bzXHh7v/3RnlZuT3ZGstxLfmE7f
# RMAFwbHdDz5gtHLqjSTXDiNF58IxPtvmZPG2rlc+Yq+2B8+5pY+QZn+1vEifI0MD
# tiA6BxxQuOnj4PnqDaK7NEKwtD1pzoA3jJFuoJiwbatwhDkg1PIjYnMDbDW+wAc9
# FtRN6pUsO405jaBgigoFZCw9hWjLNqgFVTo7lMb5rVjJ9aSBVVL2dcqzyFW2LdWk
# 5Xdp65oeeOALod7YIIMv1pbqC15R7QCYLxcK1bCl4/HpBbdE5mjy9JR70BHuYx27
# n4XNOZbwrXcG3wZf9gEUk7stbPAoBQIDAQABo4IBjjCCAYowHwYDVR0jBBgwFoAU
# X1jtTDF6omFCjVKAurNhlxmiMpswHQYDVR0OBBYEFGjvpDJJabZSOB3qQzks9BRq
# ngyFMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoG
# CCsGAQUFBwMIMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUH
# AgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEAjBKBgNVHR8EQzBB
# MD+gPaA7hjlodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1l
# U3RhbXBpbmdDQVIzNi5jcmwwegYIKwYBBQUHAQEEbjBsMEUGCCsGAQUFBzAChjlo
# dHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdD
# QVIzNi5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0G
# CSqGSIb3DQEBDAUAA4IBgQCw3C7J+k82TIov9slP1e8YTx+fDsa//hJ62Y6SMr2E
# 89rv82y/n8we5W6z5pfBEWozlW7nWp+sdPCdUTFw/YQcqvshH6b9Rvs9qZp5Z+V7
# nHwPTH8yzKwgKzTTG1I1XEXLAK9fHnmXpaDeVeI8K6Lw3iznWZdLQe3zl+Rejdq5
# l2jU7iUfMkthfhFmi+VVYPkR/BXpV7Ub1QyyWebqkjSHJHRmv3lBYbQyk08/S7Tl
# IeOr9iQ+UN57fJg4QI0yqdn6PyiehS1nSgLwKRs46T8A6hXiSn/pCXaASnds0LsM
# 5OVoKYfbgOOlWCvKfwUySWoSgrhncihSBXxH2pAuDV2vr8GOCEaePZc0Dy6O1rYn
# KjGmqm/IRNkJghSMizr1iIOPN+23futBXAhmx8Ji/4NTmyH9K0UvXHiuA2Pa3wZx
# xR9r9XeIUVb2V8glZay+2ULlc445CzCvVSZV01ZB6bgvCuUuBx079gCcepjnZDCc
# EuIC5Se4F6yFaZ8RvmiJ4hgwggaCMIIEaqADAgECAhA2wrC9fBs656Oz3TbLyXVo
# MA0GCSqGSIb3DQEBDAUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEpl
# cnNleTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJV
# U1QgTmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9u
# IEF1dGhvcml0eTAeFw0yMTAzMjIwMDAwMDBaFw0zODAxMTgyMzU5NTlaMFcxCzAJ
# BgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNl
# Y3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQCIndi5RWedHd3ouSaBmlRUwHxJBZvMWhUP2ZQQ
# RLRBQIF3FJmp1OR2LMgIU14g0JIlL6VXWKmdbmKGRDILRxEtZdQnOh2qmcxGzjqe
# mIk8et8sE6J+N+Gl1cnZocew8eCAawKLu4TRrCoqCAT8uRjDeypoGJrruH/drCio
# 28aqIVEn45NZiZQI7YYBex48eL78lQ0BrHeSmqy1uXe9xN04aG0pKG9ki+PC6VEf
# zutu6Q3IcZZfm00r9YAEp/4aeiLhyaKxLuhKKaAdQjRaf/h6U13jQEV1JnUTCm51
# 1n5avv4N+jSVwd+Wb8UMOs4netapq5Q/yGyiQOgjsP/JRUj0MAT9YrcmXcLgsrAi
# mfWY3MzKm1HCxcquinTqbs1Q0d2VMMQyi9cAgMYC9jKc+3mW62/yVl4jnDcw6ULJ
# sBkOkrcPLUwqj7poS0T2+2JMzPP+jZ1h90/QpZnBkhdtixMiWDVgh60KmLmzXiqJ
# c6lGwqoUqpq/1HVHm+Pc2B6+wCy/GwCcjw5rmzajLbmqGygEgaj/OLoanEWP6Y52
# Hflef3XLvYnhEY4kSirMQhtberRvaI+5YsD3XVxHGBjlIli5u+NrLedIxsE88WzK
# XqZjj9Zi5ybJL2WjeXuOTbswB7XjkZbErg7ebeAQUQiS/uRGZ58NHs57ZPUfECcg
# JC+v2wIDAQABo4IBFjCCARIwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rID
# ZsswHQYDVR0OBBYEFPZ3at0//QET/xahbIICL9AKPRQlMA4GA1UdDwEB/wQEAwIB
# hjAPBgNVHRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQK
# MAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVz
# dC5jb20vVVNFUlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwNQYI
# KwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3Qu
# Y29tMA0GCSqGSIb3DQEBDAUAA4ICAQAOvmVB7WhEuOWhxdQRh+S3OyWM637ayBeR
# 7djxQ8SihTnLf2sABFoB0DFR6JfWS0snf6WDG2gtCGflwVvcYXZJJlFfym1Doi+4
# PfDP8s0cqlDmdfyGOwMtGGzJ4iImyaz3IBae91g50QyrVbrUoT0mUGQHbRcF57ol
# pfHhQEStz5i6hJvVLFV/ueQ21SM99zG4W2tB1ExGL98idX8ChsTwbD/zIExAopoe
# 3l6JrzJtPxj8V9rocAnLP2C8Q5wXVVZcbw4x4ztXLsGzqZIiRh5i111TW7HV1Ats
# Qa6vXy633vCAbAOIaKcLAo/IU7sClyZUk62XD0VUnHD+YvVNvIGezjM6CRpcWed/
# ODiptK+evDKPU2K6synimYBaNH49v9Ih24+eYXNtI38byt5kIvh+8aW88WThRpv8
# lUJKaPn37+YHYafob9Rg7LyTrSYpyZoBmwRWSE4W6iPjB7wJjJpH29308ZkpKKdp
# kiS9WNsf/eeUtvRrtIEiSJHN899L1P4l6zKVsdrUu1FX1T/ubSrsxrYJD+3f3aKg
# 6yxdbugot06YwGXXiy5UUGZvOu3lXlxA+fC13dQ5OlL2gIb5lmF6Ii8+CQOYDwXM
# +yd9dbmocQsHjcRPsccUd5E9FiswEqORvz8g3s+jR3SFCgXhN4wz7NgAnOgpCdUo
# 4uDyllU9PzCCB6AwggaIoAMCAQICEx0AAZ/UlLq0rJkqcHMABAABn9QwDQYJKoZI
# hvcNAQELBQAwXTEVMBMGCgmSJomT8ixkARkWBWxvY2FsMRswGQYKCZImiZPyLGQB
# GRYLbG91aXNhcm1hbmQxJzAlBgNVBAMTHkNBMSBMeWNlZSBMb3VpcyBBUk1BTkQg
# LSBQQVJJUzAeFw0yMzEyMTUwOTEwMDNaFw0yNTEyMTUwOTIwMDNaMIGNMRUwEwYK
# CZImiZPyLGQBGRYFbG9jYWwxGzAZBgoJkiaJk/IsZAEZFgtsb3Vpc2FybWFuZDEO
# MAwGA1UEAxMFVXNlcnMxFzAVBgNVBAMTDkFkbWluaXN0cmF0ZXVyMS4wLAYJKoZI
# hvcNAQkBFh9pbmZvcm1hdGlxdWVAbG91aXMtYXJtYW5kLnBhcmlzMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvy7Z8de9bOvdMins0BfD49fVahhn/Vyd
# uPYrSsMbQkHALeOYcXp6a2mrOS1tTxbGyNYxVjYg7j3EPcBMSFWJabKOGNFth3tj
# IoN4E0rsB9Eq3Wsykp2ntWWgNY0lZsONhOKWQ38eampFgU3ktniUac/feRsm/wSZ
# y/b5MuMNRnkMcqencrKz9lMy3DWRJRMmmjZbcIkpkEUNoXg3EqmD/zVwf2x+UQV1
# v9mu7mOwjTuKeaYflDC4y2d5/Uq8lrt5wFHX5vxffLk37HUQakEZz2cAQciFn1tR
# ApINGQcN8pR1QEz+35zPbCY2TRY9ZY7N9gcPlKWheWGA9UMvRBuQEQIDAQABo4IE
# JjCCBCIwPAYJKwYBBAGCNxUHBC8wLQYlKwYBBAGCNxUIgfGgd4fd1H+RkQeHmLld
# hcjZSBGBpJBzgcCyDQIBZAIBAjATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzBcBgNVHREEVTBT
# oDAGCisGAQQBgjcUAgOgIgwgQWRtaW5pc3RyYXRldXJAbG91aXNhcm1hbmQubG9j
# YWyBH2luZm9ybWF0aXF1ZUBsb3Vpcy1hcm1hbmQucGFyaXMwHQYDVR0OBBYEFPGo
# tYxRdxh8SZ48rLhpHn3TytvuMB8GA1UdIwQYMBaAFACzLrnXeRqq1LvAWrXcprUv
# hioFMIIBSgYDVR0fBIIBQTCCAT0wggE5oIIBNaCCATGGgdhsZGFwOi8vL0NOPUNB
# MSUyMEx5Y2VlJTIwTG91aXMlMjBBUk1BTkQlMjAtJTIwUEFSSVMsQ049c3J2LWNh
# MS13dixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vydmlj
# ZXMsQ049Q29uZmlndXJhdGlvbixEQz1sb3Vpc2FybWFuZCxEQz1sb2NhbD9jZXJ0
# aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJp
# YnV0aW9uUG9pbnSGVGh0dHA6Ly9jcmwubG91aXNhcm1hbmQubG9jYWwvQ2VydEVu
# cm9sbC9DQTElMjBMeWNlZSUyMExvdWlzJTIwQVJNQU5EJTIwLSUyMFBBUklTLmNy
# bDCCAWUGCCsGAQUFBwEBBIIBVzCCAVMwgc0GCCsGAQUFBzAChoHAbGRhcDovLy9D
# Tj1DQTElMjBMeWNlZSUyMExvdWlzJTIwQVJNQU5EJTIwLSUyMFBBUklTLENOPUFJ
# QSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25m
# aWd1cmF0aW9uLERDPWxvdWlzYXJtYW5kLERDPWxvY2FsP2NBQ2VydGlmaWNhdGU/
# YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MIGABggrBgEF
# BQcwAYZ0aHR0cDovL2NybC5sb3Vpc2FybWFuZC5sb2NhbC9DZXJ0RW5yb2xsL3Ny
# di1jYTEtd3YubG91aXNhcm1hbmQubG9jYWxfQ0ExJTIwTHljZWUlMjBMb3VpcyUy
# MEFSTUFORCUyMC0lMjBQQVJJUyg0KS5jcmwwSwYJKwYBBAGCNxkCBD4wPKA6Bgor
# BgEEAYI3GQIBoCwEKlMtMS01LTIxLTE5MjUzMTE3NzUtMjI4OTE0NTkyOC03NjQ4
# MTUxLTUwMDANBgkqhkiG9w0BAQsFAAOCAQEAQ5YMvZFsDbd/n2Ak9hlmURPR2YwK
# bsYT76xNQm0RdrBarf4K96TkpM7QQ0S8YsocHQKSRTyzxm8wh2j/47Xi5Hh0r13E
# rJViNnMYN4zEy9ajZxZx1L3veNXAqmyPDitaw/o514M9IYTPQ7smQ1U8cwtvsRUc
# KcgjkdOEjLdwWV9fp/17XJJs1fvbesUleAxTrK+ui8gqPyEl+l4OaQQRXeL6K2Xo
# +khvLWdvWnm3VlSmV8VymeQLUFi+6MSEWlnXDqPk39pO4wMS9DGe/uE9AbkpakCo
# LPzfZ7TT/2yU+iPgs+IrZqpPLK1Aqjk3nJDM5q+X4lrVObg7dcwMQiyWVzGCBUww
# ggVIAgEBMHQwXTEVMBMGCgmSJomT8ixkARkWBWxvY2FsMRswGQYKCZImiZPyLGQB
# GRYLbG91aXNhcm1hbmQxJzAlBgNVBAMTHkNBMSBMeWNlZSBMb3VpcyBBUk1BTkQg
# LSBQQVJJUwITHQABn9SUurSsmSpwcwAEAAGf1DANBglghkgBZQMEAgEFAKCBhDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEi
# BCDItvTK9OLqHGRrkWHo8lY6Q9XnNqoAOnsMfGjsGnl+UTANBgkqhkiG9w0BAQEF
# AASCAQBNJ73TBN63VQROMzqyi7RGer1fYC3RSpblPItwwjLP4t1GqblwvBy/YRNp
# iQfSeq0SBBWq0J/0AaqVhnWUJZWDBnRATVmHFbkX4ddXswI6aLJGNWofrq9Vxax1
# nioZQJtFZ8L0Ygp3pTb2P04odFRF1eNHSgEbhPGeeQrIvuJAWpPbPrxbSbzP2wpv
# qKk2G4rWNJOjifBMjzPpnqsVj/ZVLbrh0HzSoA9JdmWwxQfR8hDgp6AfH2Ra9BD/
# OkiOu0VDv+2Phazfcel9mAzrc0CSXvi6E6lPs8QO363W3L4aavKiYKvoZRJmEe4r
# WFN5kHFElAzKcakr5nUH8cWyLt5/oYIDIjCCAx4GCSqGSIb3DQEJBjGCAw8wggML
# AgEBMGkwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEs
# MCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSMzYCEDpS
# aiyEzlXmHWX8zBLY6YkwDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0BCQMxCwYJ
# KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNDA5MjIxNTEzMzJaMD8GCSqGSIb3
# DQEJBDEyBDBp9/mshbWuPy7iJMXG/4ly6wetyX9KQLbdcL+a7xxEKH/aVHbVs5B9
# Ep5z3DbbJxAwDQYJKoZIhvcNAQEBBQAEggIAcO0OvelE22Wwkb60+FCe37niS7bu
# q5CviqtQdS2kA60X7ccRn/qvnlz1PL8JmotxeitKsn40r1qYMJk0VG1zm8GIqnvG
# yVf3QdAK3BR/sM+Z8cKWsmO5UvhaO0lbvxdxTEX7/5sRIBibCEZwfFXD1NCzCOU8
# OZdX7xd9uvgaQ8uVmlu3ZND+lGfKm4RFI+01+tu7kV4S7TdtfKh3CTKTmzAm3IyN
# 6Gca34MYcWRKOKTPJQBtlWKmVWP+PXWz1et635pKUhQmkO4eQ5OTtdg814gbaIYx
# vQ0RkQndXgjQUKpxArThXoETQBVBzbqMgaO6J5gKEZiY68vy4yy031FFlyyzo4Nd
# CYEfpM5XCA63F3rHmZaishLKRFVPrUgeirC3UuoSTJOVBsy50nIAJk6Knl3wOlFO
# vs+RM4oDhpDq70heVYdxU+eOH5Y54883BTd3i/ntaNJOMMnMxWoNjOdO4inbvPij
# IWQBOWreg0ba6ZAQ0EeSkJ3VJQPe9HfxN5hLbS3cEkKTL/YA7Aqx22FxMVUkW/1z
# JpUeMO4c1cNJUtdk7NGFmZsy5eSHVZEhqRGTmkGIQx5/6+YNMMsUjTnkliaGDf1w
# YacGvmon2EWIlSC3FQjNuQ4j2TNxPN91Uyn2q5LXp3JAL/DekZmnKmRXVct9O90D
# yEM1NbzfW4k2/Fk=
# SIG # End signature block
