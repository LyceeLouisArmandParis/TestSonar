<#PSScriptInfo

.VERSION 1.11.20240907.2306

.GUID ccde9ce8-62ad-417e-b674-b6e1fa45531e

.AUTHOR pascal.moussier@louis-armand.paris

.COMPANYNAME Lycée des Sciences et du Numérique Louis ARMAND

.COPYRIGHT 2023 Pascal MOUSSIER. All rights reserved.

.TAGS Library Versionning Logging

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
 Bibliothèque de fonction liées à l'installation, Gestion des fichiers de log. 

#> 

<#
.SYNOPSIS

Install library

.DESCRIPTION

Bibliothèque de fonction liées à l'installation,
Gestion des fichiers de log.

Une ligne est ajoutée automatiquement à chaque appel de la bibliothèque (en début de script appelant).

.INPUTS

-LogFile : Fichier de log (défaut : Nom du script appelant dans le dossier de bibliothèque)

.OUTPUTS

None

.NOTES

    Author : Pascal MOUSSIER 
    Purpose : PowerShell Functions library script

#>

param (
    [Parameter (Mandatory = $false)]$LogFile,
    [Parameter (Mandatory = $false)]$ConfigFile
)

function Get-AlreadyInstalled {
    <#
.SYNOPSIS

Check if an app is already installed on the system

.DESCRIPTION

Fonction de vérification de la présence d'un version du logiciel en cours d'installation,
Ecriture de log lors de l'appel

.INPUTS

 - AppToCheck  : Nom de l'application à tester (Obligatoire)
 - AppVersion  : Numéro de version à installer
 - FolderCheck : Vérification basée sur un tag dans le dossier (ancienne méthode) (défaut=$false)

.OUTPUTS

$true  : si application et version trouvée, 
$false : sinon

.NOTES

#>

    param (
        [Parameter (Mandatory = $true)]$AppToCheck, 
        [Parameter (Mandatory = $false)]$AppVersion,
        [Parameter (Mandatory = $false)][switch]$FolderCheck = $false
    )

    $exist = $false # set return value to false in case of not exist application

    if ( -Not $FolderCheck) {

        $InstalledPkg = Get-Package -Name "*$AppToCheck*" -Provider @("Programs", "msi") -ErrorAction ignore 

        if ($InstalledPkg.count -ge 1) {
            if ($AppVersion -ne "") {
                foreach ($Application in $InstalledPkg) {
                    $exist = $exist -or ([System.Version]$Application.Version -ge [System.Version]$AppVersion)
                }
            #    WriteLog -message "Found $($Application.Name) Version $($Application.Version)" -Severity Info
            }
            else {
                $exist = $true
            #    WriteLog -message "Found $($Application.Name) without Version Number" -Severity Info
            }
        }
        else { 
            $RegKey = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
            $InstalledApps = (Get-ItemProperty -Path $RegKey -Include "*$AppToCheck*")
            
            if ($InstalledApps.count -ge 1) {
                if ($AppVersion -ne "") {
                    $exist = $exist -or ([System.Version]$InstalledApps.DisplayVersion -ge [System.Version]$AppVersionTag) 
                    WriteLog -message "Found $($InstalledApps.DisplayName) Version $($InstalledApps.DisplayVersion)" -Severity Info

                }
                else {
                    $exist = $true
                    WriteLog -message "Found $($InstalledApps.DisplayName) Version without Version Number" -Severity Info
                }
            }
        }
    }
    Else {
        # use folderversion to detect installed apps
        $exist = (Test-Path "$AppDirToCheck\v$AppVersionTag" -PathType Any)
        WriteLog -message "$(&{If($exist) {"Found"} Else {"Not Found"}}) $($AppToCheck) from file system" -Severity Info
    }

    return $exist
}


Add-Type -TypeDefinition @"
    public enum Syslog_Facility
    {
        kern,
        user,
        mail,
        daemon,
        auth,
        syslog,
        lpr,
        news,
        uucp,
        clock,
        authpriv,
        ftp,
        ntp,
        logaudit,
        logalert,
        cron,
        local0,
        local1,
        local2,
        local3,
        local4,
        local5,
        local6,
        local7,
    }
"@

Add-Type -TypeDefinition @"
    public enum Syslog_Severity
    {
        Emergency,
        Alert,
        Critical,
        Error,
        Warning,
        Notice,
        Info,
        Debug
    }
"@


Function WriteLog {
    param(
        [Parameter(Mandatory = $true)][string] $Message,
        [Parameter(Mandatory = $false)]
        [Syslog_Facility] $Facility = "Local0",
        [Parameter(Mandatory = $false)]
        [Syslog_Severity] $Severity = "INFO",
        [Parameter(Mandatory = $false)]
        [int32] $ErrorCode
    )

    # Create timestamp
    $timestamp = Get-Date -Format o

    if ($Severity -eq "ERROR") {
        if ($ErrorCode -ne 0) {
            $message += ' /!\ ' + "Code Erreur : $ErrorCode"
        }
    }

    $Facility_Number = $Facility.value__
    $Severity_Number = $Severity.value__
    $Priority = ($Facility_Number * 8) + $Severity_Number

    $ScriptName = Split-Path $($global:LogFile.replace('.log', ".ps1")) -Leaf

    # Append content to log file
    Add-Content -Path $global:LogFile -Value "<$Priority> $timestamp $($env:COMPUTERNAME) $ScriptName [$facility.$($Severity.ToString().ToUpper())]$message"
}

function Get-OneDriveBaseDir {
    <#
.SYNOPSIS

Locate OneDrive Base dir

.DESCRIPTION

recherche le dossier de base de One Drive en fonction de son nom (contenu partiel aurorisé)
et du nom de l'utilisateur (contenu partiel autorisé)

.INPUTS

 - OneDriveFolderName  : Element contenu dans le nom du dossier
 - OneDriveUserName    : Element contenu dans le nom de l'utilisateur

.OUTPUTS


    - .folder       OneDrive User Folder Le nom complet du dossier de base,
    - .DisplayName  OneDrive Display Le nom d'affichage du dossier OneDrive
    - .UserName     OneDrive Username Name Le nom de l'utilisateur
    
    - $false si non trouvé

.NOTES

#>

    param (
        [Parameter (Mandatory = $true)]$OneDriveFolderName, 
        [Parameter (Mandatory = $true)]$OneDriveUserName
    )
    # Variable à retourner 
    $FolderName = $false
    # Clé de registre à balayer
    $OneDriveRegKey = @("HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\*")
    $OneDriveSets = (Get-ItemProperty -Path $OneDriveRegKey)

    foreach ($OneDriveSet in $OneDriveSets) {
        if (($OneDriveSet.UserFolder -match $OneDriveFolderName) -and ($OneDriveSet.username -match $OneDriveUserName)) {
            $FolderName = New-Object PsObject -property @{'Folder' = $OneDriveSet.UserFolder
                'DisplayName'                                      = $OneDriveSet.DisplayName
                'UserName'                                         = $OneDriveSet.Username
            }
        }

    }

    return $FolderName
}

Add-Type -TypeDefinition @"
    public enum Version_Type
    {
        Latest
    }
"@

function Get-LatestVersion {
    <#
.SYNOPSIS

Get latest version number on installer

.DESCRIPTION

Récupère le numéro de version le plus haut des fichiers du dossier courant.

.INPUTS

 - Path  : Dossier à analiser
 - AppName     : Nom de l'application 


.OUTPUTS

    - tableau structuré 
        .'Version'  : - Numéro de version extrait au format texte $Version[0] : Numéro de Version/$Version[1] : Numéro de Build
                      -$false si non trouvé
        .'FileName' : Nom du fichier d'installation              

.NOTES

#>

    param (
        [Parameter (Mandatory = $true)]$Path, 
        [Parameter (Mandatory = $true)]$AppName
    )
    # Variable à retourner 
    $Version = "0.0.0"

 #    $RegexFile = "^([0-9A-Za-z_-]+)[_.-](?:x64|64bit|x86|32bit|win)?[_.-]?(\d+(?:[._-]\d+)+)(?:[_.-](?:x64|64bit|x86|32bit|win))?.*\.(exe|msi)$"
    $RegexFile = "^(.+?)[_.-](?:((?:win)?x?(?:64|32)(?:bit)?)[_.-]?)?(\d+(?:[._-]\d+)+)(?:(?:[_.-].*)?[_.-](?:((?:win)?x?(?:64|32)(?:bit)?)[_.-]?)?)?(?:[_.-].*?)?\.(exe|msi)$"

    $FolderList = (Get-ChildItem -Path "$Path" | Where-Object { $_.Name -match $RegexFile }).Name

    foreach ($file in $FolderList) {
        if ($file -match $RegexFile) {
            #Si il y a un numéro de version
            $numversion = ($Matches[3]).Split("-") 
            if ($numversion.count -gt 1) { $numversion = $numversion[0]}
            $App = $Matches[1]
        }
        else {
            $numversion = ""
            $App = ""
        }

        if ($App -match $AppName) {
            if ([version]($numversion -join ".") -gt [version]($Version -join ".")) {
                $Version = $numversion
                $FileName = $file
            }
        }
    }
    If ($Version -eq "0.0.0") {
        <# Pas de version detectée #>
        $Version = $false
        $FileName = ""
    } 

    $Installer = @{'Version' = $(& { If ($Version -eq "0.0.0") { $false } Else { $Version } })
        'FileName'           = $FileName
    }

    return $Installer
}

function Get-ConfigFile {
    <#
.SYNOPSIS

Read configuration file with comons parameters

.DESCRIPTION

Lecture et analyse de fichier de configuration

.INPUTS

 - File     : Fichier à analyser
 
.OUTPUTS

    - Tableau avec le contenu du fichier enregistré par section

.NOTES

#>

    param (
        [Parameter (Mandatory = $true)]$File
    )

    $Config = @{}
    $section = "Config"
    $Config[$section] = @{}

    if (Test-Path $File -PathType Leaf) {
        <# Si le fichier existe bien #>
    
        switch -regex -file $file {
            #Comments.
            "^\s*([#;].*)$" {
                continue
            }     
            #Section.
            "^\[(.+)\]\s*$" {
                $section = $matches[1].Trim()
                $config[$section] = @{}
                continue
            }
            #Decimal.
            "^\s*(.+?)\s*=\s*(\d+[.,]\d+)(?>\s*(?>[;#].*)|\s*$)$" {
                $name, $value = $matches[1..2]
                $config[$section][$name] = [decimal]$value.replace(',', '.')
                continue
            }
            #Int.
            "^\s*(.+?)\s*=\s*(\d+)(?>\s*(?>[;#].*)|\s*$)$" {
                $name, $value = $matches[1..2]
                $config[$section][$name] = [int]$value
                continue
            }
            #String with quotes
            "^\s*(.+)\s*=\s*(?>`"|`'|)(.*)(?>`"|`')\s*$" {
                $name = $matches[1].Trim()
                $value = $matches[2].Trim()
                $config[$section][$name] = $value 
                continue
            }
            #Everything else.
            "^\s*(.+)\s*=\s*(.*)" {
                $name = $matches[1].Trim()
                $value = $matches[2].Trim()
                $config[$section][$name] = $value 
            }
        }
    }
    return $config
}

# Log filename (Global Variable)
if (!($PSBoundParameters.ContainsKey("LogFileParam"))) {
    # Si aucun paramètre, on récupère le nom du script appelant et on stock les log dans un dossier "..\Log"
    $LogFile = "$(Split-Path -Path $PSScriptRoot -Parent)\Log\$(Split-Path $($MyInvocation.PSCommandPath) -Leaf)"
    # Remplacement de l'extension du nom du fichier (.ps1 -> .log)
    $Global:LogFile = $LogFile -Replace (".ps1", ".log")
}

# Configuration globale
# On charge la configuration de base si elle existe
$ConfigGlobale = $($MyInvocation.MyCommand.Path) -Replace (".ps1", ".ini")
    
if (Test-Path $ConfigGlobale -PathType Leaf) {
    <# Lecture du fichier de configuration psFunctions.ps1 (Même nom que le module) #>
    $Global:Configuration = Get-ConfigFile -File $ConfigGlobale
}

# ConfigFile filename (Local Variable)
if (!($PSBoundParameters.ContainsKey("ConfigFileParam"))) {
    # Si aucun paramètre, on récupère le nom du script appelant et on cherche la config dans le même dossier.
    # Remplacement de l'extension du nom du fichier (.ps1 -> .ini)
    $ConfigFile = $($MyInvocation.PSCommandPath) -Replace (".ps1", ".ini")
}
else {
    <# Action when all if and elseif conditions are false #>
    $ConfigFile = $PSBoundParameters["ConfigFileParam"]
}
    
if (Test-Path $ConfigFile -PathType Leaf) {
    <# Lecture du fichier de configuration psFunctions.ps1 (Même nom que le module) #>
    $AppConfig = Get-ConfigFile -File $ConfigFile
    foreach ($Section in $AppConfig.GetEnumerator()) {
        <# Lecture des sections #>
        if (!$Configuration.ContainsKey($Section.Name)) {
            <# La clé n'existe pas déjà, on la crée #>
            $Configuration[$section.Name] += @{}
        }
        foreach ($Parametre in $Section.Value.GetEnumerator()) {
            if ($Configuration[$Section.Name].ContainsKey($Parametre.Name)) {
                <# La paramètre existe, on le surcharge #>
                $Configuration[$section.Name][$Parametre.Name] = $Parametre.Value
            }
            else {
                <# La paramètre n'existe pas déjà, on la crée #>
                $Configuration[$section.Name][$Parametre.Name] = $Parametre.Value
            }
        }
    }
}

$methodDefinition = @'
[DllImport("ole32")]
private static extern int CLSIDFromProgIDEx([MarshalAs(UnmanagedType.LPWStr)] string lpszProgID, out Guid lpclsid);

[DllImport("oleaut32")]
private static extern int GetActiveObject([MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, IntPtr pvReserved, [MarshalAs(UnmanagedType.IUnknown)] out object ppunk);
public static object GetActiveObject(string progId, bool throwOnError = false)
{
    if (progId == null)
        throw new ArgumentNullException(nameof(progId));

    var hr = CLSIDFromProgIDEx(progId, out var clsid);
    if (hr < 0)
    {
        if (throwOnError)
            Marshal.ThrowExceptionForHR(hr);

        return null;
    }

    hr = GetActiveObject(clsid, IntPtr.Zero, out var obj);
    if (hr < 0)
    {
        if (throwOnError)
            Marshal.ThrowExceptionForHR(hr);

        return null;
    }
    return obj;
}
'@
$interop = add-type -MemberDefinition $methodDefinition -Name "Interop" -Namespace "Interop" -PassThru

# Log Lancement du script
#WriteLog -Message "Lancement du Script $($MyInvocation.ScriptName) Version $($(Test-ScriptFileInfo -Path $MyInvocation.ScriptName).Version)"
$domainuser = ([Environment]::UserDomainName + "\" + [Environment]::UserName)
$SPW = [Security.Principal.WindowsIdentity]::GetCurrent().Name
WriteLog -Message "Paramètres Utilisateurs du Script Application : $AppName User : $domainuser SPW : $SPW"



# SIG # Begin signature block
# MIIl5wYJKoZIhvcNAQcCoIIl2DCCJdQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDpXWXA1tLCKEwT
# Bja0q/XT2MMTeBkBhj05SZVbFqGvR6CCH/EwggVKMIIEMqADAgECAhNwAAAAD1uv
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
# BCDkRvyE7ZlcS/hiD1VzYycgwCLpl3HtEGyEkZwImJnQVDANBgkqhkiG9w0BAQEF
# AASCAQAnsjqWoCMyGrmeQzb/ULEBihAcT/7RaNYfjbujfNEiPY3l6LWxKRKwqtV3
# xKQVIiR7sWrFL9OfpsdT1iowYBsAfeKYkDMlJSxg+FKriyAEYWU7s+2UA5aatHeH
# trvUeAXAI40Cso2KR5RWfB7xdcMqmEuJH7orNY/VNeWr4AyMcAg7iYs1br7u6V//
# Snm67HsF7hyF3B9n7L5ag0Sgq+BB98O012ABqXf7hzc+ryLjDw85CuebwPf+PqP3
# Y6FHsMXkP3AETw2bbnZN7E/xVXYjEbXv4kP6jZCQUkrVRWy3bbiUlGpH5XA1f8by
# rkFp1udHoM5+sc9H8xDghmoYg1nSoYIDIjCCAx4GCSqGSIb3DQEJBjGCAw8wggML
# AgEBMGkwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEs
# MCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSMzYCEDpS
# aiyEzlXmHWX8zBLY6YkwDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0BCQMxCwYJ
# KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNDA5MDcyMTA2MjRaMD8GCSqGSIb3
# DQEJBDEyBDCWgg3g6f3APzQgiJFAy/bN9FUG0b2iRyMLSLd0W4Ll1bzSn0iEpkid
# f4sunIDMqqAwDQYJKoZIhvcNAQEBBQAEggIAKJqizIgNh4yZ+lmW8e4JubNiwg0z
# pjvuclgG2o/A7/MKwSeSlYc6me1HrdbhjtQnKnf+AK16eyp0malv+GoX35teKDZT
# Ek86SWFprMUTPA2gkJR3w6Q5SUsDt6dsPhE9KilKf/eAfRg33qkp2m5ae1qRCFus
# loq3AyVsUftL4/UJ3jVdxg0uhmNGoyuUMEN6T1jtmTQnTihcpf/nN5WRGRz4DZU+
# /mc1zvjtbUDYXBj+k7F59QE6AIN5RuWNKoDSQxUgebHPyrZ9HNB3lXDFpXItnrxa
# Qkg5W0lg8zLxgMNkBqduILeV/ollR0miXL9wdETnuq6aK9T4yYxIejKmr6r2XMTj
# RVADVFz7d7xu3hM0hJyHmy7g/GOWFqlSfCUBe/+XQDMEeofNpvUraiHDcMVy2ynt
# aTH+JDtfi8M8halwOOqh3ex44hBN9aYa7dIiP2MVst+AYC3JOPh5Mx2ryhP2sZRX
# ADBM8vwDjmXcaGgEOfgRI3mEgHp2YggqayxC/X9FHe018O4wShD0QVFE5Jt+Ul5G
# IsC35J/m97lCY+l3k2sE0BjkLj/YoqheLtrZAzbHtLq4CYCf1mlzPCzlO1LnZ85C
# 9OZlM6TiZzkUFIFPkr+cDft+97Vs7682voAaY+95GKcOwMpYsWHtDVlEfNSV6ClR
# SY9u/46fytrCe10=
# SIG # End signature block
