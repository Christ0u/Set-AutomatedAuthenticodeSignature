<#PSScriptInfo

.VERSION 1.0.0

.GUID dc7214c3-ac66-4895-a263-f617d3c87ec3

.AUTHOR Christopher GERARD

.COMPANYNAME

.COPYRIGHT Copyright 2024 Christopher GERARD

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<# 

.SYNOPSIS
 Script PowerShell permettant la signature automatique de scripts PowerShell

.DESCRIPTION 
 Script PowerShell permettant la signature automatique de scripts PowerShell

.PARAMETER RootPath
 Spécifie un chemin d'accès vers un répertoire ou un fichier définissant l'étendue de la vérification des signatures

.PARAMETER Certificate
 Spécifie un chemin d'accès vers le certificat avec lequel les scripts doivent être signés

.EXAMPLE
 PS> $cert = (Get-ChildItem -Path Cert:\CurrentUser\My\E7DAC6FBC64F03BC009299DE5A46F57901010958)
 PS> .\Set-AutomatedAuthenticodeSignature.ps1 -RootPath C:\Users\christopher.gerard\Documents\WindowsPowerShell\Sources\Scripts\Set-AutomatedAuthenticodeSignature\src\Set-AutomatedAuthenticodeSignature.ps1 -Certificate $cert

    Répertoire : C:\Users\christopher.gerard\Documents\WindowsPowerShell\Sources\Scripts\Set-AutomatedAuthenticodeSignature\src

SignerCertificate                         Status                                                    Path
-----------------                         ------                                                    ----
E7DAC6FBC64F03BC009299DE5A46F57901010958  Valid                                                     Set-AutomatedAuthenticodeSignature.ps1

 Cette commande permet la signature d'un script PowerShell si celui-ci n'a pas déjà une signature valide.

.EXAMPLE
 PS> $cert = (Get-ChildItem -Path Cert:\CurrentUser\My\E7DAC6FBC64F03BC009299DE5A46F57901010958)
 PS> "C:\Users\christopher.gerard\Documents\WindowsPowerShell\Sources\" | .\Set-AutomatedAuthenticodeSignature.ps1 -Certificate $cert

 Cette commande permet la signature de scripts PowerShell, à travers un pipeline, si ceux-ci n'ont pas déjà une signature valide.

.INPUTS
 System.String

 Vous pouvez rediriger une chaîne contenant le chemin d'accès vers le répertoire ou le fichier définissant l'étendue de la vérification des signatures.

.OUTPUTS
 System.Management.Automation.Signature

 Cette applet de commande renvoie un objet Signature représentant la valeur qu'elle a définie.

#> 

[cmdletbinding()]
Param(
    # Répertoire racine
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, HelpMessage="Spécifie un chemin d'accès vers un répertoire ou un fichier définissant l'étendue de la vérification des signatures")]
    [ValidateScript({
        Test-Path -Path $_ -IsValid
    })]
    $RootPath = "$($env:HOMEDRIVE)$($env:HOMEPATH)\Documents\WindowsPowerShell\Sources",

    # Certificat
    [Parameter(Mandatory=$true, HelpMessage="Spécifie un chemin d'accès vers le certificat avec lequel les scripts doivent être signés")]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]
    $Certificate
)

PROCESS{
    while ($true) {

        # Récupération des fichiers PowerShell uniquement
        Get-ChildItem -Path $RootPath -File -Recurse | Where-Object { $_.Extension -imatch '^(.ps1|.psd1|.psm1)$' } | ForEach-Object {

            try {
                # Récupération de l'état de la signature
                $signature = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction Stop
            }
            catch {
                throw "Une erreur est survenue : $($_.Exception.Message)"
            }

            # Signature du fichier PowerShell si le fichier possède une signature non valide
            # A propos des codes de status des signatures: https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus
            if ( $signature.Status.value__ -ne 0 ){
                Set-AuthenticodeSignature -Certificate $Certificate -TimestampServer "http://timestamp.digicert.com" -FilePath $_.FullName
            }

        }

        # Pause
        Start-Sleep -Seconds 5
    }
}