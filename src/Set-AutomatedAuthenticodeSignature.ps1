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
 Script PowerShell permettant la signature automatique de scripts PowerShell.

.DESCRIPTION
 Script PowerShell permettant la signature automatique de scripts PowerShell.

.PARAMETER RootPath
 Spécifie un chemin d'accès vers un répertoire ou un fichier définissant l'étendue de la vérification des signatures.

.PARAMETER Certificate
 Spécifie le certificat avec lequel les scripts doivent être signés.

.EXAMPLE
 PS> $cert = (Get-ChildItem -Path Cert:\CurrentUser\My\E7DAC6FBC64F03BC009299DE5A46F57901010958)
 PS> .\Set-AutomatedAuthenticodeSignature.ps1 -RootPath C:\Users\christopher.gerard\Documents\WindowsPowerShell\Sources\Scripts\Set-AutomatedAuthenticodeSignature\src\Set-AutomatedAuthenticodeSignature.ps1 -Certificate $cert

    Répertoire : C:\Users\christopher.gerard\Documents\WindowsPowerShell\Sources\Scripts\Set-AutomatedAuthenticodeSignature\src

SignerCertificate                         Status                                                    Path
-----------------                         ------                                                    ----
E7DAC6FBC64F03BC009299DE5A46F57901010958  Valid                                                     Set-AutomatedAuthenticodeSignature.ps1

 Cette commande permet la signature d'un script PowerShell spécifique si celui-ci n'a pas déjà une signature valide.

.EXAMPLE
 PS> $cert = (Get-ChildItem -Path Cert:\CurrentUser\My\E7DAC6FBC64F03BC009299DE5A46F57901010958)
 PS> "C:\Users\christopher.gerard\Documents\WindowsPowerShell\Sources\" | .\Set-AutomatedAuthenticodeSignature.ps1 -Certificate $cert

    Répertoire : C:\Users\christopher.gerard\Documents\WindowsPowerShell\Sources\Scripts\Set-AutomatedAuthenticodeSignature\src

SignerCertificate                         Status                                                    Path
-----------------                         ------                                                    ----
E7DAC6FBC64F03BC009299DE5A46F57901010958  Valid                                                     Set-AutomatedAuthenticodeSignature.ps1

 Cette commande permet la signature de scripts PowerShell à l'emplacement spécifié, à travers un pipeline, si ceux-ci n'ont pas déjà une signature valide.

.EXAMPLE
 PS> $cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Where-Object{ $_.Issuer -imatch "CEA SubCA 1" }
 PS> .\Set-AutomatedAuthenticodeSignature.ps1 -Certificate $cert

    Répertoire : C:\Users\christopher.gerard\Documents\WindowsPowerShell\Sources\Scripts\Set-AutomatedAuthenticodeSignature\src

SignerCertificate                         Status                                                    Path
-----------------                         ------                                                    ----
E7DAC6FBC64F03BC009299DE5A46F57901010958  Valid                                                     Set-AutomatedAuthenticodeSignature.ps1

 Cette commande permet la signature de scripts PowerShell à l'emplacement par défaut '%HOMEDRIVE%%HOMEPATH%\Documents\WindowsPowerShell\Sources' si ceux-ci n'ont pas déjà une signature valide.

.INPUTS
 System.String

 Vous pouvez rediriger une chaîne contenant le chemin d'accès vers le répertoire ou le fichier définissant l'étendue de la vérification des signatures.

.OUTPUTS
 System.Management.Automation.Signature

 Cette applet de commande renvoie un objet Signature représentant la valeur qu'elle a définie.

.LINK
 https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus

 Documentation détaillant les codes de status des signatures d'un fichier.
#>

[cmdletbinding()]
Param(
    # Répertoire racine
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, HelpMessage = "Spécifie un chemin d'accès vers un répertoire ou un fichier définissant l'étendue de la vérification des signatures")]
    [ValidateScript({
            Test-Path -Path $_ -IsValid
        })]
    [string]
    $RootPath = "$($env:HOMEDRIVE)$($env:HOMEPATH)\Documents\WindowsPowerShell\Sources",

    # Certificat
    [Parameter(Mandatory = $true, HelpMessage = "Spécifie un chemin d'accès vers le certificat avec lequel les scripts doivent être signés")]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]
    $Certificate
)

PROCESS
{
    while ($true)
    {
        # Récupération des fichiers PowerShell uniquement dont la taille est supérieure ou égale à 4 octets

        $files = Get-ChildItem -Path $RootPath -File -Recurse | Where-Object { $_.Extension -imatch '^\.(ps1|psd1|psm1)$' -and $_.Length -ge 4 }

        foreach ($file in $files)
        {
            try
            {
                # Récupération de l'état de la signature
                $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction Stop
            }
            catch
            {
                throw "Une erreur est survenue : $($_.Exception.Message)"
            }

            # Signature du fichier PowerShell si le fichier possède une signature non valide
            # A propos des codes de status des signatures: https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus
            if ( $signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid)
            {
                Set-AuthenticodeSignature -Certificate $Certificate -TimestampServer "http://timestamp.digicert.com" -FilePath $file.FullName
            }
        }

        # Pause
        Start-Sleep -Seconds 5
    }
}