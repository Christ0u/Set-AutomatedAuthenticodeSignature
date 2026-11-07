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

    # Certificat de signature
    [Parameter(Mandatory = $true, HelpMessage = "Spécifie l'empreinte du certificat de signature de code")]
    [ValidateNotNullOrEmpty()]
    [string]
    $CertificateThumbprint
)

PROCESS
{
    $certificate = (Get-ChildItem -Path Cert:\CurrentUser\My\ -CodeSigningCert) + (Get-ChildItem -Path Cert:\LocalMachine\My\ -CodeSigningCert) | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }

    if ($null -eq $certificate)
    {
        Write-Error "Aucun certificat de signature de code d'empreinte '$($CertificateThumbprint)' n'a été trouvé dans les magasins de certificats utilisateur et machine."

        return
    }

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
                Set-AuthenticodeSignature -Certificate $certificate -TimestampServer "http://timestamp.digicert.com" -FilePath $file.FullName
            }
        }

        # Pause
        Start-Sleep -Seconds 5
    }
}

# SIG # Begin signature block
# MIIcKAYJKoZIhvcNAQcCoIIcGTCCHBUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUh970xxMI7uJT453ZMAwcIgWx
# YjOgghZ8MIIDPjCCAiagAwIBAgIQWSl0Rdk7IZ5AP4ehb0/ksDANBgkqhkiG9w0B
# AQsFADA3MTUwMwYDVQQDDCxDaHJpc3RvcGhlciBHRVJBUkQgLSBQb3dlclNoZWxs
# IENvZGUgU2lnbmluZzAeFw0yNjExMDcwMDUxNDJaFw0zNjExMDcwMTAxNDJaMDcx
# NTAzBgNVBAMMLENocmlzdG9waGVyIEdFUkFSRCAtIFBvd2VyU2hlbGwgQ29kZSBT
# aWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyvWXtB5C7Jo7
# a0FoA+RsSHS/bo7uEPKtp69XL2aq2CNtLaPJpU0piFEzVTI3C6o1lApbKL9hcW8q
# DFAGaaC8rSMyKY9ZOPaPG5O7/dBAUacz6ogD9gkJPVR9EvkfK5TiIwlcTOfOIKxl
# TDYGldJKBsQzbc7ziDF22/EhRT1aAOkIF/nQL6ej7dtxQYA7ro2ZAvPWNHAF2dZL
# 0bzXVn8KQTXuC8szsLvYfoNACwA4uwR2p5U1ca+SYveFNR8/vulmXNBHwg+CZwpz
# hbgFT6gtwaWsPpVAaJ0/OMkWSOusFJXDyOigzAZT4XONRAbCHf5KGmMtv603iKc2
# 8zdOayiPGQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFCh65QGUE215br4TOZ9ZWTGOefcHMA0GCSqGSIb3DQEB
# CwUAA4IBAQA+VN3xoubx2RjCpRqRWToxT+7hY2HYBRS8MP7rSXmhVxEZBGCLXrjP
# R9auIxx9k4i/I0FM+c3zr4eVdmMK73s5AuH4rnmas3CpWAlVOLttaD0reenD8C3M
# 3D9zMmSGNSUJcgZlVSiJ4X/0IzdL7snJWxmX3NRgSaZAI+TZeVIc5h1i6rQjWv0A
# Q5cgmJ+CQchIGHI3yRO49ADPS7vhZmbkaqU6BAvDhyiUA4HOZnhRL1mHXy5oRYFv
# jjBye+tYcPBa75hSQ1TgkgJtUCIKW60r/wh+ySccaQzJ2XhSmERLIbrijRXhuQ2m
# dGMknrZXoUDL0/MlFnEGdKUGS0w6ziysMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv
# 21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD
# ExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcN
# MzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf
# 8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1
# mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe
# 7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecx
# y9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX
# 2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX
# 9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp49
# 3ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCq
# sWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFH
# dL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauG
# i0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYw
# DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# HwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGG
# MHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXn
# OF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23
# OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFI
# tJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7s
# pNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgi
# wbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cB
# qZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG
# 9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVz
# dGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERp
# Z2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIw
# MjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+
# PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxe
# Lho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2D
# Z0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJB
# YgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7G
# b5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS
# 3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7C
# coKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUm
# s+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN
# +nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqE
# G1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhG
# NKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQY
# MBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUE
# DDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDww
# OjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0G
# CSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/D
# m1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO4
# 1P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFS
# goR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSL
# ANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJ
# DMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cva
# iIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+
# U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6
# bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+
# Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhL
# ULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3
# XDCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggUWMIIFEgIBATBLMDcxNTAzBgNVBAMMLENocmlzdG9waGVyIEdFUkFSRCAt
# IFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nAhBZKXRF2TshnkA/h6FvT+SwMAkGBSsO
# AwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqG
# SIb3DQEJBDEWBBTkPFNRvj3CsJW606zvkaVEzncfPzANBgkqhkiG9w0BAQEFAASC
# AQAjN1gXtsDidUlS9R2VLCRwevioJzMrxMRQ+KxXO6iKum0iJor5XsM6uZJpV6UX
# dtQu9xJ7zvnPqbgRYf6TdHq2jDQpGhXqyu9PH0VJCH+NykWJ8aJB9utlDdGnjMbv
# mnP4akHICCUXGgVSypghicGBuH3wFf9DqwrMQGGYTMfDUnYaDdyHFYBckU/MQsWh
# FVeKUCZsI77DklU3jRhZIMxKIfr31O/2gkwFgPO2jZu40StOhgkag3XmXe5JzuXo
# MubWUiES516hrqJ3rIs0SqOrBnrtdbOGYDXThVD2CHAoV7QqVydvl50Mxd5QM3na
# wNSX3Gl8H1H6sFglHKSKPQwUoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEB
# MH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYD
# VQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNI
# QTI1NiAyMDI1IENBMQIQCE/cM09+RU7bww+P+ZIYNTANBglghkgBZQMEAgEFAKBp
# MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTEw
# NzAxMDU0MlowLwYJKoZIhvcNAQkEMSIEIGZd1q6+8KJRxkzYOWhD4D05n7OE8iWK
# OHq0V72ZZ3orMA0GCSqGSIb3DQEBAQUABIICAC7QyuGzKCsvRO+uqRPYnxJJP1RF
# etPpd74+PhZuQMYY/WY+MSRs+eih5HrYpGYWfrVf5Iu++/H7wNeibtFeSTQXTzZ6
# nkb2SLG4sP0h1zn74YUM4Vw6ZZknW1r6MmaxGj73i3SIpX5VDL5bghlQd1qheuBk
# U9QVrq7m0TIcrxyX12ToRtx8CQf76OzkGdjQxXIdaxpx+rOnlwlc++1WthVYsPYS
# V4nXD/7wxWY3ZNRtVnamnrbRbwXTt+yu4DsKOvZihKbq0BfvoJSV8wAboIn7dX+L
# 2FE7M1MSYx759xm5Q0ks0qnC3WwGv5XlOfkN/X+sH6UUTetKSlYypJ+kP2V5AWeI
# i78J3gWVS3vnbvCPrH+A/NJrCF9jxaCmASTMYEYdAFq4+BVpjIyOIFuMtxIOWCsN
# Jb+7i/u4pU5fKM1jbcW1ablpkA183TXhO/RjR0QabfOSLe+LQgZZsiMq+vGeftJW
# 9gr0YF0MokpsI44H4mqSwH6do0wvGYgqzg600H8wR5pVfut7AOeOGDyCd1XhY76s
# 10tC1mxvUBPQMJnL7UnD8Loht+IvKWf5vNUIWEVXPGmjlXJQ7C8YJfkIQzHVylJM
# utH6HNeP5pL1eH4NjzuPb3648KnQPTQgOUAgmmrZvWfUJkFQhV4mcF/zY/oZtkEQ
# 22OcmeBrAI2UijUp
# SIG # End signature block
