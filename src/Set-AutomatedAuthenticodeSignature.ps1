<#PSScriptInfo

.VERSION 1.0.0

.GUID dc7214c3-ac66-4895-a263-f617d3c87ec3

.AUTHOR Christopher GERARD

.COMPANYNAME

.COPYRIGHT Copyright 2024-2026 Christopher GERARD

.TAGS PowerShell Authenticode CodeSigning Signature FileSystemWatcher Automation Windows

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
 Initial release.
 Automatically signs PowerShell files with an Authenticode code-signing certificate.
 Monitors a directory and its subdirectories, then re-signs modified files.

.PRIVATEDATA

#>

<#

.SYNOPSIS
 Automatically signs PowerShell files using Authenticode signatures.

.DESCRIPTION
 This script signs PowerShell files with a code-signing certificate.
 It can sign existing files before starting, then monitor the specified directory and its subdirectories to automatically re-sign files after they are modified.

.PARAMETER RootPath
 Specifies the path to the root directory to monitor and sign.
 This parameter is optional.
 The default value is '%HOMEDRIVE%%HOMEPATH%\Documents\WindowsPowerShell\Sources'.

.PARAMETER CertificateThumbprint
 Specifies the thumbprint of the code-signing certificate to use.
 This parameter is mandatory.

.PARAMETER FileExtensions
 Specifies the file extensions to monitor and sign.
 This parameter is mandatory.
 Extensions can be provided with or without a leading dot, for example: '.ps1', 'psd1', or '.PSM1'.

.EXAMPLE
 PS> .\Set-AutomatedAuthenticodeSignature.ps1 -CertificateThumbprint "E7DAC6FBC64F03BC009299DE5A46F57901010958" -FileExtensions ".ps1", ".psd1", ".psm1"

 Signs and monitors PowerShell files in the default root directory.

 .EXAMPLE
 PS> .\Set-AutomatedAuthenticodeSignature.ps1 -RootPath "$($env:HOMEDRIVE)$($env:HOMEPATH)\Sources" -CertificateThumbprint "E7DAC6FBC64F03BC009299DE5A46F57901010958" -FileExtensions ".ps1", ".psd1", ".psm1"

 Signs and monitors PowerShell files in the specified directory.

 .EXAMPLE
 "$($env:HOMEDRIVE)$($env:HOMEPATH)\Sources" | .\src\Set-AutomatedAuthenticodeSignature.ps1 -CertificateThumbprint "fe4ad9cad2a6e1ff9e8566a3c406b64d7e173a2b" -FileExtensions ".ps1", ".psd1", ".psm1"

 Signs and monitors PowerShell files in the directory received through the pipeline.

 .INPUTS
 System.String

 You can pipe a string containing the path to the root directory to monitor and sign.

.OUTPUTS
 None

 This script does not return any output.

.LINK
 https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus

 Documentation describing the signature status values of a file.
#>

[cmdletbinding()]
Param(
    # Root directory to monitor for PowerShell files.
    [Parameter(ValueFromPipeline = $true, HelpMessage = "Specifies the path to a directory or file that defines the scope of the signature verification.")]
    [ValidateScript({
            Test-Path -Path $_ -IsValid
        })]
    [string]
    $RootPath = "$($env:HOMEDRIVE)$($env:HOMEPATH)\Documents\WindowsPowerShell\Sources",

    # Thumbprint of the code-signing certificate to use.
    [Parameter(Mandatory = $true, HelpMessage = "Specifies the thumbprint of the code-signing certificate.")]
    [ValidateNotNullOrEmpty()]
    [string]
    $CertificateThumbprint,

    # File extensions to monitor and sign.
    [Parameter(Mandatory = $true, HelpMessage = "Specifies the file extensions to monitor and sign.")]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $FileExtensions
)

PROCESS
{
    # Search for the requested code-signing certificate in both the current-user and local-machine certificate stores.
    $certificate = (Get-ChildItem -Path Cert:\CurrentUser\My\ -CodeSigningCert) + (Get-ChildItem -Path Cert:\LocalMachine\My\ -CodeSigningCert) | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }

    # Stop if the requested certificate cannot be found.
    if ($null -eq $certificate)
    {
        Write-Error "No code-signing certificate with thumbprint '$($CertificateThumbprint)' was found in the current-user or local-machine certificate stores."

        return
    }

    # Normalize file extensions: trim spaces and dots, convert to lowercase, and remove duplicates.
    $FileExtensions = [array]($FileExtensions | ForEach-Object { $_.Trim(' ', '.').ToLower() } | Select-Object -Unique)

    if ($FileExtensions.Count -eq 0)
    {
        Write-Error "At least one file extension must be specified."

        return
    }

    # Build a regular expression that matches any of the normalized file extensions, for example: '^\.(ps1|psd1|psm1)$'.
    $fileExtensionPattern = "^\."
    $fileExtensionPattern = "$($fileExtensionPattern)($($FileExtensions -join '|')"
    $fileExtensionPattern = "$($fileExtensionPattern))$"

    # Get all files matching the configured extensions and at least 4 bytes long.
    $files = Get-ChildItem -Path $RootPath -File -Recurse | Where-Object {
        $_.Extension -imatch $fileExtensionPattern -and $_.Length -ge 4
    }

    # Check and sign every existing PowerShell file before starting the file watcher.
    foreach ($file in $files)
    {
        try
        {
            # Get the current Authenticode signature status of the file.
            $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction Stop
        }
        catch
        {
            throw "An error occurred: $($_.Exception.Message)"
        }

        # Sign the file only when its current signature is not valid.
        # For the available signature status values, see:
        # https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid)
        {
            Set-AuthenticodeSignature -Certificate $certificate -TimestampServer "http://timestamp.digicert.com" -FilePath $file.FullName
        }
    }

    # Create a file-system watcher for the root directory and its subdirectories.
    $fileSystemWatcher = New-Object System.IO.FileSystemWatcher
    $fileSystemWatcher.Path = Resolve-Path -Path $RootPath | Select-Object -ExpandProperty Path
    $fileSystemWatcher.IncludeSubdirectories = $true
    $fileSystemWatcher.EnableRaisingEvents = $true
    $fileSystemWatcher.NotifyFilter = [System.IO.NotifyFilters]::FileName, [System.IO.NotifyFilters]::LastWrite, [System.IO.NotifyFilters]::Size

    # Shared state passed to the event action:
    # - Certificate: certificate used to sign files.
    # - LastProcessed: date and time of the last processed event for each file.
    # - DebounceMs: minimum delay between two processed events for the same file.
    $watcherState = @{
        Certificate   = $certificate
        LastProcessed = @{}
        DebounceMs    = 500
    }

    # Action executed whenever a watched file changes.
    $action = {
        try
        {
            # Get the full path of the file that triggered the event.
            $path = $Event.SourceEventArgs.FullPath
            $now = [DateTime]::UtcNow

            # Debounce rapid events: ignore another event for the same file
            # if it occurs within the configured debounce delay.
            if ($Event.MessageData.LastProcessed.ContainsKey($path) -and
                ($now - $Event.MessageData.LastProcessed[$path]).TotalMilliseconds -lt $Event.MessageData.DebounceMs)
            {
                return
            }

            # Remember when this file was last processed.
            $Event.MessageData.LastProcessed[$path] = $now

            # Get the file that triggered the event.
            $file = Get-Item -LiteralPath $path -ErrorAction Stop

            # Process all files matching the configured extensions and at least 4 bytes long.
            if ($file.Extension -imatch $fileExtensionPattern -and
                $file.Length -ge 4)
            {
                # Wait until the file stops changing, because an editor such as
                # VS Code may write a file in several steps.
                $previousLength = $file.Length
                $previousLastWriteTime = $file.LastWriteTimeUtc

                for ($attempt = 0; $attempt -lt 10; $attempt++)
                {
                    Start-Sleep -Milliseconds 100

                    # Reload the file metadata before comparing it with the previous state.
                    $file.Refresh()

                    # Stop waiting when both the size and last-write time remain unchanged.
                    if ($file.Length -eq $previousLength -and
                        $file.LastWriteTimeUtc -eq $previousLastWriteTime)
                    {
                        break
                    }

                    # Keep the latest file metadata for the next comparison.
                    $previousLength = $file.Length
                    $previousLastWriteTime = $file.LastWriteTimeUtc
                }

                # Check whether the file still has a valid Authenticode signature.
                $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction Stop

                # Resign the file when its content has changed and its signature is no longer valid.
                if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid)
                {
                    Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $Event.MessageData.Certificate -TimestampServer "http://timestamp.digicert.com" | Out-Null

                }
            }
        }
        catch
        {
            # Report the error without stopping the file watcher.
            Write-Warning "Unable to sign file '$($Event.SourceEventArgs.FullPath)' : $($_.Exception.Message)"
        }
    }

    # Subscribe to file-change events and provide the shared state to the event action.
    Register-ObjectEvent -InputObject $fileSystemWatcher -EventName Changed -Action $action -SourceIdentifier 'PowerShellFileChanged' -MessageData $watcherState | Out-Null

    try
    {
        while ($true)
        {
            # Keep the script running and wait for the next file-change event.
            Wait-Event -SourceIdentifier 'PowerShellFileChanged' -ErrorAction Stop | Out-Null
        }
    }
    catch
    {
        Write-Error "An exception occurred: $($_.Exception.Message)"

        return
    }
    finally
    {
        # Remove the event subscription and release the file-system watcher resources.
        Unregister-Event -SourceIdentifier 'PowerShellFileChanged' -ErrorAction SilentlyContinue

        $fileSystemWatcher.Dispose()
    }
}

# SIG # Begin signature block
# MIIcKAYJKoZIhvcNAQcCoIIcGTCCHBUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOqmR946Crm2SoKQy8AwRU0M1
# UIugghZ8MIIDPjCCAiagAwIBAgIQWSl0Rdk7IZ5AP4ehb0/ksDANBgkqhkiG9w0B
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
# SIb3DQEJBDEWBBRpPaHTSk264T4v+NHnw0K1urSJWTANBgkqhkiG9w0BAQEFAASC
# AQCkuimGC5FrPTGqeng96YzUblMQ7HdaAbGBjBdUKuw2JNfq1wG78jrrlmb+KmiQ
# UWFiC65McXwCxL1P0Rwez3YfLIcq8xxE62+2kFExgYfkztaZqku4lnlQf+QzqH9g
# mmkrcSw0jrPCsN0HOaiuZXuNoh5emE3hKwZemvU4WaZI4Ku5sN1cCoYc/aJXLcGo
# zF0fxYXUsuJZgI4pzfAVSQwW2/TZ7XWWIl8KS4LhZwFBPihtyXu9zKJsbFZCBzDq
# jS1s7cZa+oBUnZE+HGymtcZmzEl9XWhEY2muSFI6VYnYrEXX0XvEhemMnlh0jUAs
# ZSZQ45tq9Ql8aL1LFnP69QZfoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEB
# MH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYD
# VQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNI
# QTI1NiAyMDI1IENBMQIQCE/cM09+RU7bww+P+ZIYNTANBglghkgBZQMEAgEFAKBp
# MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MTEx
# MjIwNTM0NVowLwYJKoZIhvcNAQkEMSIEILuQzTWCwqROeNHo54iJ7mZbTzuTmhDG
# N6I58hUSMGWIMA0GCSqGSIb3DQEBAQUABIICACYAWwRpe/2hyvLkjCHM+on6Ikpd
# OY5cpXXtvKldrPq9dm0ozGA5lvmzpTRH3cJulUvooZD9SfxZY7SbE17C07gZQCEs
# M0In04egku2/ibUUZzy69RPgyrldMUXjfBgJoeM7bymGKr/d6BqyQEV0ZXw9ZZlT
# jCc01+mqlHTsdayAwTOtVjo98iiGQnnvykzOWkIqM4/0eDUxluSRNoE6vwSOuylr
# Gx5ygucqSOHaRuX4D9dHXfwtYhep2Sq8a5buOKKJzbES/iovm+oVRfn1AUpo0/rX
# 631kWUX/SoXypryzw90V7H2vl76iPwPrHWKY9cS2aPR5iY5jQ3peyWmkgWFkzW+3
# 5N5pNGa5bEohhJFk8T15K62rvv84KP63KlPjpapnZl2ytyj3I/Ql1hZKGz6RDNhv
# lfFBkomX7FfZvLOVl+TbNHR1DqSyJW9S4SoAelsMqG0Su5ptuO9MZbv/WzrwRi+6
# 7fmdsJQd3349POsUanPEmUtzEIaXSMfAH5WDSvwiAxRLvKvVs1sUANzdz3rDrbCa
# cxS2GNY2YoqX6z4iiAf3N8EhfQvzANOfVVVFYOyNz1f1XpcAfdz8HiDIRU917FXF
# NkW1aP8oMVt46zHf1zyh3A5J3GmY3ahwvxAgvDryVGiH0ZyUZvQY0ktBU4W/ZByf
# +TpJn3+WdwA/Ejbr
# SIG # End signature block
