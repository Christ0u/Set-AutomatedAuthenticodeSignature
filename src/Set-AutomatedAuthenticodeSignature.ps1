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
