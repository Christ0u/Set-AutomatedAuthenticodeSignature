# Set-AutomatedAuthenticodeSignature

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-All%20rights%20reserved-lightgrey)

Automatically signs PowerShell files with an Authenticode code-signing certificate.

The script signs existing files when it starts, then monitors the specified directory and its subdirectories. Whenever a matching file is modified, it waits for the file to stabilize and re-signs it if its signature is no longer valid.

## Requirements

- Windows PowerShell 5.1
- Git 2.0
- A code-signing certificate installed in the current-user or local-machine certificate store

## Getting started

```bash
git clone https://github.com/Christ0u/Set-AutomatedAuthenticodeSignature.git
cd .\Set-AutomatedAuthenticodeSignature\
```

## Usage

```powershell
.\src\Set-AutomatedAuthenticodeSignature.ps1 -CertificateThumbprint "E7DAC6FBC64F03BC009299DE5A46F57901010958" -FileExtensions ".ps1", ".psd1", ".psm1"
```

This command signs matching files in the default root directory, then keeps monitoring that directory and its subdirectories.

To monitor a specific directory:

```powershell
.\src\Set-AutomatedAuthenticodeSignature.ps1 -RootPath "C:\Scripts" -CertificateThumbprint "E7DAC6FBC64F03BC009299DE5A46F57901010958" -FileExtensions ".ps1", ".psd1", ".psm1"
```

## Parameters

| Parameter               | Required | Description                                                                                                  |
| ----------------------- | -------- | ------------------------------------------------------------------------------------------------------------ |
| `RootPath`              | No       | Root directory to monitor and sign. Defaults to `%HOMEDRIVE%%HOMEPATH%\Documents\WindowsPowerShell\Sources`. |
| `CertificateThumbprint` | Yes      | Thumbprint of the code-signing certificate to use.                                                           |
| `FileExtensions`        | Yes      | File extensions to monitor and sign. Extensions can be provided with or without a leading dot.               |

## License

This project is licensed under the MIT License.

See [LICENSE](./LICENSE) for more information.
