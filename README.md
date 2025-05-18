# SecSecCertGuard

## Overview
SecSecCertGuard is a PowerShell-based tool designed to manage and inspect digital certificates on Windows systems. It provides a graphical user interface (GUI) to view, check, and manage certificates stored in the Current User and Local Machine certificate stores. Additionally, it includes a feature to scan critical directories for files with bad or missing signatures using sigcheck.

**All interface elements, messages, and comments are now fully in English for a consistent user experience.**

## Features
- **Certificate Management**: View and manage certificates in the Current User and Local Machine stores.
- **Certificate Inspection**: Check certificate validity, view details, and open certificates in the Windows certificate viewer.
- **File Signature Scanning**: Scan critical directories for `.exe` and `.dll` files with bad or missing signatures using sigcheck. (TODO)
- **English-Only Interface**: All buttons, tooltips, dialogs, and comments are in English.

## Prerequisites
- **PowerShell**: The script requires PowerShell 5.1 or later.
- **WPF Assemblies**: The script uses Windows Presentation Foundation (WPF) for the GUI. Ensure your system has the necessary WPF assemblies.
- **sigcheck**: The script requires sigcheck.exe or sigcheck64.exe to be available in the PATH or in a `Tools` folder within the script directory.

## Usage
1. **Run the Script**: Execute the script in PowerShell:
   ```powershell
   .\SecSecCertGuard.ps1
   ```
2. **Certificate Management**:
   - Use the "Current User" and "Local Machine" tabs to view and manage certificates.
   - Click on a certificate to view its details, check its validity, or open it in the Windows certificate viewer.
3. **File Signature Scanning**:
   - Use the "Scan Files" tab to scan critical directories for files with bad or missing signatures.
   - Click the "Scan Critical Files" button to start the scan.

## Dependencies
⚠️ Sysinternals License Notice  
This project uses [Sysinternals sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck), a Microsoft tool, for file signature verification.  
The tool is not included in this repository and must be downloaded separately by the user from the official Microsoft Sysinternals site.  
Use of sigcheck is subject to the [Sysinternals Software License Terms](https://learn.microsoft.com/en-us/sysinternals/license-terms).  
SecSecCertGuard simply calls sigcheck via command-line and does not modify, embed, or distribute it in any form.
- **sigcheck**: A command-line utility from Sysinternals used to verify file signatures. Ensure to install [Sysinternals Suite](https://apps.microsoft.com/detail/9p7knl5rwt25) or download sigcheck64.exe into the `Tools` directory.

### Optional
- Alternative blend: CertSentinel, TrustAudit, X509Inspector.

## Future Improvements (Beta)
- **Enhanced Scanning**: Add support for scanning additional directories and file types.
- **Improved Error Handling**: Enhance error handling and logging for better troubleshooting.
- **User Feedback**: Add more user feedback during scanning and certificate management operations.
- **Performance Optimization**: Optimize the script for better performance, especially when scanning large directories.

## Suggested Name
- **SecCertGuard**: A name that reflects the tool's purpose of guarding and managing certificates. Suggestions? SecSecCertGuard sounds good?

## More info
[PKI Repository - Microsoft PKI Services](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates)
[Install trusted TPM root certificates](https://www.microsoft.com/pkiops/docs/repository.htm)

## License

This project is licensed under the MIT License.

© 2025 [Your Name or Org]

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**Third-Party Notice – Sysinternals Sigcheck**  
This project uses the Microsoft Sysinternals tool `sigcheck.exe` or `sigcheck64.exe`, which is not distributed with this repository.  
Use of sigcheck is subject to [Microsoft Sysinternals License Terms](https://learn.microsoft.com/en-us/sysinternals/license-terms).  
You can download sigcheck from the official [Sysinternals site](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck).

SecSecCertGuard only invokes the tool externally and does not distribute or modify it in any form.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
