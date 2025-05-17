
# CertLogManager

## Overview
CertLogManager is a PowerShell-based tool designed to manage and inspect digital certificates on Windows systems. It provides a graphical user interface (GUI) to view, check, and manage certificates stored in the Current User and Local Machine certificate stores. Additionally, it includes a feature to scan critical directories for files with bad or missing signatures using sigcheck.

## Features
- **Certificate Management**: View and manage certificates in the Current User and Local Machine stores.
- **Certificate Inspection**: Check certificate validity, view details, and open certificates in the Windows certificate viewer.
- **File Signature Scanning**: Scan critical directories for `.exe` and `.dll` files with bad or missing signatures using sigcheck. (TODO)

## Prerequisites
- **PowerShell**: The script requires PowerShell 5.1 or later.
- **WPF Assemblies**: The script uses Windows Presentation Foundation (WPF) for the GUI. Ensure your system has the necessary WPF assemblies.
- **sigcheck**: The script requires sigcheck.exe or sigcheck64.exe to be available in the PATH or in a `Tools` folder within the script directory.

## Usage
1. **Run the Script**: Execute the script in PowerShell:
   ```powershell
   .\CertLogManager.ps1
   ```
2. **Certificate Management**:
   - Use the "Current User" and "Local Machine" tabs to view and manage certificates.
   - Click on a certificate to view its details, check its validity, or open it in the Windows certificate viewer.
3. **File Signature Scanning**:
   - Use the "Scan Files" tab to scan critical directories for files with bad or missing signatures.
   - Click the "Scan Critical Files" button to start the scan.

## Dependencies
⚠️ Sysinternals License Notice
This project uses [Sysinternals sigcheck](https://learn.microsoft.com/es-mx/sysinternals/downloads/sigcheck), a Microsoft tool, for file signature verification.
The tool is not included in this repository and must be downloaded separately by the user from the official Microsoft Sysinternals site.
Use of sigcheck is subject to the [Sysinternals Software License Terms](https://learn.microsoft.com/es-mx/sysinternals/license-terms).
CertLogManager simply calls sigcheck via command-line and does not modify, embed, or distribute it in any form.
- **sigcheck**: A command-line utility from Sysinternals used to verify file signatures. Ensure it is available in the PATH or in the `Tools` folder.

## Future Improvements (Beta)
- **Enhanced Scanning**: Add support for scanning additional directories and file types.
- **Improved Error Handling**: Enhance error handling and logging for better troubleshooting.
- **User Feedback**: Add more user feedback during scanning and certificate management operations.
- **Performance Optimization**: Optimize the script for better performance, especially when scanning large directories.

## Suggested Name
- **CertGuard**: A name that reflects the tool's purpose of guarding and managing certificates. Suggestions? CertLogManager sounds good?

## License
This project is open-source and available under the MIT License.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
