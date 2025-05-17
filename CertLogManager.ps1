<#
.SYNOPSIS
    CertLogManager is a PowerShell-based tool for managing and inspecting digital certificates on Windows systems.

.DESCRIPTION
    This script provides a graphical user interface (GUI) to view, check, and manage certificates stored in the Current User and Local Machine certificate stores. It also includes a feature to scan critical directories for files with bad or missing signatures using sigcheck.

.NOTES
    Author: @hackermystike - Julio Iglesias Perez
    Version: 1.1
    Date: $(Get-Date -Format '2025-05-17')
#>
# Load required assemblies
try {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
}
catch {
    Write-Error "Failed to load WPF assemblies: $($_.Exception.Message)"
    exit 1
}

# Initialize variable for sigcheck path
$sigcheckPath = $null

# Check if sigcheck.exe or sigcheck64.exe is in PATH
if (Get-Command "sigcheck.exe" -ErrorAction SilentlyContinue) {
    # Get the path of sigcheck.exe if found in PATH
    $sigcheckPath = & where.exe sigcheck.exe
    if ($null -eq $sigcheckPath) {
        Write-Host "sigcheck.exe found in PATH but not executable"
        exit 1
    }
    Write-Host "Found sigcheck.exe in PATH at: $sigcheckPath"
}
elseif (Test-Path "$env:LOCALAPPDATA\Microsoft\WindowsApps\sigcheck64.exe") {
    # Check if sigcheck64.exe is installed via Microsoft Store
    $sigcheckPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\sigcheck64.exe"
    Write-Host "Found sigcheck64.exe installed via Microsoft Store at: $sigcheckPath"
}
else {
    # Fallback to the default location (Tools folder)
    $sigcheckPath = Join-Path $PSScriptRoot "Tools\sigcheck64.exe"
    if (Test-Path $sigcheckPath) {
        Write-Host "Found sigcheck64.exe in Tools folder at: $sigcheckPath"
    }
    else {
        Write-Host "sigcheck64.exe not found in any known location"
        exit 1
    }
}

# Proceed with the rest of the script using the found sigcheck path
Write-Host "Using sigcheck at: $sigcheckPath"

# Create a temporary file for sigcheck output
$tempFile = Join-Path $env:TEMP "sigcheck_output.txt"
Write-Host "Temp file path: $tempFile"

# Remove existing temp file if it exists
if (Test-Path $tempFile) {
    $result = [System.Windows.MessageBox]::Show(
        "Found existing temp file`n$tempFile",
        "Would you like to keep working with it?",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question
    )} elseif ($result -eq [System.Windows.MessageBoxResult]::No) {
        try {
            Remove-Item $tempFile -Force -ErrorAction Stop
            Write-Host "Temporary file removed: $tempFile"
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Failed to remove temporary file: $($_.Exception.Message)",
                "Error",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Warning
            )
        }
    }
    else {
        Write-Host "Temporary file kept: $tempFile"
    }


# Load function to get SHA-256 hash
function Get-CertHashSHA256 {
    param ([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($cert.RawData)
        return ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ''
    }
    catch {
        Write-Warning "Failed to compute hash: $($_.Exception.Message)"
        return "N/A"
    }
}

# Function to create certificate card
# Function to display certificate properties using X509Certificate2UI
function Get-WindowCertificate {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
        [string]$storeName
    )

    try {
        # Display the certificate properties using X509Certificate2UI
        [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::DisplayCertificate($cert)
    }
    catch {
        Write-Warning "Failed to display certificate properties: $($_.Exception.Message)"
    }
}

# Function to check certificate status locally
function Get-CertificateStatus {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )
    try {
        # Check if certificate is within its validity period
    $now = Get-Date

        # Check certificate chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        
        # Add additional validation flags
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.VerificationTime = $now
        
        $isValid = $chain.Build($cert)
        
        # Check chain status
        if ($isValid) {
            foreach ($status in $chain.ChainStatus) {
                if ($status.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError) {
                    if ($now -lt $cert.NotBefore) {
                        return "Error. Not Yet Valid"
                    }
                    elseif ($now -gt $cert.NotAfter) {
                        return "Error. Expired"
                    }
                    return "Error. $($status.StatusInformation)"
                }
            }
            return "Valid"
        }
        else {
            return "Error. $($status.StatusInformation)"
        }
    }
    catch {
        return "Not checked"
    }
}

# Function to create certificate card with pre-checked status
function Get-CheckCertificateLocally {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
        [string]$storeName,
        [string]$status
    )
    
    try {
        # Check if certificate is trusted by verifying its chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $isValid = $chain.Build($cert)
        $hash = Get-CertHashSHA256 -cert $cert
        $thumbprint = $cert.Thumbprint.ToUpper()
        
        $card = New-Object System.Windows.Controls.Border
        $card.Margin = New-Object System.Windows.Thickness(5)
        $card.Padding = New-Object System.Windows.Thickness(10)
        $card.BorderThickness = New-Object System.Windows.Thickness(1)
        $card.BorderBrush = [System.Windows.Media.Brushes]::Gray
        $card.Background = if ($isValid) { [System.Windows.Media.Brushes]::LightGreen } else { [System.Windows.Media.Brushes]::LightPink }
        $card.CornerRadius = New-Object System.Windows.CornerRadius(5)
        
        $stackPanel = New-Object System.Windows.Controls.StackPanel
        
        $subjectText = New-Object System.Windows.Controls.TextBlock
        $subjectText.Text = $cert.Subject
        $subjectText.FontWeight = "Bold"
        $subjectText.TextWrapping = "Wrap"
        $subjectText.Margin = New-Object System.Windows.Thickness(0, 0, 0, 5)
        
        $hashText = New-Object System.Windows.Controls.TextBlock
        $hashText.Text = "SHA256: $hash"
        $hashText.TextWrapping = "Wrap"
        $hashText.Margin = New-Object System.Windows.Thickness(0, 0, 0, 5)
        
        $buttonPanel = New-Object System.Windows.Controls.StackPanel
        $buttonPanel.Orientation = "Horizontal"
        $buttonPanel.HorizontalAlignment = "Left"
        $buttonPanel.Margin = New-Object System.Windows.Thickness(0, 0, 0, 5)
        
        $checkButton = New-Object System.Windows.Controls.Button
        $checkButton.Content = "Check in crt.sh"
        $checkButton.Margin = New-Object System.Windows.Thickness(0, 0, 5, 0)
        $checkButton.Padding = New-Object System.Windows.Thickness(5, 2, 5, 2)
        $checkButton.Tag = $thumbprint
        $checkButton.Add_Click({
                $thumbprint = $_.Source.Tag
                $crtResultText = $_.Source.Parent.Parent.Children[3]
                $card = $_.Source.Parent.Parent.Parent
                $button = $_.Source

                $crtResultText.Text = "crt.sh: Checking..."
                $crtResultText.Foreground = [System.Windows.Media.Brushes]::Gray
                $card.Background = [System.Windows.Media.Brushes]::LightGray

                try {
                    $response = Invoke-WebRequest -Uri "https://crt.sh/?q=$thumbprint" -UseBasicParsing
                    if ($response.Content -match "Certificate not found") {
                        $crtResultText.Text = "crt.sh: Certificate not found"
                        $crtResultText.Foreground = [System.Windows.Media.Brushes]::Red
                        $card.Background = [System.Windows.Media.Brushes]::LightPink
                        $removeButton = $button.Parent.Children[4]
                        $removeButton.IsEnabled = $true
                        $revokeButton = $button.Parent.Children[5]
                        $revokeButton.IsEnabled = $true
                    }
                    elseif ($response.Content -match "Revoked \[by SHA-256\(SubjectPublicKeyInfo\)\]") {
                        $crtResultText.Text = "crt.sh: Certificate revoked by Google"
                        $crtResultText.Foreground = [System.Windows.Media.Brushes]::Red
                        $card.Background = [System.Windows.Media.Brushes]::LightPink
                        $removeButton = $button.Parent.Children[4]
                        $removeButton.IsEnabled = $true
                        $revokeButton = $button.Parent.Children[5]
                        $revokeButton.IsEnabled = $true
                    }
                    elseif ($response.Content -match "Revoked \[by MD5\(PublicKey\)\]") {
                        $crtResultText.Text = "crt.sh: Certificate revoked by Microsoft"
                        $crtResultText.Foreground = [System.Windows.Media.Brushes]::Red
                        $card.Background = [System.Windows.Media.Brushes]::LightPink
                        $removeButton = $button.Parent.Children[4]
                        $removeButton.IsEnabled = $true
                        $revokeButton = $button.Parent.Children[5]
                        $revokeButton.IsEnabled = $true
                    }
                    elseif ($response.Content -match "Revoked \[by Issuer Name, Serial Number\]") {
                        $crtResultText.Text = "crt.sh: Certificate revoked by Mozilla"
                        $crtResultText.Foreground = [System.Windows.Media.Brushes]::Red
                        $card.Background = [System.Windows.Media.Brushes]::LightPink
                        $removeButton = $button.Parent.Children[4]
                        $removeButton.IsEnabled = $true
                        $revokeButton = $button.Parent.Children[5]
                        $revokeButton.IsEnabled = $true
                    }
                    else {
                        $crtResultText.Text = "crt.sh: Certificate valid"
                        $crtResultText.Foreground = [System.Windows.Media.Brushes]::Green
                        $card.Background = [System.Windows.Media.Brushes]::LightGreen
                    }
                    # Disable the check button after use
                    $button.IsEnabled = $false
                }
                catch {
                    $crtResultText.Text = "Error checking certificate - $($_.Exception.Message)"
                    $crtResultText.Foreground = [System.Windows.Media.Brushes]::Red
                    $card.Background = [System.Windows.Media.Brushes]::LightPink
                    $removeButton = $button.Parent.Children[4]
                    $removeButton.IsEnabled = $true
                    $revokeButton = $button.Parent.Children[5]
                    $revokeButton.IsEnabled = $true
                    # Disable the check button after use
                    $button.IsEnabled = $false
                }
            })

        $openCrtButton = New-Object System.Windows.Controls.Button
        $openCrtButton.Content = "Open in crt.sh"
        $openCrtButton.Margin = New-Object System.Windows.Thickness(0, 0, 5, 0)
        $openCrtButton.Padding = New-Object System.Windows.Thickness(5, 2, 5, 2)
        $openCrtButton.Tag = $thumbprint
        $openCrtButton.Add_Click({
                $thumbprint = $_.Source.Tag
                Start-Process "https://crt.sh/?q=$thumbprint"
            })
        
        $sigcheckButton = New-Object System.Windows.Controls.Button
        $sigcheckButton.Content = "Check in Host"
        $sigcheckButton.Margin = New-Object System.Windows.Thickness(0, 0, 5, 0)
        $sigcheckButton.Padding = New-Object System.Windows.Thickness(5, 2, 5, 2)
        $sigcheckButton.Tag = $thumbprint
        $sigcheckButton.Add_Click({
                $thumbprint = $_.Source.Tag
                Write-Host "Checking thumbprint: $thumbprint" -ForegroundColor Cyan
                $sigcheckResultText = $_.Source.Parent.Parent.Children[4]
                $card = $_.Source.Parent.Parent.Parent
                $button = $_.Source
                $sigcheckResultText.Text = "Checking..."
                $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Gray
            
                try {
                    if (Test-Path $tempFile) {
                        Write-Host "Searching for thumbprint in output..." -ForegroundColor Cyan
                        # 5 lines before 3 lines after
                        $result = Get-Content $tempFile | Select-String -Pattern $thumbprint -Context 5, 3
                        Write-Host "Search result found: $($null -ne $results)" -ForegroundColor Cyan
                    
                        if ($result) {
                            Write-Host "Processing results..." -ForegroundColor Green
                            $output = ""
                        
                            # Get the full context around the match
                            $contextLines = @()
                            $contextLines += $result.Context.PreContext
                            $contextLines += $result.Line
                            $contextLines += $result.Context.PostContext
                        
                            # Process each line and extract relevant information
                            $certInfo = @{}
                            foreach ($line in $contextLines) {
                                if ($line -match "^\s*(Cert Status|Valid Usage|Cert Issuer|Serial Number|Valid from|Valid to):(.+)$") {
                                    $key = $matches[1].Trim()
                                    $value = $matches[2].Trim()
                                    $certInfo[$key] = $value
                                }
                            }
                        
                            # Build output in desired order
                            $orderedFields = @(
                                "Cert Status",
                                "Valid Usage",
                                "Cert Issuer",
                                "Serial Number",
                                "Valid from",
                                "Valid to"
                            )
                        
                            foreach ($field in $orderedFields) {
                                if ($certInfo.ContainsKey($field)) {
                                    $output += "$field : $($certInfo[$field])`n"
                                }
                            }
                        
                            $sigcheckResultText.Text = $output.Trim()
                        
                            # Determine certificate status and set color
                            if ($certInfo.ContainsKey("Cert Status")) {
                                $status = $certInfo["Cert Status"]
                                switch -Wildcard ($status) {
                                    "*Valid*" { 
                                        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Green
                                        $card.Background = [System.Windows.Media.Brushes]::LightGreen
                                    }
                                    "*Expired*" { 
                                        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Orange
                                        $card.Background = [System.Windows.Media.Brushes]::LightYellow
                                        $removeButton = $button.Parent.Children[4]
                                        $removeButton.IsEnabled = $true
                                        $revokeButton = $button.Parent.Children[5]
                                        $revokeButton.IsEnabled = $true
                                    }
                                    "*Revoked*" { 
                                        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Red
                                        $card.Background = [System.Windows.Media.Brushes]::LightPink
                                        $removeButton = $button.Parent.Children[4]
                                        $removeButton.IsEnabled = $true
                                        $revokeButton = $button.Parent.Children[5]
                                        $revokeButton.IsEnabled = $true
                                    }
                                    "*Not time valid*" {
                                        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Orange
                                        $card.Background = [System.Windows.Media.Brushes]::LightYellow
                                        $removeButton = $button.Parent.Children[4]
                                        $removeButton.IsEnabled = $true
                                        $revokeButton = $button.Parent.Children[5]
                                        $revokeButton.IsEnabled = $true
                                    }
                                    "*Has been revoked*" {
                                        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Red
                                        $card.Background = [System.Windows.Media.Brushes]::LightPink
                                        $removeButton = $button.Parent.Children[4]
                                        $removeButton.IsEnabled = $true
                                        $revokeButton = $button.Parent.Children[5]
                                        $revokeButton.IsEnabled = $true
                                    }
                                    "*Certificate is explicitly distrusted*" {
                                        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Red
                                        $card.Background = [System.Windows.Media.Brushes]::LightPink
                                        $removeButton = $button.Parent.Children[4]
                                        $removeButton.IsEnabled = $true
                                        $revokeButton = $button.Parent.Children[5]
                                        $revokeButton.IsEnabled = $true
                                    }
                                    "*Is based on an untrusted root*" {
                                        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Red
                                        $card.Background = [System.Windows.Media.Brushes]::LightPink
                                        $removeButton = $button.Parent.Children[4]
                                        $removeButton.IsEnabled = $true
                                        $revokeButton = $button.Parent.Children[5]
                                        $revokeButton.IsEnabled = $true
                                    }
                                    default { 
                                        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Gray
                                    }
                                }
                            }
                        }
                        else {
                            $sigcheckResultText.Text = "Certificate not found in sigcheck output"
                            $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Red
                            $card.Background = [System.Windows.Media.Brushes]::LightPink
                            $removeButton = $button.Parent.Children[4]
                            $removeButton.IsEnabled = $true
                            $revokeButton = $button.Parent.Children[5]
                            $revokeButton.IsEnabled = $true
                        }
                    }
                    else {
                        $sigcheckResultText.Text = "Output file not found. Please try again."
                        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Red
                        $card.Background = [System.Windows.Media.Brushes]::LightPink
                        $removeButton = $button.Parent.Children[4]
                        $removeButton.IsEnabled = $true
                        $revokeButton = $button.Parent.Children[5]
                        $revokeButton.IsEnabled = $true
                    }
                    # Disable the check button after use
                    $button.IsEnabled = $false
                }
                catch {
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                    $sigcheckResultText.Text = "Error checking certificate - $($_.Exception.Message)"
                    $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Red
                    $card.Background = [System.Windows.Media.Brushes]::LightPink
                    $removeButton = $button.Parent.Children[4]
                    $removeButton.IsEnabled = $true
                    $revokeButton = $button.Parent.Children[5]
                    $revokeButton.IsEnabled = $true
                    # Disable the check button after use
                    $button.IsEnabled = $false
                }
            })

        $wincheckButton = New-Object System.Windows.Controls.Button
        $wincheckButton.Content = "Open"
        $wincheckButton.Background = [System.Windows.Media.Brushes]::Orange
        $wincheckButton.Padding = New-Object System.Windows.Thickness(5, 2, 5, 2)
        $wincheckButton.Margin = New-Object System.Windows.Thickness(0, 0, 5, 0)
        $wincheckButton.Tag = @{
            Certificate = $cert
            StoreName   = $storeName
        }
        $wincheckButton.Add_Click({
                $button = $_.Source
                $cert = $button.Tag.Certificate
                $storeName = $button.Tag.StoreName
            
                try {
                    Get-WindowCertificate -cert $cert -storeName $storeName
                }
                catch {
                    [System.Windows.MessageBox]::Show("Error opening certificate card: $($_.Exception.Message)", "Error")
                }
            })
        
        $removeButton = New-Object System.Windows.Controls.Button
        $removeButton.Content = "Remove Certificate"
        $removeButton.Background = [System.Windows.Media.Brushes]::LightCoral
        $removeButton.Padding = New-Object System.Windows.Thickness(5, 2, 5, 2)
        $removeButton.IsEnabled = $false  # Start disabled
        $removeButton.Tag = @{
            Certificate = $cert
            StoreName   = $storeName
        }
        $removeButton.Add_Click({
                $button = $_.Source
                $cert = $button.Tag.Certificate
                $storeName = $button.Tag.StoreName
            
                try {
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
                    $store.Open("ReadWrite")
                    $store.Remove($cert)
                    $store.Close()
                    $button.Parent.Parent.Parent.Visibility = "Collapsed"
                }
                catch {
                    try {
                        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "CurrentUser")
                        $store.Open("ReadWrite")
                        $store.Remove($cert)
                        $store.Close()
                        $button.Parent.Parent.Parent.Visibility = "Collapsed"
                    }
                    catch {
                        [System.Windows.MessageBox]::Show("Error removing certificate: $($_.Exception.Message)`nTry running as administrator if removing from LocalMachine store.", "Error")
                    }
                }
            })

        $revokeButton = New-Object System.Windows.Controls.Button
        $revokeButton.Content = "Revoke Certificate"
        $revokeButton.Background = [System.Windows.Media.Brushes]::Red
        $revokeButton.Padding = New-Object System.Windows.Thickness(5, 2, 5, 2)
        $revokeButton.IsEnabled = $false  # Start disabled
        $revokeButton.Tag = @{
            Certificate = $cert
            StoreName   = $storeName
        }
        $revokeButton.Add_Click({
                $button = $_.Source
                $cert = $button.Tag.Certificate
                $storeName = $button.Tag.StoreName
                
                $result = [System.Windows.MessageBox]::Show(
                    "Are you sure you want to revoke this certificate?`nPlease verify manually before proceeding.`n`nCertificate: $($cert.Subject)",
                    "Confirm Revocation",
                    [System.Windows.MessageBoxButton]::YesNo,
                    [System.Windows.MessageBoxImage]::Warning
                )
                
                if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
                    # Determine if we're in CurrentUser or LocalMachine
                    $isCurrentUser = $storeName -like "*CurrentUser*"
                    $certMgrPath = if ($isCurrentUser) { "certmgr.msc" } else { "certlm.msc" }
                    
                    # Start the appropriate certificate manager
                    Start-Process $certMgrPath
                    
                    # Show instructions
                    [System.Windows.MessageBox]::Show(
                        "Please navigate to the following store in the Certificate Manager:`n$storeName",
                        "Certificate Manager Opened",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information
                    )
                }
            })
        
        [void]$buttonPanel.Children.Add($checkButton)
        [void]$buttonPanel.Children.Add($openCrtButton)
        [void]$buttonPanel.Children.Add($sigcheckButton)
        [void]$buttonPanel.Children.Add($wincheckButton)
        [void]$buttonPanel.Children.Add($removeButton)
        [void]$buttonPanel.Children.Add($revokeButton)
        
        # Add result text blocks with pre-checked status
        $crtResultText = New-Object System.Windows.Controls.TextBlock
        $crtResultText.Text = "crt.sh: Not checked"
        $crtResultText.TextWrapping = "Wrap"
        $crtResultText.Margin = New-Object System.Windows.Thickness(0, 5, 0, 5)
        $crtResultText.Foreground = [System.Windows.Media.Brushes]::Gray
        
        $sigcheckResultText = New-Object System.Windows.Controls.TextBlock
        $sigcheckResultText.Text = "Not checked"
        $sigcheckResultText.TextWrapping = "Wrap"
        $sigcheckResultText.Margin = New-Object System.Windows.Thickness(0, 0, 0, 5)
        $sigcheckResultText.Foreground = [System.Windows.Media.Brushes]::Gray
        
        [void]$stackPanel.Children.Add($subjectText)
        [void]$stackPanel.Children.Add($hashText)
        [void]$stackPanel.Children.Add($buttonPanel)
        [void]$stackPanel.Children.Add($crtResultText)
        [void]$stackPanel.Children.Add($sigcheckResultText)
        
        $card.Child = $stackPanel
        return $card
    }
    catch {
        Write-Warning "Failed to create certificate card: $($_.Exception.Message)"
        return $null
    }
}

# List of stores for comparison
$commonStores = @('Trust', 'ClientAuthIssuer', 'TrustedPeople', 'Root', 'My', 'SmartCardRoot', 'CA', 'AuthRoot', 'TrustedPublisher')
$machineOnlyStores = @('PasspointTrustedRoots', 'OpenVPN Certificate Store', 'TrustedTpm_IntermediateCA', 'TestSignRoot', 'TrustedDevices', 'TrustedAppRoot', 'FlightRoot', 'REQUEST', 'Windows Live ID Token Issuer', 'AAD Token Issuer', 'TrustedTpm_RootCA', 'AddressBook', 'WindowsServerUpdateServices', 'eSIM Certification Authorities', 'OemEsim')
$userOnlyStores = @('UserDS')

# Ensure sigcheck temp file is generated at startup if not present
if (-not (Test-Path $tempFile)) {
    try {
        Write-Host "Generating sigcheck output at startup..."
        $rawOutput = & $sigcheckPath -accepteula -t * -r -a

        if ($rawOutput) {
            $seenThumbprints = @{}
            $currentBlock = @()
            $thumbprint = $null

            foreach ($line in $rawOutput) {
                $currentBlock += $line

                # Capture thumbprint if seen
                if ($line -match 'Thumbprint\s*:\s*(.+)') {
                    $thumbprint = $matches[1].Trim()
                }

                # Block ends on empty line
                if ($line -match '^\s*$') {
                    if ($thumbprint -and -not $seenThumbprints.ContainsKey($thumbprint)) {
                        Add-Content -Path $tempFile -Value (($currentBlock -join "`n") + "`n`n")
                        $seenThumbprints[$thumbprint] = $true
                    }

                    # Reset state for next block
                    $currentBlock = @()
                    $thumbprint = $null
                }
            }

            # Handle last block if not written (no trailing blank line)
            if ($thumbprint -and -not $seenThumbprints.ContainsKey($thumbprint) -and $currentBlock.Count -gt 0) {
                Add-Content -Path $tempFile -Value (($currentBlock -join "`n") + "`n`n")
            }

            Write-Host "Unique sigcheck certificate output written to: $tempFile"
        }
        else {
            Write-Host "No output generated from sigcheck at startup"
        }
    }
    catch {
        Write-Host "Error running sigcheck at startup: $($_.Exception.Message)"
    }
}


# Add this function before the Set-Panel function
function Show-ProgressWindow {
    param (
        [string]$Title,
        [string]$Message,
        [int]$Maximum
    )

    $progressWindow = New-Object System.Windows.Window
    $progressWindow.Title = $Title
    $progressWindow.Width = 400
    $progressWindow.Height = 150
    $progressWindow.WindowStartupLocation = "CenterScreen"
    $progressWindow.Topmost = $true

    $stackPanel = New-Object System.Windows.Controls.StackPanel
    $stackPanel.Margin = New-Object System.Windows.Thickness(10)
    $stackPanel.HorizontalAlignment = "Center"

    $textBlock = New-Object System.Windows.Controls.TextBlock
    $textBlock.Text = $Message
    $textBlock.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
    $textBlock.TextWrapping = "Wrap"
    $textBlock.TextAlignment = "Center"

    $progressBar = New-Object System.Windows.Controls.ProgressBar
    $progressBar.Height = 20
    $progressBar.Width = 300
    $progressBar.IsIndeterminate = $false
    $progressBar.Minimum = 0
    $progressBar.Maximum = $Maximum
    $progressBar.Value = 0

    [void]$stackPanel.Children.Add($textBlock)
    [void]$stackPanel.Children.Add($progressBar)

    $progressWindow.Content = $stackPanel
    $progressWindow.Show()

    return @{ Window = $progressWindow; ProgressBar = $progressBar }
}

# Update Set-Panel to handle pre-checked certificates
function Set-Panel {
    param (
        [System.Windows.Controls.Panel]$panel,
        [string]$path,
        [bool]$isDisallowedTab = $false
    )
    try {
        # Add only the hyperlink at the top (no notification text)
        $hyperlink = New-Object System.Windows.Documents.Hyperlink
        $hyperlink.NavigateUri = "https://www.microsoft.com/pkiops/docs/repository.htm"
        $hyperlink.Inlines.Add("Microsoft PKI Repository")
        $hyperlink.Foreground = [System.Windows.Media.Brushes]::Blue
        $hyperlink.TextDecorations = [System.Windows.TextDecorations]::Underline
        $hyperlink.Add_Click({
                Start-Process "https://www.microsoft.com/pkiops/docs/repository.htm"
            })

        # Add only the hyperlink at the top (no notification text)
        $hyperlink2 = New-Object System.Windows.Documents.Hyperlink
        $hyperlink2.NavigateUri = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates"
        $hyperlink2.Inlines.Add("Configure certificates in Windows")
        $hyperlink2.Foreground = [System.Windows.Media.Brushes]::Blue
        $hyperlink2.TextDecorations = [System.Windows.TextDecorations]::Underline
        $hyperlink2.Add_Click({
                Start-Process "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates"
            })
        
        # Add only the hyperlink at the top (no notification text)
        $hyperlink3 = New-Object System.Windows.Documents.Hyperlink
        $hyperlink3.NavigateUri = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates"
        $hyperlink3.Inlines.Add("Install Trusted TPM Root Certificates")
        $hyperlink3.Foreground = [System.Windows.Media.Brushes]::Blue
        $hyperlink3.TextDecorations = [System.Windows.TextDecorations]::Underline
        $hyperlink3.Add_Click({
                Start-Process "https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates"
            })

        $hyperlinkTextBlock = New-Object System.Windows.Controls.TextBlock
        $hyperlinkTextBlock.Inlines.Add("Resources:  [ ")
        $hyperlinkTextBlock.Inlines.Add($hyperlink)
        $hyperlinkTextBlock.Inlines.Add(" ]  [ ")
        $hyperlinkTextBlock.Inlines.Add($hyperlink3)
        $hyperlinkTextBlock.Inlines.Add(" ]  [ ")
        $hyperlinkTextBlock.Inlines.Add($hyperlink2)
        $hyperlinkTextBlock.Inlines.Add(" ]")
        $hyperlinkTextBlock.Background = [System.Windows.Media.Brushes]::LightYellow
        $hyperlinkTextBlock.Padding = New-Object System.Windows.Thickness(10)
        $hyperlinkTextBlock.Margin = New-Object System.Windows.Thickness(5)
        $hyperlinkTextBlock.TextWrapping = "Wrap"
        [void]$panel.Children.Add($hyperlinkTextBlock)

        Write-Host "Accessing path: $path"
        $stores = Get-ChildItem -Path $path -ErrorAction Stop
        
        # Create a dictionary to store certificates by store name
        $storeCerts = @{}
        $totalCerts = 0
        
        # Process stores based on type
        foreach ($store in $stores) {
            try {
                Write-Host "Processing store: $($store.Name)"
                
                # Skip Disallowed store for non-disallowed tabs
                if (-not $isDisallowedTab -and $store.Name -eq 'Disallowed') {
                    continue
                }
                
                # For Disallowed tab, only process LocalMachine Disallowed
                if ($isDisallowedTab) {
                    if ($store.Name -ne 'Disallowed' -or $path -notlike "*LocalMachine*") {
                        continue
                    }
                }
                
                $certs = Get-ChildItem -Path "$path\$($store.Name)" -ErrorAction Stop
                Write-Host "Found $($certs.Count) certificates in store $($store.Name)"
                
                if ($certs) {
                    # Pre-check all certificates in this store
                    $checkedCerts = @()
                    foreach ($cert in $certs) {
                        $status = Get-CertificateStatus -cert $cert
                        $checkedCerts += @{
                            'Certificate' = $cert
                            'Status'      = $status
                        }
                    }
                    
                    # Sort certificates by status
                    $sortedCerts = $checkedCerts | Sort-Object {
                        switch ($_.Status) {
                            "Error" { 0 }
                            "Not checked" { 1 }
                            "Valid" { 2 }
                            default { 3 }
                        }
                    }
                    
                    $storeCerts[$store.Name] = @{
                        'Certs' = $sortedCerts
                        'Path'  = $path
                    }
                    $totalCerts += $certs.Count
                }
            }
            catch {
                Write-Warning "Failed to access store $($store.Name): $($_.Exception.Message)"
            }
        }
        
        Write-Host "Total certificates found in $path : $totalCerts"
        
        if ($isDisallowedTab) {
            # Process Disallowed stores (only from LocalMachine)
            foreach ($storeName in $storeCerts.Keys) {
                $certs = $storeCerts[$storeName].Certs
                if ($certs) {
                    $groupBox = New-Object System.Windows.Controls.GroupBox
                    $groupBox.Header = "$storeName ($($certs.Count))"
                    $groupBox.Margin = New-Object System.Windows.Thickness(5)
                    
                    # Create header panel with store name
                    $headerPanel = New-Object System.Windows.Controls.StackPanel
                    $headerPanel.Orientation = "Horizontal"
                    
                    $headerText = New-Object System.Windows.Controls.TextBlock
                    $headerText.Text = "$storeName ($($certs.Count))"
                    $headerText.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
                    
                    [void]$headerPanel.Children.Add($headerText)
                    
                    $groupBox.Header = $headerPanel
                    
                    $expander = New-Object System.Windows.Controls.Expander
                    $expander.IsExpanded = $false
                    $expander.Header = "Click to expand/collapse"
                    
                    $storePanel = New-Object System.Windows.Controls.StackPanel
                    foreach ($certInfo in $certs) {
                        try {
                            $certCard = Get-CheckCertificateLocally -cert $certInfo.Certificate -storeName $storeName -status $certInfo.Status
                            if ($certCard) {
                                [void]$storePanel.Children.Add($certCard)
                            }
                        }
                        catch {
                            Write-Warning "Error processing certificate: $($_.Exception.Message)"
                        }
                    }
                    
                    $expander.Content = $storePanel
                    $groupBox.Content = $expander
                    [void]$panel.Children.Add($groupBox)
                }
            }
        }
        else {
            # Process common stores
            foreach ($storeName in $commonStores) {
                if ($storeCerts.ContainsKey($storeName)) {
                    $certs = $storeCerts[$storeName].Certs
                    if ($certs) {
                        $groupBox = New-Object System.Windows.Controls.GroupBox
                        $groupBox.Margin = New-Object System.Windows.Thickness(5)
                        
                        # Create header panel with store name
                        $headerPanel = New-Object System.Windows.Controls.StackPanel
                        $headerPanel.Orientation = "Horizontal"
                        
                        $headerText = New-Object System.Windows.Controls.TextBlock
                        $headerText.Text = "$storeName ($($certs.Count))"
                        $headerText.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
                        
                        # Only add Check All button for LocalMachine tab
                        if ($panel.Name -eq "localMachinePanel") {
                            $checkAllButton = New-Object System.Windows.Controls.Button
                            $checkAllButton.Content = "Check All in Host"
                            $checkAllButton.Margin = New-Object System.Windows.Thickness(10, 0, 0, 0)
                            $checkAllButton.Padding = New-Object System.Windows.Thickness(5, 2, 5, 2)
                            $checkAllButton.Background = [System.Windows.Media.Brushes]::LightBlue
                            $checkAllButton.Tag = $storeName
                            
                            $checkAllButton.Add_Click({
                                    $storeName = $_.Source.Tag
                                    $expander = $_.Source.Parent.Parent.Content
                                    $storePanel = $expander.Content
                                
                                    # Show progress window
                                    $progressWindow = Show-ProgressWindow -Title "Checking Certificates" -Message "Checking certificates in $storeName store... Please wait."
                                
                                    try {
                                        # Find all "Check in Host" buttons in this store panel
                                        $progressBar = $progressWindow.ProgressBar
                                        foreach ($child in $storePanel.Children) {
                                            if ($child -is [System.Windows.Controls.Border]) {
                                                $stackPanel = $child.Child
                                                $buttonPanel = $stackPanel.Children[2]  # The button panel is the 3rd child
                                            
                                                # The "Check in Host" button is the 3rd button (index 2)
                                                $sigcheckButton = $buttonPanel.Children[2]
                                            
                                                # Only click if button is enabled
                                                if ($sigcheckButton.IsEnabled) {
                                                    $sigcheckButton.RaiseEvent(
                                                    (New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Button]::ClickEvent))
                                                    )
                                                    # Add a small delay to prevent overwhelming the system
                                                    Start-Sleep -Milliseconds 100
                                                }
                                            }
                                        
                                        }
                                    }
                                    finally {
                                        # Close progress window
                                        $progressWindow.Window.Close()
                                    }
                                })
                            
                            [void]$headerPanel.Children.Add($checkAllButton)
                        }
                        
                        [void]$headerPanel.Children.Add($headerText)
                        $groupBox.Header = $headerPanel
                        
                        $expander = New-Object System.Windows.Controls.Expander
                        $expander.IsExpanded = $false
                        $expander.Header = "Click to expand/collapse"
                        
                        $storePanel = New-Object System.Windows.Controls.StackPanel
                        foreach ($certInfo in $certs) {
                            try {
                                $certCard = Get-CheckCertificateLocally -cert $certInfo.Certificate -storeName $storeName -status $certInfo.Status
                                if ($certCard) {
                                    [void]$storePanel.Children.Add($certCard)
                                }
                            }
                            catch {
                                Write-Warning "Error processing certificate: $($_.Exception.Message)"
                            }
                        }
                        
                        $expander.Content = $storePanel
                        $groupBox.Content = $expander
                        [void]$panel.Children.Add($groupBox)
                    }
                }
            }
            
            # Process machine-only stores (only for LocalMachine)
            if ($path -like "*LocalMachine*") {
                foreach ($storeName in $machineOnlyStores) {
                    if ($storeCerts.ContainsKey($storeName)) {
                        $certs = $storeCerts[$storeName].Certs
                        if ($certs) {
                            $groupBox = New-Object System.Windows.Controls.GroupBox
                            $groupBox.Margin = New-Object System.Windows.Thickness(5)
                            
                            # Create header panel with store name
                            $headerPanel = New-Object System.Windows.Controls.StackPanel
                            $headerPanel.Orientation = "Horizontal"
                            
                            $headerText = New-Object System.Windows.Controls.TextBlock
                            $headerText.Text = "$storeName ($($certs.Count))"
                            $headerText.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
                            
                            # Add Check All button (only for LocalMachine tab)
                            if ($panel.Name -eq "localMachinePanel") {
                                $checkAllButton = New-Object System.Windows.Controls.Button
                                $checkAllButton.Content = "Check All in Host"
                                $checkAllButton.Margin = New-Object System.Windows.Thickness(10, 0, 0, 0)
                                $checkAllButton.Padding = New-Object System.Windows.Thickness(5, 2, 5, 2)
                                $checkAllButton.Background = [System.Windows.Media.Brushes]::LightBlue
                                $checkAllButton.Tag = $storeName
                                
                                $checkAllButton.Add_Click({
                                        $storeName = $_.Source.Tag
                                        $expander = $_.Source.Parent.Parent.Content
                                        $storePanel = $expander.Content
                                    
                                        # Show progress window
                                        $progressWindow = Show-ProgressWindow -Title "Checking Certificates" -Message "Checking certificates in $storeName store... Please wait."
                                    
                                        try {
                                            # Find all "Check in Host" buttons in this store panel
                                            foreach ($child in $storePanel.Children) {
                                                if ($child -is [System.Windows.Controls.Border]) {
                                                    $stackPanel = $child.Child
                                                    $buttonPanel = $stackPanel.Children[2]  # The button panel is the 3rd child
                                                
                                                    # The "Check in Host" button is the 3rd button (index 2)
                                                    $sigcheckButton = $buttonPanel.Children[2]
                                                
                                                    # Only click if button is enabled
                                                    if ($sigcheckButton.IsEnabled) {
                                                        $sigcheckButton.RaiseEvent(
                                                        (New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Button]::ClickEvent))
                                                        )
                                                        # Add a small delay to prevent overwhelming the system
                                                        Start-Sleep -Milliseconds 100
                                                    }
                                                }
                                            }
                                        }
                                        finally {
                                            # Close progress window
                                            $progressWindow.Window.Close()
                                        }
                                    })
                                
                                [void]$headerPanel.Children.Add($checkAllButton)
                            }
                            
                            [void]$headerPanel.Children.Add($headerText)
                            $groupBox.Header = $headerPanel
                            
                            $expander = New-Object System.Windows.Controls.Expander
                            $expander.IsExpanded = $false
                            $expander.Header = "Click to expand/collapse"
                            
                            $storePanel = New-Object System.Windows.Controls.StackPanel
                            foreach ($certInfo in $certs) {
                                try {
                                    $certCard = Get-CheckCertificateLocally -cert $certInfo.Certificate -storeName $storeName -status $certInfo.Status
                                    if ($certCard) {
                                        [void]$storePanel.Children.Add($certCard)
                                    }
                                }
                                catch {
                                    Write-Warning "Error processing certificate: $($_.Exception.Message)"
                                }
                            }
                            
                            $expander.Content = $storePanel
                            $groupBox.Content = $expander
                            [void]$panel.Children.Add($groupBox)
                        }
                    }
                }
            }
            
            # Process user-only stores (no Check All button)
            if ($path -like "*CurrentUser*") {
                foreach ($storeName in $userOnlyStores) {
                    if ($storeCerts.ContainsKey($storeName)) {
                        $certs = $storeCerts[$storeName].Certs
                        if ($certs) {
                            $groupBox = New-Object System.Windows.Controls.GroupBox
                            $groupBox.Header = "$storeName ($($certs.Count))"
                            $groupBox.Margin = New-Object System.Windows.Thickness(5)
                            
                            # Create header panel with store name
                            $headerPanel = New-Object System.Windows.Controls.StackPanel
                            $headerPanel.Orientation = "Horizontal"
                            
                            $headerText = New-Object System.Windows.Controls.TextBlock
                            $headerText.Text = "$storeName ($($certs.Count))"
                            $headerText.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
                            
                            [void]$headerPanel.Children.Add($headerText)
                            
                            $groupBox.Header = $headerPanel
                            
                            $expander = New-Object System.Windows.Controls.Expander
                            $expander.IsExpanded = $false
                            $expander.Header = "Click to expand/collapse"
                            
                            $storePanel = New-Object System.Windows.Controls.StackPanel
                            foreach ($certInfo in $certs) {
                                try {
                                    $certCard = Get-CheckCertificateLocally -cert $certInfo.Certificate -storeName $storeName -status $certInfo.Status
                                    if ($certCard) {
                                        [void]$storePanel.Children.Add($certCard)
                                    }
                                }
                                catch {
                                    Write-Warning "Error processing certificate: $($_.Exception.Message)"
                                }
                            }
                            
                            $expander.Content = $storePanel
                            $groupBox.Content = $expander
                            [void]$panel.Children.Add($groupBox)
                        }
                    }
                }
            }
        }
        
        # Add total count to panel
        $totalCountText = New-Object System.Windows.Controls.TextBlock
        $totalCountText.Text = "Total Certificates: $totalCerts"
        $totalCountText.FontWeight = "Bold"
        $totalCountText.Margin = New-Object System.Windows.Thickness(5)
        
        # Create a horizontal stack panel for the count and button
        $countPanel = New-Object System.Windows.Controls.StackPanel
        $countPanel.Orientation = "Horizontal"
        $countPanel.Margin = New-Object System.Windows.Thickness(5)
        
        [void]$countPanel.Children.Add($totalCountText)
        
        if (-not $isDisallowedTab) {
            if ($panel.Name -eq "currentUserPanel") {
                # Automatically filter repeated certificates at load
                $panel.Children.Clear()
                [void]$panel.Children.Add($countPanel)
                $filterPath = "Cert:\CurrentUser"
                $otherPath = "Cert:\LocalMachine"
                $stores = Get-ChildItem -Path $filterPath -ErrorAction SilentlyContinue
                $totalCerts = 0
                foreach ($store in $stores) {
                    if ($store.Name -eq 'Disallowed') { continue }
                    $certs = Get-ChildItem -Path "$filterPath\$($store.Name)" -ErrorAction SilentlyContinue
                    $otherCerts = Get-ChildItem -Path "$otherPath\$($store.Name)" -ErrorAction SilentlyContinue
                    if ($certs) {
                        $uniqueCerts = @()
                        foreach ($cert in $certs) {
                            $existsInOther = $otherCerts | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
                            if (-not $existsInOther) {
                                $uniqueCerts += $cert
                            }
                        }
                        if ($uniqueCerts.Count -gt 0) {
                            $totalCerts += $uniqueCerts.Count
                            $groupBox = New-Object System.Windows.Controls.GroupBox
                            $groupBox.Header = "$($store.Name) ($($uniqueCerts.Count))"
                            $groupBox.Margin = New-Object System.Windows.Thickness(5)
                            $expander = New-Object System.Windows.Controls.Expander
                            $expander.IsExpanded = $false
                            $expander.Header = "Click to expand/collapse"
                            $storePanel = New-Object System.Windows.Controls.StackPanel
                            foreach ($cert in $uniqueCerts) {
                                try {
                                    $status = Get-CertificateStatus -cert $cert
                                    $certCard = Get-CheckCertificateLocally -cert $cert -storeName $store.Name -status $status
                                    if ($certCard) {
                                        [void]$storePanel.Children.Add($certCard)
                                    }
                                }
                                catch {
                                    Write-Warning "Error processing certificate: $($_.Exception.Message)"
                                }
                            }
                            $expander.Content = $storePanel
                            $groupBox.Content = $expander
                            [void]$panel.Children.Add($groupBox)
                        }
                    }
                }
                # Update total count
                $totalCountText.Text = "Total Certificates: $totalCerts"
                [void]$panel.Children.Add($countPanel)
                return
            }
        }
        
        [void]$panel.Children.Insert(0, $countPanel)
        
    }
    catch {
        Write-Warning "Failed to access path ${path}: $($_.Exception.Message)"
    }
}

# Create Window
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Certificate Manager" Height="800" Width="800"
        WindowStartupLocation="CenterScreen">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TabControl Grid.Row="1" Name="tabControl" Margin="5">
            <TabItem Header="Current User">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
                    <StackPanel Name="currentUserPanel" Margin="5"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Local Machine">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
                    <StackPanel Name="localMachinePanel" Margin="5"/>
                </ScrollViewer>
            </TabItem>
            <TabItem Header="Disallowed">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
                    <StackPanel Name="disallowedPanel" Margin="5"/>
                </ScrollViewer>
            </TabItem>
        </TabControl>
    </Grid>
</Window>
"@

try {
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
    
    if ($null -eq $window) {
        throw "Failed to create window"
    }
    
    # Add logic to handle the $tempFile on window close
    $window.Add_Closing({
            param($Customsender, $e)

            if (Test-Path $tempFile) {
                $result = [System.Windows.MessageBox]::Show(
                    "Do you want to keep the temporary file for future use?`n$tempFile",
                    "Keep Temporary File?",
                    [System.Windows.MessageBoxButton]::YesNo,
                    [System.Windows.MessageBoxImage]::Question
                )

                if ($result -eq [System.Windows.MessageBoxResult]::No) {
                    try {
                        Remove-Item $tempFile -Force -ErrorAction Stop
                        Write-Host "Temporary file removed: $tempFile"
                    }
                    catch {
                        [System.Windows.MessageBox]::Show(
                            "Failed to remove temporary file: $($_.Exception.Message)",
                            "Error",
                            [System.Windows.MessageBoxButton]::OK,
                            [System.Windows.MessageBoxImage]::Warning
                        )
                    }
                }
                else {
                    Write-Host "Temporary file kept: $tempFile"
                }
            }
        })
    
    # Get panels from window
    $currentUserPanel = $window.FindName("currentUserPanel")
    $localMachinePanel = $window.FindName("localMachinePanel")
    $disallowedPanel = $window.FindName("disallowedPanel")
    
    if ($null -eq $currentUserPanel -or $null -eq $localMachinePanel -or $null -eq $disallowedPanel) {
        throw "Failed to find panel controls"
    }
    
    # Populate panels
    Write-Host "Loading certificates..."
    Set-Panel -panel $currentUserPanel -path "cert:\CurrentUser"
    Set-Panel -panel $localMachinePanel -path "cert:\LocalMachine"
    Set-Panel -panel $disallowedPanel -path "cert:\LocalMachine" -isDisallowedTab $true
    
    # Show window
    $window.ShowDialog()
}
catch {
    [System.Windows.MessageBox]::Show(
        "Error loading XAML:`n$($_.Exception.Message)",
        "XAML Load Error",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error
    )
    # Do not exit, allow the script to continue or end gracefully
}
