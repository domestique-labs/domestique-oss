# Deploy LLM Firewall CA certificate to Windows machines via GPO
# Run this on a Domain Controller or management workstation with RSAT

param(
    [Parameter(Mandatory=$true)]
    [string]$CertificatePath,

    [Parameter(Mandatory=$false)]
    [string]$GPOName = "LLM Firewall - Trusted Root CA"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Deploying LLM Firewall CA Certificate ===" -ForegroundColor Green

# Verify certificate exists
if (-not (Test-Path $CertificatePath)) {
    throw "Certificate not found: $CertificatePath"
}

# Import the certificate to verify it's valid
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
Write-Host "Certificate Subject: $($cert.Subject)"
Write-Host "Certificate Thumbprint: $($cert.Thumbprint)"
Write-Host "Valid Until: $($cert.NotAfter)"

# Option 1: Deploy to local machine (for testing)
Write-Host "`nInstalling to local Trusted Root store..."
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
Write-Host "✓ Installed to local machine" -ForegroundColor Green

# Option 2: Create GPO for domain-wide deployment
Write-Host "`nTo deploy via Group Policy:"
Write-Host "1. Open Group Policy Management Console (gpmc.msc)"
Write-Host "2. Create or edit GPO: '$GPOName'"
Write-Host "3. Navigate to: Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Trusted Root Certification Authorities"
Write-Host "4. Right-click > Import > Select: $CertificatePath"
Write-Host "5. Link GPO to the appropriate OU"
Write-Host ""
Write-Host "Or use PowerShell (requires ActiveDirectory module):" -ForegroundColor Yellow
Write-Host @"

# Import-Module GroupPolicy
# `$gpo = New-GPO -Name "$GPOName"
# # Link to domain root (adjust OU as needed)
# `$gpo | New-GPLink -Target (Get-ADDomain).DistinguishedName
# # Copy cert to GPO machine path
# `$gpoPath = "\\`$(`$env:USERDNSDOMAIN)\SYSVOL\`$(`$env:USERDNSDOMAIN)\Policies\{`$(`$gpo.Id)}\Machine"
# Copy-Item $CertificatePath "`$gpoPath\ca.crt"

"@

Write-Host "=== Also configure DNS ===" -ForegroundColor Green
Write-Host "Add these DNS records pointing to the firewall proxy IP:"
Write-Host "  api.openai.com          → <FIREWALL_IP>"
Write-Host "  api.anthropic.com       → <FIREWALL_IP>"
Write-Host "  *.openai.azure.com      → <FIREWALL_IP>"
Write-Host "  api.cohere.ai           → <FIREWALL_IP>"
Write-Host "  api.mistral.ai          → <FIREWALL_IP>"
Write-Host "  api.together.xyz        → <FIREWALL_IP>"
