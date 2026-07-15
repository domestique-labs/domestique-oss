<#
.SYNOPSIS
    Generates and trusts the LLMGuard local CA certificate.

.DESCRIPTION
    Works around the cert-setup gate failing on a fresh install: the dashboard's
    "Install Certificate" button only trusts an *existing* CA, but the CA is not
    created until the proxy first starts. This script generates the CA (if
    missing) and adds it to the current user's Trusted Root store.

    Run it from the project root as the same Windows user that runs LLMGuard:
        .\infra\certs\fix-cert.ps1

    A Windows security dialog will appear asking to install the certificate from
    "LLMGuard Local CA" - you must click Yes for trust to succeed.
#>

$ErrorActionPreference = "Stop"
# This script lives in infra\certs\; the project root (where the `app` package
# and .venv live) is two levels up.
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

# Force UTF-8 so console output from the app code doesn't crash on cp1252.
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
# The `app` package lives in the project root and is not pip-installed, so put
# the root on the import path (this is what `python -m app` relies on via cwd).
$env:PYTHONPATH = $Root

# Prefer the project venv; fall back to whatever python is on PATH.
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $Python) {
        Write-Host "Python not found. Run install.ps1 first." -ForegroundColor Red
        exit 1
    }
}

Write-Host "Generating and trusting the LLMGuard CA ..." -ForegroundColor Cyan
Write-Host "If a Windows security dialog appears, click Yes." -ForegroundColor Yellow

$pyCode = @'
from app.services.interceptor import generate_ca
from app.services.cert_manager import install_and_trust, is_cert_trusted, CA_CERT

generate_ca()
print("CA file:", CA_CERT)
ok = install_and_trust()
print("RESULT:", "trusted" if (ok and is_cert_trusted()) else "not-trusted")
'@

# Write to a temp file rather than passing multi-line code via -c, which
# PowerShell mangles when it contains quotes and spaces. Write without a BOM
# (PS 5.1's -Encoding utf8 adds one) to keep the Python source clean.
$pyFile = Join-Path $env:TEMP "llmguard_fix_cert.py"
[System.IO.File]::WriteAllText($pyFile, $pyCode, (New-Object System.Text.UTF8Encoding($false)))
try {
    & $Python $pyFile
    $code = $LASTEXITCODE
}
finally {
    Remove-Item $pyFile -ErrorAction SilentlyContinue
}

if ($code -ne 0) {
    Write-Host ""
    Write-Host "Failed to run the cert helper (exit $code)." -ForegroundColor Red
    Write-Host "Make sure you ran install.ps1 and are in the llmguard folder." -ForegroundColor Red
    exit $code
}

Write-Host ""
Write-Host "Done. Refresh the dashboard at http://127.0.0.1:9876 - the cert gate should clear." -ForegroundColor Green
Write-Host "If it still shows 'not-trusted', re-run this script and click Yes on the security dialog." -ForegroundColor Yellow
