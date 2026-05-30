param(
    [switch]$Yes,
    [string]$Features,
    [switch]$NoLocalLlm,
    [ValidateSet("minimal", "balanced", "quality", "legacy-cpu")]
    [string]$Preset
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "▶ creating .venv ..."
    $SystemPython = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $SystemPython) {
        Write-Host "Python was not found on PATH. Install Python 3.11+ from https://www.python.org/downloads/ and try again." -ForegroundColor Red
        exit 1
    }
    & $SystemPython -m venv .venv
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "▶ upgrading pip ..."
& $VenvPython -m pip install --upgrade pip --quiet

$InstallerArgs = @("scripts\install.py")
if ($Yes)           { $InstallerArgs += "--yes" }
if ($Features)      { $InstallerArgs += @("--features", $Features) }
if ($NoLocalLlm)    { $InstallerArgs += "--no-local-llm" }
if ($Preset)        { $InstallerArgs += @("--preset", $Preset) }

& $VenvPython @InstallerArgs
exit $LASTEXITCODE
