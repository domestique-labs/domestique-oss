param(
    [switch]$NoBrowser,
    [ValidateSet("auto", "native", "portable")]
    [string]$Mode = "auto",
    [int]$ApiPort = 9876
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = "python"
}

$Args = @("-m", "domestique_app", "--mode", $Mode, "--api-port", "$ApiPort")
if ($NoBrowser) {
    $Args += "--no-browser"
}

& $Python @Args
