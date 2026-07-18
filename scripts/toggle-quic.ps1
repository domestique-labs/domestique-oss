<#
.SYNOPSIS
  Disable/enable QUIC (HTTP/3) in a browser so traffic can't bypass the
  Domestique TCP proxy (:8080).

.DESCRIPTION
  QUIC runs over UDP/443 and bypasses a TCP proxy, creating a DLP blind spot.

  Chromium browsers (Chrome / Brave / Edge) expose the standard `QuicAllowed`
  machine-wide Group Policy. This writes it to HKLM (the real machine-policy location,
  the same lever device-management (MDM) tools use) and auto-elevates via UAC because the
  Policies hive is admin-controlled by design.

  Opera, Firefox, and Safari do NOT share that mechanism; for those the script
  prints the correct manual step instead of writing an ineffective key.

  Fully restart the browser after running.

.PARAMETER Browser
  chrome | brave | edge    -> automated (HKLM policy, needs admin/UAC)
  opera | firefox | safari -> guided manual instructions

.PARAMETER Enable
  Re-enable QUIC (revert) instead of disabling.

.EXAMPLE
  .\toggle-quic.ps1 -Browser brave
.EXAMPLE
  .\toggle-quic.ps1 -Browser chrome -Enable
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('chrome','brave','edge','opera','firefox','safari')]
    [string]$Browser,

    [switch]$Enable
)

# Chromium browsers: automatable via the QuicAllowed policy under HKLM.
$policyPaths = @{
    chrome = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
    brave  = 'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave'
    edge   = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
}

$value  = if ($Enable) { 1 } else { 0 }
$action = if ($Enable) { 'ENABLED' } else { 'DISABLED' }

# ---- Non-Chromium: honest manual guidance, no elevation needed ----
if (-not $policyPaths.ContainsKey($Browser)) {
    Write-Host "$Browser is NOT automatable with the Chromium QuicAllowed policy." -ForegroundColor Yellow
    Write-Host ""
    switch ($Browser) {
        'opera' {
            Write-Host "Opera uses the Chromium engine but ignores standard Chromium policies."
            Write-Host "By hand:  opera://flags/#enable-quic  ->  '$(if($Enable){'Enabled'}else{'Disabled'})'  ->  relaunch."
        }
        'firefox' {
            Write-Host "Firefox has its own engine, policy system, AND its own proxy settings"
            Write-Host "(may not route through the system proxy unless set to 'Use system proxy settings')."
            Write-Host "By hand:  about:config  ->  network.http.http3.enable  ->  $(if($Enable){'true'}else{'false'})."
        }
        'safari' {
            Write-Host "Safari is macOS-only (not on Windows) and has no supported scriptable QUIC"
            Write-Host "toggle. Nothing to do on this machine."
        }
    }
    return
}

# ---- Chromium: needs admin to write the Policies hive. Auto-elevate. ----
$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Writing browser policy requires admin. Requesting elevation (UAC)..." -ForegroundColor Yellow
    $relaunch = @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass',
                  '-File', $PSCommandPath, '-Browser', $Browser)
    if ($Enable) { $relaunch += '-Enable' }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $relaunch
        Write-Host "An elevated window opened to apply the change. This window is done." -ForegroundColor Green
    } catch {
        Write-Host "Elevation was declined/cancelled - QUIC was NOT changed." -ForegroundColor Red
        Write-Host "Either accept the UAC prompt, or set it by hand: ${Browser}://flags/#enable-quic -> Disabled."
    }
    return
}

# ---- Elevated: do the write, and only claim success if it actually worked ----
$path = $policyPaths[$Browser]
try {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
    Set-ItemProperty -Path $path -Name 'QuicAllowed' -Value $value -Type DWord -ErrorAction Stop
    Write-Host "$Browser : QUIC $action  ($path\QuicAllowed = $value)" -ForegroundColor Green
    Write-Host ""
    Write-Host "FULLY RESTART $Browser (close all windows) for it to take effect." -ForegroundColor Yellow
    Write-Host "Verify at ${Browser}://policy  ->  QuicAllowed should show value $value." -ForegroundColor Yellow
} catch {
    Write-Host "FAILED to write policy for ${Browser}: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "QUIC was NOT changed. Fallback: set it by hand at ${Browser}://flags/#enable-quic -> Disabled."
}
