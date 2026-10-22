<#
.SYNOPSIS
    Captures the README screenshots from the demo mode (fictional data only).

.DESCRIPTION
    Requires the demo server to be running first:  npm run demo   (http://localhost:5180)
    Uses Microsoft Edge in headless mode; screenshots are written to docs/images/screenshots/.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\capture-screenshots.ps1
#>
param(
    [string]$BaseUrl = "http://localhost:5180",
    [string]$Edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    [int]$Width = 1440,
    [int]$Height = 900
)

$ErrorActionPreference = "Stop"
$out = Join-Path $PSScriptRoot "..\..\docs\images\screenshots"
New-Item -ItemType Directory -Force $out | Out-Null
$profileDir = Join-Path ([System.IO.Path]::GetTempPath()) "pandore-screenshots-profile"

# File name -> demo page (?page=…, see Dashboard.jsx; device=… opens a device page).
$pages = [ordered]@{
    "dashboard"          = "overview"
    "device"             = "device-overview&device=DEMO-WKS-007"
    "compliance"         = "intune"
    "alerts"             = "widgets-test"
    "secure-score"       = "secure-score"
    "vulnerabilities"    = "vulnerabilities"
    "vanitas-overview"   = "vanitas-overview"
    "vanitas-devices"    = "vanitas-devices"
    "vanitas-suspicious" = "vanitas-suspicious-activity"
    "vanitas-updates"    = "vanitas-patch"
}

foreach ($name in $pages.Keys) {
    $target = Join-Path $out "$name.png"
    & $Edge --headless=new --disable-gpu --hide-scrollbars --user-data-dir="$profileDir" `
        --window-size="$Width,$Height" --virtual-time-budget=12000 `
        --screenshot="$target" "$BaseUrl/?page=$($pages[$name])" 2>$null | Out-Null
    Start-Sleep -Milliseconds 500
    Write-Host "captured $name.png"
}
