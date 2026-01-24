<#
.SYNOPSIS
    LOCKON Baseline Generator
    Captures the current system state (OS, Software, Services, Drivers) 
    and saves it to 'config_baseline.json' for Drift Detection.
.NOTES
    Version: 1.0
#>

# --- Load Shared Library (Optional but good for logging) ---
$LibPath = Join-Path $PSScriptRoot "LOCKON_Lib.ps1"
if (Test-Path $LibPath) { . $LibPath }

Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   LOCKON SYSTEM BASELINE GENERATOR" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$BaselineFile = Join-Path $PSScriptRoot "config_baseline.json"
$BaselineData = @{}

# --- 1. OS Information ---
Write-Host "   [1/4] Capturing OS Information..." -ForegroundColor Yellow
try {
    $CimOs = Get-CimInstance Win32_OperatingSystem
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $DisplayVersion = (Get-ItemProperty -Path $RegPath -Name "DisplayVersion").DisplayVersion
    
    $BaselineData.OsVersion = $DisplayVersion
    $BaselineData.OsBuild = $CimOs.BuildNumber
    $BaselineData.OsName = $CimOs.Caption
    Write-Host "         -> OS: $($CimOs.Caption) ($DisplayVersion)" -ForegroundColor Green
} catch {
    Write-Host "         -> Failed to capture OS Info" -ForegroundColor Red
}

# --- 2. Installed Software (Registry) ---
Write-Host "   [2/4] Capturing Installed Software..." -ForegroundColor Yellow
try {
    $SoftwareList = @()
    # Simple registry scan (HKLM/HKCU for 32/64 bit is complex, simplified here)
    $Paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($Path in $Paths) {
        Get-ItemProperty $Path -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.DisplayName) {
                $SoftwareList += $_.DisplayName
            }
        }
    }
    $SoftwareList = $SoftwareList | Sort-Object | Select-Object -Unique
    $BaselineData.InstalledSoftware = $SoftwareList
    Write-Host "         -> Found $($SoftwareList.Count) applications." -ForegroundColor Green
} catch {
    Write-Host "         -> Failed to capture Software" -ForegroundColor Red
}

# --- 3. Automatic Services ---
Write-Host "   [3/4] Capturing Automatic Services..." -ForegroundColor Yellow
try {
    $Services = Get-Service | Where-Object { $_.StartType -eq 'Automatic' } | Select-Object -ExpandProperty Name
    $BaselineData.AutoServices = $Services
    Write-Host "         -> Found $($Services.Count) automatic services." -ForegroundColor Green
} catch {
    Write-Host "         -> Failed to capture Services" -ForegroundColor Red
}

# --- 4. Drivers (Optional - can be noisy) ---
Write-Host "   [4/4] Capturing Drivers..." -ForegroundColor Yellow
try {
    # Limit to non-Microsoft for cleaner baseline? Or all? Let's do all names.
    $Drivers = Get-CimInstance Win32_SystemDriver | Select-Object -ExpandProperty Name
    $BaselineData.Drivers = $Drivers
    Write-Host "         -> Found $($Drivers.Count) drivers." -ForegroundColor Green
} catch {
    Write-Host "         -> Failed to capture Drivers" -ForegroundColor Red
}

# --- Save to JSON ---
Write-Host ""
Write-Host "   Saving Baseline to '$BaselineFile'..." -ForegroundColor Yellow
try {
    $BaselineData | ConvertTo-Json -Depth 3 | Out-File $BaselineFile -Encoding UTF8
    Write-Host "   [PASS] Baseline Generated Successfully!" -ForegroundColor Green
} catch {
    Write-Host "   [FAIL] Could not save baseline file: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to return..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
