[CmdletBinding()]
param()

# --- Configuration ---
$ScriptPath = $PSScriptRoot
if (-not $ScriptPath) { $ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition }

# Load Shared Library
$LibPath = Join-Path $ScriptPath "LOCKON_Lib.ps1"
if (Test-Path $LibPath) {
    . $LibPath
} else {
    Write-Host "[!] Critical Error: LOCKON_Lib.ps1 not found!" -ForegroundColor Red
    exit
}
Write-Log "Starting Software Inventory Export..."

$MachineName = $env:COMPUTERNAME
$ReportDir = "$ScriptPath\AuditReports\$MachineName"
if (-not (Test-Path $ReportDir)) { New-Item -Path $ReportDir -ItemType Directory | Out-Null }

$DateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CsvPath = Join-Path $ReportDir "Inventory_$DateStamp.csv"

# --- Function: Get-InstalledSoftware ---
function Get-InstalledSoftware {
    $SoftwareList = @()

    # 1. Registry Paths (HKLM, HKCU, Wow6432Node)
    $RegPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    Write-HostInfo "Scanning Registry for installed applications..."
    foreach ($Path in $RegPaths) {
        $Keys = Get-ItemProperty $Path -ErrorAction SilentlyContinue
        foreach ($Key in $Keys) {
            if ($Key.DisplayName) {
                $SoftwareList += [PSCustomObject]@{
                    Name = $Key.DisplayName
                    Version = $Key.DisplayVersion
                    Publisher = $Key.Publisher
                    InstallDate = $Key.InstallDate
                    Source = "Registry"
                }
            }
        }
    }

    # 2. Win32_Product (WMI) - Optional/Active
    # Note: Win32_Product can be slow, but it catches MSI installs well.
    Write-HostInfo "Scanning WMI (Win32_Product)... (This may take a moment)"
    try {
        $WmiApps = Get-CimInstance -ClassName Win32_Product -ErrorAction SilentlyContinue
        foreach ($App in $WmiApps) {
            $SoftwareList += [PSCustomObject]@{
                Name = $App.Name
                Version = $App.Version
                Publisher = $App.Vendor
                InstallDate = $App.InstallDate
                Source = "WMI"
            }
        }
    } catch {
        Write-HostWarn "WMI Scan skipped or failed."
        Write-Log -Message "WMI Scan Error: $($_.Exception.Message)" -Type "WARN"
    }
    
    # 3. Consolidate and Deduplicate
    # Group by Name to remove duplicates
    $UniqueSoftware = $SoftwareList | Sort-Object Name -Unique
    
    return $UniqueSoftware
}

# --- Main Execution ---
Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   LOCKON: SOFTWARE INVENTORY EXPORT" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

$Results = Get-InstalledSoftware

if ($Results.Count -gt 0) {
    Write-HostPass "Found $($Results.Count) unique applications."
    
    # Export to CSV
    $Results | Select-Object Name, Version, Publisher, InstallDate, Source | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    
    Write-HostPass "Inventory saved to: $CsvPath"
    Write-Log -Message "Inventory saved to: $CsvPath"
    
    # Auto-open folder
    Invoke-Item $ReportDir
} else {
    Write-HostFail "No software found. Weird."
    Write-Log -Message "No software found." -Type "WARN"
}

Write-Host "`n   Press Enter to return to menu..." -ForegroundColor Gray
Read-Host
