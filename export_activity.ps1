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
Write-Log "Starting User Activity Export..."

$MachineName = $env:COMPUTERNAME
$ReportDir = "$ScriptPath\AuditReports\$MachineName"
if (-not (Test-Path $ReportDir)) { New-Item -Path $ReportDir -ItemType Directory | Out-Null }

$DateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CsvPath = Join-Path $ReportDir "ActivityTimeline_$DateStamp.csv"

# --- Function: Get-UserActivity ---
function Get-UserActivity {
    $ActivityList = @()
    $RecentFolder = "$env:APPDATA\Microsoft\Windows\Recent"
    
    if (-not (Test-Path $RecentFolder)) {
        Write-HostFail "Recent items folder not accessible."
        Write-Log -Message "Recent items folder not accessible." -Type "ERROR"
        return $ActivityList
    }

    Write-HostInfo "Scanning User Activity (Recent Files)..."
    
    # Create COM Object to resolve shortcuts
    $WScript = New-Object -ComObject WScript.Shell

    $Files = Get-ChildItem -Path $RecentFolder -Filter "*.lnk" -ErrorAction SilentlyContinue
    
    $Total = $Files.Count
    $Count = 0

    foreach ($File in $Files) {
        $Count++
        # Simple progress bar
        if ($Count % 10 -eq 0) { Write-Progress -Activity "Analyzing Shortcuts" -Status "$Count / $Total" -PercentComplete (($Count / $Total) * 100) }
        
        try {
            $Shortcut = $WScript.CreateShortcut($File.FullName)
            $Target = $Shortcut.TargetPath
            
            # Filter out empty targets
            if ($Target) {
                $ActivityList += [PSCustomObject]@{
                    AccessTime = $File.LastWriteTime
                    FileName   = $File.Name.Replace(".lnk", "")
                    Target     = $Target
                    Type       = "File Access"
                }
            }
        } catch {
            # Skip broken shortcuts
        }
    }
    Write-Progress -Activity "Analyzing Shortcuts" -Completed

    # Sort by time (Newest first)
    return $ActivityList | Sort-Object AccessTime -Descending
}

# --- Main Execution ---
Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   LOCKON: USER ACTIVITY TIMELINE (FORENSICS)" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan

$Results = Get-UserActivity

if ($Results.Count -gt 0) {
    Write-HostPass "Found $($Results.Count) recent activity events."
    
    # Export to CSV
    $Results | Select-Object AccessTime, FileName, Target, Type | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    
    Write-HostPass "Timeline saved to: $CsvPath"
    Write-Log -Message "Timeline saved to: $CsvPath"
    
    # Auto-open folder
    Invoke-Item $ReportDir
} else {
    Write-HostInfo "No recent activity found."
    Write-Log -Message "No recent activity found."
}

Write-Host "`n   Press Enter to return to menu..." -ForegroundColor Gray
Read-Host
