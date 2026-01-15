<#
.SYNOPSIS
    LOCKON Main Menu (Concept: Unified Entry Point)
    Handles Admin Elevation and sub-script execution.
#>

# --- 1. Admin Rights Check ---
$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [System.Security.Principal.WindowsPrincipal]$Identity
$IsAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- 2. Menu Logic ---
$ScriptPath = $PSScriptRoot

# Load Shared Library
$LibPath = "$ScriptPath\LOCKON_Lib.ps1"
if (Test-Path $LibPath) {
    . $LibPath
} else {
    Write-Host "[!] Critical Error: LOCKON_Lib.ps1 not found!" -ForegroundColor Red
    exit
}

function Show-Header {
    Clear-Host
    Write-Host "
   __         ______     ______     __  __     ______     __   __    
  /\ \       /\  __ \   /\  ___\   /\ \/ /    /\  __ \   /\ ""-.\ \   
  \ \ \____  \ \ \/\ \  \ \ \____  \ \  _""-.  \ \ \/\ \  \ \ \-.  \  
   \ \_____\  \ \_____\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\""\_\ 
    \/_____/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/ 
                                                                   
" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "   LOCKON: SYSTEM DIAGNOSTIC ANALYZER" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   [1] SYSTEM SECURITY SCAN" -ForegroundColor White
    Write-Host "       (Audit OS, Network, AV, Ports, and Policy)"
    Write-Host ""
    Write-Host "   [2] VIEW AUDIT REPORTS" -ForegroundColor White
    Write-Host "       (Open existing dashboard)"
    Write-Host ""
    Write-Host "   [3] CONFIGURATION MANAGER" -ForegroundColor White
    Write-Host "       (View/Edit Policies, Blacklists, and KBs)"
    Write-Host ""
    Write-Host "   [4] EXPORT FULL SOFTWARE INVENTORY (CSV)" -ForegroundColor White
    Write-Host "       (Generate list of all installed programs)"
    Write-Host ""
    Write-Host "   [5] EXPORT USER ACTIVITY TIMELINE (Review History)" -ForegroundColor White
    Write-Host "       (Forensics: See what files were opened recently)"
    Write-Host ""
    Write-Host "   [6] EXIT" -ForegroundColor Red
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
}

while ($true) {
    Show-Header
    $Choice = Read-Host "   Select an option [1-6]"

    switch ($Choice) {
        "1" {
            # Run Scan
            Write-Host "`n   [+] Launching Security Scan..." -ForegroundColor Green
            Write-Log "User selected [1] Security Scan"
            & "$ScriptPath\check_security.ps1"
            
            # (v2.0) Open Single Report Only
            # Logic: Find the latest HTML report created
            $MachineName = $env:COMPUTERNAME
            $ReportFolder = Join-Path $ScriptPath "AuditReports\$MachineName"
            $LatestReport = Get-ChildItem -Path $ReportFolder -Filter "Report-*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            
            if ($LatestReport) {
                Write-Host "   [+] Opening Report: $($LatestReport.Name)" -ForegroundColor Green
                Start-Process $LatestReport.FullName
            } else {
                Write-Host "   [!] Report file not found." -ForegroundColor Red
            }
            
            Write-Host "`n   [!] Note: To view the full Dashboard (All Machines), select Option 2." -ForegroundColor Gray
            Start-Sleep -Seconds 2
        }
        "2" {
            # Generate & View Dashboard
            Write-Host "`n   [+] Aggregating Data & Generating Dashboard..." -ForegroundColor Green
            Write-Log "User selected [2] Dashboard"
            & "$ScriptPath\Generate-Dashboard.ps1"
        }
        "3" {
            # Configuration Manager
            Write-Host "`n   [+] Launching Configuration Manager..." -ForegroundColor Yellow
            $ConfigScript = "$ScriptPath\edit_config.ps1"
            if (Test-Path $ConfigScript) {
                & $ConfigScript
            } else {
                Write-Host "   [!] Error: edit_config.ps1 not found." -ForegroundColor Red
                Read-Host "   Press Enter to return..."
            }
        }
        "4" {
            # Export Inventory
            Write-Host "`n   [+] Exporting Software Inventory..." -ForegroundColor Cyan
            $InvScript = "$ScriptPath\export_inventory.ps1"
            if (Test-Path $InvScript) {
                & $InvScript
            } else {
                Write-Host "   [!] Error: export_inventory.ps1 not found." -ForegroundColor Red
                Read-Host "   Press Enter to return..."
            }
        }
        "5" {
            # Export User Activity
            Write-Host "`n   [+] Exporting User Activity Timeline..." -ForegroundColor Cyan
            $ActScript = "$ScriptPath\export_activity.ps1"
            if (Test-Path $ActScript) {
                & $ActScript
            } else {
                Write-Host "   [!] Error: export_activity.ps1 not found." -ForegroundColor Red
                Read-Host "   Press Enter to return..."
            }
        }
        "6" {
            Write-Host "`n   [+] Exiting..." -ForegroundColor Gray
            Start-Sleep -Seconds 1
            exit
        }
        default {
            Write-Host "`n   [!] Invalid selection." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}
