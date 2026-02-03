<#
.SYNOPSIS
    LOCKON Main Menu (Concept: Unified Entry Point)
    Handles Admin Elevation and sub-script execution.
#>

# --- 0. Fix Console Encoding for Thai Support ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8

# --- 1. Admin Rights Check ---
$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [System.Security.Principal.WindowsPrincipal]$Identity
$IsAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# --- 1.5 Set Console Size (Optimized for ASCII Art) ---
try {
    $pshost = Get-Host
    $pswindow = $pshost.UI.RawUI
    
    # Buffer must be set before Window Size to avoid errors if new Window > old Buffer
    $newBufferSize = $pswindow.BufferSize
    $newBufferSize.Width = 120
    $newBufferSize.Height = 3000
    $pswindow.BufferSize = $newBufferSize

    $newWindowSize = $pswindow.WindowSize
    $newWindowSize.Width = 95
    $newWindowSize.Height = 40
    $pswindow.WindowSize = $newWindowSize
} catch {
    # Suppress errors if resizing is not supported (e.g. some terminal emulators)
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
    Write-Host "   [2] CUSTOM SECURITY SCAN" -ForegroundColor White
    Write-Host "       (Select specific modules to run)"
    Write-Host ""
    Write-Host "   [3] VIEW AUDIT REPORTS" -ForegroundColor White
    Write-Host "       (Open existing dashboard)"
    Write-Host ""
    Write-Host "   [4] CONFIGURATION MANAGER" -ForegroundColor White
    Write-Host "       (View/Edit Policies, Blacklists, and KBs)"
    Write-Host ""
    Write-Host "   [5] EXPORT TECHNICAL CHECKLIST (THAI)" -ForegroundColor White
    Write-Host "       (Generate formal Audit Checklist HTML)"
    Write-Host ""
    Write-Host "   [6] GENERATE SYSTEM BASELINE" -ForegroundColor White
    Write-Host "       (Capture current state for Drift Detection)"
    Write-Host ""
    Write-Host "   [7] EXIT" -ForegroundColor Red
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
}

while ($true) {
    Show-Header
    $Choice = Read-Host "   Select an option [1-7]"
    if ($Choice) { $Choice = $Choice.Trim() }

    switch ($Choice) {
        "1" {
            # Run Full Scan
            $SelectedUnit = Get-LockonUnit
            
            Write-Host "`n   [+] Launching Full Security Scan for Unit: $SelectedUnit..." -ForegroundColor Green
            Write-Log "User selected [1] Full Security Scan for Unit: $SelectedUnit"
            
            & "$ScriptPath\check_security.ps1" -Unit $SelectedUnit -SelectedChecks "All"
            
            # Open Report Logic
            $MachineName = $env:COMPUTERNAME
            $ReportFolder = Join-Path $ScriptPath "AuditReports\$MachineName"
            
            Write-Host "   [DEBUG] Looking for report in: $ReportFolder" -ForegroundColor Gray
            if (-not (Test-Path $ReportFolder)) {
                 Write-Host "   [DEBUG] Report folder not found!" -ForegroundColor Red
            }

            $LatestReport = Get-ChildItem -Path $ReportFolder -Filter "Report-*.html" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            
            if ($LatestReport) {
                Write-Host "   [+] Opening Report: $($LatestReport.Name)" -ForegroundColor Green
                Start-Process $LatestReport.FullName
            } else {
                Write-Host "   [!] No report file found to open." -ForegroundColor Yellow
            }
            
            # Generate Checklist
            Write-Host "`n   [+] Generating Technical Checklist (Thai)..." -ForegroundColor Green
            $ChecklistScript = "$ScriptPath\Generate-Checklist.ps1"
            if (Test-Path $ChecklistScript) { & $ChecklistScript -Unit $SelectedUnit }
            
            Write-Host "`n   [!] Note: To view the full Dashboard, select Option 3." -ForegroundColor Gray
            Start-Sleep -Seconds 2
        }
        "2" {
            # Custom Scan
            # Bypass Unit Selection for Custom/Ad-hoc scans to reduce friction
            $SelectedUnit = "Custom-Scan" 
            Write-Host "`n   [+] Initializing Custom Scan..." -ForegroundColor Green
            
            # Define Checks
            $Checks = @(
                [PSCustomObject]@{ID="1"; Name="OS Version Check"}
                [PSCustomObject]@{ID="2"; Name="Network Configuration"}
                [PSCustomObject]@{ID="3"; Name="OS Update Status"}
                [PSCustomObject]@{ID="4"; Name="Antivirus & EDR Status"}
                [PSCustomObject]@{ID="5"; Name="Critical Patches (KB)"}
                [PSCustomObject]@{ID="6"; Name="Listening Ports (TCP)"}
                [PSCustomObject]@{ID="7"; Name="Listening Ports (UDP)"}
                [PSCustomObject]@{ID="8"; Name="Windows Firewall"}
                [PSCustomObject]@{ID="9"; Name="User Account Control (UAC)"}
                [PSCustomObject]@{ID="10"; Name="Suspicious Services (Masquerading)"}
                [PSCustomObject]@{ID="11"; Name="Local Administrators"}
                [PSCustomObject]@{ID="12"; Name="Open File Shares"}
                [PSCustomObject]@{ID="13"; Name="Startup Items"}
                [PSCustomObject]@{ID="14"; Name="Unwanted Software"}
                [PSCustomObject]@{ID="15"; Name="File Hash Analysis (Threats)"}
                [PSCustomObject]@{ID="16"; Name="Drift Detection"}
                [PSCustomObject]@{ID="17"; Name="Browser Extensions (Risk Analysis)"}
                [PSCustomObject]@{ID="18"; Name="Scheduled Task Hunter"}
                [PSCustomObject]@{ID="19"; Name="Hosts File Analysis"}
                [PSCustomObject]@{ID="20"; Name="DNS Cache Forensics"}
                [PSCustomObject]@{ID="21"; Name="Event Log Analysis (Last 24h)"}
                [PSCustomObject]@{ID="22"; Name="Web Browser History"}
                [PSCustomObject]@{ID="23"; Name="Recent Files Activity"}
                [PSCustomObject]@{ID="24"; Name="Downloads Folder Analysis"}
                [PSCustomObject]@{ID="25"; Name="RDP Hunter (Event Logs)"}
                [PSCustomObject]@{ID="26"; Name="Shadow Copy Check"}
                [PSCustomObject]@{ID="27"; Name="Local Admin Hunter (Deep)"}
                [PSCustomObject]@{ID="28"; Name="DNS Analyzer (Mining/C2)"}
                [PSCustomObject]@{ID="29"; Name="UserAssist Execution History"}
                [PSCustomObject]@{ID="30"; Name="Recycle Bin Scavenger"}
                [PSCustomObject]@{ID="31"; Name="Office Security"}
                [PSCustomObject]@{ID="32"; Name="Software Inventory"}
            )
            
            # Console Interactive Menu (Hacker Style)
            $CursorIndex = 0
            $TotalChecks = $Checks.Count
            $SelectedState = New-Object bool[] $TotalChecks # Array to track true/false

            # Helper to draw the menu
            function Draw-Menu {
                param ($Idx, $SelState)
                
                # Move cursor to top (faster than Clear-Host for flickering)
                try { [Console]::SetCursorPosition(0, 0) } catch { Clear-Host } 
                Write-Host ""  
                Write-Host "==========================================================" -ForegroundColor Cyan
                Write-Host "   CUSTOM SECURITY SCAN SELECTION" -ForegroundColor White
                Write-Host "   [Space] Toggle  [Enter] Start  [Esc] Cancel  [A] All  [C] Clear" -ForegroundColor DarkGray
                Write-Host "==========================================================" -ForegroundColor Cyan
                
                for ($i = 0; $i -lt $TotalChecks; $i++) {
                    $Prefix = "   "
                    $Color = "Gray"
                    $CheckMark = "[ ]"
                    
                    if ($SelState[$i]) { 
                        $CheckMark = "[x]" 
                        $Color = "Green"
                    }
                    
                    # Highlight Current Cursor
                    if ($i -eq $Idx) {
                        $Prefix = "-> "
                        $Color = "Cyan" # Highlight color
                        if ($SelState[$i]) { $Color = "Green" } # Keep green if selected
                        Write-Host "$Prefix$CheckMark $($Checks[$i].ID). $($Checks[$i].Name)" -ForegroundColor Black -BackgroundColor $Color
                    } else {
                        Write-Host "$Prefix$CheckMark $($Checks[$i].ID). $($Checks[$i].Name)" -ForegroundColor $Color
                    }
                }
                Write-Host "==========================================================" -ForegroundColor Cyan
            }
            
            # Interactive Loop
            $Running = $true
            $Cancel = $false
            
            # Hide Cursor
            try { [Console]::CursorVisible = $false } catch {}
            
            # Fix: Clear previous menu to prevent text overlapping
            Clear-Host

            while ($Running) {
                Draw-Menu -Idx $CursorIndex -SelState $SelectedState
                
                $Key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                
                switch ($Key.VirtualKeyCode) {
                    38 { # Up Arrow
                        if ($CursorIndex -gt 0) { $CursorIndex-- }
                    }
                    40 { # Down Arrow
                        if ($CursorIndex -lt ($TotalChecks - 1)) { $CursorIndex++ }
                    }
                    32 { # Spacebar
                        $SelectedState[$CursorIndex] = -not $SelectedState[$CursorIndex]
                    }
                    13 { # Enter
                        $Running = $false
                    }
                    27 { # Esc
                        $Running = $false
                        $Cancel = $true
                    }
                    65 { # 'A' - Select All
                        for ($k=0; $k -lt $TotalChecks; $k++) { $SelectedState[$k] = $true }
                    }
                    67 { # 'C' - Clear All
                        for ($k=0; $k -lt $TotalChecks; $k++) { $SelectedState[$k] = $false }
                    }
                }
                # Specific check for 'q' to quit as well
                if ($Key.Character -eq 'q') { $Running = $false; $Cancel = $true }
            }
            
            # Restore Cursor
            try { [Console]::CursorVisible = $true } catch {}
            Clear-Host

            if (-not $Cancel) {
                # Gather Selected IDs
                $SelectedIDs = @()
                for ($i = 0; $i -lt $TotalChecks; $i++) {
                    if ($SelectedState[$i]) {
                         $SelectedIDs += $Checks[$i].ID
                    }
                }

                if ($SelectedIDs.Count -gt 0) {
                    Write-Host "`n   [+] Launching Custom Scan with $($SelectedIDs.Count) modules..." -ForegroundColor Green
                    & "$ScriptPath\check_security.ps1" -Unit $SelectedUnit -SelectedChecks $SelectedIDs
                    
                    # Open Report Logic
                    $MachineName = $env:COMPUTERNAME
                    $ReportFolder = Join-Path $ScriptPath "AuditReports\$MachineName"
                    $LatestReport = Get-ChildItem -Path $ReportFolder -Filter "Report-*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($LatestReport) { Start-Process $LatestReport.FullName }
                } else {
                     Write-Host "`n   [!] No modules selected. Returning to menu." -ForegroundColor Yellow
                }
            } else {
                 Write-Host "`n   [!] Custom Scan Cancelled." -ForegroundColor Yellow
            }
            Start-Sleep -Seconds 2
        }
        "3" {
            # Generate & View Dashboard
            Write-Host "`n   [+] Aggregating Data & Generating Dashboard..." -ForegroundColor Green
            Write-Log "User selected [3] Dashboard"
            & "$ScriptPath\Generate-Dashboard.ps1"
        }
        "4" {
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
        "5" {
            # Generate Technical Checklist (Thai)
            $SelectedUnit = Get-LockonUnit 
            
            Write-Host "`n   [+] Generating Technical Checklist Report for Unit: $SelectedUnit..." -ForegroundColor Green
            $ChecklistScript = "$ScriptPath\Generate-Checklist.ps1"
            if (Test-Path $ChecklistScript) {
                & $ChecklistScript -Unit $SelectedUnit
            } else {
                Write-Host "   [!] Error: Generate-Checklist.ps1 not found." -ForegroundColor Red
                Read-Host "   Press Enter to return..."
            }
        }
        "6" {
            # Generate Baseline
            Write-Host "`n   [+] Launching Baseline Generator..." -ForegroundColor Green
            Write-Log "User selected [6] Generate Baseline"
            & "$ScriptPath\Generate-Baseline.ps1"
            pause
        }
        "7" {
            Write-Host "Exiting." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            exit
        }
        default {
            Write-Host "`n   [!] Invalid selection." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}
