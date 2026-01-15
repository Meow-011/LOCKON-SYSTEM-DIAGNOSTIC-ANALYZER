<#
.SYNOPSIS
    LOCKON Remediation System (Manual Fix) - Granular
    Allows specific targeting of detected issues.
#>

$ScriptPath = $PSScriptRoot
$ConfigPath = Join-Path $ScriptPath "config.psd1"

# Load Config
if (Test-Path $ConfigPath) {
    try {
        $Config = Import-PowerShellDataFile -Path $ConfigPath
    } catch {
        Write-Host "Error loading Config: $($_.Exception.Message)" -ForegroundColor Red
        pause
        exit
    }
} else {
    Write-Host "Config not found at $ConfigPath" -ForegroundColor Red
    pause
    exit
}

function Show-Header {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Yellow
    Write-Host "   LOCKON REMEDIATION SYSTEM (MANUAL FIX)" -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Yellow
}

function Get-FirewallStatus {
    $Profiles = Get-NetFirewallProfile
    if (($Profiles | Where-Object {$_.Enabled -ne $true})) { return "WARNING (Some Disabled)" }
    return "OK (All Enabled)"
}

function Get-OpenRiskyPorts {
    $Risky = @()
    $Ports = Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique
    foreach ($p in $Config.RiskyPorts) {
        if ($Ports -contains $p.Port) { 
            # Add Port Object
            $Risky += @{
                Port = $p.Port
                Protocol = "TCP" # Assuming TCP for simplicity
                Desc = $p.Service
            }
        }
    }
    return $Risky
}

while ($true) {
    Show-Header
    
    # Check Current State
    $FwStatus = Get-FirewallStatus
    $OpenPorts = Get-OpenRiskyPorts
    
    Write-Host "   Current Status:" -ForegroundColor Gray
    Write-Host "   [-] Firewall Status: $FwStatus" -ForegroundColor ($FwStatus -match "OK" ? "Green" : "Red")
    
    if ($OpenPorts.Count -gt 0) {
        Write-Host "   [-] Risky Ports Open: $($OpenPorts.Count)" -ForegroundColor Red
    } else {
        Write-Host "   [-] Risky Ports Open: None" -ForegroundColor Green
    }
    
    Write-Host "----------------------------------------------------------"
    
    # Menu Options
    Write-Host "   [1] Enable Windows Firewall (All Profiles)"
    
    if ($OpenPorts.Count -gt 0) {
        Write-Host "   [2] Block Risky Ports (Select Specific Ports)"
    }
    
    Write-Host "   [B] Back to Main Menu"
    Write-Host ""
    
    $Choice = Read-Host "   Select Action"
    
    switch ($Choice) {
        "1" {
            Write-Host "   Enabling Firewall..." -ForegroundColor Yellow
            try {
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                Write-Host "   Done." -ForegroundColor Green
            } catch {
                Write-Host "   Failed: $($_.Exception.Message)" -ForegroundColor Red
            }
            Start-Sleep -Seconds 1
        }
        "2" {
            if ($OpenPorts.Count -eq 0) {
                    Write-Host "   [A] Block All Listed"
                    Write-Host "   [B] Back"
                    Write-Host ""
                    
                    $PortChoice = Read-Host "   Select Port Number to Block [1-$($OpenPorts.Count)]"
                    
                    if ($PortChoice -eq 'B' -or $PortChoice -eq 'b') { break }
                    
                    if ($PortChoice -eq 'A' -or $PortChoice -eq 'a') {
                        foreach ($p in $OpenPorts) {
                            Write-Host "   Blocking Port $($p.Port)..." -ForegroundColor Yellow
                            New-NetFirewallRule -DisplayName "LOCKON Block $($p.Port)" -Direction Inbound -LocalPort $p.Port -Protocol TCP -Action Block -ErrorAction SilentlyContinue | Out-Null
                        }
                        Write-Host "   All listed ports blocked." -ForegroundColor Green
                        Start-Sleep -Seconds 2
                        break # Refresh main list
                    }
                    
                    if ($PortChoice -match '^\d+$' -and [int]$PortChoice -le $OpenPorts.Count -and [int]$PortChoice -gt 0) {
                        $Target = $OpenPorts[[int]$PortChoice - 1]
                        Write-Host "   Blocking Port $($Target.Port)..." -ForegroundColor Yellow
                        New-NetFirewallRule -DisplayName "LOCKON Block $($Target.Port)" -Direction Inbound -LocalPort $Target.Port -Protocol TCP -Action Block -ErrorAction SilentlyContinue | Out-Null
                        Write-Host "   Done." -ForegroundColor Green
                        
                        # Remove from current list view logic (visual feedback) or just break to refresh
                        Start-Sleep -Seconds 1
                        break # Refresh logic is simpler
                    }
                }
            }
        }
        "B" { return }
        "b" { return }
        default {
             Write-Host "   Invalid selection." -ForegroundColor Red
             Start-Sleep -Seconds 1
        }
    }
}
Write-Host "`nPress any key to return to main menu..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
