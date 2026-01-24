<#
.SYNOPSIS
    LOCKON Configuration Manager
    Allows safe editing of config.psd1 and critical_kbs.txt via default text editor (Notepad).
    Includes validation to prevent syntax errors.
#>

$ScriptPath = $PSScriptRoot
# Load Shared Library
$LibPath = Join-Path $ScriptPath "LOCKON_Lib.ps1"
if (Test-Path $LibPath) {
    . $LibPath
} else {
    Write-Host "[!] Critical Error: LOCKON_Lib.ps1 not found!" -ForegroundColor Red
    exit
}

# Paths are handled in Lib, but we keep local references for editors
$ConfigPath = Join-Path $ScriptPath "config.psd1"
$KbPath = Join-Path $ScriptPath "Database\critical_kbs.txt"

function Show-Header {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "   LOCKON CONFIGURATION MANAGER" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   [1] Open 'config.psd1' (Blacklist, Ports, AV Codes)" -ForegroundColor White
    Write-Host "       -> Edit UnwantedSoftware, RiskyPorts, AntivirusStateTranslations"
    Write-Host ""
    Write-Host "   [2] Open 'critical_kbs.txt' (Security Patches)" -ForegroundColor White
    Write-Host "       -> Add/Remove KB numbers"
    Write-Host ""
    Write-Host "   [3] Reload & Validate Configuration" -ForegroundColor Green
    Write-Host "       -> Check if your edits are valid syntax"
    Write-Host ""
    Write-Host "   [4] Back to Main Menu" -ForegroundColor Gray
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
}

while ($true) {
    Show-Header
    $Choice = Read-Host "   Select an option"

    switch ($Choice) {
        "1" {
            if (Test-Path $ConfigPath) {
                Write-Host "`n   [+] Opening config.psd1 in Notepad..." -ForegroundColor Yellow
                Start-Process notepad.exe "$ConfigPath"
                Write-Host "   [!] Check your taskbar if Notepad doesn't appear." -ForegroundColor Gray
            } else {
                Write-Host "`n   [!] Error: config.psd1 not found!" -ForegroundColor Red
            }
            Start-Sleep -Seconds 2
        }

        "2" {
             if (Test-Path $KbPath) {
                Write-Host "`n   [+] Opening critical_kbs.txt in Notepad..." -ForegroundColor Yellow
                Start-Process notepad.exe "$KbPath"
            } else {
                Write-Host "`n   [!] Error: critical_kbs.txt not found!" -ForegroundColor Red
            }
            Start-Sleep -Seconds 2
        }

        "3" {
            Write-Host "`n   [+] Validating config.psd1 syntax..." -ForegroundColor Cyan
            Write-Host "`n   [+] Validating config.psd1 syntax..." -ForegroundColor Cyan
            # Use Library function for validation
            $TestConfig = Load-LockonConfig
            
            if ($TestConfig) {
                Write-HostPass "Syntax is VALID."
                Write-Host "          - Risky Ports: $($TestConfig.RiskyPorts.Count)"
                Write-Host "          - Blacklisted Apps: $($TestConfig.UnwantedSoftware.Count)"
                Write-Host "          - AV Codes: $($TestConfig.AntivirusStateTranslations.Count)"
                Write-Log -Message "Config validation passed."
            } else {
                Write-HostFail "Syntax Error detected or file missing!"
                Write-Host "`n   Please re-open the file [1] and fix the error." -ForegroundColor Yellow
                Write-Log -Message "Config validation failed." -Type "ERROR"
            }
            Write-Host "`n   Press any key to continue..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }

        "4" {
            return
        }

        default {
             Write-Host "   Invalid selection." -ForegroundColor Red
             Start-Sleep -Seconds 1
        }
    }
}
