<#
.SYNOPSIS
    LOCKON Shared Library (LOCKON_Lib.ps1)
    Contains common functions for Logging and Configuration Management.
.DESCRIPTION
    This script is intended to be dot-sourced by other LOCKON scripts.
#>

# --- Global Variables ---
$Global:LockonLogFile = Join-Path $PSScriptRoot "Debug.log"

# --- Function: Write-Log ---
function Write-Log {
    param (
        [string]$Message,
        [string]$Type = "INFO" # INFO, WARN, ERROR
    )

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogLine = "[$TimeStamp] [$Type] $Message"
    
    try {
        Add-Content -Path $Global:LockonLogFile -Value $LogLine -ErrorAction SilentlyContinue
    } catch {
        # Fallback if logging fails (e.g. permission issue)
        Write-Host "   [!] Logging Failed: $_" -ForegroundColor DarkGray
    }
}

# --- Function: Load-LockonConfig ---
function Load-LockonConfig {
    param (
        [string]$ConfigPath = (Join-Path $PSScriptRoot "config.psd1")
    )

    if (-not (Test-Path $ConfigPath)) {
        $Msg = "Configuration file not found at: $ConfigPath"
        Write-Host "   [!] $Msg" -ForegroundColor Red
        Write-Log -Message $Msg -Type "ERROR"
        return $null
    }

    try {
        $Config = Import-PowerShellDataFile -Path $ConfigPath
        Write-Log -Message "Configuration loaded successfully." -Type "INFO"
        return $Config
    } catch {
        $Msg = "Failed to load config.psd1: $($_.Exception.Message)"
        Write-Host "   [!] $Msg" -ForegroundColor Red
        Write-Log -Message $Msg -Type "ERROR"
        return $null
    }
}

# --- Function: Write-SectionHeader (Moved here for reuse) ---
function Write-SectionHeader {
    param ([string]$Title)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   $Title" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Log -Message "Started Section: $Title"
}

# --- Function: Write-HostInfo (Moved here for reuse) ---
function Write-HostInfo {
    param ([string]$Message)
    Write-Host "   [INFO] $Message" -ForegroundColor Yellow
}

# --- Function: Write-HostPass (Moved here for reuse) ---
function Write-HostPass {
    param ([string]$Message)
    Write-Host "   [PASS] $Message" -ForegroundColor Green
}

# --- Function: Write-HostFail (Moved here for reuse) ---
function Write-HostFail {
    param ([string]$Message)
    Write-Host "   [FAIL] $Message" -ForegroundColor Red
    Write-Log -Message "FAIL: $Message" -Type "WARN"
}

# --- Function: Write-HostWarn (Moved here for reuse) ---
function Write-HostWarn {
    param ([string]$Message)
    Write-Host "   [WARN] $Message" -ForegroundColor Yellow
    Write-Log -Message "WARN: $Message" -Type "WARN"
}

# --- Function: Verify-Signature ---
function Verify-Signature {
    param ([string]$Path)
    
    if (-not (Test-Path $Path -PathType Leaf)) { return "FileNotFound" }
    
    try {
        $Sig = Get-AuthenticodeSignature -FilePath $Path
        if ($Sig.Status -eq "Valid") {
            return "Trusted"
        } elseif ($Sig.Status -eq "NotSigned") {
            return "Unsigned"
        } else {
            return "Invalid" # HashMismatch, UnknownError, etc.
        }
    } catch {
        return "Error"
    }
}

# --- Function: Get-LockonUnit (Unit Selection System) ---
function Get-LockonUnit {
    $UnitConfigFile = Join-Path $PSScriptRoot "Database\config_units.json"
    $Units = @()

    # Load existing units (Force Strings)
    if (Test-Path $UnitConfigFile) {
        try {
            $JsonContent = Get-Content $UnitConfigFile -Raw -Encoding UTF8
            if ($JsonContent) {
                $LoadedStats = $JsonContent | ConvertFrom-Json
                # Flatten to pure strings if it's an object array, or just cast if simple array
                if ($LoadedStats -is [Array]) {
                    foreach ($Item in $LoadedStats) {
                         if ($Item -is [string]) { $Units += $Item }
                         elseif ($Item.PSObject.Properties['value']) { $Units += $Item.value.ToString() }
                    }
                } elseif ($LoadedStats -is [string]) {
                    $Units += $LoadedStats
                }
            }
        } catch {
            Write-HostWarn "Could not load units config. Starting fresh."
        }
    }

    
    # Sort for better UX
    $Units = $Units | Sort-Object

    while ($true) {
        Clear-Host
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host "   SELECT AUDITED UNIT" -ForegroundColor Cyan
        Write-Host "==============================================" -ForegroundColor Cyan
        
        $Count = $Units.Count
        $ShowAll = $Count -le 10

        if ($Count -eq 0) {
             Write-Host "   (No units found in database)" -ForegroundColor DarkGray
        } elseif ($ShowAll) {
            # Low count: Show all
            $Index = 1
            foreach ($U in $Units) {
                Write-Host "   [$Index] $U"
                $Index++
            }
        } else {
            # High count: Show summary
            Write-Host "   Database contains $Count units." -ForegroundColor Gray
            Write-Host "   (Type unit name to search)" -ForegroundColor Gray
        }
        
        Write-Host "   ----------------------------------------------" -ForegroundColor DarkGray
        Write-Host "   [N]     CREATE NEW UNIT" -ForegroundColor Yellow
        Write-Host "   [Enter] SKIP (Unspecified)" -ForegroundColor DarkGray
        Write-Host ""
        
        $InputStr = Read-Host "   Search/Select"
        
        # 1. Skip
        if ([string]::IsNullOrWhiteSpace($InputStr)) {
            return "Unspecified-Unit"
        }

        # 2. Create New Explicitly
        if ($InputStr -eq "N" -or $InputStr -eq "n") {
            Write-Host ""
            $NewUnit = Read-Host "   Enter New Unit Name"
            if (-not [string]::IsNullOrWhiteSpace($NewUnit)) {
                $NewUnit = $NewUnit.Trim()
                # Check duplicate
                if ($Units -contains $NewUnit) {
                     Write-HostWarn "Unit '$NewUnit' already exists. Selecting it."
                     Start-Sleep -Seconds 1
                     return $NewUnit
                }
                # Save to config (Ensure flat string array)
                $Units += $NewUnit
                $Units | Sort-Object | Select-Object -Unique | ForEach-Object { "$_" } | ConvertTo-Json -Depth 2 | Out-File $UnitConfigFile -Encoding UTF8
                Write-HostPass "Saved '$NewUnit' to database."
                Start-Sleep -Seconds 1
                return $NewUnit
            }
            continue # Loop back
        }

        # 3. Direct ID Selection (Only if list is shown)
        if ($ShowAll -and $InputStr -match "^\d+$" -and [int]$InputStr -le $Count -and [int]$InputStr -gt 0) {
             return $Units[[int]$InputStr - 1]
        }

        # 4. Search Logic
        $Matches = $Units | Where-Object { $_ -like "*$InputStr*" }
        
        if ($Matches.Count -eq 1) {
            $Match = $Matches[0]
            Write-Host "   -> Found: $Match" -ForegroundColor Green
            Start-Sleep -Seconds 1
            return $Match
        }
        elseif ($Matches.Count -gt 1) {
            # Multiple matches
            Write-Host ""
            Write-Host "   [ Multiple Matches Found ]" -ForegroundColor Cyan
            $SubIndex = 1
            foreach ($M in $Matches) {
                Write-Host "   [$SubIndex] $M"
                $SubIndex++
            }
            Write-Host "   [0] Cancel / Search Again" -ForegroundColor Gray
            Write-Host ""
            
            $SubSel = Read-Host "   Select [1-$($Matches.Count)]"
            if ($SubSel -match "^\d+$" -and $SubSel -gt 0 -and $SubSel -le $Matches.Count) {
                return $Matches[[int]$SubSel - 1]
            }
        }
        else {
            # No matches - Offer creation
            Write-HostWarn "No unit found matching '$InputStr'."
            $Create = Read-Host "   Create '$InputStr' as new unit? (Y/N)"
            if ($Create -eq "Y" -or $Create -eq "y") {
                $NewUnit = $InputStr.Trim()
                $Units += $NewUnit
                $Units | Sort-Object | Select-Object -Unique | ForEach-Object { "$_" } | ConvertTo-Json -Depth 2 | Out-File $UnitConfigFile -Encoding UTF8
                Write-HostPass "Saved '$NewUnit' to database."
                Start-Sleep -Seconds 1
                return $NewUnit
            }
        }
    }
}

Write-Log "LOCKON Library Loaded."
