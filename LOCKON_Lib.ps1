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

Write-Log "LOCKON Library Loaded."
