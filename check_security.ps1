<#
.SYNOPSIS
    (v6.4) HTML TEMPLATE REVERT: Changed the Generate-HtmlReport function
           back to the "simple list" style (one row per check) as
           requested by the user, who preferred the original "art".
           Detailed tables (like AV, Ports, Admins) are now
           embedded *inside* the "Message" cell of the simple list.
    (v6.3) ...
.NOTES
    Version: 6.4
#>

# --- Load Shared Library ---
$LibPath = Join-Path $PSScriptRoot "LOCKON_Lib.ps1"
if (Test-Path $LibPath) {
    . $LibPath
} else {
    Write-Host "[!] Critical Error: LOCKON_Lib.ps1 not found!" -ForegroundColor Red
    exit
}

# --- 0. (v5.0) Script Setup & Config Loading ---
# This script is designed to be run as Admin (by the .bat launcher)
# It will only load config/defaults once.
Clear-Host
Write-SectionHeader "0. Initializing Script and Loading Configuration"

# Set script path and find config
$KbListPath = Join-Path $PSScriptRoot "critical_kbs.txt"
$ThreatDbPath = Join-Path $PSScriptRoot "threat_db.txt"

# --- Load Config via Library ---
$Config = Load-LockonConfig
if (-not $Config) {
    # If config loading fails, we must exit or define a fallback manually.
    # For now, we trust the library to handle errors, but if specific Logic needs default config,
    # we would define it here.
    exit
}

# Config is now loaded via Load-LockonConfig
# Legacy default config logic removed.

# --- Define Report Paths ---
$MachineName = $env:COMPUTERNAME
$DateStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportFileBase = "Report-$MachineName-$DateStamp"

# (v3.1) Create the directory structure
try {
    # (v3.2) Fix: Join paths sequentially
    $ChildReportPath = Join-Path $Config.MainReportFolder $MachineName
    $ReportOutputDir = Join-Path $PSScriptRoot $ChildReportPath
    
    if (-not (Test-Path $ReportOutputDir)) {
        New-Item -ItemType Directory -Path $ReportOutputDir | Out-Null
    }
    
    $HtmlReportPath = Join-Path $ReportOutputDir "$ReportFileBase.html"
    $JsonReportPath = Join-Path $ReportOutputDir "$ReportFileBase.json"
} catch {
    Write-HostFail "CRITICAL ERROR: Could not create report directory."
    Write-Log -Message "Report Dir Creation Failed: $($_.Exception.Message)" -Type "ERROR"
    pause
    exit

}

# --- Initialize Results Objects ---
# (v3.1) Fix: Initialize as HashTable, convert to PSCustomObject at the end
$AuditResults = @{
    ReportInfo = @{
        MachineName = $MachineName
        User = $env:USERNAME
        Date = (Get-Date)
        ReportFileBase = $ReportFileBase
    }
    Policy = $Config # Store the policy used for this scan
}
# (v6.4) This is no longer used, Generate-HtmlReport builds the string directly.
# $HtmlReportBody = [System.Collections.ArrayList]@()


# --- (v6.4) Helper function Add-HtmlRow is no longer needed ---


Write-HostInfo "Starting scan on $MachineName..." # (v6.3) Aligned
Write-HostInfo "HTML Report will be saved to: $HtmlReportPath" # (v6.3) Aligned
Write-HostInfo "JSON Report will be saved to: $JsonReportPath" # (v6.3) Aligned

# ============================================================
# --- 1. Check Operating System Version ---
# ============================================================
Write-SectionHeader "1. Check Operating System Version"
$OsCheck = @{ Status = "INFO"; Message = "" }
try {
    # (v4.4) HYBRID METHOD:
    # 1. Get ProductName from CIM (like systeminfo)
    $CimOs = Get-CimInstance Win32_OperatingSystem
    $ProductName = $CimOs.Caption
    
    # 2. Get DisplayVersion/Build from Registry (more accurate)
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $DisplayVersion = (Get-ItemProperty -Path $RegPath -Name "DisplayVersion").DisplayVersion
    $Build = (Get-ItemProperty -Path $RegPath -Name "CurrentBuild").CurrentBuild
    
    if (-not $DisplayVersion) { $DisplayVersion = "(N/A)" }
    
    $OsCheck.Message = "$ProductName (Version: $DisplayVersion, Build: $Build)"
    Write-HostInfo $OsCheck.Message # (v6.3) Aligned
    $OsCheck.Data = @{
        ProductName = $ProductName
        DisplayVersion = $DisplayVersion
        Build = $Build
    }
} catch {
    $OsCheck.Status = "FAIL"
    $OsCheck.Message = "Could not retrieve OS Version: $($_.Exception.Message)"
    Write-HostFail $OsCheck.Message # (v6.3) Aligned
}
$AuditResults.OsInfo = $OsCheck


# ============================================================
# --- 2. Check Network Configuration ---
# ============================================================
Write-SectionHeader "2. Check Network Configuration (Active Physical Adapters)"
$NetCheck = @{ Status = "INFO"; Message = "" }
try {
    # Get adapters that are Physical AND connected ("Up")
    $Adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }
    
    if ($Adapters) {
        $AdapterData = @()
        foreach ($Adapter in $Adapters) {
            $IpConfig = Get-NetIPConfiguration -InterfaceIndex $Adapter.InterfaceIndex
            $IpV4 = ($IpConfig | Where-Object { $_.IPv4Address -ne $null }).IPv4Address.IPAddress
            $IpV6 = ($IpConfig | Where-Object { $_.IPv6Address -ne $null }).IPv6Address.IPAddress
            
            $AdapterData += @{
                Name = $Adapter.Name
                InterfaceDescription = $Adapter.InterfaceDescription
                MacAddress = $Adapter.MacAddress
                IPv4Address = $IpV4
                IPv6Address = $IpV6
            }
            Write-HostInfo "  - Found: $($Adapter.Name) ($($Adapter.MacAddress))" # (v6.3) Aligned
            Write-HostInfo "    - IPv4: $IpV4" # (v6.3) Aligned
        }
        $NetCheck.Message = "Found $($Adapters.Count) active physical adapter(s)."
        $NetCheck.Data = $AdapterData
    } else {
        $NetCheck.Message = "No active (connected) physical adapters found."
        Write-HostInfo $NetCheck.Message # (v6.3) Aligned
    }
} catch {
    $NetCheck.Status = "FAIL"
    $NetCheck.Message = "Could not retrieve Network Info: $($_.Exception.Message)"
    Write-HostFail $NetCheck.Message # (v6.3) Aligned
}
$AuditResults.NetworkConfig = $NetCheck


# ============================================================
# --- 3. Check OS Update Status ---
# ============================================================
Write-SectionHeader "3. Check Operating System (OS) Update Status"
$OsUpdateCheck = @{ Status = "INFO"; Message = "" }
try {
    $LastUpdate = (Get-Hotfix | Sort-Object -Property InstalledOn -Descending)[0].InstalledOn
    $OsUpdateCheck.Message = "System's last update was on: $($LastUpdate.ToString('yyyy-MM-dd'))"
    Write-HostInfo $OsUpdateCheck.Message # (v6.3) Aligned
    
    # (v6.2) BUGFIX: Store as a dashboard-readable ISO 8601 string ("o")
    # This fixes the [object Object] bug in the dashboard
    $OsUpdateCheck.Data = @{ LastUpdateDate = $LastUpdate.ToString("o") }
} catch {
    $OsUpdateCheck.Status = "FAIL"
    $OsUpdateCheck.Message = "Could not retrieve Hotfix info (Get-Hotfix failed). This may be a permissions issue or the service is stopped."
    Write-HostFail $OsUpdateCheck.Message # (v6.3) Aligned
}
$AuditResults.OsUpdate = $OsUpdateCheck


# ============================================================
# --- 4. Check Antivirus (AV/EDR) Status ---
# ============================================================
Write-SectionHeader "4. Check Antivirus (AV/EDR) Status"
# (v6.5) FIX: Default status is FAIL, will turn PASS if at least one is running.
$AvCheck = @{ Status = "FAIL"; Message = "" }
$AvData = @()
$AnyAvRunning = $false # (v6.5) New logic flag

try {
    # Get AV list from Security Center
    $AvProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct"
    
    if ($AvProducts) {
        # Load translation map from config
        $TranslationMap = @{}
        $Config.AntivirusStateTranslations | ForEach-Object {
            $TranslationMap[$_.Code] = $_
        }
        
        foreach ($Product in $AvProducts) {
            $Name = $Product.displayName
            $State = $Product.productState
            
            $Translation = $TranslationMap["$State"]
            if (-not $Translation) {
                $Translation = @{ Status = "INFO"; Description = "Unknown State" }
            }
            
            $AvData += @{
                Name = $Name
                State = "$State"
                Status = $Translation.Status
                Description = $Translation.Description
            }
            
            # (v6.5) NEW LOGIC:
            if ($Translation.Status -eq "Running") {
                Write-HostPass "  - Found: $Name (State: $State, Status: $($Translation.Description))"
                $AnyAvRunning = $true # Found at least one working AV!
            } else {
                # Changed from Write-HostFail to Info, because this might be intentional (e.g. Defender snoozed)
                Write-HostInfo "  - Found: $Name (State: $State, Status: $($Translation.Description)) - (Inactive)"
            }
        }
        
        # Final Decision
        if ($AnyAvRunning) {
            $AvCheck.Status = "PASS"
            $AvCheck.Message = "At least one AV product is running."
        } else {
            $AvCheck.Status = "FAIL"
            $AvCheck.Message = "No active Antivirus products found."
            Write-HostFail "  - CRITICAL: No AV products reported as 'Running'."
        }
        $AvCheck.Data = $AvData
        
    } else {
        $AvCheck.Message = "No Antivirus products found via SecurityCenter2."
        Write-HostFail $AvCheck.Message
        $AvCheck.Data = $AvData
    }
} catch {
    $AvCheck.Message = "Could not query SecurityCenter2: $($_.Exception.Message). (This namespace may not exist on Windows Server)."
    Write-HostFail $AvCheck.Message
}
$AuditResults.Antivirus = $AvCheck


# ============================================================
# --- 5. Check for Critical Security Patches (KB) ---
# ============================================================
Write-SectionHeader "5. Check for Critical Security Patches (KB)"
$KbCheck = @{ Status = "INFO"; Message = "" }
try {
    # Get the system's installed KBs (Hotfix IDs)
    $InstalledKBs = (Get-Hotfix).HotFixID
    
    # Get the policy KBs from the text file
    if (Test-Path $KbListPath) {
        # (v6.2) BUGFIX: Sanitize input. Get-Content can return objects.
        # We must ensure we get an array of strings.
        $PolicyKBs = Get-Content $KbListPath | ForEach-Object { "$_" }
        
        Write-HostInfo "Checking against master list of $($PolicyKBs.Count) KBs from $KbListPath" # (v6.3) Aligned

        # Find matches
        $FoundKBs = @()
        $MissingKBs = @()
        
        foreach ($kb in $PolicyKBs) {
            if ($InstalledKBs -contains $kb) {
                $FoundKBs += $kb
            } else {
                $MissingKBs += $kb
            }
        }

        # (v6.2) NEW LOGIC: "PASS if Found > 0"
        # This assumes the list is a MASTER list for all OSes (XP, 7, 10, 11)
        # and finding any one of them means the machine is patched for its OS.
        if ($FoundKBs.Count -gt 0) {
            $KbCheck.Status = "PASS"
            $KbCheck.Message = "Found $($FoundKBs.Count) matching critical KB(s) from the master list."
            Write-HostPass $KbCheck.Message # (v6.3) Aligned
            Write-HostPass "  - Found: $($FoundKBs -join ', ')" # (v6.3) Aligned
        } else {
            $KbCheck.Status = "FAIL"
            $KbCheck.Message = "Did not find any matching KBs from the master list ($($MissingKBs.Count) missing)."
            Write-HostFail $KbCheck.Message # (v6.3) Aligned
        }

        # (v6.2) BUGFIX: Store only the string arrays, not the full objects
        $KbCheck.Data = @{
            Found = $FoundKBs
            Missing = $MissingKBs
        }
        
    } else {
        $KbCheck.Message = "critical_kbs.txt not found. Skipping check."
        Write-HostInfo $KbCheck.Message # (v6.3) Aligned
    }
} catch {
    $KbCheck.Status = "FAIL"
    $KbCheck.Message = "Could not check KBs: $($_.Exception.Message)"
    Write-HostFail $KbCheck.Message # (v6.3) Aligned
}
$AuditResults.CriticalPatches = $KbCheck


# ============================================================
# --- 6 & 7. Check Listening Ports ---
# ============================================================
Write-SectionHeader "6 & 7. Check Listening Ports"
$PortCheck = @{ Status = "PASS"; Message = "" }
try {
    # (v4.0) Get port numbers from the config object
    $RiskyPortNumbers = $Config.RiskyPorts | ForEach-Object { $_.Port }
    Write-HostInfo "Policy: Checking for $($RiskyPortNumbers.Count) risky ports: $($RiskyPortNumbers -join ', ')" # (v6.3) Aligned
    
    $ListeningPorts = Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique
    
    $FoundRiskyPorts = @()
    foreach ($port in $ListeningPorts) {
        if ($RiskyPortNumbers -contains $port) {
            # Find the full policy object for this port
            $Policy = $Config.RiskyPorts | Where-Object { $_.Port -eq $port }
            $FoundRiskyPorts += $Policy
        }
    }
    
    if ($FoundRiskyPorts.Count -gt 0) {
        $PortCheck.Status = "FAIL"
        $PortCheck.Message = "Found $($FoundRiskyPorts.Count) risky LISTENING ports: $($FoundRiskyPorts.Port -join ', ')"
        Write-HostFail $PortCheck.Message # (v6.3) Aligned
        foreach ($p in $FoundRiskyPorts) {
            Write-HostFail "  - Port $($p.Port) ($($p.Service)): $($p.Risk)" # (v6.3) Aligned
        }
    } else {
        $PortCheck.Message = "No risky ports (from list) are LISTENING."
        Write-HostPass $PortCheck.Message # (v6.3) Aligned
    }
    
    $PortCheck.Data = @{
        AllListening = $ListeningPorts
        FoundRisky = $FoundRiskyPorts
        Policy = $Config.RiskyPorts # (v4.0) Add policy to data for reference
    }
    
} catch {
    $PortCheck.Status = "FAIL"
    $PortCheck.Message = "Could not check ports (Get-NetTCPConnection failed): $($_.Exception.Message)"
    Write-HostFail $PortCheck.Message # (v6.3) Aligned
}
$AuditResults.ListeningPorts = $PortCheck


# ============================================================
# --- 8. Check Windows Firewall Status ---
# ============================================================
Write-SectionHeader "8. Check Windows Firewall Status"
$FwCheck = @{ Status = "PASS"; Message = "" }
$FwData = @()
try {
    $Profiles = Get-NetFirewallProfile
    $AllEnabled = $true
    
    foreach ($Profile in $Profiles) {
        $FwData += @{
            Name = $Profile.Name
            Enabled = $Profile.Enabled
        }
        if ($Profile.Enabled -ne "True") {
            $AllEnabled = $false
            Write-HostFail "  - Firewall Profile '$($Profile.Name)': DISABLED" # (v6.3) Aligned
        } else {
            Write-HostPass "  - Firewall Profile '$($Profile.Name)': Enabled" # (v6.3) Aligned
        }
    }
    
    if (-not $AllEnabled) {
        $FwCheck.Status = "FAIL"
        $FwCheck.Message = "At least one firewall profile is disabled."
    } else {
        $FwCheck.Message = "All firewall profiles are enabled."
    }
    $FwCheck.Data = $FwData
    
} catch {
    $FwCheck.Status = "FAIL"
    $FwCheck.Message = "Could not check firewall status (Get-NetFirewallProfile failed): $($_.Exception.Message)"
    Write-HostFail $FwCheck.Message # (v6.3) Aligned
}
$AuditResults.Firewall = $FwCheck


# ============================================================
# --- 9. Check User Account Control (UAC) ---
# ============================================================
Write-SectionHeader "9. Check User Account Control (UAC)"
$UacCheck = @{ Status = "FAIL"; Message = "" }
try {
    $UacValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    
    if ($UacValue.EnableLUA -eq 1) {
        $UacCheck.Status = "PASS"
        $UacCheck.Message = "UAC is Enabled (EnableLUA = 1)"
        Write-HostPass $UacCheck.Message # (v6.3) Aligned
    } else {
        $UacCheck.Message = "UAC is DISABLED (EnableLUA = 0)"
        Write-HostFail $UacCheck.Message # (v6.3) Aligned
    }
    $UacCheck.Data = @{ EnableLUA = $UacValue.EnableLUA }
    
} catch {
    $UacCheck.Status = "FAIL"
    $UacCheck.Message = "Could not check UAC status: $($_.Exception.Message)"
    Write-HostFail $UacCheck.Message # (v6.3) Aligned
}
$AuditResults.UAC = $UacCheck


# ============================================================
# --- 10. Review Automatic Services ---
# ============================================================
# ============================================================
# --- 10. Check for Suspicious Services (Non-Standard Paths) ---
# ============================================================
Write-SectionHeader "10. Check for Suspicious Services (Non-Standard Paths)"
$SvcCheck = @{ Status = "PASS"; Message = "" }
$SvcData = @()
try {
    # Get services that are Auto or Running
    $Services = Get-CimInstance -ClassName Win32_Service -Filter "StartMode = 'Auto' OR State = 'Running'"
    
    $SuspiciousServices = @()
    
    if ($Services) {
        foreach ($Svc in $Services) {
            $Path = $Svc.PathName
            # Clean up path (remove quotes and arguments) to check location
            if ($Path -match '^"([^"]+)"') { $CleanPath = $matches[1] }
            elseif ($Path -match '^(\S+)') { $CleanPath = $matches[1] }
            else { $CleanPath = $Path }
            
            # Use Library to verify signature
            $SigStatus = Verify-Signature -Path $CleanPath
            
            # Logic: If NOT in C:\Windows or C:\Program Files, it's suspicious OR if signature is not trusted
            if ($CleanPath -and (($CleanPath -notmatch "Windows") -and ($CleanPath -notmatch "Program Files")) -or ($SigStatus -ne "Trusted")) {
                $SuspiciousServices += @{
                    Name = $Svc.Name
                    DisplayName = $Svc.DisplayName
                    Path = $Path
                    State = $Svc.State
                    StartMode = $Svc.StartMode
                    Signature = $SigStatus
                }
                if ($SigStatus -ne "Trusted") {
                    Write-HostFail "  - [SUSPICIOUS] $($Svc.Name): $Path [Signature: $SigStatus]"
                } else {
                    Write-HostWarn "  - [NOTE] $($Svc.Name): $Path [Signature: $SigStatus]"
                }
            }
        }
    }
    
    if ($SuspiciousServices.Count -gt 0) {
        $SvcCheck.Status = "FAIL"
        $SvcCheck.Message = "Found $($SuspiciousServices.Count) services running from non-standard paths or with untrusted signatures (e.g. AppData, Temp)."
    } else {
        $SvcCheck.Message = "No services found running from suspicious paths or with untrusted signatures (checked $($Services.Count) services)."
        Write-HostPass $SvcCheck.Message
    }
    $SvcCheck.Data = $SuspiciousServices
    
} catch {
    $SvcCheck.Status = "FAIL"
    $SvcCheck.Message = "Could not check services: $($_.Exception.Message)"
    Write-HostFail $SvcCheck.Message
}
$AuditResults.AutomaticServices = $SvcCheck


# ============================================================
# --- 11. Check Local Administrators ---
# ============================================================
Write-SectionHeader "11. Check Local Administrators"
$AdminCheck = @{ Status = "INFO"; Message = "" }
$AdminData = @()
try {
    $AdminGroup = Get-LocalGroupMember -Group "Administrators"
    
    if ($AdminGroup) {
        foreach ($Member in $AdminGroup) {
            $AdminData += @{
                Name = $Member.Name
                ObjectClass = $Member.ObjectClass
                PrincipalSource = $Member.PrincipalSource
            }
            Write-HostInfo "  - $($Member.Name) (Type: $($Member.ObjectClass), Source: $($Member.PrincipalSource))" # (v6.3) Aligned
        }
    }
    $AdminCheck.Message = "Listing members of 'Administrators' group for manual review."
    $AdminCheck.Data = $AdminData
    Write-HostInfo $AdminCheck.Message # (v6.3) Aligned
    
} catch {
    $AdminCheck.Status = "FAIL"
    $AdminCheck.Message = "Could not check local admins (Get-LocalGroupMember failed): $($_.Exception.Message)"
    Write-HostFail $AdminCheck.Message # (v6.3) Aligned
}
$AuditResults.LocalAdmins = $AdminCheck


# ============================================================
# --- 12. Check Open File Shares ---
# ============================================================
Write-SectionHeader "12. Check Open File Shares"
$ShareCheck = @{ Status = "PASS"; Message = "" }
$ShareData = @()
try {
    # Get shares, excluding default admin shares (C$, ADMIN$)
    $Shares = Get-CimInstance -ClassName Win32_Share | Where-Object { $_.Name -notlike "*$" }
    
    if ($Shares) {
        foreach ($Share in $Shares) {
            $ShareAcl = Get-SmbShareAccess -Name $Share.Name
            
            $ShareData += @{
                Name = $Share.Name
                Path = $Share.Path
                Access = $ShareAcl | Select-Object -Property AccountName, AccessControlType, AccessRight
            }
            
            $IsOpen = $ShareAcl | Where-Object { ($_.AccountName -eq "Everyone") -and ($_.AccessRight -ne "Read") }
            if ($IsOpen) {
                $ShareCheck.Status = "FAIL"
                Write-HostFail "  - [FAIL] Share '$($Share.Name)' ($($Share.Path)) grants Write/Change access to 'Everyone'." # (v6.3) Aligned
            } else {
                Write-HostInfo "  - [INFO] Share '$($Share.Name)' ($($Share.Path)) found. (No 'Everyone' write access)." # (v6.3) Aligned
            }
        }
        if ($ShareCheck.Status -eq "FAIL") {
            $ShareCheck.Message = "Found non-default shares, at least one is open to 'Everyone' with Write access."
        } else {
            $ShareCheck.Message = "Found non-default shares, but none grant 'Everyone' Write access."
        }
        
    } else {
        $ShareCheck.Message = "No non-default file shares found."
        Write-HostPass $ShareCheck.Message # (v6.3) Aligned
    }
    $ShareCheck.Data = $ShareData
    
} catch {
    $ShareCheck.Status = "FAIL"
    $ShareCheck.Message = "Could not check file shares: $($_.Exception.Message)"
    Write-HostFail $ShareCheck.Message
}
$AuditResults.FileShares = $ShareCheck


# ============================================================
# --- 13. Check Startup Items (Registry & Folder) ---
# ============================================================
Write-SectionHeader "13. Check Startup Items (Risky Paths)"
$StartupCheck = @{ Status = "PASS"; Message = "" }
$StartupData = @()
try {
    $StartupItems = Get-CimInstance -ClassName Win32_StartupCommand
    $SuspiciousStartup = @()
    
    if ($StartupItems) {
        foreach ($Item in $StartupItems) {
            $Path = $Item.Command
            # Extract EXE path for signature check
            $CleanPath = $Path.Replace('"', '').Split(' ')[0]
            $SigStatus = Verify-Signature -Path $CleanPath

            # Check for risky paths OR Invalid Signature
            if ($Path -match "AppData" -or $Path -match "Temp" -or $SigStatus -ne "Trusted") {
                $SuspiciousStartup += @{
                    Name = $Item.Name
                    Command = $Path
                    User = $Item.User
                    Signature = $SigStatus
                }
                Write-HostFail "  - [SUSPICIOUS] $($Item.Name): $Path [Sig: $SigStatus]"
            }
        }
    }
    
    if ($SuspiciousStartup.Count -gt 0) {
        $StartupCheck.Status = "FAIL"
        $StartupCheck.Message = "Found $($SuspiciousStartup.Count) startup items pointing to AppData/Temp or with untrusted signatures."
    } else {
        $StartupCheck.Message = "No suspicious startup items found."
        Write-HostPass $StartupCheck.Message
    }
    $StartupCheck.Data = $SuspiciousStartup

} catch {
    $StartupCheck.Status = "FAIL"
    $StartupCheck.Message = "Could not check startup items: $($_.Exception.Message)"
    Write-HostFail $StartupCheck.Message
}
$AuditResults.Startup = $StartupCheck


# ============================================================
# --- 14. Check Unwanted Software (Policy Violation) ---
# ============================================================
Write-SectionHeader "14. Check Unwanted Software (Blacklist)"
$SoftwareCheck = @{ Status = "PASS"; Message = "" }
try {
    # Get Unwanted List from Config
    if ($Config.UnwantedSoftware) {
        $Blacklist = $Config.UnwantedSoftware
        Write-HostInfo "Checking against blacklist: $($Blacklist -join ', ')"
        
        # Get Installed Software (Registry - 32/64 bit)
        $UninstallKeys = @(
            "HKLM:\Setting\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        
        $FoundUnwanted = @()
        foreach ($Key in $UninstallKeys) {
            # Check if key exists (PowerShell Core / older PS compatibility)
             if (Test-Path $Key) {
                Get-ChildItem -Path $Key -ErrorAction SilentlyContinue | ForEach-Object {
                    $Props = Get-ItemProperty -Path $_.PSPath
                    $DisplayName = $Props.DisplayName
                    if ($DisplayName) {
                        foreach ($BadApp in $Blacklist) {
                            if ($DisplayName -match $BadApp) {
                                $FoundUnwanted += @{ Name = $DisplayName; Policy = $BadApp }
                                Write-HostFail "  - [VIOLATION] Found Blacklisted App: $DisplayName"
                            }
                        }
                    }
                }
            }
        }
        
        if ($FoundUnwanted.Count -gt 0) {
            $SoftwareCheck.Status = "FAIL"
            $SoftwareCheck.Message = "Found $($FoundUnwanted.Count) prohibited software installations."
            $SoftwareCheck.Data = $FoundUnwanted
        } else {
            $SoftwareCheck.Message = "No blacklisted software found."
            Write-HostPass $SoftwareCheck.Message
            $SoftwareCheck.Data = @()
        }
        
    } else {
        $SoftwareCheck.Message = "No unwanted software policy defined in config."
        Write-HostInfo $SoftwareCheck.Message
    }

} catch {
    $SoftwareCheck.Status = "FAIL"
    $SoftwareCheck.Message = "Could not check installed software: $($_.Exception.Message)"
    Write-HostFail $SoftwareCheck.Message
}
$AuditResults.UnwantedSoftware = $SoftwareCheck


$AuditResults.FileShares = $ShareCheck


# ============================================================
# --- 15. File Hash Analysis (Running Processes) ---
# ============================================================
Write-SectionHeader "15. File Hash Analysis (Threat Hunting)"
$HashCheck = @{ Status = "INFO"; Message = ""; Data = @(); Threats = @() }

# (v7.0) Load Offline Threat DB
$ThreatHashes = [System.Collections.Generic.HashSet[string]]::new()
if (Test-Path $ThreatDbPath) {
    Write-HostInfo "Loading Offline Threat DB from threat_db.txt..."
    try {
        Get-Content $ThreatDbPath | ForEach-Object { $null = $ThreatHashes.Add($_.Trim().ToLower()) }
        Write-HostPass "Loaded $($ThreatHashes.Count) known malware hashes."
    } catch {
        Write-HostFail "Error loading threat DB: $($_.Exception.Message)"
    }
}

try {
    # Get unique executable paths from running processes
    $Processes = Get-Process | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue | Sort-Object -Unique | Where-Object { $_ -and (Test-Path $_) }
    
    $HashList = @()
    $ThreatsFound = @()

    if ($Processes) {
        Write-HostInfo "Calculating SHA-256 hashes for $($Processes.Count) unique processes..."
        foreach ($ProcPath in $Processes) {
            try {
                $HashObj = Get-FileHash -Path $ProcPath -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($HashObj) {
                    $HashMin = $HashObj.Hash.ToLower()
                    
                    if ($ThreatHashes.Contains($HashMin)) {
                         $ThreatsFound += @{
                            FileName = [System.IO.Path]::GetFileName($ProcPath)
                            Path = $ProcPath
                            Hash = $HashObj.Hash
                         }
                         Write-HostFail "!!! CRITICAL THREAT DETECTED !!! Process: $($ProcPath)"
                    }

                    $HashList += @{
                        FileName = [System.IO.Path]::GetFileName($ProcPath)
                        Path = $ProcPath
                        Hash = $HashObj.Hash
                    }
                }
            } catch {}
        }
    }

    $HashCheck.Data = $HashList
    $HashCheck.Threats = $ThreatsFound

    if ($ThreatsFound.Count -gt 0) {
        $HashCheck.Status = "FAIL"
        $HashCheck.Message = "CRITICAL: Found $($ThreatsFound.Count) active processes matching known MALWARE hashes!"
    } else {
        $HashCheck.Message = "Calculated hashes for $($HashList.Count) processes. No known threats found."
        Write-HostPass "Successfully analyzed process hashes. No threats detected."
    }

} catch {
    $HashCheck.Status = "FAIL"
    $HashCheck.Message = "Hash analysis failed: $($_.Exception.Message)"
    Write-HostFail $HashCheck.Message
}
$AuditResults.HashAnalysis = $HashCheck


# ============================================================
# --- 16. Drift Detection (Baseline Comparison) ---
# ============================================================
Write-SectionHeader "16. Drift Detection (Baseline Comparison)"
$DriftCheck = @{ Status = "INFO"; Message = "No baseline found (First Scan)."; Data = @{} }

try {
    # 1. Find Latest Previous Report (JSON)
    $MachineName = $env:COMPUTERNAME
    $ReportFolder = Join-Path $PSScriptRoot "AuditReports\$MachineName"
    
    # Get all JSON reports, exclude current session (if any temp file exists, though usually we haven't saved yet)
    if (Test-Path $ReportFolder) {
        $PreviousReportFile = Get-ChildItem -Path $ReportFolder -Filter "Report-*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        
        if ($PreviousReportFile) {
            Write-HostInfo "Baseline found: $($PreviousReportFile.Name)"
            $Baseline = Get-Content -Path $PreviousReportFile.FullName -Raw | ConvertFrom-Json
            
            $DriftFound = $false
            $DriftData = @{
                NewPorts = @()
                NewAdmins = @()
                NewSoftware = @()
                ChangedHashes = @()
            }

            # --- Compare Ports ---
            $BasePorts = @($Baseline.ListeningPorts.Data.FoundRisky.Port)
            foreach ($p in $AuditResults.ListeningPorts.Data.FoundRisky) {
                if ($p.Port -notin $BasePorts) {
                    $DriftData.NewPorts += $p
                    $DriftFound = $true
                }
            }

            # --- Compare Admins ---
            $BaseAdmins = @($Baseline.LocalAdmins.Data.Name)
            foreach ($a in $AuditResults.LocalAdmins.Data) {
                if ($a.Name -notin $BaseAdmins) {
                    $DriftData.NewAdmins += $a
                    $DriftFound = $true
                }
            }
            
            # --- Compare Software ---
            if ($Baseline.UnwantedSoftware.Data) {
                $BaseSoftware = @($Baseline.UnwantedSoftware.Data.Name)
                foreach ($s in $AuditResults.UnwantedSoftware.Data) {
                    if ($s.Name -notin $BaseSoftware) {
                        $DriftData.NewSoftware += $s
                        $DriftFound = $true
                    }
                }
            }

            # --- Compare Hashes ---
            # Create Dictionary for fast lookup
            $BaseHashes = @{}
            if ($Baseline.HashAnalysis.Data) {
                foreach ($h in $Baseline.HashAnalysis.Data) {
                    if ($h.Path) { $BaseHashes[$h.Path] = $h.Hash }
                }
            }

            foreach ($curr in $AuditResults.HashAnalysis.Data) {
                if ($BaseHashes.ContainsKey($curr.Path)) {
                    if ($BaseHashes[$curr.Path] -ne $curr.Hash) {
                        $DriftData.ChangedHashes += @{
                            File = $curr.FileName
                            Path = $curr.Path
                            OldHash = $BaseHashes[$curr.Path]
                            NewHash = $curr.Hash
                        }
                        $DriftFound = $true
                    }
                }
            }

            if ($DriftFound) {
                $DriftCheck.Status = "WARN" # Use WARN to highlight difference
                $DriftCheck.Message = "Drift Detected! Changes found compared to baseline ($($PreviousReportFile.Name))."
                $DriftCheck.Data = $DriftData
                Write-HostFail "  [!] DRIFT DETECTED: New Ports/Admins/Hashes found!"
            } else {
                $DriftCheck.Status = "PASS"
                $DriftCheck.Message = "No drift detected. System state matches baseline."
                Write-HostPass "  [+] System state matches baseline."
            }

        } else {
            Write-HostInfo "  [i] No previous report found. Establishing new baseline."
        }
    }
} catch {
    $DriftCheck.Message = "Error during drift analysis: $($_.Exception.Message)"
    Write-HostFail $DriftCheck.Message
}
$AuditResults.DriftAnalysis = $DriftCheck


# ============================================================


Write-SectionHeader "17. Browser Extension Audit"
$ExtCheck = @{ Status = "INFO"; Message = ""; Data = @() }

function Get-BrowserExtensions {
    param($BrowserName, $Path)
    $Results = @()
    if (Test-Path $Path) {
        # Get all extension IDs
        $ExtFolders = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue
        foreach ($Folder in $ExtFolders) {
            $Id = $Folder.Name
            # Get Version folder (usually just one, pick last)
            $VerFolder = Get-ChildItem -Path $Folder.FullName -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if ($VerFolder) {
                $ManifestPath = Join-Path $VerFolder.FullName "manifest.json"
                if (Test-Path $ManifestPath) {
                    try {
                        $Json = Get-Content -Path $ManifestPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                        $Name = $Json.name
                        # Handle localized names (simple fallback)
                        if ($Name -match "^__MSG_(.+?)__$") { $Name = "$Id (Localized)" }
                        
                        $Results += @{
                            Browser = $BrowserName
                            Name = $Name
                            Version = $Json.version
                            Id = $Id
                        }
                    } catch {}
                }
            }
        }
    }
    return $Results
}

try {
    $Extensions = @()
    
    # Chrome
    $ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    $Extensions += Get-BrowserExtensions -BrowserName "Chrome" -Path $ChromePath
    
    # Edge
    $EdgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
    $Extensions += Get-BrowserExtensions -BrowserName "Edge" -Path $EdgePath
    
    $ExtCheck.Message = "Found $($Extensions.Count) extensions installed."
    $ExtCheck.Data = $Extensions
    Write-HostPass "Successfully audited browser extensions."

} catch {
    $ExtCheck.Status = "FAIL"
    $ExtCheck.Message = "Extension audit failed: $($_.Exception.Message)"
    Write-HostFail $ExtCheck.Message
}
$AuditResults.BrowserExtensions = $ExtCheck


# ============================================================
# --- 18. Scheduled Task Hunter (Persistence Check) ---
# ============================================================
Write-SectionHeader "18. Scheduled Task Hunter (Persistence Check)"
$TaskCheck = @{ Status = "PASS"; Message = ""; Data = @() }

try {
    # Get all scheduled tasks
    $Tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
    
    $SuspiciousTasks = @()
    
    foreach ($T in $Tasks) {
        $Action = $T.Actions
        if ($Action) {
            # Check Execute Actions
            $ExecPath = $Action.Execute
            if (-not $ExecPath) { $ExecPath = $Action.ToString() } # Fallback
            
            # Clean path for signature check
            $CleanPath = $ExecPath.Replace('"', '').Split(' ')[0]
            $SigStatus = Verify-Signature -Path $CleanPath

            # Logic: Check for risky paths OR untrusted signature
            # Attackers love AppData, Temp, Public, ProgramData (outside of legitimate subfolders)
            if ($ExecPath -match "AppData" -or 
                $ExecPath -match "Temp" -or 
                $ExecPath -match "Users\\Public" -or
                ($ExecPath -match "ProgramData" -and $ExecPath -notmatch "Microsoft") -or
                $SigStatus -ne "Trusted"
               ) {
                
                $SuspiciousTasks += @{
                    Name = $T.TaskName
                    Path = $T.TaskPath
                    Command = $ExecPath
                    State = $T.State
                    Signature = $SigStatus
                }
                Write-HostFail "  - [SUSPICIOUS TASK] $($T.TaskName): $ExecPath [Sig: $SigStatus]"
            }
        }
    }
    
    if ($SuspiciousTasks.Count -gt 0) {
        $TaskCheck.Status = "FAIL"
        $TaskCheck.Message = "Found $($SuspiciousTasks.Count) suspicious scheduled tasks running from non-standard paths."
        $TaskCheck.Data = $SuspiciousTasks
    } else {
        $TaskCheck.Message = "No suspicious scheduled tasks found (scanned $($Tasks.Count) active tasks)."
        Write-HostPass $TaskCheck.Message
    }

} catch {
    $TaskCheck.Status = "FAIL"
    $TaskCheck.Message = "Could not scan Scheduled Tasks: $($_.Exception.Message)"
    Write-HostFail $TaskCheck.Message
}
$AuditResults.ScheduledTasks = $TaskCheck


# ============================================================
# --- 19. Hosts File Analysis ---
# ============================================================
Write-SectionHeader "19. Hosts File Analysis"
$HostsCheck = @{ Status = "PASS"; Message = ""; Data = @() }

$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
try {
    if (Test-Path $HostsPath) {
        $Content = Get-Content $HostsPath
        $SuspiciousEntries = @()
        foreach ($Line in $Content) {
            $Trimmed = $Line.Trim()
            # Ignore comments (#) and empty lines
            if ($Trimmed.Length -gt 0 -and $Trimmed[0] -ne '#') {
                # Ignore standard localhost entries
                if ($Trimmed -notmatch "127.0.0.1\s+localhost" -and $Trimmed -notmatch "::1\s+localhost") {
                    $SuspiciousEntries += $Trimmed
                    Write-HostWarn "  - [NOTE] Non-standard entry: $Trimmed"
                }
            }
        }
        
        if ($SuspiciousEntries.Count -gt 0) {
            $HostsCheck.Status = "FAIL"
            $HostsCheck.Message = "Found $($SuspiciousEntries.Count) non-standard entries in Hosts file."
            $HostsCheck.Data = $SuspiciousEntries
        } else {
            $HostsCheck.Message = "Hosts file is clean (standard localhost check)."
            Write-HostPass $HostsCheck.Message
        }
    } else {
        $HostsCheck.Message = "Hosts file not found (Unusual)."
        Write-HostWarn $HostsCheck.Message
    }
} catch {
    $HostsCheck.Status = "FAIL"
    $HostsCheck.Message = "Could not read Hosts file: $($_.Exception.Message)"
    Write-HostFail $HostsCheck.Message
}
$AuditResults.HostsFile = $HostsCheck

# ============================================================
# --- 20. DNS Cache Forensics ---
# ============================================================
Write-SectionHeader "20. DNS Cache Forensics"
$DnsCheck = @{ Status = "INFO"; Message = ""; Data = @() }

try {
    $DnsCache = Get-DnsClientCache | Sort-Object Entry
    $UniqueDomains = $DnsCache | Select-Object -ExpandProperty Entry -Unique
    
    if ($UniqueDomains) {
        $DnsCheck.Message = "Retrieved $($UniqueDomains.Count) DNS cache entries."
        Write-HostInfo "  - Found $($UniqueDomains.Count) entries in DNS Cache."
        
        # Helper to format for data
        $CacheData = @()
        foreach ($Domain in $UniqueDomains) {
             $CacheData += @{ Entry = $Domain }
        }
        $DnsCheck.Data = $CacheData
    } else {
        $DnsCheck.Message = "DNS Cache is empty."
        Write-HostInfo "  - DNS Cache is empty."
    }
} catch {
    $DnsCheck.Message = "Could not retrieve DNS Cache (Requires Admin/PS5+): $($_.Exception.Message)"
    Write-HostWarn $DnsCheck.Message
}
$AuditResults.DnsCache = $DnsCheck

# ============================================================
# --- 21. Security Event Log Analysis ---
# ============================================================
Write-SectionHeader "21. Security Event Log Analysis (Last 24h)"
$LogCheck = @{ Status = "PASS"; Message = ""; Data = @{ FailedLogins=@(); LogClearing=$false; NewUsers=@() } }

try {
    # 1. Failed Logins (4625)
    $FailedEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
    if ($FailedEvents) {
        foreach ($E in $FailedEvents) {
            $Xml = [xml]$E.ToXml()
            $LogCheck.Data.FailedLogins += @{
                Time = $E.TimeCreated.ToString("HH:mm:ss")
                User = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty "#text"
                Source = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"} | Select-Object -ExpandProperty "#text"
            }
        }
    }

    # 2. Log Clearing (1102)
    $ClearEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
    if ($ClearEvents) { $LogCheck.Data.LogClearing = $true }

    # 3. New User Created (4720)
    $UserEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
    if ($UserEvents) {
        foreach ($E in $UserEvents) {
             $Xml = [xml]$E.ToXml()
             $LogCheck.Data.NewUsers += @{
                TargetUser = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty "#text"
                Creator = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"} | Select-Object -ExpandProperty "#text"
             }
        }
    }

    # Evaluate Status
    $FailCount = $LogCheck.Data.FailedLogins.Count
    if ($LogCheck.Data.LogClearing) {
        $LogCheck.Status = "FAIL"
        $LogCheck.Message = "CRITICAL: Security Event Log was CLEARED in the last 24 hours!"
        Write-HostFail $LogCheck.Message
    } elseif ($LogCheck.Data.NewUsers.Count -gt 0) {
        $LogCheck.Status = "WARN"
        $LogCheck.Message = "Suspicious: New user account(s) created in the last 24 hours."
        Write-HostWarn $LogCheck.Message
    } elseif ($FailCount -gt 5) {
        $LogCheck.Status = "WARN"
        $LogCheck.Message = "Brute Force Warning: Detected $FailCount failed login attempts."
        Write-HostWarn $LogCheck.Message
    } else {
        $LogCheck.Message = "No suspicious event logs found (Last 24h)."
        Write-HostPass $LogCheck.Message
    }

} catch {
    $LogCheck.Status = "INFO"
    $LogCheck.Message = "Could not query Security Logs (Requires Admin): $($_.Exception.Message)"
    Write-HostInfo $LogCheck.Message
}
$AuditResults.EventLogs = $LogCheck

# ============================================================
Write-SectionHeader "22. Audit Complete. Generating Reports..."

# --- (v6.4) REVERTED HTML Report Function ---
# Reverted to the "simple list" style per user request.
# Details are now embedded within the message cell.
function Generate-HtmlReport($Results) {
    $HtmlHead = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - $($Results.ReportInfo.MachineName)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', sans-serif; }
        h2 { 
            font-size: 1.25rem; 
            font-weight: 600; 
            padding-bottom: 0.5rem; 
            margin-top: 1.5rem; 
            border-bottom: 1px solid #e5e7eb; /* gray-200 */
        }
        /* (v6.4) Main table style */
        .main-table { 
            width: 100%; 
            margin-top: 1rem; 
            border-collapse: collapse; 
        }
        .main-table th, .main-table td { 
            padding: 0.75rem; 
            border: 1px solid #e5e7eb; /* gray-200 */
            text-align: left;
            vertical-align: top;
        }
        .main-table th { 
            background-color: #f9fafb; /* gray-50 */ 
            font-weight: 600;
        }
        /* (v6.4) Embedded table style (for details) */
        .sub-table {
            width: 100%;
            margin-top: 0.5rem;
            border-collapse: collapse;
            font-size: 0.875rem; /* text-sm */
        }
        .sub-table th, .sub-table td {
            border: 1px solid #d1d5db; /* gray-300 */
            padding: 0.5rem;
        }
        .sub-table th {
             background-color: #f3f4f6; /* gray-100 */
        }

        .status-pass { 
            background-color: #dcfce7; /* green-100 */ 
            color: #166534; /* green-800 */ 
            font-weight: 700;
            width: 100px; /* (v6.4) Fixed width for status */
        }
        .status-fail { 
            background-color: #fee2e2; /* red-100 */ 
            color: #991b1b; /* red-800 */ 
            font-weight: 700;
            width: 100px;
        }
        .status-info { 
            background-color: #e0f2fe; /* blue-100 */ 
            color: #075985; /* blue-800 */ 
            font-weight: 700;
            width: 100px;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 1.5rem; 
            background-color: white;
        }
        .header {
            border-bottom: 2px solid #d1d5db; /* gray-300 */
            padding-bottom: 1rem;
            margin-bottom: 1.5rem;
        }
        .header h1 {
            font-size: 2.25rem; /* 4xl */
            font-weight: 700;
        }
        pre {
            background-color: #1f2937; /* gray-800 */
            color: #f9fafb; /* gray-50 */
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            white-space: pre-wrap; /* (v6.4) Wrap pre-formatted text */
        }
        /* (v6.5) Copy Button */
        .copy-btn {
            background-color: #f3f4f6; border: 1px solid #d1d5db; padding: 2px 8px; 
            font-size: 0.75rem; border-radius: 4px; cursor: pointer; transition: background 0.2s;
        }
        .copy-btn:hover { background-color: #e5e7eb; }
        .hash-preview { font-family: monospace; font-size: 0.7rem; color: #6b7280; margin-right: 5px; }
    </style>
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                alert('Hash copied to clipboard!');
            }, function(err) {
                console.error('Could not copy text: ', err);
                // Fallback for older browsers or restricted contexts
                const textArea = document.createElement("textarea");
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand("copy");
                document.body.removeChild(textArea);
                alert('Hash copied to clipboard!');
            });
        }
    </script>
</head>
<body class="bg-gray-100">
<div class="container">
    <div class="header">
        <h1>Security Audit Report</h1>
        <p><strong>Machine Name:</strong> $($Results.ReportInfo.MachineName)</p>
        <p><strong>Scan Date:</strong> $($Results.ReportInfo.Date.ToString("yyyy-MM-dd HH:mm:ss"))</p>
        <p><strong>Scanned By:</strong> $($Results.ReportInfo.User)</p>
    </div>

    <h2>Audit Results Summary</h2>
    <table class="main-table">
        <thead>
            <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
"@
    
    $HtmlBody = ""
    
    # --- 1. OS Version ---
    $HtmlBody += "<tr><td><strong>1. OS Version</strong></td>"
    $HtmlBody += "<td class='status-info'>INFO</td>"
    $HtmlBody += "<td>$($Results.OsInfo.Message)</td></tr>"

    # --- 2. Network Config ---
    $HtmlBody += "<tr><td><strong>2. Network Configuration</strong></td>"
    $HtmlBody += "<td class='status-$($Results.NetworkConfig.Status.ToLower())'>$($Results.NetworkConfig.Status)</td>"
    # (v6.4) Embed details
    $Detail = $Results.NetworkConfig.Message
    if ($Results.NetworkConfig.Data) {
        $Detail += "<table class='sub-table'><tr><th>Name</th><th>MAC</th><th>IPv4</th></tr>"
        foreach ($Adapter in $Results.NetworkConfig.Data) {
            $Detail += "<tr><td>$($Adapter.Name)</td><td>$($Adapter.MacAddress)</td><td>$($Adapter.IPv4Address)</td></tr>"
        }
        $Detail += "</table>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"

    # --- 3. OS Update ---
    $HtmlBody += "<tr><td><strong>3. OS Update Status</strong></td>"
    $HtmlBody += "<td class='status-$($Results.OsUpdate.Status.ToLower())'>$($Results.OsUpdate.Status)</td>"
    # (v6.4) Embed details
    $UpdateDate = "N/A"
    if ($Results.OsUpdate.Data.LastUpdateDate) {
        try { $UpdateDate = (Get-Date $Results.OsUpdate.Data.LastUpdateDate).ToString("yyyy-MM-dd") } catch {}
    }
    $HtmlBody += "<td>$($Results.OsUpdate.Message) (Date: $UpdateDate)</td></tr>"
    
    # --- 4. Antivirus ---
    $HtmlBody += "<tr><td><strong>4. Antivirus (AV/EDR) Status</strong></td>"
    $HtmlBody += "<td class='status-$($Results.Antivirus.Status.ToLower())'>$($Results.Antivirus.Status)</td>"
    # (v6.4) Embed details
    $Detail = $Results.Antivirus.Message
    if ($Results.Antivirus.Data) {
        $Detail += "<table class='sub-table'><tr><th>Status</th><th>Product</th><th>Code</th><th>Description</th></tr>"
        foreach ($Av in $Results.Antivirus.Data) {
            $Detail += "<tr><td class='status-$($Av.Status.ToLower())'>$($Av.Status)</td><td>$($Av.Name)</td><td>$($Av.State)</td><td>$($Av.Description)</td></tr>"
        }
        $Detail += "</table>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    
    # --- 5. Critical Patches ---
    $HtmlBody += "<tr><td><strong>5. Critical Patches (KB)</strong></td>"
    $HtmlBody += "<td class='status-$($Results.CriticalPatches.Status.ToLower())'>$($Results.CriticalPatches.Status)</td>"
    # (v6.4) Embed details
    $Detail = $Results.CriticalPatches.Message
    if ($Results.CriticalPatches.Data.Found) {
        $Detail += "<br><strong>Found:</strong> $($Results.CriticalPatches.Data.Found -join ', ')"
    }
    if ($Results.CriticalPatches.Status -eq 'FAIL') {
         $Detail += "<br><strong>Missing (from list):</strong> $($Results.CriticalPatches.Data.Missing.Count) KBs"
    }
    $HtmlBody += "<td>$Detail</td></tr>"

    # --- 6 & 7. Listening Ports ---
    $HtmlBody += "<tr><td><strong>6 & 7. Listening Ports</strong></td>"
    $HtmlBody += "<td class='status-$($Results.ListeningPorts.Status.ToLower())'>$($Results.ListeningPorts.Status)</td>"
    # (v6.4) Embed details
    $Detail = $Results.ListeningPorts.Message
    if ($Results.ListeningPorts.Status -eq 'FAIL') {
        $Detail += "<table class='sub-table'><tr><th>Port</th><th>Service</th><th>Risk</th></tr>"
        foreach ($p in $Results.ListeningPorts.Data.FoundRisky) {
            $Detail += "<tr><td>$($p.Port)</td><td>$($p.Service)</td><td>$($p.Risk)</td></tr>"
        }
        $Detail += "</table>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"

    # --- 8. Firewall ---
    $HtmlBody += "<tr><td><strong>8. Windows Firewall Status</strong></td>"
    $HtmlBody += "<td class='status-$($Results.Firewall.Status.ToLower())'>$($Results.Firewall.Status)</td>"
    # (v6.4) Embed details
    $Detail = $Results.Firewall.Message
    $Detail += "<table class='sub-table'><tr><th>Profile</th><th>Status</th></tr>"
    foreach ($Profile in $Results.Firewall.Data) {
        $EnabledText = "Disabled"
        $Status = "FAIL"
        if ($Profile.Enabled -eq 1) { $EnabledText = "Enabled"; $Status = "PASS"; }
        $Detail += "<tr><td>$($Profile.Name)</td><td class='status-$($Status.ToLower())'>$EnabledText</td></tr>"
    }
    $Detail += "</table>"
    $HtmlBody += "<td>$Detail</td></tr>"
    
    # --- 9. UAC ---
    $HtmlBody += "<tr><td><strong>9. User Account Control (UAC)</strong></td>"
    $HtmlBody += "<td class='status-$($Results.UAC.Status.ToLower())'>$($Results.UAC.Status)</td>"
    $HtmlBody += "<td>$($Results.UAC.Message) (Value: $($Results.UAC.Data.EnableLUA))</td></tr>"

    # --- 10. Automatic Services ---
    $HtmlBody += "<tr><td><strong>10. Review Automatic Services</strong></td>"
    $HtmlBody += "<td class='status-$($Results.AutomaticServices.Status.ToLower())'>$($Results.AutomaticServices.Status)</td>"
    # (v6.4) Embed details
    $Detail = $Results.AutomaticServices.Message
    $Detail += "<br><small>Click to expand</small><details><summary>View $($Results.AutomaticServices.Data.Count) Services</summary>"
    $Detail += "<pre>"
    foreach ($Svc in $Results.AutomaticServices.Data) {
        $Detail += "$($Svc.Name) `t ($($Svc.DisplayName))`n"
    }
    $Detail += "</pre></details>"
    $HtmlBody += "<td>$Detail</td></tr>"
    
    # --- 11. Local Admins ---
    $HtmlBody += "<tr><td><strong>11. Local Administrators</strong></td>"
    $HtmlBody += "<td class='status-$($Results.LocalAdmins.Status.ToLower())'>$($Results.LocalAdmins.Status)</td>"
    # (v6.4) Embed details
    $Detail = $Results.LocalAdmins.Message
    $Detail += "<table class='sub-table'><tr><th>Name</th><th>Type</th><th>Source</th></tr>"
    foreach ($Admin in $Results.LocalAdmins.Data) {
        $Detail += "<tr><td>$($Admin.Name)</td><td>$($Admin.ObjectClass)</td><td>$($Admin.PrincipalSource)</td></tr>"
    }
    $Detail += "</table>"
    $HtmlBody += "<td>$Detail</td></tr>"
    
    # --- 12. File Shares ---
    $HtmlBody += "<tr><td><strong>12. Open File Shares</strong></td>"
    $HtmlBody += "<td class='status-$($Results.FileShares.Status.ToLower())'>$($Results.FileShares.Status)</td>"
    # (v6.4) Embed details
    $Detail = $Results.FileShares.Message
    if ($Results.FileShares.Data) {
        $Detail += "<table class='sub-table'><tr><th>Name</th><th>Path</th><th>Access (ACL)</th></tr>"
        foreach ($Share in $Results.FileShares.Data) {
            $AclString = $Share.Access | ForEach-Object { "$($_.AccountName) ($($_.AccessRight))" } | Out-String
            $Detail += "<tr><td>$($Share.Name)</td><td>$($Share.Path)</td><td><pre>$($AclString)</pre></td></tr>"
        }
        $Detail += "</table>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    
    # --- 13. Startup Items ---
    $HtmlBody += "<tr><td><strong>13. Startup Items (Risky Paths)</strong></td>"
    $HtmlBody += "<td class='status-$($Results.Startup.Status.ToLower())'>$($Results.Startup.Status)</td>"
    $Detail = $Results.Startup.Message
    if ($Results.Startup.Status -eq 'FAIL') {
        $Detail += "<table class='sub-table'><tr><th>Name</th><th>Command</th><th>User</th></tr>"
        foreach ($Item in $Results.Startup.Data) {
            $Detail += "<tr><td>$($Item.Name)</td><td>$($Item.Command)</td><td>$($Item.User)</td></tr>"
        }
        $Detail += "</table>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"

    # --- 14. Unwanted Software ---
    $HtmlBody += "<tr><td><strong>14. Unwanted Software (Blacklist)</strong></td>"
    $HtmlBody += "<td class='status-$($Results.UnwantedSoftware.Status.ToLower())'>$($Results.UnwantedSoftware.Status)</td>"
    $Detail = $Results.UnwantedSoftware.Message
    if ($Results.UnwantedSoftware.Status -eq 'FAIL') {
        $Detail += "<table class='sub-table'><tr><th>Name</th><th>Policy Violation</th></tr>"
        foreach ($Item in $Results.UnwantedSoftware.Data) {
            $Detail += "<tr><td>$($Item.Name)</td><td>$($Item.Policy)</td></tr>"
        }
        $Detail += "</table>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"

    # End Table


    # --- 15. File Hash Analysis ---
    $HtmlBody += "<tr><td><strong>15. File Hash Analysis (SHA-256)</strong></td>"
    
    $HashStatusClass = "status-info"
    if ($Results.HashAnalysis.Status -eq "FAIL") { $HashStatusClass = "status-fail"; }
    
    $HtmlBody += "<td class='$HashStatusClass'>$($Results.HashAnalysis.Status)</td>"
    
    $Detail = "$($Results.HashAnalysis.Message)<br>"

    # Alert for Threats
    if ($Results.HashAnalysis.Threats.Count -gt 0) {
        $Detail += "<div style='color:white; background-color:#ef4444; padding:10px; border-radius:5px; margin:5px 0; font-weight:bold;'>"
        $Detail += "⚠️ CRITICAL THREATS DETECTED: $($Results.HashAnalysis.Threats.Count)</div>"
        $Detail += "<table class='sub-table' style='border:2px solid red'><tr><th>Threat File</th><th>Path</th><th>Malicious Hash</th></tr>"
        foreach ($t in $Results.HashAnalysis.Threats) {
             $Detail += "<tr style='background-color:#fee2e2'><td>$($t.FileName)</td><td>$($t.Path)</td><td style='font-family:monospace'>$($t.Hash)</td></tr>"
        }
        $Detail += "</table><br>"
    }

    $Detail += "<details><summary>View All Hashes ($($Results.HashAnalysis.Data.Count))</summary>"
    $Detail += "<table class='sub-table'><tr><th>File Name</th><th>Path</th><th>SHA-256 Hash</th></tr>"
    foreach ($HashItem in $Results.HashAnalysis.Data) {
        # Truncate hash for display (first 8 chars)
        $ShortHash = if ($HashItem.Hash.Length -gt 8) { $HashItem.Hash.Substring(0, 8) + "..." } else { $HashItem.Hash }
        $Detail += "<tr><td>$($HashItem.FileName)</td><td style='font-size:0.75rem'>$($HashItem.Path)</td>"
        $Detail += "<td><span class='hash-preview'>$ShortHash</span><button class='copy-btn' onclick=`"copyToClipboard('$($HashItem.Hash)')`">Copy</button></td></tr>"
    }
    $Detail += "</table></details>"
    $HtmlBody += "<td>$Detail</td></tr>"

    # --- 16. Drift Detection ---
    $DriftStatus = "INFO"
    if ($Results.DriftAnalysis.Status -eq "WARN") { $DriftStatus = "FAIL"; } 
    elseif ($Results.DriftAnalysis.Status -eq "PASS") { $DriftStatus = "PASS"; }
    
    $HtmlBody += "<tr><td><strong>16. Drift Detection (Baseline)</strong></td>"
    $HtmlBody += "<td class='status-$($DriftStatus.ToLower())'>$($Results.DriftAnalysis.Status)</td>"
    
    $Detail = $Results.DriftAnalysis.Message
    if ($Results.DriftAnalysis.Status -eq "WARN") {
        $d = $Results.DriftAnalysis.Data
        
        # New Ports
        if ($d.NewPorts.Count -gt 0) {
            $Detail += "<div style='color:red; font-weight:bold; margin-top:5px'>[!] NEW PORTS OPENED:</div>"
            foreach ($p in $d.NewPorts) { $Detail += "- Port $($p.Port) ($($p.Service))<br>" }
        }
        
        # New Admins
        if ($d.NewAdmins.Count -gt 0) {
            $Detail += "<div style='color:red; font-weight:bold; margin-top:5px'>[!] NEW ADMINS ADDED:</div>"
            foreach ($a in $d.NewAdmins) { $Detail += "- $($a.Name)<br>" }
        }
        
        # Changed Hashes
        if ($d.ChangedHashes.Count -gt 0) {
            $Detail += "<div style='color:red; font-weight:bold; margin-top:5px'>[!] FILE HASH MISMATCH (POSSIBLE TAMPERING):</div>"
            foreach ($h in $d.ChangedHashes) { 
                $Detail += "- <b>$($h.File)</b> changed!<br>&nbsp;&nbsp;Old: $($h.OldHash)<br>&nbsp;&nbsp;New: $($h.NewHash)<br>" 
            }
        }
    }
    $HtmlBody += "<td>$Detail</td></tr>"



    # --- 17. Browser Extensions ---
    $HtmlBody += "<tr><td><strong>17. Browser Extensions</strong></td>"
    $HtmlBody += "<td class='status-info'>INFO</td>"
    $Detail = "$($Results.BrowserExtensions.Message)<br>"
    if ($Results.BrowserExtensions.Data.Count -gt 0) {
        $Detail += "<details><summary>View Extensions ($($Results.BrowserExtensions.Data.Count))</summary>"
        $Detail += "<table class='sub-table'><tr><th>Browser</th><th>Name</th><th>Version</th><th>ID</th></tr>"
        foreach ($Ext in $Results.BrowserExtensions.Data) {
             $Detail += "<tr><td>$($Ext.Browser)</td><td>$($Ext.Name)</td><td>$($Ext.Version)</td><td style='font-size:0.75rem; font-family:monospace'>$($Ext.Id)</td></tr>"
        }
        $Detail += "</table></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"

    # --- 18. Scheduled Task Hunter ---
    $HtmlBody += "<tr><td><strong>18. Scheduled Task Hunter</strong></td>"
    $HtmlBody += "<td class='status-$($Results.ScheduledTasks.Status.ToLower())'>$($Results.ScheduledTasks.Status)</td>"
    
    $Detail = $Results.ScheduledTasks.Message
    if ($Results.ScheduledTasks.Status -eq 'FAIL') {
        $Detail += "<div style='color:red; font-weight:bold; margin-top:5px'>[!] SUSPICIOUS PERSISTENCE FOUND:</div>"
        $Detail += "<table class='sub-table'><tr><th>Task Name</th><th>Command / Action</th><th>State</th></tr>"
        foreach ($Task in $Results.ScheduledTasks.Data) {
            $Detail += "<tr><td>$($Task.Name)</td><td>$($Task.Command)</td><td>$($Task.State)</td></tr>"
        }
        $Detail += "</table>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    
    # --- 19. Hosts File Analysis ---
    $HtmlBody += "<tr><td><strong>19. Hosts File Analysis</strong></td>"
    $HtmlBody += "<td class='status-$($Results.HostsFile.Status.ToLower())'>$($Results.HostsFile.Status)</td>"
    $Detail = $Results.HostsFile.Message
    if ($Results.HostsFile.Status -eq 'FAIL') {
        $Detail += "<div style='color:red; font-weight:bold; margin-top:5px'>[!] SUSPICIOUS ENTRIES FOUND:</div>"
        $Detail += "<ul style='margin:0; padding-left:15px; font-family:monospace; font-size:0.85rem'>"
        foreach ($Line in $Results.HostsFile.Data) { $Detail += "<li>$Line</li>" }
        $Detail += "</ul>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"

    # --- 20. DNS Cache Forensics ---
    $HtmlBody += "<tr><td><strong>20. DNS Cache Forensics</strong></td>"
    $HtmlBody += "<td class='status-info'>INFO</td>"
    $Detail = "$($Results.DnsCache.Message)<br>"
    if ($Results.DnsCache.Data.Count -gt 0) {
        $Detail += "<details><summary>View Recent DNS Queries ($($Results.DnsCache.Data.Count))</summary>"
        $Detail += "<div style='max-height:150px; overflow-y:auto; font-family:monospace; font-size:0.75rem; border:1px solid #ddd; padding:5px'>"
        foreach ($Record in $Results.DnsCache.Data) { $Detail += "$($Record.Entry)<br>" }
        $Detail += "</div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    


    # --- 21. Security Event Log Analysis ---
    $StatusClass = "status-$($Results.EventLogs.Status.ToLower())"
    if ($Results.EventLogs.Status -eq 'WARN') { $StatusClass = "status-fail" } # Reuse fail style for warn visibility

    $HtmlBody += "<tr><td><strong>21. Security Event Log Analysis (24h)</strong></td>"
    $HtmlBody += "<td class='$StatusClass'>$($Results.EventLogs.Status)</td>"
    
    $Detail = $Results.EventLogs.Message
    if ($Results.EventLogs.Status -ne 'PASS' -and $Results.EventLogs.Status -ne 'INFO') {
        if ($Results.EventLogs.Data.FailedLogins.Count -gt 0) {
            $Detail += "<div style='color:red; font-weight:bold; margin-top:5px'>[!] FAILED LOGINS DETECTED ($($Results.EventLogs.Data.FailedLogins.Count)):</div>"
            $Detail += "<ul style='margin:0; padding-left:15px; font-size:0.75rem'>"
            # Show top 5
            $Results.EventLogs.Data.FailedLogins | Select-Object -First 5 | ForEach-Object { $Detail += "<li>$($_.Time): User '$($_.User)' from '$($_.Source)'</li>" }
            if ($Results.EventLogs.Data.FailedLogins.Count -gt 5) { $Detail += "<li>...and more...</li>" }
            $Detail += "</ul>"
        }
        if ($Results.EventLogs.Data.LogClearing) {
            $Detail += "<div style='background:red; color:white; font-weight:bold; padding:2px; margin-top:5px'>[CRITICAL] SECURITY LOGS CLEARED!</div>"
        }
        if ($Results.EventLogs.Data.NewUsers.Count -gt 0) {
             $Detail += "<div style='color:darkorange; font-weight:bold; margin-top:5px'>[!] NEW USERS CREATED:</div>"
             foreach ($u in $Results.EventLogs.Data.NewUsers) { $Detail += "- $($u.TargetUser) by $($u.Creator)<br>" }
        }
    }
    $HtmlBody += "<td>$Detail</td></tr>"

    $HtmlFoot = @"
        </tbody>
    </table>
</div>
</body>
</html>
"@
    
    return $HtmlHead + $HtmlBody + $HtmlFoot
} # --- End of Function ---

# --- Convert final results to PSCustomObject ---
$AuditResultsObject = [PSCustomObject]$AuditResults

# --- 1. Write JSON Report ---
try {
    # (v6.1) FIX: Remove -DateAsISO8601 (not compatible with PS 5.1)
    # The dashboard (v1.2+) can handle the default Microsoft date format.
    $AuditResultsObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonReportPath -Encoding utf8
    Write-HostPass "Successfully saved JSON report to $JsonReportPath" # (v6.3) Aligned
} catch {
    Write-HostFail "Could not save JSON report: $($_.Exception.Message)" # (v6.3) Aligned
}

# --- 2. Write HTML Report ---
try {
    $HtmlContent = Generate-HtmlReport $AuditResultsObject
    $HtmlContent | Out-File -FilePath $HtmlReportPath -Encoding utf8
    Write-HostPass "Successfully saved HTML report to $HtmlReportPath" # (v6.3) Aligned
} catch {
    Write-HostFail "Could not save HTML report: $($_.Exception.Message)" # (v6.3) Aligned
}

# ============================================================
Write-SectionHeader "23. All Done"
Write-HostPass "Scan complete. Reports saved to $ReportOutputDir" # (v6.3) Aligned
pause