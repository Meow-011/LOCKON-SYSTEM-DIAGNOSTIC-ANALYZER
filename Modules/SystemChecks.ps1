
function Invoke-LockonSystemChecks {
    param (
        [Object]$Config
    )

    # Note: $AuditResults must be available in the parent scope or passed/returned. 
    # To keep it simple and compatible with existing structure, we will assume $AuditResults is a reference type or utilize the parent scope variable carefully.
    # Typically, modules should return data, but since we are refactoring a monolithic script, we will use 'Get-Variable -Scope 1' or simply relying on the caller scope for $AuditResults is common in simple PS scripts, 
    # BUT for modularity, let's return a hashtable of results to be merged.
    
    $ModuleResults = @{}

    # ============================================================
    # --- 1. Check Operating System Version ---
    # ============================================================
    $OsCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "1") {
        Write-SectionHeader "Check Operating System Version"
        $OsCheck = @{ Status = "INFO"; Message = "" }
        try {
            # HYBRID METHOD:
            # 1. Get ProductName from CIM (like systeminfo)
            $CimOs = Get-CimInstance Win32_OperatingSystem
            $ProductName = $CimOs.Caption
            
            # 2. Get DisplayVersion/Build from Registry (more accurate)
            $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            $DisplayVersion = (Get-ItemProperty -Path $RegPath -Name "DisplayVersion").DisplayVersion
            $Build = (Get-ItemProperty -Path $RegPath -Name "CurrentBuild").CurrentBuild
            
            if (-not $DisplayVersion) { $DisplayVersion = "(N/A)" }
            
            $OsCheck.Message = "$ProductName (Version: $DisplayVersion, Build: $Build)"
            Write-HostInfo $OsCheck.Message # Aligned
            $OsCheck.Data = @{
                ProductName = $ProductName
                DisplayVersion = $DisplayVersion
                Build = $Build
            }
        } catch {
            $OsCheck.Status = "FAIL"
            $OsCheck.Message = "Could not retrieve OS Version: $($_.Exception.Message)"
            Write-HostFail $OsCheck.Message # Aligned
        }
    }
    $ModuleResults.OsInfo = $OsCheck


    # ============================================================
    # --- 3. Check Operating System (OS) Update Status ---
    # ============================================================
    $UpdateCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "3") {
        Write-SectionHeader "Check Operating System (OS) Update Status"
        $UpdateCheck = @{ Status = "PASS"; Message = "" }
        try {
            # Use a faster COM Object method to check Last Search Success
            $AutoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
            $Results = $AutoUpdate.Results
            $LastSearch = $Results.LastSearchSuccessDate
            $LastInstall = $Results.LastInstallationSuccessDate
            
            # FIX: Handle raw date string if not a DateTime object
            $DateStrSearch = "Unknown"
            if ($LastSearch -is [DateTime]) { $DateStrSearch = $LastSearch.ToString("yyyy-MM-dd HH:mm") } else { $DateStrSearch = "$LastSearch" }

            $DateStrInstall = "Unknown"
            if ($LastInstall -is [DateTime]) { $DateStrInstall = $LastInstall.ToString("yyyy-MM-dd HH:mm") } else { $DateStrInstall = "$LastInstall" }
    
            $UpdateCheck.Message = "Last Search: $DateStrSearch | Last Install: $DateStrInstall"
            Write-HostInfo $UpdateCheck.Message
    
            # Policy Check: 
            # 1. Search > 30 days -> FAIL
            # 2. Install > 60 days -> FAIL
            $SearchFail = ($LastSearch -is [DateTime] -and $LastSearch -lt (Get-Date).AddDays(-30))
            $InstallFail = ($LastInstall -is [DateTime] -and $LastInstall -lt (Get-Date).AddDays(-60))
            
            if ($SearchFail -or $InstallFail) {
                 $UpdateCheck.Status = "FAIL"
                 if ($SearchFail) { $UpdateCheck.Message += " (Search > 30d!)" }
                 if ($InstallFail) { $UpdateCheck.Message += " (Install > 60d!)" }
                 Write-HostFail "  - [!] OS Update health is POOR! (Old search/install)"
            } else {
                 Write-HostPass "  - [OK] Update status is healthy."
            }
            
            $UpdateCheck.Data = @{ 
                LastSearchDate = $DateStrSearch 
                LastInstallDate = $DateStrInstall
            }
        } catch {
            $UpdateCheck.Status = "FAIL"
            $UpdateCheck.Message = "Could not check OS Update status: $($_.Exception.Message)"
            Write-HostFail $UpdateCheck.Message
        }
    }
    $ModuleResults.OsUpdate = $UpdateCheck


    # ============================================================
    # --- 5. Verify Critical Security Patches (KB) ---
    # ============================================================
    $PatchCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "5") {
        Write-SectionHeader "Verify Critical Security Patches (KB)"
        $PatchCheck = @{ Status = "PASS"; Message = ""; Data = @() }
        
        # Get KBs from Centralized Config
        $KbListPath = $Config.ResolvedPaths.CriticalKBs
        
        # Fallback if Config doesn't have it (Backward Compatibility/Safety)
        if (-not $KbListPath) {
             # Fallback if Config doesn't have it (Backward Compatibility/Safety)
             $KbListPath = Join-Path $PSScriptRoot "Database\critical_kbs.txt"
             if(-not (Test-Path $KbListPath)) { $KbListPath = Join-Path (Split-Path $PSScriptRoot -Parent) "Database\critical_kbs.txt" }
        }

        if (Test-Path $KbListPath) {
            $CriticalKBs = Get-Content $KbListPath | Where-Object { $_ -match "^KB\d+" } | ForEach-Object { $_.Trim() }
            
            if ($CriticalKBs.Count -eq 0) {
                 Write-HostInfo "No critical KBs defined in critical_kbs.txt."
            } else {
                 try {
                     # Get Installed Hotfixes
                     $InstalledHotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID
                     
                     $MissingKBs = @()
                     $FoundKBs = @()
                     foreach ($kb in $CriticalKBs) {
                         if ($InstalledHotfixes -contains $kb) {
                             $FoundKBs += $kb
                         } else {
                             $MissingKBs += $kb
                         }
                     }
                     
                     # Check Logic: Pass if AT LEAST ONE critical KB is found (as per User Request)
                     if ($FoundKBs.Count -gt 0) {
                         $PatchCheck.Status = "PASS"
                         $PatchCheck.Message = "Found $($FoundKBs.Count) critical patches. (Missing: $($MissingKBs.Count))"
                         Write-HostPass "Found $($FoundKBs.Count) critical patches."
                     } else {
                         $PatchCheck.Status = "FAIL" 
                         $PatchCheck.Message = "No critical patches found! Missing all $($CriticalKBs.Count) items."
                         Write-HostFail "No critical patches found!"
                     }
                     
                     $PatchCheck.Data = @{
                         Found = $FoundKBs
                         Missing = $MissingKBs
                     }
                 } catch {
                     $PatchCheck.Status = "FAIL"
                     $PatchCheck.Message = "Could not check hotfixes: $($_.Exception.Message)"
                     Write-HostFail $PatchCheck.Message
                 }
            }
        } else {
             $PatchCheck.Message = "critical_kbs.txt not found."
             Write-HostInfo $PatchCheck.Message
        }
    }
    $ModuleResults.CriticalPatches = $PatchCheck


    # ============================================================
    # --- 9. Check User Account Control (UAC) ---
    # ============================================================
    $UacCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "9") {
        Write-SectionHeader "User Account Control (UAC)"
        $UacCheck = @{ Status = "PASS"; Message = "" }
        try {
            $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            $EnableLUA = (Get-ItemProperty -Path $RegPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
            $Consent = (Get-ItemProperty -Path $RegPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
            
            if ($null -eq $EnableLUA) {
                 $UacCheck.Status = "FAIL"
                 $UacCheck.Message = "Could not determine UAC status (Registry key missing)."
                 Write-HostFail $UacCheck.Message
            } elseif ($EnableLUA -eq 0) {
                 $UacCheck.Status = "FAIL"
                 $UacCheck.Message = "UAC is DISABLED (EnableLUA = 0)."
                 Write-HostFail $UacCheck.Message
            } elseif ($Consent -eq 0) {
                 # 0 = Elevate without prompting (Effectively disables UAC protection)
                 $UacCheck.Status = "FAIL"
                 $UacCheck.Message = "UAC is active but configured to 'Elevate without prompting' (Consent=0). Insecure!"
                 Write-HostFail "  [!] UAC Bypass: Admin elevation is silent!"
            } else {
                 $UacCheck.Status = "PASS"
                 $UacCheck.Message = "UAC is ENABLED (Consent=$Consent)."
                 Write-HostPass $UacCheck.Message
            }
            $UacCheck.Data = @{ EnableLUA = $EnableLUA; Consent = $Consent }
        } catch {
            $UacCheck.Status = "FAIL"
            $UacCheck.Message = "Could not check UAC: $($_.Exception.Message)"
            Write-HostFail $UacCheck.Message
        }
    }
    $ModuleResults.UAC = $UacCheck


    # ============================================================
    # --- 26. Shadow Copy & Restore Point Check ---
    # ============================================================
    $ShadowCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "26") {
        Write-SectionHeader "Shadow Copy & Restore Point Check"
        $ShadowCheck = @{ Status = "INFO"; Message = "" }
    
    try {
        # Check if System Restore is enabled and has points
        # Get-ComputerRestorePoint requires Admin
        $RestorePoints = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        
        if ($RestorePoints) {
            $LastPoint = $RestorePoints | Select-Object -Last 1
            
            # FIX: Handle raw WMI date string format (e.g. 20260120...)
            $DateStr = "Unknown"
            if ($LastPoint.CreationTime -is [DateTime]) {
                 $DateStr = $LastPoint.CreationTime.ToString("yyyy-MM-dd")
            } elseif ($LastPoint.CreationTime -match "^(\d{4})(\d{2})(\d{2})") {
                 $DateStr = "$($matches[1])-$($matches[2])-$($matches[3])"
            }
    
            $ShadowCheck.Status = "PASS"
            $ShadowCheck.Message = "System Restore is ACTIVE. Last Restore Point: $DateStr ($($LastPoint.Description))"
            Write-HostPass "  [+] System Restore is active. Found $($RestorePoints.Count) restore points."
        } else {
            # Might be disabled or just no points
            $ShadowCheck.Status = "FAIL"
            $ShadowCheck.Message = "No System Restore points found (or disabled)."
            Write-HostFail "  [!] No System Restore points found! (Ransomware Risk)"
        }
    } catch {
        $ShadowCheck.Message = "Could not check System Restore: $($_.Exception.Message)"
    }
    }
    $ModuleResults.ShadowCopy = $ShadowCheck

    return $ModuleResults
}
