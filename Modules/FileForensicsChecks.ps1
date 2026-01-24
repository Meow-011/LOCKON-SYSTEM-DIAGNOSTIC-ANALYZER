
function Invoke-LockonFileForensicsChecks {
    param (
        [Object]$Config
    )
    $ModuleResults = @{}

    # ============================================================
    # --- 15. File Hash Analysis (Malware Scan) ---
    # ============================================================
    $HashCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "15") {
        Write-SectionHeader "File Hash Analysis (Threat Detection)"
        $HashCheck = @{ Status = "PASS"; Message = ""; Data = @() }
        
        # Load threat DB from Centralized Config
        $ThreatDbPath = $Config.ResolvedPaths.ThreatDB
        
        if (-not $ThreatDbPath) {
             # Fallback
             $ThreatDbPath = Join-Path $PSScriptRoot "threat_db.txt"
             if(-not (Test-Path $ThreatDbPath)) { $ThreatDbPath = Join-Path (Split-Path $PSScriptRoot -Parent) "threat_db.txt" }
        }

        if (Test-Path $ThreatDbPath) {
            $ThreatDB = Get-Content $ThreatDbPath | ConvertFrom-Csv
            
            # Scan critical directories (System32, Startup) - Limit depth for speed
            # Scan only running processes + Startup folder for speed
            $ScanFiles = @()
            
            # 1. Running Processes
            $Procs = Get-Process | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue | Select-Object -Unique
            $ScanFiles += $Procs
            
            # 2. Startup Folder
            $StartupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
            if (Test-Path $StartupPath) {
                $StartupFiles = Get-ChildItem $StartupPath -File | Select-Object -ExpandProperty FullName
                $ScanFiles += $StartupFiles
            }
            
            $FoundThreats = @()
            
            foreach ($File in $ScanFiles) {
                if ($File -and (Test-Path $File)) {
                    try {
                        $Hash = Get-FileHash -Path $File -Algorithm SHA256 -ErrorAction SilentlyContinue
                        $Match = $ThreatDB | Where-Object { $_.SHA256 -eq $Hash.Hash }
                        
                        if ($Match) {
                            $FoundThreats += @{
                                File = $File
                                Hash = $Hash.Hash
                                ThreatName = $Match.ThreatName
                                Severity = $Match.Severity
                            }
                            Write-HostFail "  [!] THREAT DETECTED: $($Match.ThreatName) in $File"
                        }
                    } catch {}
                }
            }
            
            if ($FoundThreats.Count -gt 0) {
                $HashCheck.Status = "FAIL"
                $HashCheck.Message = "Detected $($FoundThreats.Count) active threats matching signature database!"
                $HashCheck.Data = $FoundThreats
            } else {
                $HashCheck.Message = "No active threats found in running processes/startup."
                Write-HostPass "  [+] No known threats hash matched."
            }
        } else {
            $HashCheck.Message = "Threat DB (threat_db.txt) not found."
            Write-HostInfo "  [i] Threat DB not found. Skipping hash check."
        }
    }
    $ModuleResults.HashAnalysis = $HashCheck


    # ============================================================
    # --- 16. Drift Detection (Moved to DriftCheck.ps1) ---
    # ============================================================
    $ModuleResults.DriftAnalysis = @{ Status = "INFO"; Message = "Moved to specialized module."; Data = @{} }


    # ============================================================
    # --- 23. Execution Artifacts (BAM / ShimCache / RecentApps) ---
    # ============================================================
    $ActivityCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "23") {
        Write-SectionHeader "Execution Artifacts (BAM / ShimCache / RecentApps)"
        $ActivityCheck = @{ Status = "INFO"; Message = ""; Data = @() }

    try {
        $ExecutionEvidence = @()

        # 1. BAM / DAM (Background Activity Moderator) - High Fidelity Execution
        # HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
        $BamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        if (Test-Path $BamPath) {
            $Sids = Get-ChildItem $BamPath
            foreach ($SidKey in $Sids) {
                # Get User Name from SID if possible
                $User = $SidKey.PSChildName
                try {
                    $ObjSID = New-Object System.Security.Principal.SecurityIdentifier($User)
                    $ObjUser = $ObjSID.Translate([System.Security.Principal.NTAccount])
                    $User = $ObjUser.Value
                } catch {}

                $Values = Get-ItemProperty $SidKey.PSPath
                foreach ($Prop in $Values.PSObject.Properties) {
                    if ($Prop.Name -ne "PSPath" -and $Prop.Name -ne "PSParentPath" -and $Prop.Name -ne "PSChildName" -and $Prop.Name -ne "PSProvider" -and $Prop.Name -ne "PSDrive" -and $Prop.Name -ne "SequenceNumber" -and $Prop.Name -ne "Version") {
                         # BAM timestamp is in the binary blob (Last 8 bytes usually 64bit filetime? or just modify time of key?)
                         # Actually BAM values are binary. The timestamp is embedded.
                         # For simplicity without binary parsing class: We just list the PATH as "Executed".
                         $ExecutionEvidence += @{ Source="BAM"; User=$User; Path=$Prop.Name; Time="Unknown (Binary)" }
                    }
                }
            }
        }

        # 2. RecentApps (Windows 10+)
        # HKCU\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps
        $RecentAppsKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
        if (Test-Path $RecentAppsKey) {
            $Apps = Get-ChildItem $RecentAppsKey
            foreach ($App in $Apps) {
                $Props = Get-ItemProperty $App.PSPath
                if ($Props.AppId) {
                    $ExecutionEvidence += @{ Source="RecentApps"; User=$env:USERNAME; Path=$Props.AppId; Time=$Props.LastAccessedTime }
                }
            }
        }

        # 3. Simple ShimCache (AppCompatCache) - String Extraction only
        # HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
        $ShimKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        if (Test-Path $ShimKey) {
            try {
                $ShimData = (Get-ItemProperty $ShimKey).AppCompatCache
                if ($ShimData) {
                    # Convert binary to simple ascii strings and look for .exe paths (Quick & Dirty)
                    # Note: ShimCache is unicode.
                    $StringData = [System.Text.Encoding]::Unicode.GetString($ShimData)
                    # Regex for full paths (e.g. C:\... .exe)
                    $Matches = [regex]::Matches($StringData, '[a-zA-Z]:\\[a-zA-Z0-9_\\\.\-\s]+\.exe')
                    foreach ($m in $Matches) {
                         # Deduplicate later
                         $ExecutionEvidence += @{ Source="ShimCache"; User="System"; Path=$m.Value; Time="N/A" }
                    }
                }
            } catch {}
        }
        
        # 4. Old School Recent Docs (Keep existing logic slightly)
        $RecentFolder = "$env:APPDATA\Microsoft\Windows\Recent"
        if (Test-Path $RecentFolder) {
            $Files = Get-ChildItem -Path $RecentFolder -Filter "*.lnk" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 15
            foreach ($File in $Files) {
                $ExecutionEvidence += @{ Source="RecentDocs"; User=$env:USERNAME; Path=$File.Name; Time=$File.LastWriteTime }
            }
        }

        # Deduplicate and sort
        $UniqueEvidence = $ExecutionEvidence | Sort-Object Path -Unique
        
        # Filtering & Prioritization Logic
        $ProcessedEvidence = @()
        $SuspiciousKeywords = "mimikatz|psexec|powershell|cmd\.exe|net\.exe|whoami|nmap|wireshark|metasploit|c2|beacon|cobalt"
        $OfficeExtensions = "\.(docx|xlsx|pptx|pdf|txt|rtf)$"
        $NoiseFilter = "svchost\.exe|RuntimeBroker\.exe|backgroundTaskHost\.exe|SearchProtocolHost\.exe|System32\\(?!cmd\.exe|powershell\.exe|net\.exe)|Program Files"

        foreach ($Item in $UniqueEvidence) {
            $Path = $Item.Path
            $Type = "Normal"
            
            # 1. Filter Noise
            if ($Path -match $NoiseFilter) { continue }
            
            # 2. Identify Type
            if ($Path -match $SuspiciousKeywords -or $Path -match "Temp|Downloads") {
                $Type = "Suspicious"
            } elseif ($Path -match $OfficeExtensions) {
                $Type = "Document"
            }
            
            # Add Type to Item
            $Item | Add-Member -MemberType NoteProperty -Name "ActivityType" -Value $Type -Force
            $ProcessedEvidence += $Item
        }

        # Sort: Suspicious first, then Documents, then Normal. Then by Time.
        # Custom sort weight: Suspicious=0, Document=1, Normal=2
        $FinalList = $ProcessedEvidence | Sort-Object @{Expression={
            switch ($_.ActivityType) { "Suspicious" {0} "Document" {1} "Normal" {2} }
        }}, Time -Descending | Select-Object -First 50

        if ($FinalList.Count -gt 0) {
            $ActivityCheck.Message = "Forensics found $($FinalList.Count) significant artifacts."
            $ActivityCheck.Data = $FinalList
            
            Write-HostInfo "  -> Processed $($FinalList.Count) artifacts (Filtered)."
            
            # Alert on Suspicious
            $SuspiciousFound = $FinalList | Where-Object { $_.ActivityType -eq "Suspicious" }
            if ($SuspiciousFound) {
                 $ActivityCheck.Status = "WARN" 
                 Write-HostWarn "  [!] Found Suspicious Executions:"
                 $SuspiciousFound | Select-Object -First 5 | ForEach-Object { Write-HostWarn "      - [$($_.Source)] $($_.Path)" }
            } else {
                 # Just Info if only Docs/Normal
                 $ActivityCheck.Message += " (No suspicious tools detected)."
            }
        } else {
            $ActivityCheck.Message = "No significant execution artifacts found (Clean or Filtered)."
            Write-HostInfo $ActivityCheck.Message
        }

    } catch {
        $ActivityCheck.Message = "Could not check Execution Artifacts: $($_.Exception.Message)"
    }
    }
    $ModuleResults.UserActivity = $ActivityCheck


    # ============================================================
    # --- 24. Downloads Folder Analyzer (Risky Files) ---
    # ============================================================
    $DownloadCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "24") {
        Write-SectionHeader "Downloads Folder Analysis"
        $DownloadCheck = @{ Status = "INFO"; Message = ""; Data = @() }
    
    $DownloadsPath = "$env:USERPROFILE\Downloads"
    if (Test-Path $DownloadsPath) {
        # Extensions to watch
        $RiskyExt = @(".exe", ".msi", ".bat", ".ps1", ".vbs", ".js", ".iso", ".zip", ".rar", ".7z")
        
        # Get last 20 files matching extensions
        $DownloadFiles = Get-ChildItem -Path $DownloadsPath -File | 
                         Where-Object { 
                            $Ext = $_.Extension.ToLower()
                            $RiskyExt -contains $Ext 
                         } | Sort-Object LastWriteTime -Descending | Select-Object -First 20
    
        if ($DownloadFiles) {
            $DLList = @()
            foreach ($f in $DownloadFiles) {
                $DLList += @{
                    Name = $f.Name
                    Size = "{0:N2} MB" -f ($f.Length / 1MB)
                    Time = $f.LastWriteTime
                    Extension = $f.Extension
                }
            }
            $DownloadCheck.Data = $DLList
            $DownloadCheck.Message = "Found $($DLList.Count) risky files in Downloads."
            
            # Check if any are very recent (< 24 hours) -> FAIL
            $RecentRisky = $DownloadFiles | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
            if ($RecentRisky) {
                $DownloadCheck.Status = "FAIL" # (v8.4) Escalated to FAIL for recent
                $DownloadCheck.Message += " (Recent uploads detected!)"
                Write-HostWarn "  [!] Found recent risky files in Downloads!"
            } else {
                $DownloadCheck.Status = "WARN" # (v8.4) Warn for historical findings (not INFO)
                Write-HostInfo "  [i] Found $($DLList.Count) historical risky files."
            }
            
        } else {
            $DownloadCheck.Message = "No risky file types found in Downloads."
            Write-HostPass "  [+] Clean Downloads folder (No risky types)."
        }
    } else {
        $DownloadCheck.Message = "Downloads folder not found."
    }
    }
    $ModuleResults.Downloads = $DownloadCheck


    # ============================================================
    # --- 30. Recycle Bin Scavenger ---
    # ============================================================
    $RecycleCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "30") {
        Write-SectionHeader "Recycle Bin Scavenger"
        $RecycleCheck = @{ Status = "INFO"; Message = ""; Data = @() }
    
    try {
        # This requires ComObject Shell.Application
        $Shell = New-Object -ComObject Shell.Application
        $Bin = $Shell.Namespace(0xA) # 0xA = Recycle Bin
        
        $Items = $Bin.Items()
        if ($Items.Count -gt 0) {
            $BinItems = @()
            $SuspiciousCount = 0
            $SensitiveCount = 0
            
            # Enhanced Detection
            foreach ($Item in $Items) {
                $Type = "Normal"
                $Name = $Item.Name
                
                # Check Suspicious (Executables/Scripts)
                if ($Name -match "\.(exe|msi|bat|cmd|ps1|vbs|js|jar|py|sh)$") {
                    $Type = "Suspicious"
                    $SuspiciousCount++
                }
                # Check Sensitive (Config/Keys)
                elseif ($Name -match "\.(kdbx|key|pem|crt|ovpn|conf|ini|password|txt|rdp)$") {
                    $Type = "Sensitive"
                    $SensitiveCount++
                }
                
                $BinItems += @{
                    Name = $Name
                    Path = $Item.Path
                    Size = $Item.Size
                    DeletedDate = $Item.ModifyDate # Approximate
                    Type = $Type
                }
            }
            
            # Sort by Date Descending
            $SortedItems = $BinItems | Sort-Object DeletedDate -Descending | Select-Object -First 50
            
            $RecycleCheck.Data = $SortedItems
            
            if ($SuspiciousCount -gt 0 -or $SensitiveCount -gt 0) {
                $RecycleCheck.Status = "WARN"
                $RecycleCheck.Message = "Found $SuspiciousCount suspicious and $SensitiveCount sensitive files in Recycle Bin."
                Write-HostWarn "  [!] Found Risky files in Recycle Bin (Suspicious: $SuspiciousCount, Sensitive: $SensitiveCount)"
            } else {
                $RecycleCheck.Message = "Recycle Bin contains $($Items.Count) general items. (Showing last 50)"
                Write-HostInfo "  [i] Recycle Bin has items (Clean)."
            }
            
            # Store Total Count for UI
            $RecycleCheck | Add-Member -MemberType NoteProperty -Name "TotalCount" -Value $Items.Count -Force
            
        } else {
            $RecycleCheck.Message = "Recycle Bin is empty."
            Write-HostPass "  [+] Recycle Bin is clean."
        }
    } catch {
        $RecycleCheck.Status = "FAIL"
        $RecycleCheck.Message = "Could not check Recycle Bin: $($_.Exception.Message)"
    }
    }
    $ModuleResults.RecycleBin = $RecycleCheck

    return $ModuleResults
}
