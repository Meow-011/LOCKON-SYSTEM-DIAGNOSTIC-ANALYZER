
function Invoke-LockonUserLogChecks {
    param (
        [Object]$Config
    )
    $ModuleResults = @{}

    # ============================================================
    # --- 11. Check Local Administrators Group ---
    # ============================================================
    $AdminCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "11") {
        Write-SectionHeader "Check Local Administrators Group"
        $AdminCheck = @{ Status = "PASS"; Message = ""; Data = @() }
        
        try {
            $LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
            if (-not $LocalAdmins) {
                # Fallback for older PS versions or Domain joined restrictions
                $GroupObj = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
                $LocalAdmins = @($GroupObj.Members()) | ForEach-Object { 
                    $Path = $_.GetType().InvokeMember("ADsPath","GetProperty",$null,$_,$null)
                    $Name = $Path -replace "WinNT://", ""
                    [PSCustomObject]@{ Name = $Name; ObjectClass = "User" }
                }
            }
            
            $AdminNames = $LocalAdmins | Select-Object -ExpandProperty Name
            
            # Policy Check: Compare against allowed list from Config
            $AllowedAdmins = $Config.AllowedAdmins # Array of regex or exact names
            $UnexpectedAdmins = @()
            
            foreach ($admin in $AdminNames) {
                $IsAllowed = $false
                foreach ($pattern in $AllowedAdmins) {
                    if ($admin -match $pattern) { $IsAllowed = $true; break }
                }
                if (-not $IsAllowed) { $UnexpectedAdmins += $admin }
            }
            
            # Map for Report Data (Name, ObjectClass, PrincipalSource)
            $AdminDetails = @()
            foreach ($admin in $LocalAdmins) {
                # Handle ADSI Fallback objects vs Get-LocalGroupMember objects
                $Src = if ($admin.PrincipalSource) { $admin.PrincipalSource } else { "Local/Unknown" }
                $Class = if ($admin.ObjectClass) { $admin.ObjectClass } else { "User" }
                
                $AdminDetails += @{
                    Name = $admin.Name
                    ObjectClass = $Class
                    PrincipalSource = $Src
                }
            }
            
            if ($UnexpectedAdmins.Count -gt 0) {
                $AdminCheck.Status = "FAIL"
                $AdminCheck.Message = "Found unexpected Local Admins: $($UnexpectedAdmins -join ', ')"
                Write-HostFail "Unexpected Admins: $($UnexpectedAdmins -join ', ')"
            } else {
                $AdminCheck.Message = "Local Administrators group is compliant."
                Write-HostPass "Admins compliant: $($AdminNames -join ', ')"
            }
            
            $AdminCheck.Data = $AdminDetails
        } catch {
            $AdminCheck.Status = "FAIL"
            $AdminCheck.Message = "Could not check Local Admins: $($_.Exception.Message)"
            Write-HostFail $AdminCheck.Message
        }
    }
    $ModuleResults.LocalAdmins = $AdminCheck


    # ============================================================
    # --- 21. Security Event Log Analysis (Last 24h) ---
    # ============================================================
    $LogCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "21") {
        Write-SectionHeader "Security Event Log Analysis (24h)"
        $LogCheck = @{ Status = "PASS"; Message = ""; Data = @{ FailedLogins=@(); NewUsers=@(); LogClearing=$false; SuspiciousPowerShell=@(); NewServices=@() } }
    
    try {
        # 1. Failed Logins (Event ID 4625)
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
    
        # 4. Deep Blue: PowerShell Script Block Logging (4104) - Looking for Keywords
        # Keywords: EncodedCommand, Net.WebClient, DownloadString, Invoke-Expression
        $PsEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
        $SuspiciousPS = @()
        if ($PsEvents) {
            foreach ($E in $PsEvents) {
                if ($E.Message -match "EncodedCommand|Net\.WebClient|DownloadString|Invoke-Expression|Bypass") {
                     $SuspiciousPS += @{ Time=$E.TimeCreated; Message=$E.Message.Substring(0, [math]::Min(100, $E.Message.Length)) }
                }
            }
        }
        if ($SuspiciousPS) { $LogCheck.Data['SuspiciousPowerShell'] = $SuspiciousPS }
    
        # 5. Deep Blue: New Service Installed (7045)
        $SvcEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
        if ($SvcEvents) {
            $LogCheck.Data['NewServices'] = $SvcEvents | Select-Object TimeCreated, @{N='Details';E={$_.Message}}
        }
        
        # 6. Deep Blue: Process Creation (4688) - Only if Audit enabled
        # Look for cmd/powershell running from Temp/Downloads
        $ProcEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
        $SuspiciousProc = @()
        if ($ProcEvents) {
            foreach ($E in $ProcEvents) {
                 if ($E.Message -match "AppData\\Local\\Temp|Downloads" -and $E.Message -match "cmd\.exe|powershell\.exe") {
                     $SuspiciousProc += @{ Time=$E.TimeCreated; Message=$E.Message }
                 }
            }
        }
        if ($SuspiciousProc) { $LogCheck.Data['SuspiciousProcesses'] = $SuspiciousProc }
    
    
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
        } elseif ($LogCheck.Data.SuspiciousPowerShell.Count -gt 0) {
            $LogCheck.Status = "WARN"
            $LogCheck.Message = "Deep Blue Alert: Found $($LogCheck.Data.SuspiciousPowerShell.Count) Suspicious PowerShell commands (Encoded/Download)."
            Write-HostWarn $LogCheck.Message
        } elseif ($LogCheck.Data.NewServices.Count -gt 0) {
            $LogCheck.Status = "INFO"
            $LogCheck.Message = "Notice: $($LogCheck.Data.NewServices.Count) New Service(s) installed in last 24h."
            Write-HostInfo $LogCheck.Message
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
    }
    $ModuleResults.EventLogs = $LogCheck


    # ============================================================
    # --- 22. Web Browser History Spy (String Extraction) ---
    # ============================================================
    $HistoryCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "22") {
        Write-SectionHeader "Web Browser History Analysis (Forensics)"
        $HistoryCheck = @{ Status = "INFO"; Message = ""; Data = @() }
    
    # Define Paths
    $BrowserPaths = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
        "Edge"   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    }
    
    $FoundHistory = @()
    
    foreach ($BrowserName in $BrowserPaths.Keys) {
        $HistoryPath = $BrowserPaths[$BrowserName]
        if (Test-Path $HistoryPath) {
            Write-HostInfo "Found $BrowserName History DB. extracting..."
            
            # Copy to Temp to bypass file lock
            $TempPath = "$env:TEMP\LOCKON_$($BrowserName)_History"
            try {
                Copy-Item -Path $HistoryPath -Destination $TempPath -Force -ErrorAction SilentlyContinue
                
                # String Extraction (Quick & Dirty method for SQLite without DLLs)
                # Find strings that look like URLs (http/https)
                # Filter out common junk (fonts, css, js, local host, search params)
                # (v7.4) Optimization: Read only the last 10MB of the file (Tail Read)
                # This prevents hanging on huge history files (e.g. 500MB+)
                $MaxReadSize = 10 * 1024 * 1024
                $FileInfo = Get-Item $TempPath
                $Bytes = $null
    
                if ($FileInfo.Length -gt $MaxReadSize) {
                    # File is huge, read tail only
                    Write-HostInfo "    -> Optimization: Reading last 10MB of $($FileInfo.Length / 1MB) MB..."
                    $FileStream = [System.IO.File]::OpenRead($TempPath)
                    $FileStream.Seek(-$MaxReadSize, [System.IO.SeekOrigin]::End) | Out-Null
                    $Bytes = New-Object byte[] $MaxReadSize
                    $FileStream.Read($Bytes, 0, $MaxReadSize) | Out-Null
                    $FileStream.Close()
                    $RawData = $Bytes
                } else {
                    # File is small, read all
                    $RawData = Get-Content -Path $TempPath -Encoding Byte -ReadCount 0
                }
                
                $StringData = [System.Text.Encoding]::ASCII.GetString($RawData)
                
                # Regex for URL
                $Pattern = '(https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9\-\._~:/?#\[\]@!$&''()*+,;=]*)?)'
                $Matches = [regex]::Matches($StringData, $Pattern)
                
                # Process Matches (Get unique, filter noise)
                $Urls = $Matches | ForEach-Object { $_.Value } | 
                    Where-Object { 
                        $_ -notmatch ".css$|.js$|.png$|.jpg$|.woff$|.ico$" -and 
                        $_ -notmatch "google.com/search|bing.com/search|schema.org|w3.org|microsoft.com/pki" 
                    } | Select-Object -Unique | Select-Object -Last 20 # Get recent ones (History appends to end)
                
                if ($Urls) {
                    Write-HostPass "  -> Extracted $($Urls.Count) recent URLs from $BrowserName"
                    foreach ($Link in $Urls) {
                        $FoundHistory += @{ Browser = $BrowserName; Url = $Link }
                    }
                } else {
                     Write-HostInfo "  -> No readable URLs found (Encrypted or Empty)."
                }
                
                # Clean up
                Remove-Item -Path $TempPath -Force -ErrorAction SilentlyContinue
                
            } catch {
                Write-HostFail "  -> Failed to extract ${BrowserName}: $($_.Exception.Message)"
            }
        }
    }
    
    if ($FoundHistory.Count -gt 0) {
        $HistoryCheck.Status = "WARN" # Warn so user checks it
        $HistoryCheck.Message = "Found $($FoundHistory.Count) history entries. Review recommended."
        $HistoryCheck.Data = $FoundHistory
        
        # Show Top 5 in Console
        Write-HostWarn "  [!] Top 5 Recent URLs:"
        $FoundHistory | Select-Object -Last 5 | ForEach-Object { Write-HostWarn "      - [$($_.Browser)] $($_.Url)" }
    } else {
        $HistoryCheck.Message = "No browser history extracted."
        Write-HostInfo $HistoryCheck.Message
    }
    }
    $ModuleResults.History = $HistoryCheck


    # ============================================================
    # --- 27. Local Admin Hunter (Deep Enumeration) ---
    # ============================================================
    $AdminHunterCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "27") {
        Write-SectionHeader "Local Admin Hunter (Deep Analysis)"
        $AdminHunterCheck = @{ Status = "INFO"; Message = ""; Data = @() }
        
        # This checks for nested groups or potentially dangerous users that act as Admin
        # Current logic repeats some of Section 11 but is intended for more complex AD environments
        # Simplified for consistency with Section 11, focusing on "Shadow Admins" if possible
        # For now, we perform a redundancy check or check for specific 'Administrator' named accounts that might be renamed.
        
        try {
            # 1. Administrators
            $Admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
            # 2. Remote Desktop Users
            $RdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
            # 3. Remote Management Users
            $WinRMUsers = Get-LocalGroupMember -Group "Remote Management Users" -ErrorAction SilentlyContinue

            $ReportData = @()
            $SuspiciousFound = $false

            # Helper to process groups
            $ProcessGroup = {
                param($Group, $Name)
                if ($Group) {
                    foreach ($m in $Group) {
                         $IsSuspicious = $false
                         # If it's a known risky account or unexpected (Not Admin/DomainAdmin)
                         # Simple heuristic: If it's in RDP/WinRM and NOT an Admin/DomainAdmin -> Worth reviewing
                         if ($m.Name -match "Guest|Everyone|Anonymous" -or ($m.ObjectClass -eq "User" -and $m.Name -notmatch "Administrator|Domain Admins")) {
                             $IsSuspicious = $true
                         }
                         
                         $ReportData += @{
                             Group = $Name
                             User = $m.Name
                             Class = $m.ObjectClass
                             IsSuspicious = $IsSuspicious
                         }
                         if ($IsSuspicious) { $global:SuspiciousFound = $true }
                    }
                }
            }
            
            # Use closure or scope fix for variable update
            $SuspiciousFound = $false
            if ($Admins) { foreach ($m in $Admins) { 
                $IsSuspicious = ($m.Name -match "Guest|Everyone|Anonymous")
                $ReportData += @{ Group="Administrators"; User=$m.Name; Class=$m.ObjectClass; IsSuspicious=$IsSuspicious }
                if ($IsSuspicious) { $SuspiciousFound = $true }
            }}
            
            if ($RdpUsers) { foreach ($m in $RdpUsers) {
                # Review anyone in RDP group who isn't a known Admin
                $IsSuspicious = ($m.Name -notmatch "Administrator|Domain Admins")
                $ReportData += @{ Group="Remote Desktop Users"; User=$m.Name; Class=$m.ObjectClass; IsSuspicious=$IsSuspicious }
                if ($IsSuspicious) { $SuspiciousFound = $true }
            }}

            if ($WinRMUsers) { foreach ($m in $WinRMUsers) {
                $IsSuspicious = ($m.Name -notmatch "Administrator|Domain Admins")
                $ReportData += @{ Group="Remote Management Users"; User=$m.Name; Class=$m.ObjectClass; IsSuspicious=$IsSuspicious }
                if ($IsSuspicious) { $SuspiciousFound = $true }
            }}

            $AdminHunterCheck.Data = $ReportData
            
            if ($SuspiciousFound) {
                 $AdminHunterCheck.Status = "WARN"
                 $AdminHunterCheck.Message = "Found potential Shadow Admins or Remote Access Users."
                 Write-HostWarn "  [!] Review Local Groups: Anomalous users found in Privileged Groups!"
            } else {
                 $AdminHunterCheck.Status = "PASS"
                 $AdminHunterCheck.Message = "Privileged groups appear standard (Only known Admins found)."
                 Write-HostPass "  [+] Local Groups look clean."
            }
        } catch {
            $AdminHunterCheck.Status = "FAIL"
            $AdminHunterCheck.Message = "Could not enum local groups: $($_.Exception.Message)"
        }
    }
    $ModuleResults.LocalAdminsHunter = $AdminHunterCheck


    # ============================================================
    # --- 29. UserAssist Forensics (Execution History) ---
    # ============================================================
    $UserAssistCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "29") {
        Write-SectionHeader "UserAssist Forensics (GUI Executions)"
        $UserAssistCheck = @{ Status = "INFO"; Message = ""; Data = @() }
    
    try {
        # UserAssist Key (ROT13 encoded)
        $UAKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        
        if (Test-Path $UAKey) {
            $SubKeys = Get-ChildItem $UAKey
            $Entries = @()
            
            # Helper to ROT13 decode
            function From-Rot13 ($str) {
                # Simple ROT13 implementation
                $chars = $str.ToCharArray()
                for ($i = 0; $i -lt $chars.Count; $i++) {
                    $c = [int]$chars[$i]
                    if     ($c -ge 65 -and $c -le 77) { $c += 13 }
                    elseif ($c -ge 78 -and $c -le 90) { $c -= 13 }
                    elseif ($c -ge 97 -and $c -le 109) { $c += 13 }
                    elseif ($c -ge 110 -and $c -le 122) { $c -= 13 }
                    $chars[$i] = [char]$c
                }
                return -join $chars
            }
            
            foreach ($Sub in $SubKeys) {
                $CountKey = Join-Path $Sub.PSPath "Count"
                if (Test-Path $CountKey) {
                    $Props = Get-ItemProperty $CountKey
                    foreach ($p in $Props.PSObject.Properties) {
                        # Name is ROT13 encoded path (GUIDs are not)
                        if ($p.Name -ne "PSPath" -and $p.Name -ne "PSParentPath" -and $p.Name -ne "PSChildName" -and $p.Name -ne "PSProvider" -and $p.Name -ne "PSDrive") {
                            $Decoded = From-Rot13 $p.Name
                            
                            # Filter for interesting executables / shortcuts
                            if ($Decoded -match "\.exe$|\.lnk$") {
                                $Binary = $p.Value
                                $RunCount = 0
                                $LastRun = "Unknown"
                                $LastRunRaw = 0
                                
                                # Binary Parsing Logic
                                # Structure varies by Windows version, but usually:
                                # Offset 4 (4 bytes) = Run Count
                                # Offset 60 (8 bytes) = Last Execution Time (FILETIME)
                                try {
                                    if ($Binary -is [byte[]] -and $Binary.Length -ge 68) {
                                        $RunCount = [BitConverter]::ToInt32($Binary, 4)
                                        $LastRunRaw = [BitConverter]::ToInt64($Binary, 60)
                                        if ($LastRunRaw -gt 0) {
                                            $LastRun = [DateTime]::FromFileTime($LastRunRaw)
                                        }
                                    }
                                } catch {
                                    $RunCount = -1 # Parse Error
                                }

                                $Entries += @{
                                    Path = $Decoded
                                    RunCount = $RunCount
                                    LastRun = $LastRun
                                    LastRunRaw = $LastRunRaw
                                }
                            }
                        }
                    }
                }
            }
            
            if ($Entries.Count -gt 0) {
                # Sort by Last Running Time Descending
                $SortedEntries = $Entries | Sort-Object LastRunRaw -Descending | Select-Object -First 50
                
                $UserAssistCheck.Message = "Found $($Entries.Count) execution records in UserAssist."
                $UserAssistCheck.Data = $SortedEntries
                
                # Check for known bad tools
                $BadTools = $SortedEntries | Where-Object { $_.Path -match "mimikatz|psexec|nmap|wireshark|metasploit|cobalt" }
                if ($BadTools) {
                    $UserAssistCheck.Status = "WARN"
                    $Message = " (Suspicious tools executed: $($BadTools.Path -join ', '))"
                    # Truncate message if too long
                    if ($Message.Length -gt 100) { $Message = $Message.Substring(0, 97) + "..." }
                    $UserAssistCheck.Message += $Message
                    
                    Write-HostWarn "  [!] Evidence of hacking tools executed: $($BadTools.Path -join ', ')"
                } else {
                    $UserAssistCheck.Message += " (Showing last 50 executed items)"
                    Write-HostInfo "  [i] UserAssist history analyzed."
                }
            } else {
                $UserAssistCheck.Message = "No UserAssist records found (Clean or Disabled)."
            }
            
        } else {
             $UserAssistCheck.Message = "UserAssist registry key not found."
        }
    } catch {
        $UserAssistCheck.Message = "Could not check UserAssist: $($_.Exception.Message)"
    }
    }
    $ModuleResults.UserAssist = $UserAssistCheck

    return $ModuleResults
}
