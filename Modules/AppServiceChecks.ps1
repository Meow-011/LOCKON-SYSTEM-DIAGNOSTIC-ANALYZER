
function Invoke-LockonAppServiceChecks {
    param (
        [Object]$Config
    )
    $ModuleResults = @{}

    # ============================================================
    # --- 4. Check Antivirus/EDR Status ---
    # ============================================================
    $AvCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "4") {
        Write-SectionHeader "Check Antivirus/EDR Status"
        $AvCheck = @{ Status = "INFO"; Message = "" }
        try {
            # 1. Get AV Product from SecurityCenter2
            $AvList = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
            
            # Handle multiple AVs
            $AvDetails = @()
            $AnyActive = $false
            
            foreach ($av in $AvList) {
                # Hex state parsing
                $StateHex = "0x" + "{0:X}" -f $av.productState
                # Simple bitwise approximation for "On Access Scanning" (0x1000)
                $IsActive = ($av.productState -band 0x1000) -ne 0
                
                $StatusStr = if ($IsActive) { "Running" } else { "Snoozed/Disabled" }
                
                # Resolve Description from Config
                $Desc = "Unknown State"
                if ($Config.AntivirusStateTranslations) {
                    $Trans = $Config.AntivirusStateTranslations | Where-Object { $_.Code -eq $av.productState }
                    if ($Trans) { $Desc = $Trans.Description }
                }

                $AvDetails += @{
                    Name = $av.displayName
                    Status = $StatusStr
                    State = $StateHex # HTML wrapper expects 'State'
                    Description = $Desc
                    Path = $av.pathToSignedProductExe
                    Type = "Antivirus (WMI)"
                }
                
                if ($IsActive) { $AnyActive = $true }
            }

            # 2. EDR Service Hunter (Check for Enterprise Agents)
            $EdrServices = @(
                @{Name="CSAgent"; Display="CrowdStrike Falcon"},
                @{Name="SentinelAgent"; Display="SentinelOne"},
                @{Name="SentinelStaticEngine"; Display="SentinelOne Static Engine"},
                @{Name="CbDefense"; Display="Carbon Black Defense"},
                @{Name="CbDefenseWSC"; Display="Carbon Black WSC"},
                @{Name="CyveraService"; Display="Cortex XDR (Cyvera)"},
                @{Name="Traps"; Display="Palo Alto Traps"},
                @{Name="Tanium Client"; Display="Tanium Endpoint"},
                @{Name="ElasticEndpoint"; Display="Elastic Security"},
                @{Name="QualysAgent"; Display="Qualys Cloud Agent"},
                @{Name="xagt"; Display="FireEye HX"},
                @{Name="CylanceSvc"; Display="BlackBerry Cylance"}
            )

            foreach ($edr in $EdrServices) {
                if (Get-Service -Name $edr.Name -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq "Running"}) {
                    $AvDetails += @{
                        Name = $edr.Display
                        Status = "Running"
                        State = "Service Running"
                        Description = "Enterprise EDR Agent Detected"
                        Path = "Service: $($edr.Name)"
                        Type = "EDR / Next-Gen AV"
                    }
                    $AnyActive = $true
                }
            }

            if ($AnyActive) {
                # Check if it's just Defender or 3rd Party
                $Names = $AvDetails.Name -join ", "
                $AvCheck.Status = "PASS"
                $AvCheck.Message = "Active Protection found: $Names"
                Write-HostPass "Active Security Agent found: $Names"
            } else {
                $AvCheck.Status = "FAIL"
                $AvCheck.Message = "No active Antivirus or EDR found!"
                Write-HostFail "No active Antivirus/EDR found!" 
            }
            
            if ($AvDetails.Count -eq 0) {
                 $AvCheck.Status = "FAIL"
                 $AvCheck.Message = "No Security products registered or running."
            }
            
            $AvCheck.Data = $AvDetails
        } catch {
            $AvCheck.Status = "FAIL"
            $AvCheck.Message = "Could not check Antivirus: $($_.Exception.Message)"
            Write-HostFail $AvCheck.Message
        }
    }
    $ModuleResults.Antivirus = $AvCheck


    # ============================================================
    # --- 10. Review Automatic Services (Non-Standard) ---
    # ============================================================
    $ServiceCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "10") {
        Write-SectionHeader "Review Automatic Services (Non-Standard Paths)"
        $ServiceCheck = @{ Status = "PASS"; Message = ""; Data = @() }
        
        try {
            # Use CIM instead of WMI for Core compatibility
            $Services = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Running" }
            
            $SuspiciousServices = @()
            $MasqueradeNames = @("svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe")

            foreach ($svc in $Services) {
                $Path = $svc.PathName
                if ($Path) { 
                    # Clean quotes & env vars
                    if ($Path -match '^"([^"]+)"') { $Path = $matches[1] } else { $Path = $Path.Split(' ')[0] }
                    $Path = [Environment]::ExpandEnvironmentVariables($Path)
                } 
                
                $IsSuspicious = $false
                $Reason = ""
                $Signer = "Not Checked"

                # 1. Masquerading Check (Critically Important)
                $FileName = [System.IO.Path]::GetFileName($Path)
                if ($MasqueradeNames -contains $FileName) {
                    if ($Path -notmatch "System32" -and $Path -notmatch "SysWOW64") {
                        $IsSuspicious = $true
                        $Reason = "MASQUERADING (System Binary in User Path)"
                        $Signer = "Likely Malicious"
                    }
                }

                # 2. Non-Standard Path Check
                # Check if path is NOT in C:\Windows (Simple heuristic)
                if (-not $IsSuspicious) {
                     if ($Path -and $Path -notmatch "^C:\\Windows" -and $Path -notmatch "^C:\\Program Files") {
                         $IsSuspicious = $true
                         $Reason = "Non-Standard Path"
                         
                         # Verify Signature for user-space services
                         if (Test-Path $Path) {
                             $Sig = Get-AuthenticodeSignature $Path
                             $Signer = $Sig.SignerCertificate.Subject
                             if ($Sig.Status -eq "Valid" -and ($Signer -match "Google|Intel|NVIDIA|AMD|Adobe|Mozilla|Microsoft")) {
                                 # Whitelisted based on signature
                                 $IsSuspicious = $false 
                             } else {
                                 $Reason += " (Unsigned/Untrusted)"
                                 if ($Sig.Status -eq "Valid") { $Reason = "Non-Standard Path (Signed: $Signer)" }
                             }
                         } else {
                             $Reason += " (File Not Found)"
                         }
                     }
                }

                if ($IsSuspicious) {
                     $SuspiciousServices += @{
                         Name = $svc.Name
                         DisplayName = $svc.DisplayName
                         Path = $Path
                         Reason = $Reason
                         Signer = $Signer
                     }
                }
            }
            
            if ($SuspiciousServices.Count -gt 0) {
                 $ServiceCheck.Status = "WARN"
                 $ServiceCheck.Message = "Found $($SuspiciousServices.Count) non-standard/suspicious services."
                 $ServiceCheck.Data = $SuspiciousServices
                 Write-HostWarn "  [!] Review Services: Found potential risks (Masquerading or Unsigned)."
            } else {
                 $ServiceCheck.Message = "All automatic services appear standard (Windows/Program Files/Signed)."
                 Write-HostPass "  [+] Service configuration looks clean."
            }
        } catch {
            $ServiceCheck.Status = "FAIL"
            $ServiceCheck.Message = "Could not check Services: $($_.Exception.Message)"
            Write-HostFail $ServiceCheck.Message
        }
    }
    $ModuleResults.AutomaticServices = $ServiceCheck


    # ============================================================
    # --- 13. Startup Items Check ---
    # ============================================================
    $StartupCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "13") {
        Write-SectionHeader "Startup Items (Registry & Folder)"
        $StartupCheck = @{ Status = "PASS"; Message = ""; Data = @() }
        
        try {
            $StartupItems = Get-CimInstance Win32_StartupCommand | Sort-Object Command -Unique
            $RiskyStartup = @()
            
            # Startup Whitelist (Regex)
            $StartupWhitelist = @(
                "OneDrive\.exe", 
                "Microsoft Teams", 
                "com\.squirrel\.Teams\.Teams",
                "msedge\.exe",
                "SecurityHealthSystray\.exe",
                "RtkAudUService64\.exe", # Realtek
                "igfx.*\.exe" # Intel Graphics
            )

            # Masquerading Names (System Binaries that should NOT be in User folders)
            $MasqueradeNames = @("svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "services.exe", "winlogon.exe")

            foreach ($Item in $StartupItems) {
                $Issues = @()
                
                # --- 1. Robust Path Parsing ---
                $CleanPath = $Item.Command
                if ($CleanPath -match '^"([^"]+)"') {
                    $CleanPath = $matches[1]
                } else {
                    $CleanPath = $CleanPath.Split(' ')[0]
                }
                $CleanPath = [Environment]::ExpandEnvironmentVariables($CleanPath)
                $FileName = [System.IO.Path]::GetFileName($CleanPath)

                # --- 2. Check Risky Locations ---
                if ($Item.Command -match "AppData" -or $Item.Command -match "Temp" -or $Item.Command -match "Public") {
                     # Whitelist check
                     $IsWhitelisted = $false
                     foreach ($White in $StartupWhitelist) {
                         if ($Item.Command -match $White -or $Item.Name -match $White) { $IsWhitelisted = $true; break }
                     }
                     
                     if (-not $IsWhitelisted) {
                         $Issues += "Risky Path (AppData/Temp)"
                     }
                }
                
                # --- 3. Check Masquerading ---
                if ($MasqueradeNames -contains $FileName) {
                    # If it's a system name but NOT in System32...
                    if ($CleanPath -notmatch "System32" -and $CleanPath -notmatch "SysWOW64") {
                        $Issues += "MASQUERADING (Fake System File!)"
                    }
                }

                # --- 4. Check Digital Signature ---
                if (Test-Path $CleanPath) {
                    try {
                        $Sig = Get-AuthenticodeSignature $CleanPath -ErrorAction Stop
                        if ($Sig.Status -ne "Valid") {
                            $Issues += "Invalid Signature ($($Sig.Status))"
                        }
                    } catch {
                        $Issues += "Sig Check Error (Locked)"
                    }
                }

                # --- 5. Report if Issues Found ---
                if ($Issues.Count -gt 0) {
                    $RiskyStartup += @{
                        Name = $Item.Name
                        Command = $Item.Command
                        User = $Item.User
                        Location = $Item.Location
                        Issue = $Issues -join ", "
                    }
                }
            }
    
            if ($RiskyStartup.Count -gt 0) {
                # Escalation: If Masquerading found -> CRITICAL Warning (but report logic handles FAIL)
                $StartupCheck.Status = "FAIL"
                $StartupCheck.Message = "Found $($RiskyStartup.Count) suspicious startup items."
                $StartupCheck.Data = $RiskyStartup
                Write-HostFail "Suspicious startup items found!"
            } else {
                $StartupCheck.Message = "No suspicious startup items found."
                Write-HostPass "  [+] Startup items look clean."
            }
        } catch {
            $StartupCheck.Status = "FAIL"
            $StartupCheck.Message = "Could not check Startup items: $($_.Exception.Message)"
            Write-HostFail $StartupCheck.Message
        }
    }
    $ModuleResults.Startup = $StartupCheck


    # ============================================================
    # --- 14. Unwanted Software Check (Blacklist) ---
    # ============================================================
    $SoftwareCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "14") {
        Write-SectionHeader "Unwanted Software Check (Blacklist)"
        $SoftwareCheck = @{ Status = "PASS"; Message = ""; Data = @() }
    
    try {
        # Load blacklist from config
        $Blacklist = $Config.SoftwareBlacklist # Array of strings (Regex)
        $InstalledParams = @{ ClassName = "Win32_Product"; ErrorAction = "SilentlyContinue" }
        # Note: Win32_Product is slow. 
        # Optimization: Use Registry Uninstall keys instead of Win32_Product (Much Faster/Safer)
        
        $UninstallKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $InstalledApps = Get-ItemProperty $UninstallKeys -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher
        
        $FoundUnwanted = @()
        foreach ($App in $InstalledApps) {
            if ($App.DisplayName) {
                foreach ($Bad in $Blacklist) {
                    if ($App.DisplayName -match $Bad) {
                        $FoundUnwanted += @{
                            Name = $App.DisplayName
                            Version = $App.DisplayVersion
                            Policy = $Bad
                        }
                    }
                }
            }
        }
    
        if ($FoundUnwanted.Count -gt 0) {
            $SoftwareCheck.Status = "FAIL"
            $SoftwareCheck.Message = "Found $($FoundUnwanted.Count) blacklisted software packages."
            $SoftwareCheck.Data = $FoundUnwanted
            Write-HostFail "Unwanted software found: $($FoundUnwanted.Name -join ', ')"
        } else {
            $SoftwareCheck.Message = "No blacklisted software found."
             Write-HostPass "  [+] No blacklisted software installed."
        }
    } catch {
        $SoftwareCheck.Status = "FAIL"
        $SoftwareCheck.Message = "Could not check Installed Software: $($_.Exception.Message)"
         Write-HostFail $SoftwareCheck.Message
    }
    }
    $ModuleResults.UnwantedSoftware = $SoftwareCheck


    # ============================================================
    # --- 17. Browser Extensions Check ---
    # ============================================================
    $ExtensionCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "17") {
        Write-SectionHeader "Browser Extensions (Chrome/Edge)"
        $ExtensionCheck = @{ Status = "INFO"; Message = ""; Data = @() }

    # Helper to scan JSON preferences (Chrome/Edge)
    function Get-BrowserExtensions ($Path, $BrowserName) {
        $Results = @()
        if (Test-Path $Path) {
            try {
                $Content = Get-Content $Path -Raw | ConvertFrom-Json
                $Exts = $Content.extensions.settings
                if ($Exts) {
                    foreach ($Prop in $Exts.PSObject.Properties) {
                        # (v8.2) Deep Parse for Name/Version
                        $ExtData = $Prop.Value
                        $Name = "Unknown"
                        $Ver = "Unknown"
                        $Permissions = @()
                        $InstallType = "Normal"
                        
                        if ($ExtData.manifest) {
                            if ($ExtData.manifest.name) { $Name = $ExtData.manifest.name }
                            if ($ExtData.manifest.version) { $Ver = $ExtData.manifest.version }
                            if ($ExtData.manifest.permissions) { $Permissions = $ExtData.manifest.permissions }
                        }
                        
                        if ($ExtData.path) { $InstallType = "Unpacked/Dev" } # Extensions with direct paths are usually unpacked

                        # Risk Analysis
                        $Risk = "Low"
                        $RiskPoints = 0
                        
                        if ($Permissions -contains "<all_urls>" -or $Permissions -contains "http://*/*" -or $Permissions -contains "https://*/*") { $RiskPoints += 2 }
                        if ($Permissions -contains "webRequest" -or $Permissions -contains "webRequestBlocking") { $RiskPoints += 3 }
                        if ($Permissions -contains "proxy") { $RiskPoints += 2 }
                        if ($Permissions -contains "cookies") { $RiskPoints += 1 }
                        
                        if ($InstallType -eq "Unpacked/Dev") { $RiskPoints += 5 } # Unpacked is suspicious

                        if ($RiskPoints -ge 5) { $Risk = "High" }
                        elseif ($RiskPoints -ge 2) { $Risk = "Medium" }

                        $Results += @{
                            Browser = $BrowserName
                            Id = $Prop.Name
                            Name = $Name
                            Version = $Ver
                            Risk = $Risk
                            Permissions = ($Permissions -join ", ")
                            InstallType = $InstallType
                        }
                    }
                }
            } catch {}
        }
        return $Results
    }

    $FoundExtensions = @()
    # Chrome Path
    $ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Secure Preferences"
    # Edge Path
    $EdgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Secure Preferences"

    $FoundExtensions += Get-BrowserExtensions $ChromePath "Chrome"
    $FoundExtensions += Get-BrowserExtensions $EdgePath "Edge"

    if ($FoundExtensions.Count -gt 0) {
        $ExtensionCheck.Message = "Found $($FoundExtensions.Count) browser extensions installed."
        $ExtensionCheck.Data = $FoundExtensions
        Write-HostInfo "  [i] Found $($FoundExtensions.Count) extensions."
    } else {
        $ExtensionCheck.Message = "No browser extensions found (or unable to read Preferences)."
        Write-HostInfo "  [i] No extensions found."
    }
    }
    $ModuleResults.BrowserExtensions = $ExtensionCheck


    # ============================================================
    # --- 18. Scheduled Task Hunter (Persistence) ---
    # ============================================================
    $TaskCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "18") {
        Write-SectionHeader "Scheduled Task Hunter"
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
                
                # (v8.1) Improved Path Parsing: Handle quotes and arguments properly
                $CleanPath = $ExecPath
                if ($CleanPath -match '^"([^"]+)"') {
                    # Extract content inside first pair of quotes
                    $CleanPath = $matches[1]
                } else {
                    # No quotes? Split by space, but be careful.
                    # Simple heuristic: Take first token. 
                    $CleanPath = $CleanPath.Split(' ')[0]
                }
                
                # Expand Env Vars (e.g. %windir%)
                $CleanPath = [Environment]::ExpandEnvironmentVariables($CleanPath)

                $SigStatus = if (Test-Path $CleanPath) { (Get-AuthenticodeSignature $CleanPath).Status } else { "FileNotFound" }
    
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
    }
    $ModuleResults.ScheduledTasks = $TaskCheck


    # ============================================================
    # --- 31. Office Macro Security Check ---
    # ============================================================
    $OfficeCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "31") {
        Write-SectionHeader "Office Macro Security Check"
        $OfficeCheck = @{ Status = "PASS"; Message = ""; Data = @() }

    $OfficeResults = @()
    # Check Word, Excel, PowerPoint for Version 16.0 (Office 2016/2019/365)
    # HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Word\Security
    # VBAWarnings: 1 = Enable All (Bad), 2 = Disable w/ Notify (Good), 3 = Disable Digital Only, 4 = Disable All
    
    $OfficeApps = @("Word", "Excel", "PowerPoint")
    $BaseKey = "HKCU:\Software\Microsoft\Office\16.0"
    
    foreach ($App in $OfficeApps) {
        $Key = "$BaseKey\$App\Security"
        try {
            if (Test-Path $Key) {
                $VBA = (Get-ItemProperty -Path $Key -Name "VBAWarnings" -ErrorAction SilentlyContinue).VBAWarnings
                $Status = "Unknown"
                if ($VBA -eq 1) { $Status = "VULNERABLE (Macros Enabled!)" }
                elseif ($VBA -eq 2) { $Status = "SECURE (Disable with Notification)" }
                elseif ($VBA -eq 4) { $Status = "SECURE (Disable All)" }
                else { $Status = "Configuration Not Set/Default" }
                
                $OfficeResults += @{ Version = "16.0"; App = $App; Setting = "VBAWarnings=$VBA"; Status = $Status }
                if ($VBA -eq 1) { Write-HostFail "  [!] $App Macros are ENABLED!" }
            } else {
                $OfficeResults += @{ App = $App; Setting = "N/A"; Status = "Not Installed / Key Missing" }
            }
        } catch {}
    }
    
    $VulnApps = $OfficeResults | Where-Object { $_.Status -match "VULNERABLE" }
    
    if ($VulnApps) {
        $OfficeCheck.Status = "FAIL"
        $OfficeCheck.Message = "Office Macros are enabled for: $($VulnApps.App -join ', ')"
    } else {
        $OfficeCheck.Message = "Office Macro settings appear secure (or not configured significantly)."
        Write-HostPass "  [+] Office Macro settings are secure."
    }
    $OfficeCheck.Data = $OfficeResults
    }
    $ModuleResults.OfficeSecurity = $OfficeCheck


    # ============================================================
    # --- 32. Software Inventory (Installed Apps) ---
    # ============================================================
    $InvCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "32") {
        Write-SectionHeader "Full Software Inventory"
        $InvCheck = @{ Status = "INFO"; Message = ""; Data = @() }
        
        Write-HostInfo "  Gathering installed software list (Registry)..."
        try {
            # Use same logic as Sec 14 Unwanted Software (Registry)
            $UninstallKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            
            $Apps = Get-ItemProperty $UninstallKeys -ErrorAction SilentlyContinue | 
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Where-Object { $_.DisplayName -ne $null } |
            Sort-Object DisplayName
            
            # Map to Report schema (Name, Ver, Pub)
            $MappedApps = @()
            foreach ($a in $Apps) {
                $MappedApps += @{
                    Name = $a.DisplayName
                    Ver = $a.DisplayVersion
                    Pub = $a.Publisher
                }
            }

            $InvCheck.Message = "Inventory collected ($($MappedApps.Count) items)."
            $InvCheck.Data = $MappedApps
            
            Write-HostPass "  [+] Inventory complete. $($Apps.Count) applications listed."
            
        } catch {
            $InvCheck.Status = "FAIL"
            $InvCheck.Message = "Could not gather inventory: $($_.Exception.Message)"
            Write-HostFail $InvCheck.Message
        }
    }
    $ModuleResults.SoftwareInventory = $InvCheck

    return $ModuleResults
}
