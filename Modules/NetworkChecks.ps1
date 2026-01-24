
function Invoke-LockonNetworkChecks {
    param (
        [Object]$Config
    )
    $ModuleResults = @{}

    # ============================================================
    # --- 2. Check Network Configuration (Active Physical Adapters) ---
    # ============================================================
    $NetworkCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "2") {
        Write-SectionHeader "Check Network Configuration (Active Physical Adapters)"
        $NetworkCheck = @{ Status = "INFO"; Message = "" }
        try {
            $Adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }
            if ($Adapters) {
                $NetInfo = @()
                foreach ($Adapter in $Adapters) {
                    $IPObj = Get-NetIPAddress -InterfaceAlias $Adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
                    $IP = if ($IPObj) { ($IPObj.IPAddress | ForEach-Object { $_ }) -join ", " } else { "No IPv4" }
                    
                    $NetInfo += @{
                        Name = $Adapter.Name
                        Description = $Adapter.InterfaceDescription
                        MacAddress = $Adapter.MacAddress
                        IPv4Address = $IP
                    }
                    Write-HostInfo "  - Found: $($Adapter.Name) ($IP)" # Aligned
                }
                $NetworkCheck.Status = "PASS"
                
                # Add Established External Connections (Forensics)
                # Filter out 127.0.0.1, 10.x, 192.168.x, 172.16-31.x
                $Established = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
                               Where-Object { 
                                   $_.RemoteAddress -notmatch "^127\." -and 
                                   $_.RemoteAddress -notmatch "^10\." -and 
                                   $_.RemoteAddress -notmatch "^192\.168\." -and 
                                   $_.RemoteAddress -notmatch "^172\.(1[6-9]|2[0-9]|3[0-1])\." -and
                                   $_.RemoteAddress -ne "::1"
                               }
                
                if ($Established) {
                    Write-HostInfo "  [!] Found $($Established.Count) external connections."
                    foreach ($conn in $Established) {
                        $NetInfo += @{
                            RemoteAddress = $conn.RemoteAddress
                            RemotePort = $conn.RemotePort
                            OwningProcess = $conn.OwningProcess
                            # HTML Report checks for 'RemoteAddress' property to distinguish from Adapters
                        }
                    }
                }

                $NetworkCheck.Message = "Found $($Adapters.Count) active adapters. External Conns: $($Established.Count)"
                $NetworkCheck.Data = $NetInfo
            } else {
                $NetworkCheck.Status = "WARN"
                $NetworkCheck.Message = "No active physical network adapters found."
                Write-HostWarn $NetworkCheck.Message # Aligned
            }
        } catch {
            $NetworkCheck.Status = "FAIL"
            $NetworkCheck.Message = "Could not retrieve Network Info via NetAdapter: $($_.Exception.Message)"
            Write-HostFail $NetworkCheck.Message # Aligned
        }
    }
    $ModuleResults.NetworkConfig = $NetworkCheck


    # ============================================================
    # --- 6 & 7. Check Listening Ports ---
    # ============================================================
    $ModuleResults.ListeningPortsTCP = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    $ModuleResults.ListeningPortsUDP = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    
    if (Should-RunCheck "6" -or Should-RunCheck "7") {
        Write-SectionHeader "Check Listening Ports"
        
    try {
        # Get port numbers from the config object
        $RiskyPortNumbers = $Config.RiskyPorts | ForEach-Object { $_.Port }
        Write-HostInfo "Policy: Checking for $($RiskyPortNumbers.Count) risky ports: $($RiskyPortNumbers -join ', ')" # Aligned
        
        # --- TCP Check ---
        $TcpCheck = @{ Status = "PASS"; Message = ""; Data = @() }
        if (Should-RunCheck "6") {
            Write-SectionHeader "Listening Ports (TCP)"
            
            $TcpPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique
            
            $RiskyTcp = @()
            foreach ($port in $TcpPorts) {
                if ($RiskyPortNumbers -contains $port) {
                    $Policy = $Config.RiskyPorts | Where-Object { $_.Port -eq $port }
                    $RiskyTcp += $Policy
                }
            }
            
            if ($RiskyTcp.Count -gt 0) {
                $TcpCheck.Status = "FAIL"
                $TcpCheck.Message = "Found $($RiskyTcp.Count) risky TCP ports: $($RiskyTcp.Port -join ', ')"
                Write-HostFail $TcpCheck.Message
                foreach ($p in $RiskyTcp) { Write-HostFail "  - [TCP] Port $($p.Port) ($($p.Service)): $($p.Risk)" }
            } else {
                $TcpCheck.Message = "No risky TCP ports found."
                Write-HostPass "  [+] No risky TCP ports found."
            }
            $TcpCheck.Data = @{ AllListening = $TcpPorts; FoundRisky = $RiskyTcp }
            $ModuleResults.ListeningPortsTCP = $TcpCheck
        }

        # --- UDP Check ---
        $UdpCheck = @{ Status = "PASS"; Message = ""; Data = @() }
        if (Should-RunCheck "7") {
            Write-SectionHeader "Listening Ports (UDP)"
            
            $UdpPorts = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique
            
            $RiskyUdp = @()
            foreach ($port in $UdpPorts) {
                if ($RiskyPortNumbers -contains $port) {
                    $Policy = $Config.RiskyPorts | Where-Object { $_.Port -eq $port }
                    $RiskyUdp += $Policy
                }
            }
            
            if ($RiskyUdp.Count -gt 0) {
                $UdpCheck.Status = "FAIL"
                $UdpCheck.Message = "Found $($RiskyUdp.Count) risky UDP ports: $($RiskyUdp.Port -join ', ')"
                Write-HostFail $UdpCheck.Message
                foreach ($p in $RiskyUdp) { Write-HostFail "  - [UDP] Port $($p.Port) ($($p.Service)): $($p.Risk)" }
            } else {
                $UdpCheck.Message = "No risky UDP ports found."
                Write-HostPass "  [+] No risky UDP ports found."
            }
            $UdpCheck.Data = @{ AllListening = $UdpPorts; FoundRisky = $RiskyUdp }
            $ModuleResults.ListeningPortsUDP = $UdpCheck
        }

    } catch {
        Write-HostFail "Could not check ports: $($_.Exception.Message)"
        if (Should-RunCheck "6") { $ModuleResults.ListeningPortsTCP.Status = "FAIL"; $ModuleResults.ListeningPortsTCP.Message = "Error checking TCP ports." }
        if (Should-RunCheck "7") { $ModuleResults.ListeningPortsUDP.Status = "FAIL"; $ModuleResults.ListeningPortsUDP.Message = "Error checking UDP ports." }
    }
    }


    # ============================================================
    # --- 8. Check Windows Firewall Status ---
    # ============================================================
    $FirewallCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "8") {
        Write-SectionHeader "Windows Firewall Status"
        $FirewallCheck = @{ Status = "PASS"; Message = "" }
        try {
            # Check all profiles (Domain, Private, Public)
            $Profiles = Get-NetFirewallProfile
            $Disabled = $Profiles | Where-Object { $_.Enabled -eq $False }
            
            if ($Disabled) {
                $FirewallCheck.Status = "FAIL"
                $FirewallCheck.Message = "Firewall is DISABLED on profiles: $($Disabled.Name -join ', ')"
                Write-HostFail $FirewallCheck.Message # Aligned
            } else {
                $FirewallCheck.Status = "PASS"
                $FirewallCheck.Message = "Firewall is ENABLED on all profiles."
                Write-HostPass $FirewallCheck.Message # Aligned
            }
            $FirewallCheck.Data = $Profiles | Select-Object Name, Enabled
        } catch {
            $FirewallCheck.Status = "FAIL"
            $FirewallCheck.Message = "Could not check Firewall: $($_.Exception.Message)"
            Write-HostFail $FirewallCheck.Message # Aligned
        }
    }
    $ModuleResults.Firewall = $FirewallCheck


    # ============================================================
    # --- 12. Check Open File Shares ---
    # ============================================================
    $ShareCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "12") {
        Write-SectionHeader "Check Open File Shares"
        $ShareCheck = @{ Status = "PASS"; Message = ""; Data = @() }
        
        try {
            # Get only custom shares (Type 0 implies disk drive share, exclusions for IPC$, C$, ADMIN$, print$)
            # Refined filtering
            $Shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -notin @("IPC$", "ADMIN$", "C$", "D$", "E$") -and $_.Name -notmatch "print\$" 
            }
            
            if ($Shares) {
                $ShareCheck.Status = "WARN" # Warn user to review
                $ShareCheck.Message = "Found $($Shares.Count) active file shares."
                $DetailShares = @()
                
                foreach ($Share in $Shares) {
                     # Get Access Control List
                     $Acl = Get-SmbShareAccess -Name $Share.Name -ErrorAction SilentlyContinue
                     $DetailShares += @{
                         Name = $Share.Name
                         Path = $Share.Path
                         Description = $Share.Description
                         Access = $Acl | Select-Object AccountName, AccessRight
                     }
                     Write-HostWarn "  - [SHARE] $($Share.Name) -> $($Share.Path)"
                }
                $ShareCheck.Data = $DetailShares
            } else {
                $ShareCheck.Message = "No custom file shares active."
                Write-HostPass "  [+] No risky open shares found."
            }
        } catch {
            $ShareCheck.Status = "FAIL"
            $ShareCheck.Message = "Could not check SMB Shares: $($_.Exception.Message)"
             Write-HostFail $ShareCheck.Message
        }
    }
    $ModuleResults.FileShares = $ShareCheck


    # ============================================================
    # --- 19. Hosts File Analysis ---
    # ============================================================
    $HostsCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "19") {
        Write-SectionHeader "Hosts File Analysis"
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
    }
    $ModuleResults.HostsFile = $HostsCheck


    # ============================================================
    # --- 20. DNS Cache Forensics ---
    # ============================================================
    $DnsCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "20") {
        Write-SectionHeader "DNS Cache Forensics"
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
    }
    $ModuleResults.DnsCache = $DnsCheck


    # ============================================================
    # --- 25. RDP Hunter (Remote Desktop Forensics) ---
    # ============================================================
    $RdpCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "25") {
        Write-SectionHeader "RDP Hunter (Remote Logs)"
        $RdpCheck = @{ Status = "INFO"; Message = ""; Data = @() }
    
    try {
        $RdpList = @()

        # 1. TerminalServices-LocalSessionManager (Session Events)
        # Event ID 21 = Session Logon, 25 = Reconnect
        $RdpEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -FilterXPath "*[System[(EventID=21 or EventID=25)]]" -ErrorAction SilentlyContinue | 
                     Select-Object -First 50
    
        if ($RdpEvents) {
            foreach ($Ev in $RdpEvents) {
                $Xml = [xml]$Ev.ToXml()
                $User = $Xml.Event.UserData.EventXML.User
                $SourceIP = $Xml.Event.UserData.EventXML.Address
                
                $RdpList += @{
                    Time = $Ev.TimeCreated
                    Action = if ($Ev.Id -eq 21) { "Session Logon" } else { "Session Reconnect" }
                    User = $User
                    Source = $SourceIP
                    LogSource = "SessionManager"
                }
            }
        }

        # 2. Security Log (Event 4624 Type 10 - RDP)
        # Added Security Log Query for redundancy
        $SecEvents = Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']]" -ErrorAction SilentlyContinue | 
                     Select-Object -First 50
        
        if ($SecEvents) {
            foreach ($Ev in $SecEvents) {
                $Xml = [xml]$Ev.ToXml()
                $User = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty "#text"
                $SourceIP = $Xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"} | Select-Object -ExpandProperty "#text"

                $RdpList += @{
                    Time = $Ev.TimeCreated
                    Action = "Network Logon"
                    User = $User
                    Source = $SourceIP
                    LogSource = "SecurityLog"
                }
            }
        }

        # Deduplicate and Sort
        if ($RdpList.Count -gt 0) {
            $RdpList = $RdpList | Sort-Object Time -Descending | Select-Object -First 50
            $RdpCheck.Data = $RdpList
            
            # Check for External IPs
            # Filter out Local IPs (192.168, 10., 172.16-31, 127., ::1, fe80)
            $ExternalRdp = $RdpList | Where-Object { 
                $_.Source -and $_.Source -notmatch "^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|::1|fe80:|LOCAL|-)" 
            }
    
            if ($ExternalRdp) {
                 # CRITICAL: External RDP is high risk
                 $RdpCheck.Status = "WARN"
                 $RdpCheck.Message = "Detected $($ExternalRdp.Count) EXTERNAL RDP Connections!"
                 Write-HostWarn "  [!] WARNING: External IP Remote Desktop detected! ($($ExternalRdp[0].Source))"
            } else {
                 $RdpCheck.Message = "Found $($RdpList.Count) local RDP connections."
                 Write-HostInfo "  [i] Found historical RDP logs (Local Network)."
            }
        } else {
            $RdpCheck.Message = "No RDP connection logs found (Service disabled or clean)."
            Write-HostPass "  [+] No RDP logs found."
        }

    } catch {
        $RdpCheck.Message = "Could not query RDP Logs: $($_.Exception.Message)"
    }
    }
    $ModuleResults.RdpHunter = $RdpCheck


    # ============================================================
    # --- 28. DNS Cache Analyzer (Risky Domains) ---
    # ============================================================
    $DnsAnalyzerCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }
    if (Should-RunCheck "28") {
        Write-SectionHeader "DNS Cache Analyzer (High Entropy / Known Bad)"
        $DnsAnalyzerCheck = @{ Status = "INFO"; Message = ""; Data = @() }
    
    try {
        # Re-using Get-DnsClientCache logic if not already done, but usually this checks specific bad domains
        # For simplicity, we scan the cache again for suspicious patterns
        $DnsCache = Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique
        
        $SuspiciousDns = @()
        # (v8.5) Trusted Domains Whitelist (Skip these)
        $WhitelistRegex = "(microsoft|windows|azure|office|google|gstatic|youtube|amazonaws|cloudfront|akamai|edge|live|bing|skype|ntp\.org|adobe|symantec|mcafee|digicert)"

        foreach ($d in $DnsCache) {
            # 1. Skip Whitelisted
            if ($d -match $WhitelistRegex) { continue }

            $Type = $null
            
            # 2. Check Crypto Mining (Specific Pools)
            if ($d -match "nanopool|ethermine|minergate|nicehash|coinhive|monero|xmrig|stratum|tcp:\/\/") {
                $Type = "Crypto Mining"
            }
            # 3. Check Risky TLDs & C2 Keywords
            elseif ($d -match "\.(xyz|top|pw|ru|cn|cc|tk)$" -or $d -match "c2|beacon|payload|shell|ngrok|portmap") {
                $Type = "Suspicious/Risky TLD"
            }
            # 4. Check Valid DGA (High Entropy / Length > 35)
            elseif ($d.Length -gt 35 -and $d -notmatch "\.") {
                 # Simple length check for now, excluding dots to avoid FQDN subdomains
                 $Type = "High Entropy (Potential DGA)"
            }

            if ($Type) {
                $SuspiciousDns += @{ Domain=$d; Type=$Type }
            }
        }
        
        if ($SuspiciousDns.Count -gt 0) {
            $DnsAnalyzerCheck.Status = "WARN"
            $DnsAnalyzerCheck.Message = "Found $($SuspiciousDns.Count) suspicious DNS entries."
            $DnsAnalyzerCheck.Data = $SuspiciousDns
            Write-HostWarn "  [!] Found suspicious DNS resolutions!"
        } else {
            $DnsAnalyzerCheck.Status = "PASS"
            $DnsAnalyzerCheck.Message = "No suspicious DNS patterns detected."
            Write-HostPass "  [+] Clean DNS analysis."
        }
    } catch {
        $DnsAnalyzerCheck.Message = "Could not analyze DNS Cache: $($_.Exception.Message)"
    }
    }
    $ModuleResults.DnsAnalyzer = $DnsAnalyzerCheck




    return $ModuleResults
}
