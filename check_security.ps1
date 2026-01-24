<#
.SYNOPSIS
    (v6.4) HTML TEMPLATE REVERT: Changed the Generate-HtmlReport function
           back to the "simple list" style (one row per check) as
           requested by the user, who preferred the original "art".
           Detailed tables (like AV, Ports, Admins) are now
           embedded *inside* the "Message" cell of the simple list.
    (v6.3) ...
# .NOTES
#     Version: 7.2 (Added Unit Selection)
#>

param (
    [string]$Unit = "Unknown-Unit", # Audited Unit Name
    [string[]]$SelectedChecks = @("All") # List of check IDs to run (e.g. "1", "30", "All")
)

# --- Load Shared Library ---
$LibPath = Join-Path $PSScriptRoot "LOCKON_Lib.ps1"
if (Test-Path $LibPath) {
    . $LibPath
} else {
    Write-Host "[!] Critical Error: LOCKON_Lib.ps1 not found!" -ForegroundColor Red
    exit
}



# Helper Function: Check if a section should run
function Should-RunCheck ($CheckId) {
    if ($SelectedChecks -contains "All") { return $true }
    if ($SelectedChecks -contains $CheckId) { return $true }
    return $false
}

# --- 0. Script Setup & Config Loading ---
# This script is designed to be run as Admin (by the .bat launcher)
# It will only load config/defaults once.
Clear-Host
Write-SectionHeader "Initializing Script and Loading Configuration"

# --- Load Config via Library ---
$Config = Load-LockonConfig
if (-not $Config) {
    # If config loading fails, we must exit.
    exit
}

# Resolve Centralized Paths
# Use paths defined in defined in config.psd1 relative to PSScriptRoot
if ($Config.SystemPaths) {
    $KbListPath = Join-Path $PSScriptRoot $Config.SystemPaths.CriticalKBs
    $ThreatDbPath = Join-Path $PSScriptRoot $Config.SystemPaths.ThreatDB
    
    # Inject absolute paths back into Config for Modules to use easily
    $Config | Add-Member -MemberType NoteProperty -Name "ResolvedPaths" -Value @{
        CriticalKBs = $KbListPath
        ThreatDB = $ThreatDbPath
        Baseline = Join-Path $PSScriptRoot $Config.SystemPaths.Baseline
    } -Force
} else {
    # Fallback for old configs
    $KbListPath = Join-Path $PSScriptRoot "Database\critical_kbs.txt"
    $ThreatDbPath = Join-Path $PSScriptRoot "Database\threat_db.txt"
}

# Config is now loaded via Load-LockonConfig
# Legacy default config logic removed.

# --- Define Report Paths ---
$MachineName = $env:COMPUTERNAME
$DateStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportFileBase = "Report-$MachineName-$DateStamp"

# Create the directory structure
try {
    # Fix: Ensure parent directory exists first
    $ParentReportPath = Join-Path $PSScriptRoot $Config.MainReportFolder
    if (-not (Test-Path $ParentReportPath)) {
        New-Item -ItemType Directory -Path $ParentReportPath -Force | Out-Null
    }

    $ReportOutputDir = Join-Path $ParentReportPath $MachineName
    if (-not (Test-Path $ReportOutputDir)) {
        New-Item -ItemType Directory -Path $ReportOutputDir -Force | Out-Null
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
# Fix: Initialize as HashTable, convert to PSCustomObject at the end
$AuditResults = @{
    ReportInfo = @{
        MachineName = $MachineName
        User = $env:USERNAME
        Unit = $Unit # Store Unit Name
        Date = (Get-Date)
        ReportFileBase = $ReportFileBase
    }
    Policy = $Config # Store the policy used for this scan
}
# This is no longer used, Generate-HtmlReport builds the string directly.
# $HtmlReportBody = [System.Collections.ArrayList]@()


# --- Helper function Add-HtmlRow is no longer needed ---


Write-HostInfo "Starting scan on $MachineName..."
Write-HostInfo "HTML Report will be saved to: $HtmlReportPath"
Write-HostInfo "JSON Report will be saved to: $JsonReportPath"

# ============================================================
# --- Load and Execute Security Modules ---
# ============================================================

# Refactored: Modules are now loaded from external files for better maintainability.
$ModulesDir = Join-Path $PSScriptRoot "Modules"
$ModuleFiles = @(
    "SystemChecks.ps1",
    "NetworkChecks.ps1",
    "AppServiceChecks.ps1",
    "FileForensicsChecks.ps1",
    "UserLogChecks.ps1",
    "DriftCheck.ps1"
)

Write-HostInfo "Loading Security Modules..."

foreach ($ModName in $ModuleFiles) {
    $ModPath = Join-Path $ModulesDir $ModName
    if (Test-Path $ModPath) {
        try {
            . $ModPath
        } catch {
             Write-HostFail "CRITICAL ERROR: Failed to load module $ModName : $($_.Exception.Message)"
        }
    } else {
        Write-HostFail "CRITICAL ERROR: Module $ModName not found at $ModPath"
    }
}

# Define Execution Order and Invoke
# We maintain the sequential logic by calling them in order and merging results.

# 1. System Checks (Sec 1, 3, 5, 9, 26)
if (Get-Command "Invoke-LockonSystemChecks" -ErrorAction SilentlyContinue) {
    $Res = Invoke-LockonSystemChecks -Config $Config
    if ($Res) { foreach ($k in $Res.Keys) { $AuditResults[$k] = $Res[$k] } }
}

# 2. Network Checks (Sec 2, 6, 7, 8, 12, 19, 20, 25, 28)
if (Get-Command "Invoke-LockonNetworkChecks" -ErrorAction SilentlyContinue) {
    $Res = Invoke-LockonNetworkChecks -Config $Config
    if ($Res) { foreach ($k in $Res.Keys) { $AuditResults[$k] = $Res[$k] } }
}

# 3. App & Service Checks (Sec 4, 10, 13, 14, 17, 18, 31, 32)
if (Get-Command "Invoke-LockonAppServiceChecks" -ErrorAction SilentlyContinue) {
    $Res = Invoke-LockonAppServiceChecks -Config $Config
    if ($Res) { foreach ($k in $Res.Keys) { $AuditResults[$k] = $Res[$k] } }
}

# 4. File Forensics Checks (Sec 15, 16, 23, 24, 30)
if (Get-Command "Invoke-LockonFileForensicsChecks" -ErrorAction SilentlyContinue) {
    $Res = Invoke-LockonFileForensicsChecks -Config $Config
    if ($Res) { foreach ($k in $Res.Keys) { $AuditResults[$k] = $Res[$k] } }
}

# 5. User & Log Checks (Sec 11, 21, 22, 27, 29)
if (Get-Command "Invoke-LockonUserLogChecks" -ErrorAction SilentlyContinue) {
    $Res = Invoke-LockonUserLogChecks -Config $Config
    if ($Res) { foreach ($k in $Res.Keys) { $AuditResults[$k] = $Res[$k] } }
}

# 6. Drift Detection (Section 16 - Runs last to check all)
# Now runs as a dedicated final check using full AuditResults
if (Get-Command "Invoke-LockonDriftCheck" -ErrorAction SilentlyContinue) {
    $Res = Invoke-LockonDriftCheck -Config $Config -RunResults $AuditResults
    if ($Res) { foreach ($k in $Res.Keys) { $AuditResults[$k] = $Res[$k] } }
}

# ============================================================
Write-SectionHeader "Audit Complete. Generating Reports..."

# REVERTED HTML Report Function
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
        .status-warn { 
            background-color: #fef9c3; /* yellow-100 */ 
            color: #854d0e; /* yellow-800 */ 
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
    if ($Results.OsInfo -and $Results.OsInfo.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>1. OS Version</strong></td>"
    $HtmlBody += "<td class='status-info'>INFO</td>"
    $HtmlBody += "<td>$($Results.OsInfo.Message)</td></tr>"
    }

    # --- 2. Network Config ---
    if ($Results.NetworkConfig -and $Results.NetworkConfig.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>2. Network Configuration</strong></td>"
    $HtmlBody += "<td class='status-$($Results.NetworkConfig.Status.ToLower())'>$($Results.NetworkConfig.Status)</td>"
    # Embed details
    $Detail = $Results.NetworkConfig.Message
    if ($Results.NetworkConfig.Data) {
        $Detail += "<table class='sub-table'><tr><th>Name</th><th>MAC</th><th>IPv4</th></tr>"
        foreach ($Adapter in $Results.NetworkConfig.Data) {
            # Only show adapters here
            if ($Adapter.MacAddress) {
                $Detail += "<tr><td>$($Adapter.Name)</td><td>$($Adapter.MacAddress)</td><td>$($Adapter.IPv4Address)</td></tr>"
            }
        }
        $Detail += "</table>"

        # Show Established Connections
        $ExternalConns = $Results.NetworkConfig.Data | Where-Object { $_.RemoteAddress }
        if ($ExternalConns) {
            $Detail += "<div style='color:red; font-weight:bold; margin-top:5px'>[!] ESTABLISHED EXTERNAL CONNECTIONS:</div>"
            $Detail += "<details><summary style='cursor:pointer'>View Connections ($($ExternalConns.Count))</summary>"
            $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; margin-top:5px'>"
            $Detail += "<table class='sub-table' style='border:1px solid red'><tr><th>Remote IP</th><th>Port</th><th>Process</th></tr>"
            foreach ($c in $ExternalConns) {
                # Try resolve process name again if needed
                $ProcName = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                if (-not $ProcName) { $ProcName = "PID:$($c.OwningProcess)" }
                $Detail += "<tr><td>$($c.RemoteAddress)</td><td>$($c.RemotePort)</td><td>$ProcName</td></tr>"
            }
            $Detail += "</table></div></details>"
        }
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 3. OS Update ---
    if ($Results.OsUpdate -and $Results.OsUpdate.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>3. OS Update Status</strong></td>"
    $HtmlBody += "<td class='status-$($Results.OsUpdate.Status.ToLower())'>$($Results.OsUpdate.Status)</td>"
    # Embed details
    $UpdateDate = "N/A"
    if ($Results.OsUpdate.Data.LastUpdateDate) {
        try { $UpdateDate = (Get-Date $Results.OsUpdate.Data.LastUpdateDate).ToString("yyyy-MM-dd") } catch {}
    }
    $HtmlBody += "<td>$($Results.OsUpdate.Message) (Date: $UpdateDate)</td></tr>"
    }
    
    # --- 4. Antivirus ---
    if ($Results.Antivirus -and $Results.Antivirus.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>4. Antivirus (AV/EDR) Status</strong></td>"
    $HtmlBody += "<td class='status-$($Results.Antivirus.Status.ToLower())'>$($Results.Antivirus.Status)</td>"
    # Embed details
    $Detail = $Results.Antivirus.Message
    if ($Results.Antivirus.Data) {
        $Detail += "<table class='sub-table'><tr><th>Type</th><th>Status</th><th>Product</th><th>Description</th></tr>"
        foreach ($Av in $Results.Antivirus.Data) {
            $RowStyle = ""
            if ($Av.Type -match "EDR") { 
                $RowStyle = "background-color:#dcfce7; color:#166534; font-weight:bold" 
            }
            $Detail += "<tr style='$RowStyle'><td>$($Av.Type)</td><td class='status-$($Av.Status.ToLower())'>$($Av.Status)</td><td>$($Av.Name)</td><td>$($Av.Description)</td></tr>"
        }
        $Detail += "</table>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }
    
    # --- 5. Critical Patches ---
    if ($Results.CriticalPatches -and $Results.CriticalPatches.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>5. Critical Patches (KB)</strong></td>"
    $HtmlBody += "<td class='status-$($Results.CriticalPatches.Status.ToLower())'>$($Results.CriticalPatches.Status)</td>"
    # Embed details
    $Detail = $Results.CriticalPatches.Message
    if ($Results.CriticalPatches.Data.Found) {
        $Detail += "<br><strong>Found:</strong> $($Results.CriticalPatches.Data.Found -join ', ')"
    }
    if ($Results.CriticalPatches.Status -eq 'FAIL') {
         $Detail += "<br><strong>Missing (from list):</strong> $($Results.CriticalPatches.Data.Missing.Count) KBs"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 6. Listening Ports (TCP) ---
    if ($Results.ListeningPortsTCP -and $Results.ListeningPortsTCP.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>6. Listening Ports (TCP)</strong></td>"
    $HtmlBody += "<td class='status-$($Results.ListeningPortsTCP.Status.ToLower())'>$($Results.ListeningPortsTCP.Status)</td>"
    $Detail = $Results.ListeningPortsTCP.Message
    if ($Results.ListeningPortsTCP.Status -eq 'FAIL') {
        $Detail += "<details><summary style='cursor:pointer'>View Risky Ports ($($Results.ListeningPortsTCP.Data.FoundRisky.Count))</summary>"
        $Detail += "<table class='sub-table'><tr><th>Port</th><th>Service</th><th>Risk</th></tr>"
        foreach ($p in $Results.ListeningPortsTCP.Data.FoundRisky) {
            $Detail += "<tr><td>$($p.Port)</td><td>$($p.Service)</td><td>$($p.Risk)</td></tr>"
        }
        $Detail += "</table></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 7. Listening Ports (UDP) ---
    if ($Results.ListeningPortsUDP -and $Results.ListeningPortsUDP.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>7. Listening Ports (UDP)</strong></td>"
    $HtmlBody += "<td class='status-$($Results.ListeningPortsUDP.Status.ToLower())'>$($Results.ListeningPortsUDP.Status)</td>"
    $Detail = $Results.ListeningPortsUDP.Message
    if ($Results.ListeningPortsUDP.Status -eq 'FAIL') {
        $Detail += "<details><summary style='cursor:pointer'>View Risky Ports ($($Results.ListeningPortsUDP.Data.FoundRisky.Count))</summary>"
        $Detail += "<table class='sub-table'><tr><th>Port</th><th>Service</th><th>Risk</th></tr>"
        foreach ($p in $Results.ListeningPortsUDP.Data.FoundRisky) {
            $Detail += "<tr><td>$($p.Port)</td><td>$($p.Service)</td><td>$($p.Risk)</td></tr>"
        }
        $Detail += "</table></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 8. Firewall ---
    if ($Results.Firewall -and $Results.Firewall.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>8. Windows Firewall Status</strong></td>"
    $HtmlBody += "<td class='status-$($Results.Firewall.Status.ToLower())'>$($Results.Firewall.Status)</td>"
    # Embed details
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
    }
    
    # --- 9. UAC ---
    if ($Results.UAC -and $Results.UAC.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>9. User Account Control (UAC)</strong></td>"
    $HtmlBody += "<td class='status-$($Results.UAC.Status.ToLower())'>$($Results.UAC.Status)</td>"
    $HtmlBody += "<td>$($Results.UAC.Message) (Value: $($Results.UAC.Data.EnableLUA))</td></tr>"
    }

    # --- 10. Automatic Services ---
    if ($Results.AutomaticServices -and $Results.AutomaticServices.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>10. Review Automatic Services</strong></td>"
    $HtmlBody += "<td class='status-$($Results.AutomaticServices.Status.ToLower())'>$($Results.AutomaticServices.Status)</td>"
    # Embed details
    $Detail = $Results.AutomaticServices.Message
    if ($Results.AutomaticServices.Status -ne "PASS") {
        $Detail += "<br><small>Click to expand</small><details><summary>View Risk Services ($($Results.AutomaticServices.Data.Count))</summary>"
        $Detail += "<div style='overflow-x:auto'><table class='sub-table'><tr><th>Name</th><th>Path</th><th>Reason</th><th>Signer</th></tr>"
        foreach ($Svc in $Results.AutomaticServices.Data) {
            $RowStyle = "background-color:#fff7ed; color:#c2410c"
            if ($Svc.Reason -match "MASQUERADING") { $RowStyle = "background-color:#fee2e2; color:#991b1b; font-weight:bold" }
            
            $Detail += "<tr style='$RowStyle'><td>$($Svc.Name)</td><td>$($Svc.Path)</td><td>$($Svc.Reason)</td><td>$($Svc.Signer)</td></tr>"
        }
        $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }
    
    # --- 11. Local Admins ---
    if ($Results.LocalAdmins -and $Results.LocalAdmins.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>11. Local Administrators</strong></td>"
    $HtmlBody += "<td class='status-$($Results.LocalAdmins.Status.ToLower())'>$($Results.LocalAdmins.Status)</td>"
    # Embed details
    $Detail = $Results.LocalAdmins.Message
    $Detail += "<table class='sub-table'><tr><th>Name</th><th>Type</th><th>Source</th></tr>"
    foreach ($Admin in $Results.LocalAdmins.Data) {
        $Detail += "<tr><td>$($Admin.Name)</td><td>$($Admin.ObjectClass)</td><td>$($Admin.PrincipalSource)</td></tr>"
    }
    $Detail += "</table>"
    $HtmlBody += "<td>$Detail</td></tr>"
    }
    
    # --- 12. File Shares ---
    if ($Results.FileShares -and $Results.FileShares.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>12. Open File Shares</strong></td>"
    $HtmlBody += "<td class='status-$($Results.FileShares.Status.ToLower())'>$($Results.FileShares.Status)</td>"
    # Embed details
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
    }
    
    # --- 13. Startup Items ---
    if ($Results.Startup -and $Results.Startup.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>13. Startup Items (Risky Paths)</strong></td>"
    $HtmlBody += "<td class='status-$($Results.Startup.Status.ToLower())'>$($Results.Startup.Status)</td>"
    $Detail = $Results.Startup.Message
    if ($Results.Startup.Status -eq 'FAIL') {
        $Detail += "<details><summary style='cursor:pointer'>View Risky Items ($($Results.Startup.Data.Count))</summary>"
        $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; margin-top:5px'>"
        $Detail += "<table class='sub-table'><tr><th>Name</th><th>Command</th><th>Issue</th></tr>"
        foreach ($Item in $Results.Startup.Data) {
            $RowStyle = ""
            if ($Item.Issue -match "MASQUERADING") { 
                $RowStyle = "background-color:#fee2e2; color:#991b1b; font-weight:bold" 
            }
            $Detail += "<tr style='$RowStyle'><td>$($Item.Name)</td><td>$($Item.Command)</td><td>$($Item.Issue)</td></tr>"
        }
        $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 14. Unwanted Software ---
    if ($Results.UnwantedSoftware -and $Results.UnwantedSoftware.Message -ne "Skipped") {
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
    }

    # End Table

    # --- 15. File Hash Analysis ---
    if ($Results.HashAnalysis -and $Results.HashAnalysis.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>15. File Hash Analysis (SHA-256)</strong></td>"
    
    # Dynamic Status Class
    $HashStatusClass = "status-" + $Results.HashAnalysis.Status.ToLower()
    $HtmlBody += "<td class='$HashStatusClass'>$($Results.HashAnalysis.Status)</td>"
    
    $Detail = "$($Results.HashAnalysis.Message)<br>"

    # Alert for Threats
    if ($Results.HashAnalysis.Threats.Count -gt 0) {
        $Detail += "<div style='color:white; background-color:#ef4444; padding:10px; border-radius:5px; margin:5px 0; font-weight:bold;'>"
        $Detail += "[!] CRITICAL THREATS DETECTED: $($Results.HashAnalysis.Threats.Count)</div>"
        $Detail += "<table class='sub-table' style='border:2px solid red'><tr><th>Threat File</th><th>Path</th><th>Malicious Hash</th></tr>"
        foreach ($t in $Results.HashAnalysis.Threats) {
             $Detail += "<tr style='background-color:#fee2e2'><td>$($t.FileName)</td><td>$($t.Path)</td><td style='font-family:monospace'>$($t.Hash)</td></tr>"
        }
        $Detail += "</table><br>"
    }

    if ($Results.HashAnalysis.Data) {
        $Detail += "<details><summary>View All Hashes ($($Results.HashAnalysis.Data.Count))</summary>"
        $Detail += "<table class='sub-table'><tr><th>File Name</th><th>Path</th><th>SHA-256 Hash</th></tr>"
        foreach ($HashItem in $Results.HashAnalysis.Data) {
            # Truncate hash for display (first 8 chars)
            $ShortHash = if ($HashItem.Hash.Length -gt 8) { $HashItem.Hash.Substring(0, 8) + "..." } else { $HashItem.Hash }
            $Detail += "<tr><td>$($HashItem.FileName)</td><td style='font-size:0.75rem'>$($HashItem.Path)</td>"
            $Detail += "<td><span class='hash-preview'>$ShortHash</span><button class='copy-btn' onclick=`"copyToClipboard('$($HashItem.Hash)')`">Copy</button></td></tr>"
        }
        $Detail += "</table></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 16. Drift Detection ---
    if ($Results.DriftAnalysis -and $Results.DriftAnalysis.Message -ne "Skipped") {
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
    }



    # --- 17. Browser Extensions ---
    if ($Results.BrowserExtensions -and $Results.BrowserExtensions.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>17. Browser Extensions</strong></td>"
    $HtmlBody += "<td class='status-info'>INFO</td>"
    $Detail = "$($Results.BrowserExtensions.Message)<br>"
    if ($Results.BrowserExtensions.Data.Count -gt 0) {
        $Detail += "<details><summary>View Extensions ($($Results.BrowserExtensions.Data.Count))</summary>"
        $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; margin-top:5px'>"
        $Detail += "<table class='sub-table'><tr><th>Browser</th><th>Name</th><th>Ver</th><th>Risk</th><th>Permissions</th></tr>"
        foreach ($Ext in $Results.BrowserExtensions.Data) {
             $RowStyle = ""
             $RiskDisplay = $Ext.Risk
             if ($Ext.Risk -eq "High") { 
                 $RowStyle = "background-color:#fee2e2; color:#991b1b; font-weight:bold"
                 $RiskDisplay = "[!] HIGH" 
             } elseif ($Ext.Risk -eq "Medium") {
                 $RowStyle = "background-color:#fff7ed; color:#c2410c"
             }
             $Detail += "<tr style='$RowStyle'><td>$($Ext.Browser)</td><td>$($Ext.Name)</td><td>$($Ext.Version)</td><td>$RiskDisplay</td><td style='font-size:0.8em'>$($Ext.Permissions)</td></tr>"
        }
        $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 18. Scheduled Task Hunter ---
    if ($Results.ScheduledTasks -and $Results.ScheduledTasks.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>18. Scheduled Task Hunter</strong></td>"
    $HtmlBody += "<td class='status-$($Results.ScheduledTasks.Status.ToLower())'>$($Results.ScheduledTasks.Status)</td>"
    
    $Detail = $Results.ScheduledTasks.Message
    if ($Results.ScheduledTasks.Status -eq 'FAIL') {
        $Detail += "<div style='color:red; font-weight:bold; margin-top:5px'>[!] SUSPICIOUS PERSISTENCE FOUND:</div>"
        $Detail += "<details><summary style='cursor:pointer'>View Tasks ($($Results.ScheduledTasks.Data.Count))</summary>"
        $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; margin-top:5px'>"
        $Detail += "<table class='sub-table'><tr><th>Task Name</th><th>Command / Action</th><th>State</th></tr>"
        foreach ($Task in $Results.ScheduledTasks.Data) {
            $Detail += "<tr><td>$($Task.Name)</td><td>$($Task.Command)</td><td>$($Task.State)</td></tr>"
        }
        $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }
    
    # --- 19. Hosts File Analysis ---
    if ($Results.HostsFile -and $Results.HostsFile.Message -ne "Skipped") {
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
    }

    # --- 20. DNS Cache Forensics ---
    if ($Results.DnsCache -and $Results.DnsCache.Message -ne "Skipped") {
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
    }
    


    # --- 21. Security Event Log Analysis ---
    if ($Results.EventLogs -and $Results.EventLogs.Message -ne "Skipped") {
    $StatusClass = "status-$($Results.EventLogs.Status.ToLower())"
    if ($Results.EventLogs.Status -eq 'WARN') { $StatusClass = "status-warn" } # (v8) Use proper Yellow Warn

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

        # Deep Blue Details
        if ($Results.EventLogs.Data.SuspiciousPowerShell.Count -gt 0) {
            $Detail += "<details><summary style='color:red; font-weight:bold; margin-top:5px; cursor:pointer'>[!] SUSPICIOUS POWERSHELL COMMANDS ($($Results.EventLogs.Data.SuspiciousPowerShell.Count))</summary>"
            $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; margin-top:5px'>"
            $Detail += "<table class='sub-table' style='border:1px solid red'><tr><th>Time</th><th>Snippet</th></tr>"
            foreach ($p in $Results.EventLogs.Data.SuspiciousPowerShell) {
                $Detail += "<tr><td style='white-space:nowrap'>$($p.Time)</td><td style='font-family:monospace; font-size:0.75rem; word-break:break-all'>$($p.Message)</td></tr>"
            }
            $Detail += "</table></div></details>"
        }
        if ($Results.EventLogs.Data.NewServices.Count -gt 0) {
            $Detail += "<div style='color:blue; font-weight:bold; margin-top:5px'>[i] NEW SERVICES INSTALLED:</div>"
             foreach ($s in $Results.EventLogs.Data.NewServices) { $Detail += "- $($s.TimeCreated): $($s.Details)<br>" }
        }
        if ($Results.EventLogs.Data.SuspiciousProcesses.Count -gt 0) {
            $Detail += "<details><summary style='color:red; font-weight:bold; margin-top:5px; cursor:pointer'>[!] SUSPICIOUS PROCESS LAUNCHES</summary>"
            $Detail += "<table class='sub-table' style='border:1px solid red'><tr><th>Time</th><th>Process / Path</th></tr>"
            foreach ($proc in $Results.EventLogs.Data.SuspiciousProcesses) {
                 $Detail += "<tr><td>$($proc.Time)</td><td style='font-family:monospace; font-size:0.75rem'>$($proc.Message)</td></tr>"
            }
            $Detail += "</table></details>"
        }

    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 22. Web Browser History Spy ---
    if ($Results.History -and $Results.History.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>22. Web Browser History Spy (Forensics)</strong></td>"
    $HtmlBody += "<td class='status-info'>INFO</td>" 
    $Detail = "$($Results.History.Message)<br>"
    if ($Results.History.Data.Count -gt 0) {
         $Detail += "<div style='color:red; font-weight:bold; margin-top:5px'>[!] RECENT BROWSER HISTORY:</div>"
         $Detail += "<details open><summary>View URLs ($($Results.History.Data.Count))</summary>"
         $Detail += "<div style='max-height:200px; overflow-y:auto; border:1px solid #ddd; padding:5px; font-size:0.75rem'>"
         $Detail += "<table class='sub-table'><tr><th>Browser</th><th>URL (Extracted)</th></tr>"
         # Copy array to reverse for display
         $RevHistory = @($Results.History.Data)
         [array]::Reverse($RevHistory)
         foreach ($h in $RevHistory) {
             # Shorten URL for display
             $DisplayUrl = if ($h.Url.Length -gt 80) { $h.Url.Substring(0, 77) + "..." } else { $h.Url }
             $Detail += "<tr><td>$($h.Browser)</td><td style='font-family:monospace; word-break:break-all' title='$($h.Url)'>$DisplayUrl</td></tr>"
         }
         $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 23. Recent Files Activity ---
    if ($Results.UserActivity -and $Results.UserActivity.Message -ne "Skipped") {
    $StatusClass = "status-" + $Results.UserActivity.Status.ToLower()
    if ($Results.UserActivity.Status -eq 'WARN') { $StatusClass = "status-warn" }

    $HtmlBody += "<tr><td><strong>23. Recent Files Activity</strong></td>"
    $HtmlBody += "<td class='$StatusClass'>$($Results.UserActivity.Status)</td>" 
    $Detail = "$($Results.UserActivity.Message)<br>"
    if ($Results.UserActivity.Data.Count -gt 0) {
         $Detail += "<div style='font-weight:bold; margin-top:5px'> RECENTLY OPENED FILES (Filtered & Prioritized):</div>"
         $Detail += "<details><summary>View Files ($($Results.UserActivity.Data.Count))</summary>"
         $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; padding:5px; margin-top:5px'>"
         $Detail += "<table class='sub-table'><tr><th>Time</th><th>Type</th><th>File Name</th><th>Path</th></tr>"
         foreach ($f in $Results.UserActivity.Data) {
             # Style based on ActivityType
             $RowStyle = ""
             $TypeDisplay = "Normal"
             if ($f.ActivityType -eq "Suspicious") { 
                 $RowStyle = "background-color:#fee2e2; color:#991b1b; font-weight:bold"
                 $TypeDisplay = "⚠️ SUSPICIOUS"
             } elseif ($f.ActivityType -eq "Document") {
                 $RowStyle = "background-color:#eff6ff; color:#1e40af"
                 $TypeDisplay = "📄 Document"
             }
             
             # Shorten path
             $DisplayPath = if ($f.Path.Length -gt 60) { "..." + $f.Path.Substring($f.Path.Length - 57) } else { $f.Path }
             $TimeStr = $f.Time
             try { $TimeStr = (Get-Date $f.Time).ToString('MM-dd HH:mm') } catch { }
             $Detail += "<tr style='$RowStyle'><td style='white-space:nowrap'>$TimeStr</td><td>$TypeDisplay</td><td>$($f.Name)</td><td style='font-size:0.75rem' title='$($f.Path)'>$DisplayPath</td></tr>"
         }
         $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 24. Downloads Folder Analyzer ---
    if ($Results.Downloads -and $Results.Downloads.Message -ne "Skipped") {
    $StatusClass = "status-$($Results.Downloads.Status.ToLower())"
    if ($Results.Downloads.Status -eq 'WARN') { $StatusClass = "status-fail" }

    $HtmlBody += "<tr><td><strong>24. Downloads Folder Analysis</strong></td>"
    $HtmlBody += "<td class='$StatusClass'>$($Results.Downloads.Status)</td>"
    $Detail = "$($Results.Downloads.Message)<br>"
    if ($Results.Downloads.Data.Count -gt 0) {
        $Detail += "<div style='margin-top:5px; font-weight:bold'> Risky File Types Found:</div>"
        $Detail += "<details><summary>View Files ($($Results.Downloads.Data.Count))</summary>"
        $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; margin-top:5px'>"
        $Detail += "<table class='sub-table'><tr><th>Time</th><th>File Name</th><th>Size</th></tr>"
        foreach ($d in $Results.Downloads.Data) {
            $Style = ""
            # Highlight recent ones (<24h)
            try {
                if ((Get-Date $d.Time) -gt (Get-Date).AddHours(-24)) { $Style = "background-color:#fee2e2; font-weight:bold" }
            } catch {}
            $TimeStr = $d.Time
            try { $TimeStr = (Get-Date $d.Time).ToString('MM-dd HH:mm') } catch { }
            $Detail += "<tr style='$Style'><td style='white-space:nowrap'>$TimeStr</td><td>$($d.Name)</td><td>$($d.Size)</td></tr>"
        }
        $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 25. RDP Hunter ---
    if ($Results.RdpHunter -and $Results.RdpHunter.Message -ne "Skipped") {
    $StatusClass = "status-$($Results.RdpHunter.Status.ToLower())"
    if ($Results.RdpHunter.Status -eq 'WARN') { $StatusClass = "status-fail" } # Red alert for external RDP

    $HtmlBody += "<tr><td><strong>25. RDP Hunter (Remote Desktop)</strong></td>"
    $HtmlBody += "<td class='$StatusClass'>$($Results.RdpHunter.Status)</td>"
    $Detail = "$($Results.RdpHunter.Message)<br>"
    if ($Results.RdpHunter.Data.Count -gt 0) {
        $Detail += "<div style='margin-top:5px; font-weight:bold'> Connection History (Last 50):</div>"
        $Detail += "<details><summary>View Logs</summary>"
        $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; margin-top:5px'>"
        $Detail += "<table class='sub-table'><tr><th>Time</th><th>Action</th><th>User</th><th>Source IP</th><th>Log Source</th></tr>"
        foreach ($r in $Results.RdpHunter.Data) {
            $Style = ""
            # Highlight External IP (Robust Regex)
             if ($r.Source -and $r.Source -notmatch "^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|::1|fe80:|LOCAL|-)") { 
                 $Style = "background-color:#fee2e2; font-weight:bold; color:red" 
            }
            $TimeStr = $r.Time
            try { $TimeStr = (Get-Date $r.Time).ToString('MM-dd HH:mm') } catch { }
            $Detail += "<tr style='$Style'><td style='white-space:nowrap'>$TimeStr</td><td>$($r.Action)</td><td>$($r.User)</td><td>$($r.Source)</td><td>$($r.LogSource)</td></tr>"
        }
        $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 26. Shadow Copy Check ---
    if ($Results.ShadowCopy -and $Results.ShadowCopy.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>26. Shadow Copy & Restore Points</strong></td>"
    $HtmlBody += "<td class='status-$($Results.ShadowCopy.Status.ToLower())'>$($Results.ShadowCopy.Status)</td>"
    $HtmlBody += "<td>$($Results.ShadowCopy.Message)</td></tr>"
    }

    # --- 27. Local Admin Hunter ---
    if ($Results.LocalAdminsHunter -and $Results.LocalAdminsHunter.Message -ne "Skipped") {
    $StatusClass = "status-info"
    if ($Results.LocalAdminsHunter.Status -eq 'WARN') { $StatusClass = "status-fail" }
    
    $HtmlBody += "<tr><td><strong>27. Local Admin Hunter</strong></td>"
    $HtmlBody += "<td class='$StatusClass'>$($Results.LocalAdminsHunter.Status)</td>"
    $Detail = "$($Results.LocalAdminsHunter.Message)<br>"
    if ($Results.LocalAdminsHunter.Data.Count -gt 0) {
        $Detail += "<details><summary>View Recursive Groups</summary>"
        $Detail += "<table class='sub-table'><tr><th>Group</th><th>User/Member</th><th>Class</th></tr>"
        foreach ($u in $Results.LocalAdminsHunter.Data) { 
             $RowStyle = ""
             if ($u.IsSuspicious) { $RowStyle = "background-color:#fee2e2; color:#991b1b; font-weight:bold" }
             $Detail += "<tr style='$RowStyle'><td>$($u.Group)</td><td>$($u.User)</td><td>$($u.Class)</td></tr>" 
        }
        $Detail += "</table></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 28. DNS Cache Analyzer ---
    if ($Results.DnsAnalyzer -and $Results.DnsAnalyzer.Message -ne "Skipped") {
    # Dynamic Status Class
    $StatusClass = "status-" + $Results.DnsAnalyzer.Status.ToLower()
    $HtmlBody += "<tr><td><strong>28. DNS Cache Analyzer</strong></td>"
    $HtmlBody += "<td class='$StatusClass'>$($Results.DnsAnalyzer.Status)</td>"
    $Detail = "$($Results.DnsAnalyzer.Message)<br>"
    if ($Results.DnsAnalyzer.Data.Count -gt 0) {
        $Detail += "<details><summary>View DNS Cache</summary>"
        $Detail += "<table class='sub-table'><tr><th>Domain / Entry</th><th>Type</th></tr>"
        foreach ($d in $Results.DnsAnalyzer.Data) {
             $RowStyle = ""
             if ($d.Type -match "Mining") { 
                 $RowStyle = "background-color:#fee2e2; color:#991b1b; font-weight:bold" 
             }
             $Detail += "<tr style='$RowStyle'><td>$($d.Domain)</td><td>$($d.Type)</td></tr>" 

        }
        $Detail += "</table></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 29. UserAssist Forensics ---
    if ($Results.UserAssist -and $Results.UserAssist.Message -ne "Skipped") {
    # Dynamic Status Class
    $StatusClass = "status-" + $Results.UserAssist.Status.ToLower()
    $HtmlBody += "<tr><td><strong>29. UserAssist (Execution History)</strong></td>"
    $HtmlBody += "<td class='$StatusClass'>$($Results.UserAssist.Status)</td>"
    $Detail = "$($Results.UserAssist.Message)<br>"
    if ($Results.UserAssist.Data.Count -gt 0) {
        $Detail += "<details><summary>View Executed Programs</summary>"
        $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; padding:5px; margin-top:5px'>"
        $Detail += "<table class='sub-table'><tr><th>Last Run</th><th>Count</th><th>Program Path</th></tr>"
        foreach ($u in $Results.UserAssist.Data) { 
             $RowStyle = ""
             if ($u.Path -match "mimikatz|psexec|nmap|wireshark|metasploit|cobalt") {
                 $RowStyle = "background-color:#fee2e2; color:#991b1b; font-weight:bold"
             }
             
             $TimeStr = $u.LastRun
             try { if ($u.LastRun -is [DateTime]) { $TimeStr = $u.LastRun.ToString("yyyy-MM-dd HH:mm") } } catch {}
             
             $Detail += "<tr style='$RowStyle'><td style='white-space:nowrap'>$TimeStr</td><td>$($u.RunCount)</td><td style='word-break:break-all'>$($u.Path)</td></tr>"
        }
        $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 30. Recycle Bin Scavenger ---
    if ($Results.RecycleBin -and $Results.RecycleBin.Message -ne "Skipped") {
    $StatusClass = "status-" + $Results.RecycleBin.Status.ToLower()
    if ($Results.RecycleBin.Status -eq 'WARN') { $StatusClass = "status-warn" }
    
    $HtmlBody += "<tr><td><strong>30. Recycle Bin Scavenger</strong></td>"
    $HtmlBody += "<td class='$StatusClass'>$($Results.RecycleBin.Status)</td>"
    $Detail = "$($Results.RecycleBin.Message)<br>"
    if ($Results.RecycleBin.Data.Count -gt 0) {
        # Show "Showing 20 of X" logic if truncated
        $TotalCount = if ($Results.RecycleBin.TotalCount) { $Results.RecycleBin.TotalCount } else { $Results.RecycleBin.Data.Count }
        $SummaryText = "View Deleted Files ($TotalCount)"
        if ($Results.RecycleBin.Data.Count -lt $TotalCount) {
             $SummaryText = "View Deleted Files (Showing first $($Results.RecycleBin.Data.Count) of $TotalCount)"
        }
    
        $Detail += "<details><summary>$SummaryText</summary>"
        $Detail += "<div style='max-height:300px; overflow-y:auto; border:1px solid #ddd; margin-top:5px'>"
        $Detail += "<table class='sub-table'><tr><th>Type</th><th>File Name</th><th>Original Path</th><th>Size</th></tr>"
        foreach ($b in $Results.RecycleBin.Data) { 
             $RowStyle = ""
             $TypeDisplay = "Normal"
             if ($b.Type -eq "Suspicious") {
                 $RowStyle = "background-color:#fee2e2; color:#991b1b; font-weight:bold"
                 $TypeDisplay = "[!] Suspicious"
             } elseif ($b.Type -eq "Sensitive") {
                 $RowStyle = "background-color:#fff7ed; color:#9a3412"
                 $TypeDisplay = "[*] Sensitive"
             }
             $Detail += "<tr style='$RowStyle'><td>$TypeDisplay</td><td>$($b.Name)</td><td>$($b.Path)</td><td>$($b.Size)</td></tr>" 
        }
        $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }



    # --- 31. Office Macro Security ---
    if ($Results.OfficeSecurity -and $Results.OfficeSecurity.Message -ne "Skipped") {
    $StatusClass = "status-" + $Results.OfficeSecurity.Status.ToLower()
    $HtmlBody += "<tr><td><strong>31. Office Macro Security</strong></td>"
    $HtmlBody += "<td class='$StatusClass'>$($Results.OfficeSecurity.Status)</td>"
    $Detail = "$($Results.OfficeSecurity.Message)<br>"
    if ($Results.OfficeSecurity.Data.Count -gt 0) {
         $Detail += "<table class='sub-table' style='margin-top:5px'><tr><th>Ver</th><th>App</th><th>Setting</th></tr>"
         foreach ($o in $Results.OfficeSecurity.Data) {
             $Detail += "<tr><td>$($o.Version)</td><td>$($o.App)</td><td>$($o.Setting)</td></tr>"
         }
         $Detail += "</table>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

    # --- 32. Software Inventory ---
    if ($Results.SoftwareInventory -and $Results.SoftwareInventory.Message -ne "Skipped") {
    $HtmlBody += "<tr><td><strong>32. Software Inventory</strong></td>"
    $HtmlBody += "<td class='status-info'>INFO</td>"
    $Detail = "$($Results.SoftwareInventory.Message)<br>"
    if ($Results.SoftwareInventory.Data.Count -gt 0) {
        $Detail += "<details><summary>View All Apps ($($Results.SoftwareInventory.Data.Count))</summary>"
        # Use a scrolling div for long list
        $Detail += "<div style='max-height:300px; overflow-y:auto; margin-top:5px; border:1px solid #ddd'>"
        $Detail += "<table class='sub-table'><tr><th>Name</th><th>Version</th><th>Publisher</th></tr>"
        foreach ($s in $Results.SoftwareInventory.Data) {
             $Detail += "<tr><td>$($s.Name)</td><td>$($s.Ver)</td><td>$($s.Pub)</td></tr>"
        }
        $Detail += "</table></div></details>"
    }
    $HtmlBody += "<td>$Detail</td></tr>"
    }

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
    # FIX: Remove -DateAsISO8601 (not compatible with PS 5.1)
    # The dashboard can handle the default Microsoft date format.
    $AuditResultsObject | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonReportPath -Encoding utf8
    Write-HostPass "Successfully saved JSON report to $JsonReportPath" # Aligned
} catch {
    Write-HostFail "Could not save JSON report: $($_.Exception.Message)" # Aligned
}

# --- 2. Write HTML Report ---
try {
    $HtmlContent = Generate-HtmlReport $AuditResultsObject
    $HtmlContent | Out-File -FilePath $HtmlReportPath -Encoding utf8
    Write-HostPass "Successfully saved HTML report to $HtmlReportPath" # Aligned
} catch {
    Write-HostFail "Could not save HTML report: $($_.Exception.Message)" # Aligned
}

# ============================================================
Write-SectionHeader "All Done"
Write-HostPass "Scan complete. Reports saved to $ReportOutputDir" # Aligned
pause