<#
.SYNOPSIS
    (v4.4) UI CHANGE: Removed version number badge next to Export button.
           FEATURE: Finalized "Pro Export" logic (includes Network Interfaces in CSV).
           FEATURE: Detail Modal shows Network Interfaces.
.NOTES
    Version: 4.4
#>

# --- Load Shared Library ---
$LibPath = Join-Path $PSScriptRoot "LOCKON_Lib.ps1"
if (Test-Path $LibPath) {
    . $LibPath
} else {
    Write-Host "[!] Critical Error: LOCKON_Lib.ps1 not found!" -ForegroundColor Red
    exit
}

Clear-Host
Write-HostInfo "Starting Dashboard Generator (v4.4)..."
Write-Log "Starting Dashboard Generator..."

# Find scripts and report directories
$PSScriptRoot = Split-Path $PSCommandPath -Parent
$ReportDir = Join-Path $PSScriptRoot "AuditReports"

# --- CACHE BUSTER ---
Write-HostInfo "Cleaning up old dashboards..."
Get-ChildItem -Path $PSScriptRoot -Filter "Dashboard_Generated_*.html" | Remove-Item -ErrorAction SilentlyContinue
$DateStamp = Get-Date -Format "yyyyMMddHHmmss"
$DashboardFile = Join-Path $PSScriptRoot "Dashboard_Generated_$($DateStamp).html"

if (-not (Test-Path $ReportDir)) {
    Write-HostFail "Report directory not found: $ReportDir"
    pause
    exit
}

# --- Load Reports (JSON ONLY) ---
$JsonStringArray = [System.Collections.ArrayList]@()
$ReportCount = 0

Write-HostInfo "Searching for valid .json reports in $ReportDir"
$JsonFiles = Get-ChildItem -Path $ReportDir -Recurse -Filter "*.json"

foreach ($ReportFile in $JsonFiles) {
    try {
        $JsonString = Get-Content $ReportFile.FullName -Raw
        $null = $JsonString | ConvertFrom-Json # Validate
        $JsonStringArray.Add($JsonString) | Out-Null
        $ReportCount++
    } catch {
        Write-HostFail "  - Skipping invalid file: $($ReportFile.Name)"
    }
}

if ($ReportCount -eq 0) {
    Write-HostFail "No valid reports found."
    pause
    exit
}

$JsonBlob = "[" + ($JsonStringArray -join ",") + "]"

Write-HostInfo "Generating HTML template..."
$GeneratedDate = Get-Date

$HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LOCKON: SYSTEM DIAGNOSTIC ANALYZER Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: 'Inter', sans-serif; }
        .status-pass { background-color: #dcfce7; color: #166534; }
        .status-fail { background-color: #fee2e2; color: #991b1b; }
        .status-info { background-color: #e0f2fe; color: #075985; }
        
        th { position: sticky; top: 0; background-color: #f9fafb; cursor: pointer; user-select: none; }
        th:hover { background-color: #e5e7eb; }
        
        .stat-card { transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-2px); }

        .clickable-name { color: #2563eb; cursor: pointer; font-weight: 600; }
        .clickable-name:hover { text-decoration: underline; color: #1e40af; }

        #detail-modal { display: none; }
    </style>
</head>
<body class="bg-gray-100 p-4 md:p-8">
    <div class="max-w-7xl mx-auto">
        <!-- Header & Actions -->
        <div class="flex flex-col md:flex-row justify-between items-end mb-6 gap-4">
            <div>
                <h1 class="text-3xl font-bold text-gray-800">LOCKON: SYSTEM DIAGNOSTIC ANALYZER Dashboard</h1>
                <p class="text-sm text-gray-500">Generated on __GENERATED_DATE__</p>
            </div>
            <div class="flex items-center gap-2">
                <button onclick="exportDataToCSV()" class="bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-2 px-4 rounded inline-flex items-center shadow transition">
                    <svg class="fill-current w-4 h-4 mr-2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M13 8V2H7v6H2l8 8 8-8h-5zM0 18h20v2H0v-2z"/></svg>
                    <span>Export CSV</span>
                </button>
                <!-- (v4.4) Version badge removed as requested -->
            </div>
        </div>

        <!-- Filters -->
        <div class="bg-white rounded-lg shadow p-4 mb-6">
            <div class="flex flex-col md:flex-row justify-between items-center mb-3">
                <h2 class="text-xs font-bold text-gray-400 uppercase tracking-wide">Filters & Search</h2>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
                <div class="md:col-span-1 relative">
                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <svg class="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                    </div>
                    <input type="text" id="searchInput" placeholder="Search Machine Name..." class="pl-10 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 bg-gray-50 p-2 text-sm border">
                </div>
                <div><select id="filterAV" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 bg-gray-50 p-2 text-sm"><option value="All">Antivirus: All</option><option value="PASS">PASS Only</option><option value="FAIL">FAIL Only</option></select></div>
                <div><select id="filterPatch" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 bg-gray-50 p-2 text-sm"><option value="All">Patches: All</option><option value="PASS">PASS Only</option><option value="FAIL">FAIL Only</option></select></div>
                <div><select id="filterPorts" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 bg-gray-50 p-2 text-sm"><option value="All">Ports: All</option><option value="PASS">PASS Only</option><option value="FAIL">FAIL Only</option></select></div>
                <div><select id="filterUAC" class="block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 bg-gray-50 p-2 text-sm"><option value="All">UAC: All</option><option value="PASS">PASS Only</option><option value="FAIL">FAIL Only</option></select></div>
            </div>
        </div>

        <!-- Stats -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div class="stat-card bg-white rounded-lg shadow p-4 border-l-4 border-blue-500">
                <div class="flex justify-between items-center">
                    <div>
                        <div class="text-gray-400 text-xs uppercase font-bold">Total Machines</div>
                        <div class="text-3xl font-bold text-gray-800" id="stat-total">0</div>
                        <div class="text-xs text-gray-500 mt-1">Scanned Devices</div>
                    </div>
                    <div class="p-3 bg-blue-50 rounded-full text-blue-500">
                        <svg class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
                    </div>
                </div>
            </div>
            <div class="stat-card bg-white rounded-lg shadow p-4 border-l-4 border-green-500">
                <div class="flex justify-between items-center">
                    <div>
                        <div class="text-gray-400 text-xs uppercase font-bold">AV Protected</div>
                        <div class="text-3xl font-bold text-gray-800" id="stat-av-count">0</div>
                        <div class="text-xs text-gray-500 mt-1" id="stat-av-percent">0% of Total</div>
                    </div>
                    <div class="p-3 bg-green-50 rounded-full text-green-500">
                        <svg class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                    </div>
                </div>
            </div>
            <div class="stat-card bg-white rounded-lg shadow p-4 border-l-4 border-yellow-500">
                <div class="flex justify-between items-center">
                    <div>
                        <div class="text-gray-400 text-xs uppercase font-bold">Fully Patched</div>
                        <div class="text-3xl font-bold text-gray-800" id="stat-patch-count">0</div>
                        <div class="text-xs text-gray-500 mt-1" id="stat-patch-percent">0% of Total</div>
                    </div>
                    <div class="p-3 bg-yellow-50 rounded-full text-yellow-500">
                        <svg class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg>
                    </div>
                </div>
            </div>
        </div>

        <!-- Table -->
        <div id="report-container" class="bg-white rounded-lg shadow overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200" id="report-table">
                <thead class="bg-gray-50">
                    <tr>
                        <th onclick="sortTable(0)" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-indigo-600">Machine Name &#8597;</th>
                        <th onclick="sortTable(1)" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-indigo-600">OS Version &#8597;</th>
                        <th onclick="sortTable(2)" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-indigo-600">Last Update &#8597;</th>
                        <th onclick="sortTable(3)" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-indigo-600">AV Status &#8597;</th>
                        <th onclick="sortTable(4)" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-indigo-600">Patch Status &#8597;</th>
                        <th onclick="sortTable(5)" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-indigo-600">Risky Ports &#8597;</th>
                        <th onclick="sortTable(6)" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-indigo-600">Firewall &#8597;</th>
                        <th onclick="sortTable(7)" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-indigo-600">UAC &#8597;</th>
                        <th onclick="sortTable(8)" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hover:text-indigo-600">Risky Items &#8597;</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200" id="report-body"></tbody>
            </table>
        </div>
    </div>

    <!-- Detail Modal -->
    <div id="detail-modal" class="fixed inset-0 bg-gray-900 bg-opacity-75 z-50 flex items-center justify-center hidden">
        <div class="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 p-6 relative flex flex-col max-h-[90vh]">
            <button onclick="document.getElementById('detail-modal').style.display='none'" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600 text-2xl font-bold">&times;</button>
            <div id="detail-content-body" class="overflow-y-auto flex-grow pr-2"></div>
            <div class="mt-6 text-right pt-4 border-t border-gray-100">
                <button onclick="document.getElementById('detail-modal').style.display='none'" class="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 text-sm">Close</button>
            </div>
        </div>
    </div>

    <script>
        window.ALL_REPORTS = __JSON_BLOB_PLACEHOLDER__;
        window.VISIBLE_REPORTS = []; // Store currently filtered reports for export

        const filters = ['filterAV', 'filterPatch', 'filterPorts', 'filterUAC'].map(id => document.getElementById(id));
        const searchInput = document.getElementById('searchInput');
        
        filters.forEach(f => f.addEventListener('change', renderTable));
        searchInput.addEventListener('keyup', renderTable);
        window.onload = () => renderTable();

        function calculateStats(reports) {
            const total = reports.length;
            if (total === 0) {
                ['stat-total', 'stat-av-count', 'stat-patch-count'].forEach(id => document.getElementById(id).textContent = '0');
                ['stat-av-percent', 'stat-patch-percent'].forEach(id => document.getElementById(id).textContent = '0%');
                return;
            }
            let avPass = 0;
            let patchPass = 0;
            reports.forEach(r => {
                if (r.Antivirus?.Status === 'PASS') avPass++;
                if (r.CriticalPatches?.Status === 'PASS') patchPass++;
            });
            document.getElementById('stat-total').textContent = total;
            document.getElementById('stat-av-count').textContent = avPass;
            document.getElementById('stat-patch-count').textContent = patchPass;
            document.getElementById('stat-av-percent').textContent = Math.round((avPass / total) * 100) + '% of Total';
            document.getElementById('stat-patch-percent').textContent = Math.round((patchPass / total) * 100) + '% of Total';
        }

        function parseDate(dateString) {
            if (!dateString) return null;
            if (typeof dateString !== 'string') return null; 
            if (dateString.startsWith('/Date(')) {
                try { return new Date(parseInt(dateString.substr(6))); } catch (e) { return null; }
            }
            const d = new Date(dateString);
            return isNaN(d.getTime()) ? null : d;
        }

        // (v4.4) CSV Export Logic: Includes Network Interfaces & Enhanced Security Checks
        function exportDataToCSV() {
            if (!window.VISIBLE_REPORTS || window.VISIBLE_REPORTS.length === 0) {
                alert("No data to export");
                return;
            }

            const headers = [
                "Machine Name", "OS Details", "Last Update", "AV Status", "Patch Status", 
                "Risky Ports", "Firewall", "UAC", "Risky Items", 
                "Drift Status", "Threats Found", "Untrusted Items (Sig)", "Forensics (Hosts/DNS)", "Suspicious Events (24h)",
                "Network Interfaces (Name: IP (MAC))"
            ];
            const csvRows = [];
            csvRows.push(headers.join(","));

            window.VISIBLE_REPORTS.forEach(r => {
                const mName = r.ReportInfo?.MachineName || 'Unknown';
                
                // Enhanced OS Details
                let os = r.OsInfo?.Data?.ProductName || 'Unknown OS';
                if (r.OsInfo?.Data?.DisplayVersion) os += ` (${r.OsInfo.Data.DisplayVersion})`;

                const dObj = parseDate(r.OsUpdate?.Data?.LastUpdateDate);
                const date = dObj ? dObj.toLocaleDateString() : 'N/A';
                const av = r.Antivirus?.Status || 'N/A';
                const patch = r.CriticalPatches?.Status || 'N/A';
                
                let ports = r.ListeningPorts?.Status || 'N/A';
                if (ports === 'FAIL') ports += ` (${r.ListeningPorts?.Data?.FoundRisky?.length || 0})`;
                
                const fw = r.Firewall?.Status || 'N/A';
                const uac = r.UAC?.Status || 'N/A';

                // Calc Risky Items
                let riskyCount = 0;
                if (r.AutomaticServices?.Status === 'FAIL') riskyCount += (r.AutomaticServices?.Data?.length || 1);
                if (r.Startup?.Status === 'FAIL') riskyCount += (r.Startup?.Data?.length || 1);
                if (r.UnwantedSoftware?.Status === 'FAIL') riskyCount += (r.UnwantedSoftware?.Data?.length || 1);
                const risky = riskyCount > 0 ? `FAIL (${riskyCount})` : 'PASS';

                // New Security Columns
                const drift = r.DriftAnalysis?.Status || 'INFO';
                const threats = r.HashAnalysis?.Threats?.length > 0 ? `FAIL (${r.HashAnalysis.Threats.length})` : 'PASS';
                
                // Untrusted Items (Approximation from Task/StartupFAIL)
                let untrusted = 0;
                if (r.ScheduledTasks?.Status === 'FAIL') untrusted += (r.ScheduledTasks?.Data?.length || 0);
                // Note: Startup signature failures are part of Startup Status FAIL, but count isn't explicitly separate in simple object without parsing.
                // We'll use the specific data counts we have.
                const sigStatus = untrusted > 0 ? `FAIL (${untrusted})` : 'PASS';

                // Forensics
                let forensics = "PASS";
                if (r.HostsFile?.Status === 'FAIL') forensics = "FAIL (Hosts)";
                if (r.DnsCache?.Data?.length > 0) forensics += `; DNS: ${r.DnsCache.Data.length}`;

                // Event Logs
                let events = "PASS";
                if (r.EventLogs?.Status !== 'PASS' && r.EventLogs?.Status !== 'INFO') {
                     let eDetails = [];
                     if (r.EventLogs?.Data?.LogClearing) eDetails.push("Logs Cleared");
                     if (r.EventLogs?.Data?.FailedLogins?.length > 0) eDetails.push(`Failed Login: ${r.EventLogs.Data.FailedLogins.length}`);
                     if (r.EventLogs?.Data?.NewUsers?.length > 0) eDetails.push(`New Users: ${r.EventLogs.Data.NewUsers.length}`);
                     events = `WARN (${eDetails.join(', ')})`;
                }

                // Construct Network String
                let netStr = "N/A";
                if (r.NetworkConfig?.Data && Array.isArray(r.NetworkConfig.Data)) {
                    netStr = r.NetworkConfig.Data.map(n => {
                        return `${n.Name}: ${n.IPv4Address} (${n.MacAddress})`;
                    }).join("; ");
                }

                // Escape quotes for CSV
                const row = [
                    mName, os, date, av, patch, 
                    ports, fw, uac, risky, 
                    drift, threats, sigStatus, forensics, events,
                    netStr
                ].map(field => {
                    const str = String(field || "");
                    return `"${str.replace(/"/g, '""')}"`; // Wrap in quotes and escape existing quotes
                });

                csvRows.push(row.join(","));
            });

            const csvContent = "\uFEFF" + csvRows.join("\n"); // Add BOM for Excel
            const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url; a.download = "Security_Audit_Export.csv"; 
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
        }

        function sortTable(n) {
            const table = document.getElementById("report-table");
            let switching = true, dir = "asc", switchcount = 0;
            while (switching) {
                switching = false;
                const rows = table.rows;
                for (var i = 1; i < (rows.length - 1); i++) {
                    var shouldSwitch = false;
                    const x = rows[i].getElementsByTagName("TD")[n];
                    const y = rows[i + 1].getElementsByTagName("TD")[n];
                    if (dir == "asc") {
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) { shouldSwitch = true; break; }
                    } else {
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) { shouldSwitch = true; break; }
                    }
                }
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true; switchcount++;
                } else {
                    if (switchcount == 0 && dir == "asc") { dir = "desc"; switching = true; }
                }
            }
        }

        function showMachineDetails(machineName) {
            const report = window.ALL_REPORTS.find(r => (r.ReportInfo?.MachineName || 'Unknown') === machineName);
            if (!report) { alert("Details not found."); return; }
            let content = `<h3 class="text-lg font-bold mb-4 text-gray-800 border-b pb-2">Machine Details: ${machineName}</h3>`;
            
            // Network
            content += '<h4 class="font-semibold text-indigo-600 mb-2 mt-4 flex items-center">Network Interfaces</h4>';
            if (report.NetworkConfig?.Data && Array.isArray(report.NetworkConfig.Data) && report.NetworkConfig.Data.length > 0) {
                content += '<div class="space-y-3 max-h-40 overflow-y-auto pr-2">';
                report.NetworkConfig.Data.forEach(adapter => {
                    content += `<div class="bg-gray-50 p-2 rounded border border-gray-200 text-sm"><div class="font-bold">${adapter.Name}</div><div class="text-xs text-gray-500">IP: ${adapter.IPv4Address} | MAC: ${adapter.MacAddress}</div></div>`;
                });
                content += '</div>';
            } else { content += '<p class="text-gray-400 text-sm">No active adapters.</p>'; }

            // Risky Items Section
            content += '<h4 class="font-semibold text-red-600 mb-2 mt-4 flex items-center">Security Risks & Policy Violations</h4>';
            let foundRisks = false;

            // 1. Services
            if (report.AutomaticServices?.Status === 'FAIL') {
                foundRisks = true;
                content += '<div class="mb-2"><div class="font-bold text-sm text-red-700"> suspicious Services (Non-Standard Path):</div><ul class="list-disc pl-5 text-sm text-gray-700">';
                report.AutomaticServices.Data.forEach(s => content += `<li><b>${s.Name}</b>: ${s.Path}</li>`);
                content += '</ul></div>';
            }

            // 2. Startup
            if (report.Startup?.Status === 'FAIL') {
                foundRisks = true;
                content += '<div class="mb-2"><div class="font-bold text-sm text-red-700">Suspicious Startup Items:</div><ul class="list-disc pl-5 text-sm text-gray-700">';
                report.Startup.Data.forEach(s => content += `<li><b>${s.Name}</b>: ${s.Command}</li>`);
                content += '</ul></div>';
            }

            // 3. Unwanted Software
            if (report.UnwantedSoftware?.Status === 'FAIL') {
                foundRisks = true;
                content += '<div class="mb-2"><div class="font-bold text-sm text-red-700">Unwanted Software Found:</div><ul class="list-disc pl-5 text-sm text-gray-700">';
                report.UnwantedSoftware.Data.forEach(s => content += `<li><b>${s.Name}</b> (Policy: ${s.Policy})</li>`);
                content += '</ul></div>';
            }

            if (!foundRisks) {
                content += '<div class="bg-green-50 text-green-700 p-3 rounded text-sm">No suspicious items or policy violations found.</div>';
            }

            document.getElementById('detail-content-body').innerHTML = content;
            const modal = document.getElementById('detail-modal');
            modal.style.display = 'flex';
            modal.onclick = (e) => { if(e.target === modal) modal.style.display = 'none'; };
        }

        function renderTable() {
            const tableBody = document.getElementById('report-body');
            tableBody.innerHTML = ''; 
            window.VISIBLE_REPORTS = []; // Reset visible list

            const activeFilters = {
                AV: document.getElementById('filterAV').value,
                Patch: document.getElementById('filterPatch').value,
                Ports: document.getElementById('filterPorts').value,
                UAC: document.getElementById('filterUAC').value,
                Search: searchInput.value.toLowerCase()
            };

            if (!window.ALL_REPORTS || window.ALL_REPORTS.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="8" class="px-6 py-4 text-center text-gray-500">No reports found.</td></tr>';
                calculateStats([]);
                return;
            }

            window.ALL_REPORTS.forEach(report => {
                const mName = report.ReportInfo?.MachineName || 'Unknown';
                const av = report.Antivirus?.Status || 'N/A';
                const patch = report.CriticalPatches?.Status || 'N/A';
                const port = report.ListeningPorts?.Status || 'N/A';
                const uac = report.UAC?.Status || 'N/A';

                if (activeFilters.Search && !mName.toLowerCase().includes(activeFilters.Search)) return;
                if (activeFilters.AV !== 'All' && av !== activeFilters.AV) return;
                if (activeFilters.Patch !== 'All' && patch !== activeFilters.Patch) return;
                if (activeFilters.Ports !== 'All' && port !== activeFilters.Ports) return;
                if (activeFilters.UAC !== 'All' && uac !== activeFilters.UAC) return;

                window.VISIBLE_REPORTS.push(report); // Add to visible list

                const tr = document.createElement('tr');
                tr.className = 'hover:bg-gray-50';
                
                const addCell = (text) => {
                    const td = document.createElement('td');
                    td.className = 'px-6 py-4 whitespace-nowrap text-sm text-gray-700';
                    td.textContent = text || 'N/A';
                    tr.appendChild(td);
                };
                const addBadge = (status, label) => {
                    const td = document.createElement('td');
                    td.className = 'px-6 py-4 whitespace-nowrap';
                    const span = document.createElement('span');
                    span.className = 'px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full status-' + (status ? status.toLowerCase() : 'info');
                    span.textContent = label || status || 'N/A';
                    td.appendChild(span);
                    tr.appendChild(td);
                };

                const safeName = mName.replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/"/g, '\\"');
                const nameTd = document.createElement('td');
                nameTd.className = 'px-6 py-4 whitespace-nowrap text-sm text-gray-700 font-bold';
                nameTd.innerHTML = `<span class="clickable-name text-indigo-600 hover:text-indigo-800 cursor-pointer" onclick="showMachineDetails('${safeName}')">${mName}</span>`;
                tr.appendChild(nameTd);

                addCell(report.OsInfo?.Data?.DisplayVersion);
                const d = parseDate(report.OsUpdate?.Data?.LastUpdateDate);
                addCell(d ? d.toLocaleDateString() : 'N/A');

                let avLabel = av;
                if (av === 'PASS' && Array.isArray(report.Antivirus?.Data)) {
                    const active = report.Antivirus.Data.find(a => a.Status === 'Running' || a.Status === 'PASS');
                    if (active) avLabel = `PASS (${active.Name})`;
                }
                addBadge(av, avLabel);
                addBadge(patch, patch); // Simplified Patch Status
                
                let portLabel = port;
                if (port === 'FAIL') portLabel += ` (${report.ListeningPorts?.Data?.FoundRisky?.length || 0})`;
                addBadge(port, portLabel);

                addBadge(report.Firewall?.Status, null);
                addBadge(uac, null);

                // Risky Items Aggregated Column
                let riskyCount = 0;
                if (report.AutomaticServices?.Status === 'FAIL') riskyCount += (report.AutomaticServices?.Data?.length || 1);
                if (report.Startup?.Status === 'FAIL') riskyCount += (report.Startup?.Data?.length || 1);
                if (report.UnwantedSoftware?.Status === 'FAIL') riskyCount += (report.UnwantedSoftware?.Data?.length || 1);
                addBadge(riskyCount > 0 ? 'FAIL' : 'PASS', riskyCount > 0 ? `FAIL (${riskyCount})` : 'PASS');

                tableBody.appendChild(tr);
            });

            calculateStats(window.VISIBLE_REPORTS);
        }
    </script>
</body>
</html>
'@ 

Write-HostInfo "Injecting JSON data into template..."
$FinalHtml = $HtmlTemplate -replace '__JSON_BLOB_PLACEHOLDER__', $JsonBlob
$FinalHtml = $FinalHtml -replace '__GENERATED_DATE__', $($GeneratedDate.ToString('yyyy-MM-dd HH:mm:ss'))
$FinalHtml = $FinalHtml -replace '__REPORT_COUNT__', $ReportCount

$FinalHtml | Out-File -FilePath $DashboardFile -Encoding utf8

Write-HostPass "Successfully generated dashboard: $DashboardFile"
Write-HostInfo "Opening dashboard in your default browser..."
Start-Process $DashboardFile

pause