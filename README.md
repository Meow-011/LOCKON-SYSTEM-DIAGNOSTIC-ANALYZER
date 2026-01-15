#  LOCKON: SYSTEM DIAGNOSTIC ANALYZER

**LOCKON: SYSTEM DIAGNOSTIC ANALYZER** is an automated PowerShell security auditing and forensics tool designed for Windows environments. It performs deep system inspections to detect misconfigurations, potential threats, and suspicious activities using a baseline-comparison approach.

![Dashboard Preview](images/dashboard_preview.png)

---

##  Key Features

*   **Holistic Security Audit:** Scans 20+ system components including Firewall, UAC, Ports, and Patches.
*   **Threat Hunting:** Integrated File Hash analysis (SHA256) against a local Threat DB and Digital Signature verification for Auto-Start items.
*   **Drift Detection:** Automatically compares the current scan against a previous baseline to flag new open ports, new admins, or changed system files.
*   **Forensics:**
    *   **Network:** Hosts file analysis & DNS Cache dump.
    *   **Logs:** Scans Security Event Logs (Last 24h) for Brute Force (4625), Log Clearing (1102), and New Users (4720).
*   **Interactive Dashboard:** Generates a rich HTML report with sorting, filtering, and CSV export capabilities.

---

## Installation & Usage

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/Meow-011/LOCKON-SYSTEM-DIAGNOSTIC-ANALYZER.git
    cd LOCKON-SYSTEM-DIAGNOSTIC-ANALYZER
    ```

2.  **Run the Tool:**
    *   **Double-click** `LOCKON_PCheck.bat` (Recommended - Auto-Admin check)
    *   **OR run via PowerShell:**
        ```powershell
        Set-ExecutionPolicy Bypass -Scope Process -Force
        .\LOCKON_Menu.ps1
        ```

3.  **Main Menu:**
    *   `[1] SYSTEM SECURITY SCAN`: Start the full system scan & view HTML Report.
    *   `[2] VIEW AUDIT REPORTS`: Launch the interactive Dashboard (All Machines).
    *   `[3] CONFIGURATION MANAGER`: Edit policies, blacklists, and KBs.
    *   `[4] EXPORT INVENTORY`: Dump installed software list to CSV.
    *   `[5] EXPORT ACTIVITY TIMELINE`: Forensic dump of recent user activity (Recent Files).
    *   `[6] EXIT`

---

## Configuration Guide (`config.psd1`)

LOCKON is highly customizable. You can adjust the security policy in `config.psd1`:

*   **RiskyPorts:** Define which TCP/UDP ports are considered dangerous.
    *   *Example:* Add port `8080` if you want to flag Web Proxies.
*   **UnwantedSoftware:** A blacklist of software names.
    *   *Example:* Add `"TeamViewer"` or `"AnyDesk"` to detect unauthorized remote access tools.
*   **AntivirusStateTranslations:** Map antivirus status codes to human-readable descriptions (useful for localized Windows).
*   **MainReportFolder:** Change where the reports are saved (Default: `AuditReports`).

---

## Detailed Audit Checklist

<details>
<summary><strong>Click to view all 21 Security Checks</strong></summary>

| ID | Check Name | Description |
| :--- | :--- | :--- |
| **01** | OS Information | Verifies OS Version and Build number. |
| **02** | Network Config | Lists active physical network adapters and IP configurations. |
| **03** | Windows Update | Checks the last time the OS was updated. |
| **04** | Antivirus Status | Verifies if AV/EDR is installed, updated, and running. |
| **05** | Critical KBs | Checks for presence of specific Security Hotfixes (KB). |
| **06** | Listening Ports | Scans for risky open ports (e.g., SMB 445, Telnet 23). |
| **08** | Firewall Profiles | Ensures Domain, Private, and Public firewalls are Enabled. |
| **09** | UAC Status | Verifies User Account Control (EnableLUA) is active. |
| **10** | Suspicious Services | Flags services running from Temp/AppData or untrusted paths. |
| **11** | Local Admins | Enumerates members of the Administrators group. |
| **12** | Open Shares | Checks for file shares open to "Everyone" with Write access. |
| **13** | Startup Items | Scans Registry/Folder startups for risky items/signatures. |
| **14** | Unwanted Software | Checks installed apps against the Policy Blacklist. |
| **15** | Hash Analysis | Computes SHA256 of running processes vs Threat DB. |
| **16** | Drift Detection | Compares current state vs previous baseline report. |
| **17** | Browser Extensions | Lists installed extensions for Chrome/Edge/Firefox. |
| **18** | Scheduled Tasks | Flags tasks executing from suspicious paths. |
| **19** | Hosts File Analysis | Scans `C:\Windows\System32\drivers\etc\hosts` for hijacks. |
| **20** | DNS Cache Forensics | Dumps recent DNS queries to spot C2 connections. |
| **21** | Event Log Analysis | Scans for Failed Logins, Log Clearing, and User Creation (24h). |

</details>

---

##  Troubleshooting

**Q: "Script is not signed" or "Execution of scripts is disabled on this system."**
**A:** This is a Windows security feature. Run this command in PowerShell (Admin) to allow the script to run:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
```
*Tip: You can revert this later by setting it back to `Restricted`.*

**Q: "Access Denied" errors?**
**A:** LOCKON requires **Administrator Privileges** to access the Registry, Security Event Logs, and System Folders. Please run `LOCKON_PCheck.bat` as Admin.

---

##  Version History

*   **v7.0:** Added Offline Threat DB & Process Hash Analysis.
*   **v6.4:** Refined HTML Report template and corrected table alignment.
*   **v6.0:** Introduced Drift Detection (Baseline Comparison).
*   **v5.7:** Added detailed Antivirus state translations for non-English Windows.
*   **v4.4:** Implemented Hybrid OS detection (CIM + Registry).
*   **v3.0:** Introduced JSON report export for dashboard integration.
*   **v1.0:** Initial Release (Rule-based Audit).

---

*Verified by LOCKON Defense System*
