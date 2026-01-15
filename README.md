# 🛡️ LOCKON: SYSTEM DIAGNOSTIC ANALYZER

**LOCKON** is an advanced PowerShell-based security auditing and forensic tool designed for Windows environments. It provides deep visibility into system security posture, detecting potential threats, misconfigurations, and suspicious activities through over 20+ specialized checks.

![Dashboard Preview](https://via.placeholder.com/800x400?text=LOCKON+Dashboard+Preview) 
*(Replace with actual screenshot if available)*

## 🚀 Key Features

### 🔍 Security Auditing
- **Comprehensive Scan:** Performs 23+ security checks including Firewall status, UAC, Anti-Virus, and Patch levels.
- **Vulnerability Detection:** Identifies risky open ports (SMB, RDP, etc.), unpatched critical vulnerabilities, and insecure configurations.
- **Drift Detection:** Compares current system state against a baseline to detect unauthorized changes (New Admins, New Ports, File Hash Mismatches).

### 🕵️ Forensic Analysis
- **Network Forensics:** Analyzes `Hosts` file for hijacking and dumps `DNS Cache` to identify suspicious connections.
- **Event Log Analysis:** Scans Windows Security Logs (last 24h) for Brute Force attacks (4625), Log Clearing events (1102), and Account Creations (4720).
- **Persistence Hunting:** Detects suspicious Scheduled Tasks and Startup items hidden in non-standard paths (AppData, Temp).
- **Process & Connection Mapping:** Correlates active TCP/UDP connections with running processes using Threat Intelligence.

### 📊 Visualization & Reporting
- **Interactive Dashboard:** Generates a modern HTML5 Dashboard (`Generate-Dashboard.ps1`) for easy analysis.
- **Detailed Reporting:** Exports findings in JSON, HTML, and CSV formats.
- **Threat Intelligence:** Integrated hash-based malware scanning (SHA256) against a local Threat DB.

---

## 📋 Prerequisites

- **OS:** Windows 10 / 11 / Server 2016+
- **PowerShell:** Version 5.1 or later
- **Privileges:** **Administrator** rights are required for deep system scans (Registry, Event Logs, System Files).

---

## 🛠️ Installation & Usage

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Meow-011/LOCKON-SYSTEM-DIAGNOSTIC-ANALYZER.git
   cd LOCKON-SYSTEM-DIAGNOSTIC-ANALYZER
   ```

2. **Run the Tool:**
   - Double-click `LOCKON_PCheck.bat` to verify Admin privileges and launch the menu.
   - OR run via PowerShell:
     ```powershell
     .\LOCKON_Menu.ps1
     ```

3. **Menu Options:**
   - `[1] RUN SECURITY ASSESSMENT`: Full system scan with HTML/JSON report generation.
   - `[2] EDIT CONFIGURATION`: Customize check policies (e.g., allowed ports, risky software list).
   - `[3] VIEW DASHBOARD`: Launch the HTML Dashboard viewer.
   - `[4] EXPORT INVENTORY`: Dump installed software list to CSV.
   - `[5] EXIT`

---

## 📂 Project Structure

```plaintext
LOCKON/
├── LOCKON_Menu.ps1          # Main Entry Point & UI
├── check_security.ps1       # Core Security Engine (Checks 1-23)
├── Generate-Dashboard.ps1   # HTML Dashboard Generator
├── LOCKON_Lib.ps1           # Shared Library (Logging, Config)
├── threat_db.txt            # Database of known malicious hashes
├── config.psd1              # Configuration file (Policies)
├── AuditReports/            # Output Directory for scan results
└── ...
```

## ⚠️ Disclaimer

This tool is provided "as is" for educational and defensive purposes. The authors are not responsible for any damage or misuse. Always test in a controlled environment before running on production systems.

---

*Verified by LOCKON Defense System* 🛡️
