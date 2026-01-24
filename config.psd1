# 
# Security Policy Configuration File
# ----------------------------------
# This file stores the policies for check_security.ps1
# (v5.7) NEW: Added more AV state codes (397568, 397328)
# (v5.5) NEW: Added AntivirusStateTranslations for localization.
# (v4.5) Removed DaysSinceUpdateThreshold

@{
    # === 4 & 7. Risky Ports Policy ===
    # (v4.0) Upgraded to object list for detailed reporting.
    # Define risky ports with their service name and risk description.

    RiskyPorts = @(
        @{ 
            Port = 21
            Service = "FTP (File Transfer Protocol)"
            Risk = "รับส่งไฟล์แบบไม่เข้ารหัส; มักเปิด Anonymous/ส่งรหัสผ่านแบบชัดเจน เสี่ยงถูกดักฟัง/Brute-force/อัปโหลดไฟล์อันตราย" 
        },
        @{ 
            Port = 22
            Service = "SSH (Secure Shell)"
            Risk = "ช่องทาง Remote Access ยอดนิยมของ Linux/Admin; ใน Windows ทั่วไปไม่ควรเปิด เว้นแต่ติดตั้ง OpenSSH Server ซึ่งเสี่ยงต่อการถูก Brute Force" 
        },
        @{ 
            Port = 23
            Service = "Telnet"
            Risk = "อันตรายมาก! รับส่งข้อมูลแบบ Plain Text สามารถถูกดักจับรหัสผ่านได้ง่ายดาย ควรปิดถาวรและใช้ SSH แทน" 
        },
        @{ 
            Port = 25
            Service = "SMTP (Simple Mail Transfer Protocol)"
            Risk = "พอร์ตส่งอีเมล; เครื่อง Client ปกติไม่ควรเปิด ถ้าเปิดอาจเป็น Spam Bot หรือ Relay ที่ถูกแฮก" 
        },
        @{ 
            Port = 135
            Service = "RPC (Remote Procedure Call)"
            Risk = "ใช้สำหรับการเชื่อมต่อและค้นหาบริการระยะไกลของ Windows, มักถูกใช้เป็นจุดเริ่มต้นในการโจมตีภายใน" 
        },
        @{ 
            Port = 137
            Service = "NetBIOS Name Service (NBNS, UDP/137)"
            Risk = "ใช้ resolve ชื่อแบบเก่าใน Windows; เสี่ยง NBNS spoofing/ข้อมูลหลุด (ชื่อโฮสต์ โดเมน) และเป็นจุดเริ่มต้นของการ enumeration ภายใน" 
        },
        @{ 
            Port = 138
            Service = "NetBIOS Datagram Service (UDP/138)"
            Risk = "บริการประกาศ/ค้นหาทรัพยากรแชร์ยุคเก่า; เสี่ยงข้อมูลเครือข่าย/แชร์โฟลเดอร์รั่วไหล และถูกใช้ต่อยอดโจมตี SMB ภายใน" 
        },
        @{ 
            Port = 139
            Service = "NetBIOS Session Service"
            Risk = "บริการเวอร์ชันเก่าสำหรับ File/Printer Sharing, ควรปิดและใช้พอร์ต 445 (SMB) ผ่าน TCP/IP โดยตรง" 
        },
        @{ 
            Port = 445
            Service = "SMB (Server Message Block)"
            Risk = "พอร์ตหลักสำหรับ File/Printer Sharing นี่คือช่องโหว่ที่ Ransomware (เช่น WannaCry, NotPetya) ใช้โจมตีเพื่อแพร่กระจาย" 
        },
        @{ 
            Port = 1433
            Service = "SQL Server (MSSQL)"
            Risk = "ฐานข้อมูล Microsoft SQL; ไม่ควรเปิด Public/Internet ถ้าตั้งรหัสผ่าน sa อ่อนแอ จะถูกยึดเครื่องโดยง่าย" 
        },
        @{ 
            Port = 3306
            Service = "MySQL Database"
            Risk = "ฐานข้อมูล MySQL; มักตกเป็นเป้าหมายของการยิงรหัสผ่านและการโจมตี Web Application" 
        },
        @{ 
            Port = 3389
            Service = "RDP (Remote Desktop Protocol)"
            Risk = "ช่องทางยอดนิยมที่แฮกเกอร์ใช้ Brute Force (เดาสุ่มรหัสผ่าน) เพื่อยึดเครื่องจากระยะไกล" 
        },
        @{ 
            Port = 5900
            Service = "VNC (Virtual Network Computing)"
            Risk = "โปรแกรม Remote Desktop ทางเลือกที่มักไม่ปลอดภัย (ไม่มีการเข้ารหัสที่ดี) และมักถูก Hacker แอบติดตั้ง (Backdoor)" 
        },
        @{ 
            Port = 5985
            Service = "WinRM (HTTP)"
            Risk = "พอร์ตสำหรับ PowerShell Remoting (แบบไม่เข้ารหัส) ถ้าตั้งค่าไม่ปลอดภัยจะเสี่ยงมาก" 
        },
        @{ 
            Port = 5986
            Service = "WinRM (HTTPS)"
            Risk = "พอร์ตสำหรับ PowerShell Remoting (แบบเข้ารหัส) ควรตรวจสอบว่าจำเป็นต้องเปิดหรือไม่ และจำกัด IP ที่เข้าถึงได้" 
        },
        @{ 
            Port = 53
            Service = "DNS (Domain Name System)"
            Risk = "เครื่อง Client ปกติ 'ห้ามเปิด' Port นี้; ถ้าเปิดแปลว่าเครื่องคุณทำตัวเป็น DNS Server หรือติดมัลแวร์ DNS Hijacking" 
        },
        @{ 
            Port = 1080
            Service = "SOCKS Proxy"
            Risk = "บริการ Proxy; มักถูก Malware ใช้เป็น 'ทางผ่าน' (Pivot) เพื่อโจมตีเครื่องอื่นในเครือข่าย หรือใช้หลีกเลี่ยง Firewall" 
        },
        @{ 
            Port = 3128
            Service = "Squid Proxy"
            Risk = "บริการ Web Proxy; ถ้าไม่ได้ตั้งใจติดตั้ง แสดงว่าอาจมีโปรแกรมแฝงเปิดช่องทางลับออกสู่อินเทอร์เน็ต" 
        },
        @{ 
            Port = 8080
            Service = "HTTP Alternate / Proxy"
            Risk = "พอร์ตยอดนิยมของ Web Admin Panel หรือ Proxy; ตรวจสอบว่าโปรแกรมใดเปิดใช้ (เช่น Tomcat, Jenkins) หากไม่ทราบที่มาควรปิด" 
        },
        @{ 
            Port = 8443
            Service = "HTTPS Alternate / Proxy"
            Risk = "เหมือนกับ 8080 แต่เป็นแบบเข้ารหัส (HTTPS); มักเป็นหน้า Login ของระบบจัดการต่างๆ ที่ไม่ควรเปิด Public" 
        },
        @{ 
            Port = 5432
            Service = "PostgreSQL"
            Risk = "ฐานข้อมูล PostgreSQL; เป้าหมายใหม่ของ Ransomware หากเปิด Public และตั้งรหัสผ่าน Default ไว้" 
        },
        @{ 
            Port = 6379
            Service = "Redis"
            Risk = "ระบบแคช Redis; มักไม่มี Authentication โดย Default ถ้าเปิด Public จะถูกยึดเครื่องได้ง่ายมาก (Remote Code Execution)" 
        },
        @{ 
            Port = 27017
            Service = "MongoDB"
            Risk = "ฐานข้อมูล NoSQL ยอดนิยม; มักถูก Ransomware โจมตีโดยการลบข้อมูลทั้งหมดแล้วเรียกค่าไถ่ (เพราะ Default Config เปิดกว้าง)" 
        }
    )

    # === Report Folder Policy ===
    # The main folder (in the script's root) to store all reports.


    # === (v5.7) Antivirus State Translations ===
    # Define the translations for AV state codes.
    # The script will use these to populate the report.
    # It will fall back to English if a code is missing.
    AntivirusStateTranslations = @(
        @{ Code = "397312"; Status = "Running"; Description = "เปิดสมบูรณ์แบบ (Real-time protection ทำงาน)" },
        @{ Code = "397568"; Status = "Running"; Description = "เปิดสมบูรณ์แบบ (อัปเดตล่าสุด)" }, # (v5.7) NEW
        @{ Code = "397584"; Status = "Running"; Description = "เปิดสมบูรณ์แบบ (อัปเดตและป้องกันครบถ้วน)" }, # Win11/Modern Defender
        @{ Code = "393216"; Status = "Running"; Description = "เปิดอยู่ (แต่ Real-time protection อาจจะถูกปิดไว้ชั่วคราว)" },
        @{ Code = "393232"; Status = "WARN";    Description = "เปิดอยู่ (แต่ต้องการการดำเนินการ/สแกน)" }, # Action Needed
        @{ Code = "397328"; Status = "Running"; Description = "เปิดอยู่ (แต่ต้องการรีบูตเครื่อง)" }, # (v5.7) NEW
        @{ Code = "266240"; Status = "Not Running"; Description = "ปิด (Off)" },
        @{ Code = "393472"; Status = "Not Running"; Description = "ปิดชั่วคราว (Snoozed) (มักเกิดเมื่อมี AV ตัวอื่นทำงานอยู่)" }
        # Add other state codes here as you discover them
    )

    # === Unwanted Software Policy ===
    # List of software names (partial match) that violate company policy.
    UnwantedSoftware = @(
        "uTorrent",
        "BitTorrent",
        "Cheat Engine",
        "Baidu",
        "KMSPico",
        "KMSAuto",
        "Microsoft Toolkit",
        "AAct",
        "Re-Loader",
        "HWIDGen",
        "Keygen",
        "Mimikatz"
    )

    # === (v8.2) System Paths (Centralized Database Locations) ===
    # These paths are relative to the script execution folder ($PSScriptRoot).
    # Modules should use these values via $Config.SystemPaths
    SystemPaths = @{
        CriticalKBs  = "critical_kbs.txt"
        ThreatDB     = "threat_db.txt"
        Baseline     = "config_baseline.json"
        UnitsConfig  = "config_units.json"
    }

    # (v8.3) Main Report Folder (Relative to script root)
    MainReportFolder = "AuditReports";
}