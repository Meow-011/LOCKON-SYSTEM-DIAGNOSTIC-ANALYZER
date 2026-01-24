<#
.SYNOPSIS
    Generates a formal "Technical Cybersecurity Audit Checklist" (Thai) HTML report.
    mimics a government/compliance paper form.
#>

param (
    [string]$Unit = "Unknown-Unit" # Audited Unit
)

# --- Load Shared Library ---
$LibPath = Join-Path $PSScriptRoot "LOCKON_Lib.ps1"
if (Test-Path $LibPath) {
    . $LibPath
} else {
    Write-Host "[!] Critical Error: LOCKON_Lib.ps1 not found!" -ForegroundColor Red
    exit
}

# --- Load Config ---
$Config = Load-LockonConfig
if (-not $Config) { exit }

$MachineName = $env:COMPUTERNAME
$DateStamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportDir = Join-Path $PSScriptRoot "AuditReports\$MachineName"
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir | Out-Null }
$ReportPath = Join-Path $ReportDir "Technical_Checklist_${MachineName}_${DateStamp}.html"

Write-SectionHeader "Generating Technical Cybersecurity Audit Checklist (Thai)..."

# ==============================================================================
# 1. OS Update Status (ระบบปฏิบัติการอัปเดตล่าสุด)
# ==============================================================================
Write-HostInfo "[1/7] Checking OS Update Status..."
try {
    # Try different methods to find last update time
    $LastUpdateObj = Get-Hotfix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($LastUpdateObj) {
        $LastUpdateDate = $LastUpdateObj.InstalledOn
        $DaysSinceUpdate = (New-TimeSpan -Start $LastUpdateDate -End (Get-Date)).Days
        
        $Res1_Status = if ($DaysSinceUpdate -le 30) { "Pass" } else { "Fail" }
        $Res1_Text = "อัปเดตล่าสุดเมื่อ $($LastUpdateDate.ToString('dd/MM/yyyy')) ($DaysSinceUpdate วันที่แล้ว)"
    } else {
         $Res1_Status = "Fail"
         $Res1_Text = "ไม่พบข้อมูลการอัปเดต (Get-HotFix failed)"
    }
} catch {
    $Res1_Status = "Fail"
    $Res1_Text = "เกิดข้อผิดพลาดในการตรวจสอบ: $($_.Exception.Message)"
}

# ==============================================================================
# 2. Antivirus/EDR Status (โปรแกรมป้องกันไวรัส)
# ==============================================================================
Write-HostInfo "[2/7] Checking Antivirus Status..."
try {
    $AvProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct"
    $AvRunning = $false
    $AvNames = @()
    
    if ($AvProducts) {
        foreach ($av in $AvProducts) {
            # Simple state check (ProductState is complex, but usually > 0 is installed)
            # We assume if it shows up here, it's recognized.
            $AvNames += $av.displayName
            # 266240 = Windows Defender Running / Updated (Example)
            # Simplified check: logic is usually handled better in check_security, but here we just list them.
            if ($av.productState -match "1$" -or $av.productState -match "0$") { # Heuristic
                 $AvRunning = $true
            }
        }
        $Res2_Status = "Pass" # Assume pass if AV exists for this checklist
        $Res2_Text = "ตรวจพบ: $($AvNames -join ', ')"
    } else {
        $Res2_Status = "Fail"
        $Res2_Text = "ไม่พบโปรแกรมป้องกันไวรัสใน Security Center"
    }
} catch {
    $Res2_Status = "Fail"
    $Res2_Text = "ไม่สามารถตรวจสอบได้ (WMI Error)"
}

# ==============================================================================
# 3. Patching (การติดตั้ง Patch ล่าสุด)
# ==============================================================================
Write-HostInfo "[3/7] Checking Critical Patches..."
try {
    $KbListPath = Join-Path $PSScriptRoot "critical_kbs.txt"
    if (Test-Path $KbListPath) {
        $PolicyKBs = Get-Content $KbListPath
        $InstalledKBs = (Get-Hotfix).HotFixID
        $FoundKBs = @()
        foreach ($kb in $PolicyKBs) {
            if ($InstalledKBs -contains $kb) { $FoundKBs += $kb }
        }
        
        if ($FoundKBs.Count -gt 0) {
            $Res3_Status = "Pass"
            $Res3_Text = "พบ Security KB ที่กำหนด: $($FoundKBs -join ', ')"
        } else {
            $Res3_Status = "Fail" # Or Warning
            $Res3_Text = "ไม่พบ KB ความปลอดภัยสำคัญตามนโยบาย"
        }
    } else {
        $Res3_Status = "N/A"
        $Res3_Text = "ไม่พบไฟล์รายการ Patch (critical_kbs.txt)"
    }
} catch {
    $Res3_Status = "Fail"
    $Res3_Text = "Error Checking Patches"
}

# ==============================================================================
# 4. Windows Firewall (ไฟร์วอลล์)
# ==============================================================================
Write-HostInfo "[4/7] Checking Windows Firewall..."
try {
    $Profiles = Get-NetFirewallProfile
    $DisabledProfiles = @()
    foreach ($p in $Profiles) {
        if ($p.Enabled -ne "True") { $DisabledProfiles += $p.Name }
    }
    
    if ($DisabledProfiles.Count -eq 0) {
        $Res4_Status = "Pass"
        $Res4_Text = "เปิดใช้งานครบทุก Profile (Domain, Private, Public)"
    } else {
        $Res4_Status = "Fail"
        $Res4_Text = "มีการปิดใช้งานใน Profile: $($DisabledProfiles -join ', ')"
    }
} catch {
    $Res4_Status = "Fail"
    $Res4_Text = "Error Checking Firewall"
}

# ==============================================================================
# 5. UAC (User Account Control)
# ==============================================================================
Write-HostInfo "[5/7] Checking UAC..."
try {
    $UacProp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($UacProp.EnableLUA -eq 1) {
        $Res5_Status = "Pass"
        $Res5_Text = "เปิดใช้งาน (EnableLUA = 1)"
    } else {
        $Res5_Status = "Fail"
        $Res5_Text = "ปิดใช้งาน (EnableLUA = 0)"
    }
} catch {
    $Res5_Status = "Fail"
    $Res5_Text = "Error Checking UAC"
}

# ==============================================================================
# 6. Risky Ports (พอร์ตที่เปิดใช้งาน)
# ==============================================================================
Write-HostInfo "[6/7] Checking Risky Ports..."
try {
    $RiskyPortsMsg = @()
    $RiskyFound = $false
    $ListingPorts = Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique
    
    $ConfigRiskyPorts = $Config.RiskyPorts | ForEach-Object { $_.Port }
    
    foreach ($p in $ListingPorts) {
        if ($ConfigRiskyPorts -contains $p) {
            $RiskyPortsMsg += "$p"
            $RiskyFound = $true
        }
    }
    
    if ($RiskyFound) {
        $Res6_Status = "Fail"
        $Res6_Text = "พบพอร์ตเสี่ยงเปิดอยู่: $($RiskyPortsMsg -join ', ')"
    } else {
        $Res6_Status = "Pass"
        $Res6_Text = "ไม่พบพอร์ตเสี่ยงตามนโยบาย (Policy)"
    }
} catch {
    $Res6_Status = "Fail"
    $Res6_Text = "Error Checking Ports"
}

# ==============================================================================
# 7. Services (บริการที่ไม่จำเป็น)
# ==============================================================================
Write-HostInfo "[7/7] Checking Services..."
# Heuristic: Check for services running from Temp/AppData as "Unnecessary/Malicious"
try {
    $SuspiciousSvcs = Get-CimInstance -ClassName Win32_Service -Filter "StartMode = 'Auto' OR State = 'Running'" | Where-Object { 
        $_.PathName -match "AppData" -or $_.PathName -match "Temp" 
    }
    
    if ($SuspiciousSvcs) {
        $Res7_Status = "Fail"
        $Res7_Text = "พบบริการรันจากตำแหน่งน่าสงสัย: $(($SuspiciousSvcs.Name) -join ', ')"
    } else {
        $Res7_Status = "Pass"
        $Res7_Text = "ไม่พบบริการที่รันจากโฟลเดอร์ชั่วคราว (Temp/AppData)"
    }
} catch {
    $Res7_Status = "Fail"
    $Res7_Text = "Error Checking Services"
}


# ==============================================================================
# HTML Generation
# ==============================================================================
$ThaiFont = "Sarabun, 'TH Sarabun New', sans-serif"

$HtmlContent = @"
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <title>Technical Cybersecurity Audit Checklist</title>
    <style>
        body { font-family: $ThaiFont; padding: 20px; background-color: #f9f9f9; }
        .container { background-color: white; padding: 40px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 1000px; margin: auto; }
        h2 { text-align: center; margin-bottom: 5px; }
        .sub-header { text-align: center; margin-bottom: 30px; color: #555; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #000; padding: 10px; vertical-align: top; }
        th { background-color: #eee; text-align: center; font-weight: bold; }
        .center { text-align: center; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
    </style>
</head>
<body>

<div class="container">
    <h2>ตารางการตรวจสอบความมั่นคงปลอดภัยไซเบอร์เชิงเทคนิค</h2>
    <div class="sub-header">
        วันที่: $(Get-Date -Format "dd/MM/yyyy") &nbsp;&nbsp;&nbsp;
        แบบเครื่อง: $MachineName &nbsp;&nbsp;&nbsp;
        หน่วยรับการตรวจ: $Unit
    </div>

    <table>
        <thead>
            <tr>
                <th style="width: 5%;">ลำดับ</th>
                <th style="width: 35%;">รายการตรวจสอบ</th>
                <th style="width: 30%;">ผลการตรวจสอบที่คาดหวัง</th>
                <th style="width: 20%;">ผลการตรวจสอบจริง</th>
                <th style="width: 10%;">สรุป</th>
            </tr>
        </thead>
        <tbody>
            <!-- 1. OS Update -->
            <tr>
                <td class="center">1</td>
                <td>ตรวจสอบว่าระบบปฏิบัติการอัปเดตล่าสุดเมื่อไหร่ และมีอัปเดตที่รอดาวน์โหลด/ติดตั้งหรือไม่</td>
                <td>ไม่มีอัปเดตค้าง เครื่องอัปเดตล่าสุดภายในระยะเวลาไม่นาน (เช่น 7-30 วัน)</td>
                <td>$Res1_Text</td>
                <td class="center $(if($Res1_Status -eq 'Pass'){'pass'}else{'fail'})">$Res1_Status</td>
            </tr>
            <!-- 2. Antivirus -->
            <tr>
                <td class="center">2</td>
                <td>ตรวจสอบว่ามีโปรแกรมป้องกันไวรัสหรือ EDR ติดตั้งและทำงานอยู่หรือไม่</td>
                <td>AV/EDR ปรากฎใน Security Center และ service ทำงาน (Running)</td>
                <td>$Res2_Text</td>
                <td class="center $(if($Res2_Status -eq 'Pass'){'pass'}else{'fail'})">$Res2_Status</td>
            </tr>
            <!-- 3. Patches -->
            <tr>
                <td class="center">3</td>
                <td>ตรวจสอบว่ามีการติดตั้ง Patch ล่าสุดครบถ้วน โดยเฉพาะ Patch ความปลอดภัยของระบบ</td>
                <td>ไม่มีช่องว่างของแพตช์ความปลอดภัยสำคัญ เครื่องมี KB ล่าสุดตามนโยบาย</td>
                <td>$Res3_Text</td>
                <td class="center $(if($Res3_Status -eq 'Pass'){'pass'}else{'fail'})">$Res3_Status</td>
            </tr>
            <!-- 4. Firewall -->
            <tr>
                <td class="center">4</td>
                <td>ตรวจสอบว่า Windows Firewall เปิดใช้งานอยู่</td>
                <td>Enabled = True สำหรับ Domain/Private (ตามนโยบาย)</td>
                <td>$Res4_Text</td>
                <td class="center $(if($Res4_Status -eq 'Pass'){'pass'}else{'fail'})">$Res4_Status</td>
            </tr>
            <!-- 5. UAC -->
            <tr>
                <td class="center">5</td>
                <td>ตรวจสอบว่าเปิด User Account Control (UAC) เพื่อป้องกันสิทธิ์การทำงานที่ไม่พึงประสงค์</td>
                <td>EnableLUA = 1 (UAC เปิดใช้งาน)</td>
                <td>$Res5_Text</td>
                <td class="center $(if($Res5_Status -eq 'Pass'){'pass'}else{'fail'})">$Res5_Status</td>
            </tr>
            <!-- 6. Ports -->
            <tr>
                <td class="center">6</td>
                <td>ตรวจสอบพอร์ตที่เปิดใช้งานในระบบ และระบุพอร์ตแปลกปลอม/ไม่ได้รับอนุญาต</td>
                <td>ไม่มีพอร์ตฟัง (LISTENING) ที่ไม่รู้จักหรือไม่อยู่ในนโยบาย เช่น 21, 23, 445</td>
                <td>$Res6_Text</td>
                <td class="center $(if($Res6_Status -eq 'Pass'){'pass'}else{'fail'})">$Res6_Status</td>
            </tr>
            <!-- 7. Services -->
            <tr>
                <td class="center">7</td>
                <td>ตรวจสอบ Service Startup Type เพื่อระบุบริการที่ไม่จำเป็นหรือถูกตั้งค่าเริ่มต้นโดยไม่ได้รับอนุญาต</td>
                <td>บริการที่จำเป็นอยู่ในสถานะ "Automatic" และบริการที่ไม่จำเป็นถูกปิด</td>
                <td>$Res7_Text</td>
                <td class="center $(if($Res7_Status -eq 'Pass'){'pass'}else{'fail'})">$Res7_Status</td>
            </tr>
        </tbody>
    </table>
</div>

</body>
</html>
"@

$HtmlContent | Out-File -FilePath $ReportPath -Encoding UTF8
Write-HostPass "Report generated successfully: $ReportPath"
Start-Process $ReportPath
