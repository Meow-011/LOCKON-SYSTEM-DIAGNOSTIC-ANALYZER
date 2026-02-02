
# Force Clean Units Database
$UnitConfigFile = "c:\Users\natth\OneDrive\Desktop\MyProject\LOCKON PCheck\updated test\Database\config_units.json"

$CleanUnits = @(
    "บน.๖", "สบ.ทอ.", "คปอ.", "กบ.ทอ.", "สพ.ทอ.", "สอ.ทอ.", "ศปวอ.ทอ.", "ศซบ.ทอ.", "สตน.ทอ.", "ศวอ.ทอ.",
    "สธน.ทอ.", "ขส.ทอ.", "ชย.ทอ.", "สนภ.ทอ.", "อย.", "LMIS", "HRIS", "บน.๔", "บน.๒", "บน.๔๖",
    "บน.๑", "รร.นนก.", "บน.๒๓", "บน.๒๑", "บน.๓", "บน.๕", "รร.การบิน", "รพ.จันทรุเบกษา", "รพ.สีกัน",
    "บน.๗", "บน.๕๖", "กวป.ทอ.", "กวบ.ทอ.", "รพ.ภูมิพล", "พอ.ทอ.", "HIS", "CIS", "บน.๔๑"
) | Sort-Object

$Json = $CleanUnits | ConvertTo-Json -Depth 2
Set-Content -Path $UnitConfigFile -Value $Json -Encoding UTF8

Write-Host "Database reset to $($CleanUnits.Count) clean units." -ForegroundColor Green
