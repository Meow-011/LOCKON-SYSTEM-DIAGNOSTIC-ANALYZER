@echo off
title LOCKON: SYSTEM DIAGNOSTIC ANALYZER
cls

REM --- 1. Check for Admin Rights ---
REM We do this by trying to check permissions on a system file.
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --- 2. If Error (Not Admin), Relaunch Self as Admin ---
REM If the 'errorlevel' is NOT 0, we are not admin.
if '%errorlevel%' NEQ '0' (
    echo ==========================================================
    echo  Requesting Administrator permissions...
    echo ==========================================================
    REM Relaunch this same .bat file ("%~f0") using PowerShell's "RunAs" verb
    powershell.exe -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM --- 3. If We Are Here, We ARE Admin ---
cls
echo ==========================================================
echo  SUCCESS: Running Security Audit as Administrator
echo ==========================================================
echo.

REM --- 4. Run the PowerShell Script (which now assumes it is admin) ---
powershell.exe -ExecutionPolicy Bypass -File "%~dp0LOCKON_Menu.ps1"

echo.
echo ==========================================================
echo  Audit Complete.
echo ==========================================================
echo.
pause