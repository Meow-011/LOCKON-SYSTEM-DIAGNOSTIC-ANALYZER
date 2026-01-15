@echo off
cls
echo ==========================================================
echo  Launching the Security Audit Dashboard Generator...
echo ==========================================================
echo.
echo  This will scan the 'AuditReports' folder and
echo  open a summary in your browser.
echo.

REM --- This script does NOT require Admin rights ---
REM We just Bypass the execution policy to run the .ps1 file

powershell.exe -ExecutionPolicy Bypass -File "%~dp0Generate-Dashboard.ps1"

echo.
echo ==========================================================
echo  Dashboard generation complete.
echo  If the browser did not open, the script may
echo  have encountered an error.
echo ==========================================================
echo.
pause