@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Dell-Pilot-RC4.ps1"
echo.
echo Review the result above. Press any key to close.
pause >nul
