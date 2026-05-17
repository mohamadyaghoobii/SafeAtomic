@echo off
REM ============================================================
REM   AtomicHunt Launcher  -  by Mohamad Yaghoobi
REM ============================================================
REM   - Self-elevates to Administrator
REM   - Auto-detects offline mode (if .\Modules\ folder exists,
REM     passes -OfflineOnly so the script does not try PSGallery)
REM   - Bypasses execution policy
REM ============================================================

setlocal
cd /d "%~dp0"

REM Self-elevate to admin
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo.
    echo  Requesting Administrator privileges...
    echo  Click "Yes" on the UAC prompt.
    echo.
    powershell.exe -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo  Running as Administrator: OK
echo  Launching AtomicHunt from: %~dp0

REM Detect offline mode: if Modules\ exists, force -OfflineOnly so we never
REM reach out to PSGallery on this isolated host.
set "OFFLINE_FLAG="
if exist "%~dp0Modules" (
    set "OFFLINE_FLAG=-OfflineOnly"
    echo  Offline mode: Modules\ folder detected -^> using bundled modules.
) else (
    echo  Online mode: no Modules\ folder; will use system / PSGallery.
)
echo.

REM Unblock the PS1 in case it was downloaded from the internet
powershell.exe -NoProfile -Command "Unblock-File -Path '%~dp0Invoke-AtomicHunt.ps1' -ErrorAction SilentlyContinue"

REM Run the script
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-AtomicHunt.ps1" %OFFLINE_FLAG%

echo.
pause
