@echo off
REM ============================================================
REM   VlanHopSim Launcher  -  by Mohamad Yaghoobi
REM ============================================================
REM   Bypasses execution policy and path issues automatically.
REM   Just double-click this file (or right-click -> Run as Admin
REM   for the first run to register the Event Log source).
REM ============================================================

setlocal
cd /d "%~dp0"

echo.
echo  Launching VlanHopSim from: %~dp0
echo.

REM Unblock the PS1 in case it was downloaded
powershell.exe -NoProfile -Command "Unblock-File -Path '%~dp0VlanHopSim-Final.ps1' -ErrorAction SilentlyContinue"

REM Run the script with execution policy bypass
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0VlanHopSim-Final.ps1"

echo.
pause
