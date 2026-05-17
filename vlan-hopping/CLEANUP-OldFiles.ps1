# ============================================================
#  CLEANUP - Run this ONCE to remove all broken old copies
#  by Mohamad Yaghoobi
# ============================================================

$ErrorActionPreference = 'SilentlyContinue'

Write-Host ""
Write-Host "  Cleaning up old broken VlanHopSim copies..." -ForegroundColor Yellow
Write-Host ""

# Common locations where old broken copies might be
$paths = @(
    "$env:USERPROFILE\Downloads\Invoke-VlanHopSim.ps1",
    "$env:USERPROFILE\Downloads\Invoke-VlanHopSim (1).ps1",
    "$env:USERPROFILE\Downloads\Invoke-VlanHopSim (2).ps1",
    "$env:USERPROFILE\Downloads\Invoke-VlanHopSim (3).ps1",
    "$env:USERPROFILE\Desktop\Invoke-VlanHopSim.ps1",
    "$env:USERPROFILE\Desktop\Invoke-VlanHopSim (1).ps1"
)

$removed = 0
foreach ($p in $paths) {
    if (Test-Path $p) {
        # Check if it has the OLD bug
        $content = Get-Content $p -Raw
        if ($content -match '\$host\s*=\s*\$env:COMPUTERNAME' -or
            $content -match '\$pid\s*=\s*\$PID') {
            Write-Host "  [BUGGY] Removing: $p" -ForegroundColor Red
            Remove-Item $p -Force
            $removed++
        } else {
            Write-Host "  [OK]    Keeping: $p" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "  Done. Removed $removed buggy file(s)." -ForegroundColor Cyan
Write-Host "  Now run: .\VlanHopSim-Final.ps1   (or double-click RUN.bat)" -ForegroundColor Cyan
Write-Host ""
Read-Host "  Press Enter to exit"
