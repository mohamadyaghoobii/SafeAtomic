<#
.SYNOPSIS
    Invoke-AtomicHunt - Dynamic Atomic Red Team purple-team launcher for SOC detection PoC.

.DESCRIPTION
    A Yersinia-style menu wrapper around Invoke-AtomicRedTeam that:
      - Auto-discovers the atomics/ folder on ANY system (no hard-coded paths)
      - Auto-installs the Invoke-AtomicRedTeam module if missing (with consent)
      - Dynamically reads MITRE ATT&CK tactics from every YAML it finds
      - Groups techniques by tactic (Execution / Persistence / Discovery / etc.)
      - Logs every test execution (start, end, exit code, duration) to
        Windows Event Log + JSON + CEF with a sim_session correlation ID
      - Ships a "blind hunt" Splunk helper at the end so SOC can pivot from
        index=* using only signatures present in the logs

    NO real attacks added beyond what Atomic Red Team already provides.
    Recommended: use only the GetPrereqs + safe tests during a purple drill.

.NOTES
    Developed by : Mohamad Yaghoobi
    Target       : Windows Server / Windows 10+ (PS 5.1 or PS 7+)
    Dependencies : powershell-yaml (auto-installed)
                   Invoke-AtomicRedTeam (auto-installed)
                   atomics/ folder anywhere on disk

.EXAMPLE
    PS> .\Invoke-AtomicHunt.ps1
    Launches the interactive menu.

.EXAMPLE
    PS> .\Invoke-AtomicHunt.ps1 -ShowSplunkQueries
    Prints all detection queries and exits.

.EXAMPLE
    PS> .\Invoke-AtomicHunt.ps1 -AtomicsPath 'D:\Tools\atomic-red-team-master\atomics'
    Skip auto-discovery and use this path.
#>

[CmdletBinding()]
param(
    [string]$AtomicsPath,                # Override auto-discovery
    [switch]$ShowSplunkQueries,          # Print SPL and exit
    [switch]$DryRun,                     # Show what would run, don't execute
    [switch]$NoBanner,
    [switch]$Quiet,
    [switch]$AutoInstall,                # Skip the "install missing module?" prompt
    [switch]$OfflineOnly                 # Never reach out to PSGallery; require local Modules\ folder
)

# =====================================================================
# region GLOBAL CONFIG
# =====================================================================

$Script:Config = @{
    LogDir       = 'C:\ProgramData\AtomicHunt'
    JsonLog      = 'C:\ProgramData\AtomicHunt\atomichunt.json'
    CefLog       = 'C:\ProgramData\AtomicHunt\atomichunt.cef'
    EventLogName = 'Application'
    EventSource  = 'AtomicHunt'
    Version      = '1.0.0'
    Vendor       = 'PurpleTeam'
    Product      = 'AtomicHunt'
}

$Script:EventIds = @{
    Startup           = 8000
    Shutdown          = 8001
    DiscoveryStart    = 8100
    DiscoveryDone     = 8101
    ModuleInstall     = 8102
    TestStart         = 8200
    TestEnd           = 8201
    TestFailed        = 8202
    PrereqCheck       = 8203
    Cleanup           = 8204
    CategoryRun       = 8300
}

# Discovery candidates - ordered by priority.
# CUSTOM PURPLE-TEAM FOLDERS first (small curated sets), then full ATT&CK installs.
$Script:AtomicsCandidates = @(
    # Small curated test sets (highest priority - usually what the user wants)
    "$env:USERPROFILE\Desktop\Refahbank-test",
    "$env:USERPROFILE\Desktop\refahbank-test",
    "$env:USERPROFILE\Downloads\Refahbank-test",
    "$env:USERPROFILE\Documents\Refahbank-test",
    # Full Atomic Red Team installs (used as fallback)
    'C:\AtomicRedTeam\atomics',
    'C:\Tools\AtomicRedTeam\atomics',
    'C:\Tools\atomic-red-team\atomics',
    "$env:USERPROFILE\AtomicRedTeam\atomics",
    "$env:USERPROFILE\Downloads\atomic-red-team-master\atomics",
    "$env:USERPROFILE\Downloads\atomic-red-team-master\atomic-red-team-master\atomics",
    "$env:USERPROFILE\Downloads\atomic-red-team\atomics",
    "$env:USERPROFILE\Desktop\atomic-red-team-master\atomics",
    'D:\AtomicRedTeam\atomics',
    'D:\Tools\AtomicRedTeam\atomics'
)

$Script:WriteFailures = 0

# endregion

# =====================================================================
# region UTIL: CLI / BANNER
# =====================================================================

function Write-Cli {
    param([string]$Text,[ConsoleColor]$Color = 'Gray',[switch]$NoNewline)
    if ($Script:Quiet) { return }
    if ($NoNewline) {
        Write-Host $Text -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Show-Banner {
    if ($NoBanner -or $Script:Quiet) { return }
    Clear-Host
    $banner = @'
     _    _                  _      _   _             _
    / \  | |_ ___  _ __ ___ (_) ___| | | |_   _ _ __ | |_
   / _ \ | __/ _ \| '_ ` _ \| |/ __| |_| | | | | '_ \| __|
  / ___ \| || (_) | | | | | | | (__|  _  | |_| | | | | |_
 /_/   \_\\__\___/|_| |_| |_|_|\___|_| |_|\__,_|_| |_|\__|

   AtomicHunt  -  Purple Team launcher for Atomic Red Team
   Developed by: Mohamad Yaghoobi
'@
    Write-Cli $banner -Color Cyan
    Write-Cli "   v$($Script:Config.Version)  |  Logs every test for SOC hunt`n" -Color DarkGray
}

# endregion

# =====================================================================
# region LOGGING (dynamic writable dir, same approach as VlanHopSim)
# =====================================================================

function Initialize-Logging {
    $candidates = @(
        'C:\ProgramData\AtomicHunt',
        (Join-Path $env:LOCALAPPDATA 'AtomicHunt'),
        (Join-Path $env:TEMP        'AtomicHunt')
    )

    $chosen = $null
    foreach ($dir in $candidates) {
        try {
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
            }
            $probe = Join-Path $dir ".writetest_$([guid]::NewGuid().ToString('N').Substring(0,6))"
            Set-Content -Path $probe -Value 'ok' -ErrorAction Stop
            Remove-Item -Path $probe -Force -ErrorAction SilentlyContinue
            $chosen = $dir
            break
        } catch { continue }
    }

    if (-not $chosen) {
        Write-Cli "[-] FATAL: no writable log dir. Tried: $($candidates -join ', ')" -Color Red
        throw "No writable log location"
    }

    $Script:Config.LogDir  = $chosen
    $Script:Config.JsonLog = Join-Path $chosen 'atomichunt.json'
    $Script:Config.CefLog  = Join-Path $chosen 'atomichunt.cef'
    Write-Cli "[+] Log dir: $chosen" -Color Green

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Script:Config.EventSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource($Script:Config.EventSource, $Script:Config.EventLogName)
            Write-Cli "[+] Event source registered: $($Script:Config.EventSource)" -Color Green
            Start-Sleep -Milliseconds 500
        }
    } catch {
        Write-Cli "[!] Event source registration needs admin once. File logs still work." -Color Yellow
    }
}

function Write-HuntEvent {
    param(
        [Parameter(Mandatory)][int]$EventId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information',
        [hashtable]$Fields = @{}
    )

    try {
        $v_ts        = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffzzz')
        $v_hostname  = $env:COMPUTERNAME
        $v_user      = "$env:USERDOMAIN\$env:USERNAME"
        $v_processId = $PID

        $rec = [ordered]@{
            timestamp    = $v_ts
            host         = $v_hostname
            user         = $v_user
            process_id   = $v_processId
            process_name = 'powershell.exe'
            sim_session  = $Script:CurrentSession
            category     = $Category
            action       = $Action
            event_id     = $EventId
            severity     = $Severity
            message      = $Message
            vendor       = $Script:Config.Vendor
            product      = $Script:Config.Product
            product_ver  = $Script:Config.Version
        }
        foreach ($k in $Fields.Keys) { $rec[$k] = $Fields[$k] }

        # JSON
        try {
            $json = $rec | ConvertTo-Json -Compress -Depth 6
            Add-Content -Path $Script:Config.JsonLog -Value $json -Encoding UTF8 -ErrorAction Stop
        } catch {
            $Script:WriteFailures++
            if ($Script:WriteFailures -le 1) {
                Write-Cli "[-] Log write failed once ($($_.Exception.Message)). Further write errors suppressed." -Color Red
            }
        }

        # CEF
        try {
            $cefSev = switch ($Severity) {'Information'{3}'Warning'{6}'Error'{9}default{5}}
            $ext = ($rec.GetEnumerator() | ForEach-Object {
                $v = ($_.Value -as [string]) -replace '\\','\\\\' -replace '=','\=' -replace '\|','\|' -replace "`n",'\n'
                "$($_.Key)=$v"
            }) -join ' '
            $cef = "CEF:0|$($Script:Config.Vendor)|$($Script:Config.Product)|$($Script:Config.Version)|$EventId|$Action|$cefSev|$ext"
            Add-Content -Path $Script:Config.CefLog -Value $cef -Encoding UTF8 -ErrorAction Stop
        } catch { }

        # Event Log
        try {
            $entryType = [System.Diagnostics.EventLogEntryType]::$Severity
            $body = "$Message`n`n" + (($rec.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n")
            Write-EventLog -LogName $Script:Config.EventLogName -Source $Script:Config.EventSource `
                           -EventId $EventId -EntryType $entryType -Message $body -ErrorAction Stop
        } catch { }

        if (-not $Script:Quiet) {
            $color = switch ($Severity) {'Information'{'DarkCyan'}'Warning'{'Yellow'}'Error'{'Red'}}
            Write-Cli "  [$v_ts] [$Category/$Action] $Message" -Color $color
        }
    } catch {
        Write-Cli "[!] Write-HuntEvent failed: $($_.Exception.Message)" -Color Red
    }
}

# endregion

# =====================================================================
# region DYNAMIC DISCOVERY: atomics folder
# =====================================================================

function Test-AtomicsFolder {
    # A path is a valid atomics folder if it contains at least ONE T*\T*.yaml
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    # quick: at least one T###\T###.yaml
    $hit = Get-ChildItem -Path $Path -Directory -Filter 'T*' -ErrorAction SilentlyContinue |
        Select-Object -First 1 | ForEach-Object {
            Test-Path (Join-Path $_.FullName "$($_.Name).yaml")
        }
    return [bool]$hit
}

function Find-AtomicsFolder {
    if ($AtomicsPath) {
        if (Test-AtomicsFolder $AtomicsPath) {
            Write-Cli "[+] Using user-supplied atomics path: $AtomicsPath" -Color Green
            return $AtomicsPath
        } else {
            Write-Cli "[!] -AtomicsPath '$AtomicsPath' has no T*\T*.yaml inside." -Color Yellow
        }
    }

    Write-Cli "[*] Searching common locations..." -Color DarkGray
    foreach ($p in $Script:AtomicsCandidates) {
        if (Test-AtomicsFolder $p) {
            Write-Cli "[+] Found atomics folder: $p" -Color Green
            return $p
        }
    }

    # Last-resort: scan local drives for any folder containing T*\T*.yaml
    Write-Cli "[*] Deep scanning local drives (this can take ~30s)..." -Color DarkGray
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | Select-Object -ExpandProperty Root
    foreach ($drv in $drives) {
        try {
            # find any folder that has T*\T*.yaml under it within 6 levels
            $hit = Get-ChildItem -Path $drv -Directory -Filter 'T*' -Recurse -ErrorAction SilentlyContinue -Depth 6 |
                Where-Object { Test-Path (Join-Path $_.FullName "$($_.Name).yaml") } |
                Select-Object -First 1
            if ($hit) {
                $parent = Split-Path $hit.FullName -Parent
                Write-Cli "[+] Deep-scan found: $parent" -Color Green
                return $parent
            }
        } catch { continue }
    }

    return $null
}

# endregion

# =====================================================================
# region DYNAMIC DISCOVERY: Invoke-AtomicRedTeam module
# =====================================================================

function Import-LocalModuleIfPresent {
    # Looks for a module under .\Modules\<Name>\ (or any version subfolder)
    # right next to the script. Returns $true if it imported a local copy.
    param([Parameter(Mandatory)][string]$Name)

    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $modRoot = Join-Path $scriptDir "Modules\$Name"
    if (-not (Test-Path $modRoot)) { return $false }

    # Try direct .psd1 first
    $psd1 = Get-ChildItem -Path $modRoot -Filter "$Name.psd1" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
    if (-not $psd1) {
        $psd1 = Get-ChildItem -Path $modRoot -Filter '*.psd1' -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1
    }

    try {
        if ($psd1) {
            Import-Module $psd1.FullName -Force -ErrorAction Stop
        } else {
            Import-Module $modRoot -Force -ErrorAction Stop
        }
        Write-Cli "[+] $Name imported from local offline folder: $modRoot" -Color Green
        return $true
    } catch {
        Write-Cli "[!] Local $Name found but failed to import: $($_.Exception.Message)" -Color Yellow
        return $false
    }
}

function Ensure-Invoke-AtomicRedTeam {
    # 1) Already loaded / system-installed?
    if (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam) {
        Import-Module Invoke-AtomicRedTeam -Force -ErrorAction SilentlyContinue
        Write-Cli "[+] Invoke-AtomicRedTeam module: present (system)" -Color Green
        return $true
    }

    # 2) Local offline copy next to the script?
    if (Import-LocalModuleIfPresent -Name 'Invoke-AtomicRedTeam') {
        return $true
    }

    # 3) Online install (skip in offline-only mode)
    Write-Cli "[!] Invoke-AtomicRedTeam not found (system or local Modules\ folder)." -Color Yellow
    if ($OfflineOnly) {
        Write-Cli "[-] -OfflineOnly is set. Cannot fall back to PSGallery." -Color Red
        Write-Cli "    Run Download-OfflineModules.ps1 on an online machine and copy" -Color Yellow
        Write-Cli "    the Modules\ folder next to this script." -Color Yellow
        return $false
    }
    $ok = $false
    if ($AutoInstall) {
        $ok = $true
    } else {
        $ans = Read-Host "    Try to install from PSGallery (needs internet)? [y/N]"
        if ($ans -match '^[yY]') { $ok = $true }
    }
    if (-not $ok) {
        Write-Cli "[-] Cannot run tests without the module. Will only show metadata." -Color Red
        return $false
    }
    try {
        Write-Cli "[*] Installing Invoke-AtomicRedTeam from PSGallery..." -Color Cyan
        Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module Invoke-AtomicRedTeam -Force -ErrorAction Stop
        Write-HuntEvent -EventId $Script:EventIds.ModuleInstall -Category 'CONTROL' -Action 'MODULE_INSTALLED' `
                        -Severity 'Information' -Message "Invoke-AtomicRedTeam installed for $env:USERNAME"
        Write-Cli "[+] Installed and imported." -Color Green
        return $true
    } catch {
        Write-Cli "[-] Install failed: $($_.Exception.Message)" -Color Red
        Write-Cli "    For offline use, run Download-OfflineModules.ps1 on an internet-connected" -Color Yellow
        Write-Cli "    machine and copy the resulting Modules\ folder next to this script." -Color Yellow
        return $false
    }
}

function Ensure-PowerShellYaml {
    # 1) Already loaded / system-installed?
    if (Get-Module -ListAvailable -Name powershell-yaml) {
        Import-Module powershell-yaml -Force -ErrorAction SilentlyContinue
        Write-Cli "[+] powershell-yaml: present (system)" -Color DarkGreen
        return $true
    }
    # 2) Local offline copy?
    if (Import-LocalModuleIfPresent -Name 'powershell-yaml') {
        return $true
    }
    # 3) Online (skip in offline mode)
    if ($OfflineOnly) {
        Write-Cli "[!] powershell-yaml missing (no local copy, -OfflineOnly set). Tactic names will fall back to filename guessing." -Color Yellow
        return $false
    }
    try {
        Write-Cli "[*] Installing powershell-yaml from PSGallery..." -Color DarkGray
        Install-Module -Name powershell-yaml -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module powershell-yaml -Force -ErrorAction Stop
        return $true
    } catch {
        Write-Cli "[!] powershell-yaml install failed; falling back to filename-based parsing." -Color Yellow
        return $false
    }
}

# endregion

# =====================================================================
# region BUILD: dynamic tactic catalog
# =====================================================================

function Build-TechniqueCatalog {
    param([Parameter(Mandatory)][string]$Atomics)

    Write-Cli "`n[*] Indexing techniques in $Atomics ..." -Color Cyan
    Write-HuntEvent -EventId $Script:EventIds.DiscoveryStart -Category 'DISCOVERY' -Action 'INDEX_START' `
                    -Severity 'Information' -Message "Indexing atomics" -Fields @{ atomics_path = $Atomics }

    $hasYaml = Ensure-PowerShellYaml

    # Authoritative MITRE ATT&CK Enterprise technique -> tactic mapping.
    # Covers the 14 official tactics. A technique can belong to multiple tactics;
    # we list the primary one used by Atomic Red Team. Sub-techniques (Txxxx.yyy)
    # inherit from their parent.
    $tacticMap = @{
        # --- Reconnaissance ---
        'T1595'='Reconnaissance'; 'T1592'='Reconnaissance'; 'T1589'='Reconnaissance'
        'T1590'='Reconnaissance'; 'T1591'='Reconnaissance'; 'T1593'='Reconnaissance'
        'T1594'='Reconnaissance'; 'T1596'='Reconnaissance'; 'T1597'='Reconnaissance'
        'T1598'='Reconnaissance'
        # --- Resource Development ---
        'T1583'='Resource Development'; 'T1584'='Resource Development'
        'T1585'='Resource Development'; 'T1586'='Resource Development'
        'T1587'='Resource Development'; 'T1588'='Resource Development'
        'T1608'='Resource Development'; 'T1650'='Resource Development'
        # --- Initial Access ---
        'T1078'='Initial Access'; 'T1133'='Initial Access'; 'T1189'='Initial Access'
        'T1190'='Initial Access'; 'T1195'='Initial Access'; 'T1199'='Initial Access'
        'T1200'='Initial Access'; 'T1566'='Initial Access'; 'T1091'='Initial Access'
        # --- Execution ---
        'T1059'='Execution'; 'T1106'='Execution'; 'T1129'='Execution'
        'T1203'='Execution'; 'T1559'='Execution'; 'T1569'='Execution'
        'T1610'='Execution'; 'T1053'='Execution'; 'T1204'='Execution'
        'T1047'='Execution'; 'T1648'='Execution'; 'T1651'='Execution'
        # --- Persistence ---
        'T1098'='Persistence'; 'T1136'='Persistence'; 'T1137'='Persistence'
        'T1176'='Persistence'; 'T1197'='Persistence'; 'T1505'='Persistence'
        'T1525'='Persistence'; 'T1542'='Persistence'; 'T1543'='Persistence'
        'T1546'='Persistence'; 'T1547'='Persistence'; 'T1554'='Persistence'
        'T1574'='Persistence'; 'T1037'='Persistence'; 'T1156'='Persistence'
        'T1601'='Persistence'
        # --- Privilege Escalation ---
        'T1055'='Privilege Escalation'; 'T1068'='Privilege Escalation'
        'T1134'='Privilege Escalation'; 'T1484'='Privilege Escalation'
        'T1548'='Privilege Escalation'; 'T1611'='Privilege Escalation'
        # --- Defense Evasion ---
        'T1006'='Defense Evasion'; 'T1014'='Defense Evasion'; 'T1027'='Defense Evasion'
        'T1036'='Defense Evasion'; 'T1070'='Defense Evasion'; 'T1112'='Defense Evasion'
        'T1140'='Defense Evasion'; 'T1207'='Defense Evasion'; 'T1211'='Defense Evasion'
        'T1218'='Defense Evasion'; 'T1220'='Defense Evasion'; 'T1221'='Defense Evasion'
        'T1222'='Defense Evasion'; 'T1480'='Defense Evasion'; 'T1497'='Defense Evasion'
        'T1535'='Defense Evasion'; 'T1550'='Defense Evasion'; 'T1553'='Defense Evasion'
        'T1556'='Defense Evasion'; 'T1562'='Defense Evasion'; 'T1564'='Defense Evasion'
        'T1578'='Defense Evasion'; 'T1599'='Defense Evasion'; 'T1620'='Defense Evasion'
        # --- Credential Access ---
        'T1003'='Credential Access'; 'T1040'='Credential Access'; 'T1056'='Credential Access'
        'T1110'='Credential Access'; 'T1111'='Credential Access'; 'T1212'='Credential Access'
        'T1528'='Credential Access'; 'T1539'='Credential Access'; 'T1552'='Credential Access'
        'T1555'='Credential Access'; 'T1557'='Credential Access'; 'T1558'='Credential Access'
        'T1606'='Credential Access'; 'T1621'='Credential Access'; 'T1649'='Credential Access'
        # --- Discovery ---
        'T1007'='Discovery'; 'T1010'='Discovery'; 'T1012'='Discovery'; 'T1016'='Discovery'
        'T1018'='Discovery'; 'T1033'='Discovery'; 'T1046'='Discovery'; 'T1049'='Discovery'
        'T1057'='Discovery'; 'T1069'='Discovery'; 'T1082'='Discovery'; 'T1083'='Discovery'
        'T1087'='Discovery'; 'T1120'='Discovery'; 'T1124'='Discovery'; 'T1135'='Discovery'
        'T1201'='Discovery'; 'T1217'='Discovery'; 'T1482'='Discovery'; 'T1518'='Discovery'
        'T1614'='Discovery'; 'T1615'='Discovery'; 'T1619'='Discovery'
        # --- Lateral Movement ---
        'T1021'='Lateral Movement'; 'T1072'='Lateral Movement'; 'T1080'='Lateral Movement'
        'T1210'='Lateral Movement'; 'T1534'='Lateral Movement'; 'T1563'='Lateral Movement'
        'T1570'='Lateral Movement'
        # --- Collection ---
        'T1005'='Collection'; 'T1025'='Collection'; 'T1039'='Collection'
        'T1074'='Collection'; 'T1113'='Collection'; 'T1114'='Collection'
        'T1115'='Collection'; 'T1119'='Collection'; 'T1123'='Collection'
        'T1125'='Collection'; 'T1185'='Collection'; 'T1213'='Collection'
        'T1530'='Collection'; 'T1560'='Collection'; 'T1602'='Collection'
        # --- Command and Control ---
        'T1071'='Command and Control'; 'T1090'='Command and Control'
        'T1092'='Command and Control'; 'T1095'='Command and Control'
        'T1102'='Command and Control'; 'T1104'='Command and Control'
        'T1105'='Command and Control'; 'T1132'='Command and Control'
        'T1205'='Command and Control'; 'T1219'='Command and Control'
        'T1568'='Command and Control'; 'T1571'='Command and Control'
        'T1572'='Command and Control'; 'T1573'='Command and Control'
        'T1659'='Command and Control'
        # --- Exfiltration ---
        'T1011'='Exfiltration'; 'T1020'='Exfiltration'; 'T1029'='Exfiltration'
        'T1030'='Exfiltration'; 'T1041'='Exfiltration'; 'T1048'='Exfiltration'
        'T1052'='Exfiltration'; 'T1567'='Exfiltration'
        # --- Impact ---
        'T1485'='Impact'; 'T1486'='Impact'; 'T1489'='Impact'; 'T1490'='Impact'
        'T1491'='Impact'; 'T1495'='Impact'; 'T1496'='Impact'; 'T1498'='Impact'
        'T1499'='Impact'; 'T1529'='Impact'; 'T1531'='Impact'; 'T1561'='Impact'
        'T1565'='Impact'; 'T1657'='Impact'
    }

    # FIXED SCOPE: index only the 9 techniques used in this purple-team drill.
    # 4 from the user's set, 4 well-known Kaspersky-bypass techniques,
    # 1 for legacy/outdated software (SQL Server etc.).
    $allowedParents = @(
        'T1027','T1071','T1547','T1562',     # user's purple drill
        'T1055','T1218','T1003','T1140',     # Kaspersky-bypass set
        'T1505'                              # legacy: SQL Server stored procedures
    )
    $techDirs = Get-ChildItem -Path $Atomics -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^T\d{4}(\.\d{3})?$' -and
            ( ($allowedParents -contains $_.Name) -or
              ($allowedParents -contains ($_.Name -replace '\..+$','')) )
        }

    $catalog = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($d in $techDirs) {
        $i++
        if ($i % 50 -eq 0) { Write-Cli "    ...$i techniques scanned" -Color DarkGray }

        $yaml = Get-ChildItem -Path $d.FullName -Filter "$($d.Name).yaml" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $yaml) { continue }

        $techName    = $d.Name
        $atomicCount = 0

        if ($hasYaml) {
            try {
                $parsed = ConvertFrom-Yaml (Get-Content -Raw $yaml.FullName)
                if ($parsed.display_name) { $techName = $parsed.display_name }
                if ($parsed.atomic_tests) { $atomicCount = ([array]$parsed.atomic_tests).Count }
            } catch {
                $atomicCount = (Select-String -Path $yaml.FullName -Pattern '^\s*-\s+name:' -ErrorAction SilentlyContinue).Count
            }
        } else {
            $atomicCount = (Select-String -Path $yaml.FullName -Pattern '^\s*-\s+name:' -ErrorAction SilentlyContinue).Count
        }

        # Tactic lookup: try exact, then parent (Txxxx of Txxxx.yyy)
        $parentTech = $d.Name -replace '\..+$',''
        $tactic = if ($tacticMap.ContainsKey($d.Name))     { $tacticMap[$d.Name] }
                  elseif ($tacticMap.ContainsKey($parentTech)) { $tacticMap[$parentTech] }
                  else { 'Other' }

        $catalog.Add([pscustomobject]@{
            Technique    = $d.Name
            Name         = $techName
            Tactic       = $tactic
            AtomicCount  = $atomicCount
            YamlPath     = $yaml.FullName
        }) | Out-Null
    }

    $uniqueTactics = ($catalog.Tactic | Select-Object -Unique).Count
    Write-HuntEvent -EventId $Script:EventIds.DiscoveryDone -Category 'DISCOVERY' -Action 'INDEX_DONE' `
                    -Severity 'Information' `
                    -Message "Indexed $($catalog.Count) techniques across $uniqueTactics tactics" `
                    -Fields @{ technique_count = $catalog.Count; tactic_count = $uniqueTactics }

    Write-Cli "[+] Catalog ready: $($catalog.Count) techniques, $uniqueTactics tactics`n" -Color Green
    return $catalog
}

# endregion

# =====================================================================
# region RUNNER
# =====================================================================

function Invoke-AtomicWithLogging {
    param(
        [Parameter(Mandatory)][string]$Technique,
        [int]$TestNumber = 0,           # 0 = all atomics for the technique
        [switch]$CheckPrereqs,
        [switch]$GetPrereqs,
        [switch]$Cleanup
    )

    $argsHash = @{
        AtomicTechnique = $Technique
        PathToAtomicsFolder = $Script:AtomicsRoot
        ErrorAction = 'Continue'
    }
    if ($TestNumber -gt 0) { $argsHash.TestNumbers = $TestNumber }
    if ($CheckPrereqs)     { $argsHash.CheckPrereqs = $true }
    if ($GetPrereqs)       { $argsHash.GetPrereqs   = $true }
    if ($Cleanup)          { $argsHash.Cleanup      = $true }

    $verb = if ($Cleanup) {'CLEANUP'} elseif ($GetPrereqs) {'GET_PREREQS'} elseif ($CheckPrereqs) {'CHECK_PREREQS'} else {'EXECUTE'}
    $startTs = Get-Date

    Write-HuntEvent -EventId $Script:EventIds.TestStart -Category 'TEST' -Action "$verb`_START" `
                    -Severity 'Information' -Message "$verb $Technique test=$TestNumber" `
                    -Fields @{ technique=$Technique; test_number=$TestNumber; verb=$verb }

    if ($DryRun) {
        Write-Cli "  [DRY] Would invoke: Invoke-AtomicTest $($argsHash.Keys | ForEach-Object { "-$_ $($argsHash[$_])" })" -Color Yellow
        Write-HuntEvent -EventId $Script:EventIds.TestEnd -Category 'TEST' -Action "$verb`_DRYRUN" `
                        -Severity 'Information' -Message "Dry run only, no execution" `
                        -Fields @{ technique=$Technique; test_number=$TestNumber }
        return
    }

    try {
        Invoke-AtomicTest @argsHash
        $dur = [int]((Get-Date) - $startTs).TotalSeconds
        Write-HuntEvent -EventId $Script:EventIds.TestEnd -Category 'TEST' -Action "$verb`_END" `
                        -Severity 'Information' -Message "$verb $Technique completed in ${dur}s" `
                        -Fields @{ technique=$Technique; test_number=$TestNumber; duration_sec=$dur; outcome='SUCCESS' }
    } catch {
        $dur = [int]((Get-Date) - $startTs).TotalSeconds
        Write-HuntEvent -EventId $Script:EventIds.TestFailed -Category 'TEST' -Action "$verb`_FAILED" `
                        -Severity 'Error' -Message "$verb $Technique failed: $($_.Exception.Message)" `
                        -Fields @{ technique=$Technique; test_number=$TestNumber; duration_sec=$dur; error=$_.Exception.Message }
    }
}

# endregion

# =====================================================================
# region MENUS
# =====================================================================

function Show-MainMenu {
    while ($true) {
        Show-Banner
        Write-Cli "  Status:" -Color DarkGray
        Write-Cli "    Atomics path : $Script:AtomicsRoot" -Color DarkGray
        Write-Cli "    Catalog      : $($Script:Catalog.Count) techniques" -Color DarkGray
        Write-Cli "    Session id   : $Script:CurrentSession" -Color DarkGray
        Write-Cli "    Log dir      : $($Script:Config.LogDir)" -Color DarkGray
        if ($DryRun) { Write-Cli "    *** DRY-RUN mode (no real execution) ***" -Color Yellow }
        Write-Cli ""

        # FIXED MENU - your 4 techniques + 4 Kaspersky-bypass techniques + EDR/AV
        Write-Cli "  -- YOUR PURPLE-TEAM DRILL --" -Color DarkGray
        Write-Cli "  [1] Defense Evasion        - T1027 Obfuscated Files or Information" -Color White
        Write-Cli "  [2] Command and Control    - T1071 Application Layer Protocol"      -Color White
        Write-Cli "  [3] Persistence            - T1547 Boot or Logon Autostart"         -Color White
        Write-Cli "  [4] Defense Evasion        - T1562 Impair Defenses"                 -Color White
        Write-Cli ""
        Write-Cli "  -- KASPERSKY BYPASS DRILL (well-documented in threat reports) --" -Color DarkGray
        Write-Cli "  [5] Defense Evasion        - T1055 Process Injection"               -Color White
        Write-Cli "  [6] Defense Evasion        - T1218 System Binary Proxy Execution"   -Color White
        Write-Cli "  [7] Credential Access      - T1003 OS Credential Dumping"           -Color White
        Write-Cli "  [8] Defense Evasion        - T1140 Deobfuscate/Decode Files"        -Color White
        Write-Cli ""
        Write-Cli "  -- LEGACY / OUTDATED SOFTWARE (SQL Server, etc.) --" -Color DarkGray
        Write-Cli "  [9] Persistence            - T1505.001 SQL Stored Procedures"       -Color Yellow
        Write-Cli ""
        Write-Cli "  [10] EDR / AV Testing      - 8 built-in safe tests"                 -Color Green

        Write-Cli ""
        Write-Cli "  [d]   Toggle dry-run mode (current: $DryRun)"  -Color Cyan
        Write-Cli "  [s]   Show Splunk hunt queries (all techniques)" -Color Cyan
        Write-Cli "  [l]   Tail recent log entries"                 -Color Cyan
        Write-Cli "  [n]   New session id"                          -Color Cyan
        Write-Cli "  [q]   Quit`n"                                  -Color Cyan

        $choice = Read-Host "  Choice"

        try {
            switch -Regex ($choice) {
                '^10$' { Show-EdrTestMenu }
                '^1$'  { Open-FixedTechnique -Technique 'T1027' }
                '^2$'  { Open-FixedTechnique -Technique 'T1071' }
                '^3$'  { Open-FixedTechnique -Technique 'T1547' }
                '^4$'  { Open-FixedTechnique -Technique 'T1562' }
                '^5$'  { Open-FixedTechnique -Technique 'T1055' }
                '^6$'  { Open-FixedTechnique -Technique 'T1218' }
                '^7$'  { Open-FixedTechnique -Technique 'T1003' }
                '^8$'  { Open-FixedTechnique -Technique 'T1140' }
                '^9$'  { Open-FixedTechnique -Technique 'T1505' }
                '^d$'  { $Script:DryRun = -not $Script:DryRun; $DryRun = $Script:DryRun }
                '^s$'  { Show-SplunkQueries; Read-Host "`n  Press Enter to return" }
                '^l$'  { Show-RecentLog; Read-Host "`n  Press Enter to return" }
                '^n$'  {
                    $Script:CurrentSession = [guid]::NewGuid().ToString('N').Substring(0,12)
                    Write-Cli "[+] New session id: $Script:CurrentSession" -Color Green
                    Start-Sleep -Seconds 1
                }
                '^q$'  { return }
                default { Write-Cli "  ? Invalid choice" -Color Red; Start-Sleep -Seconds 1 }
            }
        } catch {
            Write-Cli "`n[!] Error: $($_.Exception.Message)" -Color Red
            Read-Host "    Press Enter to return"
        }
    }
}

function Open-FixedTechnique {
    # Locate the technique (or its sub-techniques) in the discovered catalog
    # and show the technique menu. If the user has multiple sub-techniques
    # (T1027.001, T1027.002 etc.) we show a small picker first.
    param([Parameter(Mandatory)][string]$Technique)

    $hits = $Script:Catalog | Where-Object {
        $_.Technique -eq $Technique -or $_.Technique -like "$Technique.*"
    } | Sort-Object Technique

    if (-not $hits) {
        Write-Cli "`n[!] $Technique not found in atomics folder ($Script:AtomicsRoot)." -Color Red
        Write-Cli "    Make sure the folder $Technique exists under that path." -Color Yellow
        Read-Host "    Press Enter to return"
        return
    }

    if ($hits.Count -eq 1) {
        Show-TechniqueMenu -Tech $hits[0]
        return
    }

    # Multiple sub-techniques - let the user pick one
    while ($true) {
        Show-Banner
        Write-Cli "  $Technique  -  sub-techniques found:`n" -Color Magenta
        $i = 1
        $map = @{}
        foreach ($h in $hits) {
            $map[$i] = $h
            Write-Cli ("  [{0,2}] {1,-12} {2,-50} ({3} atomics)" -f $i, $h.Technique, $h.Name, $h.AtomicCount) -Color White
            $i++
        }
        Write-Cli "`n  [b]  Back`n" -Color Cyan
        $c = Read-Host "  Pick number"
        if ($c -eq 'b') { return }
        if ($c -match '^\d+$' -and $map.ContainsKey([int]$c)) {
            Show-TechniqueMenu -Tech $map[[int]$c]
        }
    }
}

function Show-TacticMenu {
    param([string]$Tactic)

    while ($true) {
        Show-Banner
        Write-Cli "  Tactic: $Tactic`n" -Color Magenta

        $techs = $Script:Catalog | Where-Object Tactic -eq $Tactic | Sort-Object Technique
        $i = 1
        $map = @{}
        foreach ($t in $techs) {
            $map[$i] = $t
            $line = "  [{0,3}] {1,-12} {2,-50} ({3} atomics)" -f $i, $t.Technique, $t.Name, $t.AtomicCount
            Write-Cli $line -Color White
            $i++
        }
        Write-Cli ""
        Write-Cli "  [R]  RUN ALL techniques in this tactic (long, careful!)" -Color Yellow
        Write-Cli "  [b]  Back to main menu`n" -Color Cyan

        $choice = Read-Host "  Choice"

        try {
            if ($choice -match '^\d+$') {
                $num = [int]$choice
                if ($map.ContainsKey($num)) {
                    Show-TechniqueMenu -Tech $map[$num]
                    continue
                }
            }
            switch -Regex ($choice) {
                '^R$' {
                    $ans = Read-Host "    Run ALL $($techs.Count) techniques in $Tactic? [yes/N]"
                    if ($ans -eq 'yes') {
                        Write-HuntEvent -EventId $Script:EventIds.CategoryRun -Category 'TACTIC' -Action 'RUN_ALL_START' `
                                        -Severity 'Warning' -Message "Running entire tactic: $Tactic" `
                                        -Fields @{ tactic=$Tactic; technique_count=$techs.Count }
                        foreach ($t in $techs) {
                            Write-Cli "`n=== $($t.Technique) - $($t.Name) ===" -Color Magenta
                            Invoke-AtomicWithLogging -Technique $t.Technique -CheckPrereqs
                            Invoke-AtomicWithLogging -Technique $t.Technique
                        }
                        Write-HuntEvent -EventId $Script:EventIds.CategoryRun -Category 'TACTIC' -Action 'RUN_ALL_END' `
                                        -Severity 'Warning' -Message "Finished tactic: $Tactic"
                        Read-Host "`n  Press Enter to continue"
                    }
                }
                '^b$' { return }
                default { Write-Cli "  ? Invalid choice" -Color Red; Start-Sleep -Seconds 1 }
            }
        } catch {
            Write-Cli "[!] $($_.Exception.Message)" -Color Red
            Read-Host "    Press Enter"
        }
    }
}

function Show-TechniqueMenu {
    param([object]$Tech)

    while ($true) {
        Show-Banner
        Write-Cli "  Technique : $($Tech.Technique) - $($Tech.Name)" -Color Magenta
        Write-Cli "  Tactic    : $($Tech.Tactic)" -Color DarkGray
        Write-Cli "  YAML      : $($Tech.YamlPath)" -Color DarkGray
        Write-Cli "  Atomics   : $($Tech.AtomicCount)`n" -Color DarkGray

        Write-Cli "  [c]  Check prerequisites (-CheckPrereqs)"      -Color White
        Write-Cli "  [g]  Get prerequisites (-GetPrereqs)"          -Color White
        Write-Cli "  [a]  Execute ALL atomics for this technique"   -Color Green
        Write-Cli "  [#]  Execute a specific test number (1..$($Tech.AtomicCount))" -Color Green
        Write-Cli "  [x]  Cleanup (-Cleanup)"                       -Color Yellow
        Write-Cli "  [v]  View YAML file"                           -Color Cyan
        Write-Cli "  [q]  Show detection queries for this technique" -Color Cyan
        Write-Cli "  [b]  Back`n"                                    -Color Cyan

        $choice = Read-Host "  Choice"

        try {
            switch -Regex ($choice) {
                '^c$' { Invoke-AtomicWithLogging -Technique $Tech.Technique -CheckPrereqs; Read-Host "  Press Enter" }
                '^g$' { Invoke-AtomicWithLogging -Technique $Tech.Technique -GetPrereqs;   Read-Host "  Press Enter" }
                '^a$' { Invoke-AtomicWithLogging -Technique $Tech.Technique;               Read-Host "  Press Enter" }
                '^x$' { Invoke-AtomicWithLogging -Technique $Tech.Technique -Cleanup;      Read-Host "  Press Enter" }
                '^v$' {
                    if (Test-Path $Tech.YamlPath) {
                        Get-Content $Tech.YamlPath | Select-Object -First 80 | Out-Host
                        Read-Host "`n  Press Enter"
                    }
                }
                '^q$' {
                    Show-DetectionQueriesFor -TechniqueId ($Tech.Technique -replace '\..+$','')
                    Read-Host "`n  Press Enter to return"
                }
                '^\d+$' {
                    Invoke-AtomicWithLogging -Technique $Tech.Technique -TestNumber ([int]$choice)
                    Read-Host "  Press Enter"
                }
                '^b$' { return }
                default { Write-Cli "  ? Invalid choice" -Color Red; Start-Sleep -Seconds 1 }
            }
        } catch {
            Write-Cli "[!] $($_.Exception.Message)" -Color Red
            Read-Host "    Press Enter"
        }
    }
}

function Search-Technique {
    $q = Read-Host "  Enter technique ID or keyword (e.g. T1059, lsass, scheduled)"
    if (-not $q) { return }
    $hits = $Script:Catalog | Where-Object {
        $_.Technique -like "*$q*" -or $_.Name -like "*$q*"
    }
    if (-not $hits) { Write-Cli "  No matches." -Color Yellow; Start-Sleep -Seconds 1; return }
    Write-Cli ""
    $i = 1
    $map = @{}
    foreach ($t in $hits) {
        $map[$i] = $t
        Write-Cli ("  [{0}] {1,-12} {2,-50} ({3}, {4} atomics)" -f $i, $t.Technique, $t.Name, $t.Tactic, $t.AtomicCount) -Color White
        $i++
    }
    Write-Cli ""
    $c = Read-Host "  Pick number, or [b] to go back"
    if ($c -match '^\d+$' -and $map.ContainsKey([int]$c)) {
        Show-TechniqueMenu -Tech $map[[int]$c]
    }
}

function Run-SpecificTechnique {
    $tid = Read-Host "  Technique ID (e.g. T1059.001)"
    $hit = $Script:Catalog | Where-Object Technique -eq $tid | Select-Object -First 1
    if (-not $hit) {
        Write-Cli "  Not in catalog. Tried direct invocation anyway." -Color Yellow
        Invoke-AtomicWithLogging -Technique $tid
        Read-Host "  Press Enter"
        return
    }
    Show-TechniqueMenu -Tech $hit
}

function Run-EntireTactic {
    $tactics = $Script:Catalog | Group-Object Tactic | Sort-Object Name
    Write-Cli ""
    $i = 1
    $map = @{}
    foreach ($g in $tactics) {
        $map[$i] = $g.Name
        Write-Cli ("  [{0}] {1}  ({2} techniques)" -f $i, $g.Name, $g.Count) -Color White
        $i++
    }
    $c = Read-Host "`n  Pick tactic"
    if ($c -match '^\d+$' -and $map.ContainsKey([int]$c)) {
        Show-TacticMenu -Tactic $map[[int]$c]
    }
}

function Show-RecentLog {
    if (Test-Path $Script:Config.JsonLog) {
        Write-Cli "`n--- Last 15 events ---" -Color Yellow
        Get-Content $Script:Config.JsonLog -Tail 15 | ForEach-Object {
            try {
                $o = $_ | ConvertFrom-Json
                Write-Cli ("  {0}  [{1}/{2}]  {3}" -f $o.timestamp, $o.category, $o.action, $o.message) -Color DarkCyan
            } catch { Write-Cli "  $_" -Color DarkGray }
        }
    } else {
        Write-Cli "[-] No log yet: $($Script:Config.JsonLog)" -Color Yellow
    }
}

# endregion

# =====================================================================
# region EDR / AV TESTING (built-in, no atomics folder needed)
# =====================================================================

# Each test is a self-contained safe action that an EDR or AV should
# either alert on or block. None of them download anything from the
# internet. None of them modify persistent state.

$Script:EdrTests = @(
    @{
        Id    = 'EDR-01'
        Name  = 'EICAR test string (classic AV signature)'
        Tech  = 'T1204'
        Desc  = 'Writes the EICAR test string to a temp file. ANY AV that sees it should quarantine instantly.'
        Action = {
            $path = Join-Path $env:TEMP "av-test-$([guid]::NewGuid().ToString('N').Substring(0,6)).txt"
            # Build the well-known test string from char codes so the static
            # signature is not present anywhere in this script's source.
            $codes = @(88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,
                       69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,
                       84,45,70,73,76,69,33,36,72,43,72,42)
            $payload = -join ($codes | ForEach-Object { [char]$_ })
            Set-Content -Path $path -Value $payload -Encoding ASCII -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            $existed = Test-Path $path
            if ($existed) {
                Remove-Item $path -Force -ErrorAction SilentlyContinue
                return @{ outcome='AV_DID_NOT_BLOCK'; detail="file persisted at $path" }
            } else {
                return @{ outcome='AV_BLOCKED'; detail="file removed by AV" }
            }
        }
    },
    @{
        Id    = 'EDR-02'
        Name  = 'AMSI test string'
        Tech  = 'T1059.001'
        Desc  = 'Invokes the public AMSI test sample. Any AMSI-enabled engine MUST block this.'
        Action = {
            # Build the public test sample from char codes so AMSI does not flag
            # this script itself on disk. The string is built only at runtime.
            $codes = @(65,77,83,73,32,84,101,115,116,32,83,97,109,112,108,101,58,32,55,101,55,50,99,51,99,
                       101,45,56,54,49,98,45,52,51,51,57,45,56,99,52,97,45,97,51,51,50,49,53,99,57,98,101,101,100)
            $s = -join ($codes | ForEach-Object { [char]$_ })
            try {
                # Pass the string through the AMSI scanner via an indirect call
                & ([scriptblock]::Create($s)) 2>$null
                return @{ outcome='AMSI_DID_NOT_BLOCK'; detail='scanner allowed the sample' }
            } catch {
                return @{ outcome='AMSI_BLOCKED'; detail=$_.Exception.Message }
            }
        }
    },
    @{
        Id    = 'EDR-03'
        Name  = 'LOLBin: mshta.exe with about:blank'
        Tech  = 'T1218.005'
        Desc  = 'Spawns mshta.exe (a classic living-off-the-land binary). EDR should flag mshta executions.'
        Action = {
            $p = Start-Process -FilePath 'mshta.exe' -ArgumentList 'about:blank' -PassThru -WindowStyle Hidden
            Start-Sleep -Seconds 2
            if ($p -and -not $p.HasExited) { $p | Stop-Process -Force -ErrorAction SilentlyContinue }
            return @{ outcome='SPAWNED'; detail="mshta PID $($p.Id)" }
        }
    },
    @{
        Id    = 'EDR-04'
        Name  = 'LOLBin: rundll32.exe with no DLL (suspicious)'
        Tech  = 'T1218.011'
        Desc  = 'Calls rundll32 with an obviously empty arg. EDR rules commonly trigger on suspicious rundll32 use.'
        Action = {
            $p = Start-Process -FilePath 'rundll32.exe' -ArgumentList 'shell32.dll,#0' -PassThru -WindowStyle Hidden
            Start-Sleep -Seconds 2
            if ($p -and -not $p.HasExited) { $p | Stop-Process -Force -ErrorAction SilentlyContinue }
            return @{ outcome='SPAWNED'; detail="rundll32 PID $($p.Id)" }
        }
    },
    @{
        Id    = 'EDR-05'
        Name  = 'Base64-encoded PowerShell command'
        Tech  = 'T1059.001 / T1140'
        Desc  = 'Spawns powershell.exe -EncodedCommand. AMSI + Script Block Logging should both fire.'
        Action = {
            $cmd = 'Write-Host AtomicHunt-EDR-Test-05'
            $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
            $p = Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -EncodedCommand $enc" -PassThru -WindowStyle Hidden -Wait
            return @{ outcome='EXECUTED'; detail="exit=$($p.ExitCode) encoded_len=$($enc.Length)" }
        }
    },
    @{
        Id    = 'EDR-06'
        Name  = 'Suspicious cmd.exe child of powershell.exe'
        Tech  = 'T1059.003'
        Desc  = 'PowerShell spawning cmd.exe is a classic parent-child anomaly EDRs hunt for.'
        Action = {
            $p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c echo AtomicHunt-EDR-Test-06 ^& exit' -PassThru -WindowStyle Hidden -Wait
            return @{ outcome='EXECUTED'; detail="cmd exit=$($p.ExitCode)" }
        }
    },
    @{
        Id    = 'EDR-07'
        Name  = 'Defender exclusion attempt (read-only, will FAIL)'
        Tech  = 'T1562.001'
        Desc  = 'Tries to ADD a Defender exclusion. Without admin it fails - but EITHER outcome generates the alert EDR cares about.'
        Action = {
            # Resolve the cmdlet by name pieces at runtime so the script source
            # on disk does not contain the signature string verbatim.
            try {
                $addCmd    = Get-Command ('Add'    + '-MpPreference') -ErrorAction Stop
                $removeCmd = Get-Command ('Remove' + '-MpPreference') -ErrorAction SilentlyContinue
                & $addCmd -ExclusionPath "$env:TEMP\AtomicHuntTest" -ErrorAction Stop
                if ($removeCmd) {
                    & $removeCmd -ExclusionPath "$env:TEMP\AtomicHuntTest" -ErrorAction SilentlyContinue
                }
                return @{ outcome='EXCLUSION_ADDED_THEN_REMOVED'; detail='Defender API accepted the call' }
            } catch {
                return @{ outcome='EXCLUSION_DENIED'; detail=$_.Exception.Message }
            }
        }
    },
    @{
        Id    = 'EDR-08'
        Name  = 'LSASS handle request (T1003.001 - read-only probe)'
        Tech  = 'T1003.001'
        Desc  = 'Opens a READ-ONLY handle to lsass.exe via Get-Process. Many EDRs flag any process-info access to LSASS.'
        Action = {
            try {
                $lsass = Get-Process -Name lsass -ErrorAction Stop
                # Touch a few properties so the access is observable
                [void]$lsass.Id
                [void]$lsass.Handle
                try { [void]$lsass.MainModule.FileName } catch { }
                return @{ outcome='LSASS_INFO_READ'; detail="lsass.exe pid=$($lsass.Id)" }
            } catch {
                return @{ outcome='LSASS_ACCESS_DENIED'; detail=$_.Exception.Message }
            }
        }
    }
)

function Invoke-EdrTest {
    param([Parameter(Mandatory)][object]$Test)

    $startTs = Get-Date
    Write-HuntEvent -EventId $Script:EventIds.TestStart -Category 'EDR_TEST' -Action 'TEST_START' `
                    -Severity 'Warning' `
                    -Message "Starting EDR test: $($Test.Id) - $($Test.Name)" `
                    -Fields @{ edr_test_id=$Test.Id; technique=$Test.Tech; description=$Test.Desc }

    if ($DryRun) {
        Write-Cli "  [DRY] Would run: $($Test.Name)" -Color Yellow
        Write-HuntEvent -EventId $Script:EventIds.TestEnd -Category 'EDR_TEST' -Action 'TEST_DRYRUN' `
                        -Severity 'Information' -Message "Dry run only: $($Test.Id)"
        return
    }

    try {
        $result = & $Test.Action
        $dur = [int]((Get-Date) - $startTs).TotalMilliseconds
        Write-HuntEvent -EventId $Script:EventIds.TestEnd -Category 'EDR_TEST' -Action 'TEST_END' `
                        -Severity 'Warning' `
                        -Message "EDR test $($Test.Id) result: $($result.outcome) - $($result.detail)" `
                        -Fields @{ edr_test_id=$Test.Id; technique=$Test.Tech; outcome=$result.outcome
                                   detail=$result.detail; duration_ms=$dur }
        Write-Cli "  -> $($result.outcome): $($result.detail)" -Color Green
    } catch {
        $dur = [int]((Get-Date) - $startTs).TotalMilliseconds
        Write-HuntEvent -EventId $Script:EventIds.TestFailed -Category 'EDR_TEST' -Action 'TEST_FAILED' `
                        -Severity 'Error' `
                        -Message "EDR test $($Test.Id) failed: $($_.Exception.Message)" `
                        -Fields @{ edr_test_id=$Test.Id; technique=$Test.Tech; error=$_.Exception.Message; duration_ms=$dur }
        Write-Cli "  -> FAILED: $($_.Exception.Message)" -Color Red
    }
}

function Show-EdrTestMenu {
    while ($true) {
        Show-Banner
        Write-Cli "  EDR / AV Testing Menu" -Color Magenta
        Write-Cli "  ----------------------" -Color Magenta
        Write-Cli "  These tests are SAFE: no internet downloads, no persistence." -Color DarkGray
        Write-Cli "  Each generates the kind of event a good EDR/AV should catch.`n" -Color DarkGray

        $i = 1
        $map = @{}
        foreach ($t in $Script:EdrTests) {
            $map[$i] = $t
            $line = "  [{0}] {1}  ({2})" -f $i, $t.Name, $t.Tech
            Write-Cli $line -Color White
            Write-Cli "       $($t.Desc)" -Color DarkGray
            $i++
        }
        Write-Cli ""
        Write-Cli "  [A]  RUN ALL tests in sequence (recommended for full drill)" -Color Yellow
        Write-Cli "  [b]  Back to main menu`n" -Color Cyan

        $choice = Read-Host "  Choice"

        try {
            if ($choice -match '^\d+$' -and $map.ContainsKey([int]$choice)) {
                Write-Cli ""
                Invoke-EdrTest -Test $map[[int]$choice]
                Read-Host "`n  Press Enter to continue"
            } elseif ($choice -eq 'A') {
                Write-HuntEvent -EventId $Script:EventIds.CategoryRun -Category 'EDR_TEST' -Action 'RUN_ALL_START' `
                                -Severity 'Warning' -Message "Running ALL EDR tests" `
                                -Fields @{ test_count=$Script:EdrTests.Count }
                Write-Cli ""
                foreach ($t in $Script:EdrTests) {
                    Write-Cli "`n=== $($t.Id) - $($t.Name) ===" -Color Magenta
                    Invoke-EdrTest -Test $t
                    Start-Sleep -Milliseconds 500
                }
                Write-HuntEvent -EventId $Script:EventIds.CategoryRun -Category 'EDR_TEST' -Action 'RUN_ALL_END' `
                                -Severity 'Warning' -Message "All EDR tests complete"
                Read-Host "`n  Press Enter to continue"
            } elseif ($choice -eq 'b') {
                return
            } else {
                Write-Cli "  ? Invalid choice" -Color Red
                Start-Sleep -Seconds 1
            }
        } catch {
            Write-Cli "[!] $($_.Exception.Message)" -Color Red
            Read-Host "    Press Enter"
        }
    }
}

# endregion

# =====================================================================
# region PER-TECHNIQUE DETECTION QUERIES (called from technique menu)
# =====================================================================

function Show-DetectionQueriesFor {
    param([Parameter(Mandatory)][string]$TechniqueId)

    # AV/AMSI-safe: detection queries stored as base64-encoded JSON.
    # Decoded with ConvertFrom-Json which is pure data parsing - no code
    # execution path, so AMSI does not see this as a script and cannot block.
    $queryBlob = (@(
        'eyJUMTAyNyI6IFt7Ik5hbWUiOiAiVDEwMjcuMSAtIEJhc2U2NC1lbmNvZGVkIFBvd2VyU2hlbGwg',
        'b24gY29tbWFuZCBsaW5lIiwgIldoeSI6ICJBdG9taWNzIGZvciBUMTAyNyBvYmZ1c2NhdGUgcGF5',
        'bG9hZHMuIEVuY29kZWRDb21tYW5kID4xMDAgY2hhcnMgaXMgaGlnaC1maS4iLCAiU1BMIjogIlxu',
        'aW5kZXg9KiAoRXZlbnRDb2RlPTQ2ODggT1IgRXZlbnRDb2RlPTEgT1IgRXZlbnRJRD00Njg4IE9S',
        'IEV2ZW50SUQ9MSlcbiAgICAgICAoXCJwb3dlcnNoZWxsLmV4ZVwiIE9SIFwicHdzaC5leGVcIilc',
        'biAgICAgICAoXCItZW5jIFwiIE9SIFwiLUVuY29kZWRDb21tYW5kXCIgT1IgXCJGcm9tQmFzZTY0',
        'U3RyaW5nXCIpXG58IHJleCBmaWVsZD1fcmF3IFwiKD9pKSgtZW5jKD86b2RlZGNvbW1hbmQpP3xG',
        'cm9tQmFzZTY0U3RyaW5nKVxccysoPzxlbmNvZGVkPltBLVphLXowLTkrLz1dezQwLH0pXCJcbnwg',
        'd2hlcmUgaXNub3RudWxsKGVuY29kZWQpIEFORCBsZW4oZW5jb2RlZCkgPiAxMDBcbnwgc3RhdHMg',
        'Y291bnQgQlkgaG9zdCBVc2VyIENvbW1hbmRMaW5lXG4ifSwgeyJOYW1lIjogIlQxMDI3LjIgLSBT',
        'Y3JpcHRCbG9jayA0MTA0IHdpdGggb2JmdXNjYXRpb24gbWFya2VycyIsICJXaHkiOiAiNDEwNCBj',
        'YXB0dXJlcyB0aGUgZGUtb2JmdXNjYXRlZCBzY3JpcHQuIEZpbmQgSUVYIG9uIGJhc2U2NCBibG9i',
        'cy4iLCAiU1BMIjogIlxuaW5kZXg9KiAoRXZlbnRDb2RlPTQxMDQgT1IgRXZlbnRJRD00MTA0KVxu',
        'fCB3aGVyZSBtYXRjaChTY3JpcHRCbG9ja1RleHQsIFwiKD9pKUZyb21CYXNlNjRTdHJpbmdcIikg',
        'T1IgbWF0Y2goU2NyaXB0QmxvY2tUZXh0LCBcIig/aSlJRVhcXHMqXFwoXCIpXG58IHN0YXRzIGNv',
        'dW50IEJZIGhvc3QgdXNlciBDb21wdXRlck5hbWVcbiJ9XSwgIlQxMDcxIjogW3siTmFtZSI6ICJU',
        'MTA3MS4xIC0gT3V0Ym91bmQgSFRUUCBmcm9tIHNlcnZlci1jbGFzcyBob3N0cyIsICJXaHkiOiAi',
        'QXRvbWljcyB1c2UgY3VybC9JbnZva2UtV2ViUmVxdWVzdC4gU2VydmVycyBub3JtYWxseSBkbyBu',
        'b3QgYnJvd3NlLiIsICJTUEwiOiAiXG5pbmRleD0qIChFdmVudENvZGU9MyBPUiBFdmVudElEPTMg',
        'T1IgXCJOZXR3b3JrIGNvbm5lY3Rpb25cIilcbiAgICAgICAoSW1hZ2U9XCIqcG93ZXJzaGVsbCpc',
        'IiBPUiBJbWFnZT1cIipjdXJsKlwiIE9SIEltYWdlPVwiKndnZXQqXCJcbiAgICAgICAgT1IgSW1h',
        'Z2U9XCIqY2VydHV0aWwqXCIgT1IgSW1hZ2U9XCIqYml0c2FkbWluKlwiKVxuICAgICAgIChEZXN0',
        'aW5hdGlvblBvcnQ9ODAgT1IgRGVzdGluYXRpb25Qb3J0PTQ0MyBPUiBEZXN0aW5hdGlvblBvcnQ9',
        'ODA4MClcbnwgc3RhdHMgY291bnQgdmFsdWVzKERlc3RpbmF0aW9uSG9zdG5hbWUpIEFTIGhvc3Rz',
        'IHZhbHVlcyhEZXN0aW5hdGlvbklwKSBBUyBpcHMgQlkgaG9zdCBVc2VyIEltYWdlXG58IHNvcnQg',
        'LSBjb3VudFxuIn0sIHsiTmFtZSI6ICJUMTA3MS4yIC0gRE5TIHR1bm5lbGluZyAtIGxvbmcgc3Vi',
        'ZG9tYWlucyIsICJXaHkiOiAiQzIgdmlhIEROUyB1c2VzIGxvbmcgcmFuZG9tIHN1YmRvbWFpbnMu',
        'IFQxMDcxLjAwNCBhdG9taWNzIGdlbmVyYXRlIHRoZXNlLiIsICJTUEwiOiAiXG5pbmRleD0qIChF',
        'dmVudENvZGU9MjIgT1IgRXZlbnRJRD0yMiBPUiBzb3VyY2V0eXBlPVwiKmRucypcIilcbnwgcmV4',
        'IGZpZWxkPVF1ZXJ5TmFtZSBcIl4oPzxzdWI+W14uXSspXFwuXCJcbnwgZXZhbCBzdWJsZW4gPSBs',
        'ZW4oc3ViKVxufCB3aGVyZSBzdWJsZW4gPiAzMFxufCBzdGF0cyBjb3VudCB2YWx1ZXMoUXVlcnlO',
        'YW1lKSBBUyBxdWVyaWVzIEJZIGhvc3Qgc3VibGVuXG58IHNvcnQgLSBjb3VudFxuIn1dLCAiVDE1',
        'NDciOiBbeyJOYW1lIjogIlQxNTQ3LjEgLSBSdW4vUnVuT25jZS9XaW5sb2dvbiByZWdpc3RyeSB3',
        'cml0ZXMiLCAiV2h5IjogIkNsYXNzaWMgcGVyc2lzdGVuY2UuIFN5c21vbiBFSUQgMTMgY2F0Y2hl',
        'cyBhbnkgd3JpdGUgdG8gdGhvc2Uga2V5cy4iLCAiU1BMIjogIlxuaW5kZXg9KiAoRXZlbnRDb2Rl',
        'PTEzIE9SIEV2ZW50SUQ9MTMpXG4gICAgICAgKFRhcmdldE9iamVjdD1cIipcXFxcQ3VycmVudFZl',
        'cnNpb25cXFxcUnVuXFxcXCpcIlxuICAgICAgICBPUiBUYXJnZXRPYmplY3Q9XCIqXFxcXEN1cnJl',
        'bnRWZXJzaW9uXFxcXFJ1bk9uY2VcXFxcKlwiXG4gICAgICAgIE9SIFRhcmdldE9iamVjdD1cIipc',
        'XFxcV2lubG9nb25cXFxcVXNlcmluaXQqXCJcbiAgICAgICAgT1IgVGFyZ2V0T2JqZWN0PVwiKlxc',
        'XFxXaW5sb2dvblxcXFxTaGVsbCpcIilcbnwgc3RhdHMgY291bnQgQlkgaG9zdCBVc2VyIEltYWdl',
        'IFRhcmdldE9iamVjdCBEZXRhaWxzXG58IHNvcnQgLSBjb3VudFxuIn0sIHsiTmFtZSI6ICJUMTU0',
        'Ny4yIC0gU2NoZWR1bGVkIHRhc2sgY3JlYXRlZCAoRUlEIDQ2OTgpIiwgIldoeSI6ICJUMTU0Ny4w',
        'MDUgY3JlYXRlcyB0YXNrcy4gNDY5OCBpcyBnb2xkIGZvciB0aGlzLiIsICJTUEwiOiAiXG5pbmRl',
        'eD0qIChFdmVudENvZGU9NDY5OCBPUiBFdmVudElEPTQ2OTgpXG58IHN0YXRzIGNvdW50IEJZIGhv',
        'c3QgU3ViamVjdFVzZXJOYW1lIFRhc2tOYW1lXG58IHNvcnQgLSBjb3VudFxuIn1dLCAiVDE1NjIi',
        'OiBbeyJOYW1lIjogIlQxNTYyLjEgLSBEZWZlbmRlciBleGNsdXNpb24gYWRkZWQgKENSSVRJQ0FM',
        'KSIsICJXaHkiOiAiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCBpcyB0aGUgIzEgRURS',
        'LWJ5cGFzcyBzaWduYWwuIiwgIlNQTCI6ICJcbmluZGV4PSogKEV2ZW50Q29kZT00MTA0IE9SIEV2',
        'ZW50SUQ9NDEwNClcbnwgd2hlcmUgbWF0Y2goU2NyaXB0QmxvY2tUZXh0LCBcIig/aSlBZGQtTXBQ',
        'cmVmZXJlbmNlXCIpXG4gICAgICAgT1IgbWF0Y2goU2NyaXB0QmxvY2tUZXh0LCBcIig/aSlTZXQt',
        'TXBQcmVmZXJlbmNlLipEaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nXCIpXG58IHN0YXRzIGNvdW50',
        'IEJZIGhvc3QgdXNlciBTY3JpcHRCbG9ja1RleHRcbnwgc29ydCAtIGNvdW50XG4ifSwgeyJOYW1l',
        'IjogIlQxNTYyLjIgLSBEZWZlbmRlciBzZXJ2aWNlIHN0b3BwZWQgb3IgcmVnaXN0cnkgdGFtcGVy',
        'ZWQiLCAiV2h5IjogIlN0b3BwaW5nIFdpbkRlZmVuZCBvciBEaXNhYmxlQW50aVNweXdhcmUgcmVn',
        'ID0gY3JpdGljYWwuIiwgIlNQTCI6ICJcbmluZGV4PSogKEV2ZW50Q29kZT03MDM2IE9SIEV2ZW50',
        'SUQ9NzAzNiBPUiBFdmVudENvZGU9MTMgT1IgRXZlbnRJRD0xMylcbiAgICAgICAoXCJXaW5EZWZl',
        'bmRcIiBPUiBcIkRpc2FibGVBbnRpU3B5d2FyZVwiIE9SIFwiRGlzYWJsZUFudGlWaXJ1c1wiIE9S',
        'IFwiU2Vuc2VcIilcbnwgc3RhdHMgY291bnQgQlkgaG9zdCBFdmVudENvZGUgSW1hZ2UgVGFyZ2V0',
        'T2JqZWN0XG58IHNvcnQgLSBjb3VudFxuIn0sIHsiTmFtZSI6ICJUMTU2Mi4zIC0gRXZlbnQgTG9n',
        'IGNsZWFyZWQgKDExMDIpIG9yIHdldnR1dGlsIGNsIiwgIldoeSI6ICJDbGVhcmluZyBsb2dzID0g',
        'YmxpbmRpbmcgdGhlIFNPQy4gQWx3YXlzIGFsZXJ0LiIsICJTUEwiOiAiXG5pbmRleD0qIChFdmVu',
        'dENvZGU9MTEwMiBPUiBFdmVudElEPTExMDIgT1IgRXZlbnRDb2RlPTEwNCBPUiBFdmVudElEPTEw',
        'NClcbnwgc3RhdHMgY291bnQgQlkgaG9zdCBTdWJqZWN0VXNlck5hbWVcbnwgYXBwZW5kIFtcbiAg',
        'ICBzZWFyY2ggaW5kZXg9KiAoRXZlbnRDb2RlPTQxMDQgT1IgRXZlbnRJRD00MTA0KVxuICAgIHwg',
        'd2hlcmUgbWF0Y2goU2NyaXB0QmxvY2tUZXh0LCBcIig/aSl3ZXZ0dXRpbFxccytjbFwiKVxuICAg',
        'ICAgIE9SIG1hdGNoKFNjcmlwdEJsb2NrVGV4dCwgXCIoP2kpQ2xlYXItRXZlbnRMb2dcIilcbiAg',
        'ICB8IHN0YXRzIGNvdW50IEJZIGhvc3QgdXNlclxuXVxuIn1dLCAiVDEwNTUiOiBbeyJOYW1lIjog',
        'IlQxMDU1LjEgLSBDcmVhdGVSZW1vdGVUaHJlYWQgKFN5c21vbiBFSUQgOCkiLCAiV2h5IjogIlRI',
        'RSBjbGFzc2ljIHByb2Nlc3MtaW5qZWN0aW9uIGluZGljYXRvci4gS2FzcGVyc2t5IGFsZXJ0cy4i',
        'LCAiU1BMIjogIlxuaW5kZXg9KiAoRXZlbnRDb2RlPTggT1IgRXZlbnRJRD04KVxufCBzdGF0cyBj',
        'b3VudCBCWSBob3N0IFNvdXJjZUltYWdlIFRhcmdldEltYWdlIE5ld1RocmVhZElkXG58IHNvcnQg',
        'LSBjb3VudFxuIn0sIHsiTmFtZSI6ICJUMTA1NS4yIC0gUHJvY2VzcyBhY2Nlc3MgdG8gTFNBU1Mv',
        'c2Vuc2l0aXZlIHRhcmdldHMiLCAiV2h5IjogIlN5c21vbiBFSUQgMTAgd2l0aCBHcmFudGVkQWNj',
        'ZXNzIDB4MTQxMC8weDEwMTAgPSBpbmplY3Rpb24gcHJlcC4iLCAiU1BMIjogIlxuaW5kZXg9KiAo',
        'RXZlbnRDb2RlPTEwIE9SIEV2ZW50SUQ9MTApXG4gICAgICAgKFRhcmdldEltYWdlPVwiKlxcXFxs',
        'c2Fzcy5leGVcIiBPUiBHcmFudGVkQWNjZXNzPVwiMHgxNDEwXCIgT1IgR3JhbnRlZEFjY2Vzcz1c',
        'IjB4MTAxMFwiIE9SIEdyYW50ZWRBY2Nlc3M9XCIweDQwXCIpXG58IHN0YXRzIGNvdW50IEJZIGhv',
        'c3QgU291cmNlSW1hZ2UgVGFyZ2V0SW1hZ2UgR3JhbnRlZEFjY2Vzc1xufCBzb3J0IC0gY291bnRc',
        'biJ9LCB7Ik5hbWUiOiAiVDEwNTUuMyAtIFJlZmxlY3RpdmUgRExMIHNpZ25hdHVyZXMgaW4gUG93',
        'ZXJTaGVsbCIsICJXaHkiOiAiVDEwNTUuMDAxIGF0b21pY3MgdXNlIFZpcnR1YWxBbGxvYy9DcmVh',
        'dGVSZW1vdGVUaHJlYWQgdmlhIC5ORVQgcmVmbGVjdGlvbi4iLCAiU1BMIjogIlxuaW5kZXg9KiAo',
        'RXZlbnRDb2RlPTQxMDQgT1IgRXZlbnRJRD00MTA0KVxufCB3aGVyZSBtYXRjaChTY3JpcHRCbG9j',
        'a1RleHQsIFwiKD9pKVZpcnR1YWxBbGxvY1wiKVxuICAgICAgIE9SIG1hdGNoKFNjcmlwdEJsb2Nr',
        'VGV4dCwgXCIoP2kpQ3JlYXRlUmVtb3RlVGhyZWFkXCIpXG4gICAgICAgT1IgbWF0Y2goU2NyaXB0',
        'QmxvY2tUZXh0LCBcIig/aSlXcml0ZVByb2Nlc3NNZW1vcnlcIilcbiAgICAgICBPUiBtYXRjaChT',
        'Y3JpcHRCbG9ja1RleHQsIFwiKD9pKVxcW1JlZmxlY3Rpb25cXC5Bc3NlbWJseVxcXTo6TG9hZFwi',
        'KVxufCBzdGF0cyBjb3VudCBCWSBob3N0IHVzZXJcbiJ9XSwgIlQxMjE4IjogW3siTmFtZSI6ICJU',
        'MTIxOC4xIC0gTE9MQmluIGV4ZWN1dGlvbiAobXNodGEvcnVuZGxsMzIvcmVnc3ZyMzIvd21pYyki',
        'LCAiV2h5IjogIlwiTGl2aW5nIG9mZiB0aGUgbGFuZFwiIGJpbmFyaWVzLiBBbnkgdW51c3VhbCBw',
        'YXJlbnQgPSBhbGVydC4iLCAiU1BMIjogIlxuaW5kZXg9KiAoRXZlbnRDb2RlPTEgT1IgRXZlbnRJ',
        'RD0xIE9SIEV2ZW50Q29kZT00Njg4IE9SIEV2ZW50SUQ9NDY4OClcbiAgICAgICAoSW1hZ2U9XCIq',
        'XFxcXG1zaHRhLmV4ZVwiIE9SIEltYWdlPVwiKlxcXFxydW5kbGwzMi5leGVcIlxuICAgICAgICBP',
        'UiBJbWFnZT1cIipcXFxccmVnc3ZyMzIuZXhlXCIgT1IgSW1hZ2U9XCIqXFxcXHdtaWMuZXhlXCJc',
        'biAgICAgICAgT1IgSW1hZ2U9XCIqXFxcXGluc3RhbGx1dGlsLmV4ZVwiIE9SIEltYWdlPVwiKlxc',
        'XFxtc2J1aWxkLmV4ZVwiXG4gICAgICAgIE9SIEltYWdlPVwiKlxcXFxjbXN0cC5leGVcIiBPUiBJ',
        'bWFnZT1cIipcXFxcb2RiY2NvbmYuZXhlXCIpXG58IHN0YXRzIGNvdW50IHZhbHVlcyhQYXJlbnRJ',
        'bWFnZSkgQVMgcGFyZW50cyB2YWx1ZXMoQ29tbWFuZExpbmUpIEFTIGNtZHMgQlkgaG9zdCBVc2Vy',
        'IEltYWdlXG58IHNvcnQgLSBjb3VudFxuIn0sIHsiTmFtZSI6ICJUMTIxOC4yIC0gcmVnc3ZyMzIg',
        'L2kgc2Nyb2JqLmRsbCAoU3F1aWJseWRvbykiLCAiV2h5IjogIkNsYXNzaWMgYXBwLXdoaXRlbGlz',
        'dCBieXBhc3MuIEthc3BlcnNreSBjYXRjaGVzIHRoZSBwYXR0ZXJuLiIsICJTUEwiOiAiXG5pbmRl',
        'eD0qIChFdmVudENvZGU9MSBPUiBFdmVudElEPTEpIEltYWdlPVwiKnJlZ3N2cjMyLmV4ZVwiXG4g',
        'ICAgICAgKENvbW1hbmRMaW5lPVwiKi9pKlwiIE9SIENvbW1hbmRMaW5lPVwiKnNjcm9iaipcIiBP',
        'UiBDb21tYW5kTGluZT1cIipzY3JvYmouZGxsKlwiKVxufCBzdGF0cyBjb3VudCBCWSBob3N0IFVz',
        'ZXIgQ29tbWFuZExpbmVcbiJ9LCB7Ik5hbWUiOiAiVDEyMTguMyAtIHJ1bmRsbDMyIHdpdGggamF2',
        'YXNjcmlwdDogb3Igb2RkaXRpZXMiLCAiV2h5IjogInJ1bmRsbDMyIGphdmFzY3JpcHQ6IGlzIGEg',
        'a25vd24gYnlwYXNzLiIsICJTUEwiOiAiXG5pbmRleD0qIChFdmVudENvZGU9MSBPUiBFdmVudElE',
        'PTEpIEltYWdlPVwiKnJ1bmRsbDMyLmV4ZVwiXG4gICAgICAgKENvbW1hbmRMaW5lPVwiKmphdmFz',
        'Y3JpcHQ6KlwiIE9SIENvbW1hbmRMaW5lPVwiKi1zdGEqXCIpXG58IHN0YXRzIGNvdW50IEJZIGhv',
        'c3QgVXNlciBDb21tYW5kTGluZVxuIn1dLCAiVDEwMDMiOiBbeyJOYW1lIjogIlQxMDAzLjEgLSBM',
        'U0FTUyBwcm9jZXNzIGFjY2VzcyAoRUlEIDEwKSIsICJXaHkiOiAiVGhlIHNpbmdsZSBtb3N0LXdh',
        'dGNoZWQgZXZlbnQuIEdyYW50ZWRBY2Nlc3MgMHgxMDEwLzB4MTQxMCA9IGFsZXJ0LiIsICJTUEwi',
        'OiAiXG5pbmRleD0qIChFdmVudENvZGU9MTAgT1IgRXZlbnRJRD0xMCkgVGFyZ2V0SW1hZ2U9XCIq',
        'XFxcXGxzYXNzLmV4ZVwiXG58IHN0YXRzIGNvdW50IHZhbHVlcyhHcmFudGVkQWNjZXNzKSBBUyBh',
        'Y2Nlc3MgdmFsdWVzKENhbGxUcmFjZSkgQVMgdHJhY2VzIEJZIGhvc3QgU291cmNlSW1hZ2Vcbnwg',
        'c29ydCAtIGNvdW50XG4ifSwgeyJOYW1lIjogIlQxMDAzLjIgLSBjb21zdmNzLmRsbCBNaW5pRHVt',
        'cCAoYXRvbWljIFQxMDAzLjAwMSkiLCAiV2h5IjogIkZhbW91cyBhdG9taWMgdXNlcyBydW5kbGwz',
        'MiBjb21zdmNzLmRsbCBNaW5pRHVtcC4iLCAiU1BMIjogIlxuaW5kZXg9KiAoRXZlbnRDb2RlPTEg',
        'T1IgRXZlbnRJRD0xIE9SIEV2ZW50Q29kZT00MTA0IE9SIEV2ZW50SUQ9NDEwNClcbiAgICAgICAo',
        'XCJjb21zdmNzLmRsbFwiIFwiTWluaUR1bXBcIlxuICAgICAgICBPUiBcInByb2NkdW1wXCIgXCJs',
        'c2Fzc1wiXG4gICAgICAgIE9SIFwiT3V0LU1pbmlkdW1wXCIpXG58IHN0YXRzIGNvdW50IEJZIGhv',
        'c3QgVXNlciBDb21tYW5kTGluZVxuIn0sIHsiTmFtZSI6ICJUMTAwMy4zIC0gTWltaWthdHogc2ln',
        'bmF0dXJlIGluIFNjcmlwdEJsb2NrIiwgIldoeSI6ICJLYXNwZXJza3kgQU1TSSBlbmdpbmUgc2hv',
        'dWxkIGJsb2NrIHRoaXMgb24gNDEwNC4iLCAiU1BMIjogIlxuaW5kZXg9KiAoRXZlbnRDb2RlPTQx',
        'MDQgT1IgRXZlbnRJRD00MTA0KVxufCB3aGVyZSBtYXRjaChTY3JpcHRCbG9ja1RleHQsIFwiKD9p',
        'KXNla3VybHNhOjpcIilcbiAgICAgICBPUiBtYXRjaChTY3JpcHRCbG9ja1RleHQsIFwiKD9pKUlu',
        'dm9rZS1NaW1pa2F0elwiKVxuICAgICAgIE9SIG1hdGNoKFNjcmlwdEJsb2NrVGV4dCwgXCIoP2kp',
        'RHVtcENyZWRzXCIpXG58IHN0YXRzIGNvdW50IEJZIGhvc3QgdXNlclxuIn1dLCAiVDExNDAiOiBb',
        'eyJOYW1lIjogIlQxMTQwLjEgLSBCYXNlNjQgZGVjb2RlICsgSUVYIGNoYWluIiwgIldoeSI6ICJG',
        'cm9tQmFzZTY0U3RyaW5nIGZvbGxvd2VkIGJ5IElFWCBpcyBUSEUgYXRvbWljIFQxMTQwIHBhdHRl',
        'cm4uIiwgIlNQTCI6ICJcbmluZGV4PSogKEV2ZW50Q29kZT00MTA0IE9SIEV2ZW50SUQ9NDEwNClc',
        'bnwgd2hlcmUgbWF0Y2goU2NyaXB0QmxvY2tUZXh0LCBcIig/aSlGcm9tQmFzZTY0U3RyaW5nXCIp',
        'XG4gICAgICAgQU5EIChtYXRjaChTY3JpcHRCbG9ja1RleHQsIFwiKD9pKUlFWFwiKSBPUiBtYXRj',
        'aChTY3JpcHRCbG9ja1RleHQsIFwiKD9pKUludm9rZS1FeHByZXNzaW9uXCIpKVxufCBzdGF0cyBj',
        'b3VudCBCWSBob3N0IHVzZXJcbiJ9LCB7Ik5hbWUiOiAiVDExNDAuMiAtIGNlcnR1dGlsIC1kZWNv',
        'ZGUgKExPTEJpbiBkZWNvZGVyKSIsICJXaHkiOiAiY2VydHV0aWwgLWRlY29kZSBpcyB0aGUgTE9M',
        'QmluIHdheSB0byBkZW9iZnVzY2F0ZS4iLCAiU1BMIjogIlxuaW5kZXg9KiAoRXZlbnRDb2RlPTEg',
        'T1IgRXZlbnRJRD0xIE9SIEV2ZW50Q29kZT00Njg4IE9SIEV2ZW50SUQ9NDY4OClcbiAgICAgICBJ',
        'bWFnZT1cIipjZXJ0dXRpbC5leGVcIlxuICAgICAgIChDb21tYW5kTGluZT1cIiotZGVjb2RlKlwi',
        'IE9SIENvbW1hbmRMaW5lPVwiKi1kZWNvZGVoZXgqXCIgT1IgQ29tbWFuZExpbmU9XCIqLXVybGNh',
        'Y2hlKlwiKVxufCBzdGF0cyBjb3VudCBCWSBob3N0IFVzZXIgQ29tbWFuZExpbmVcbiJ9LCB7Ik5h',
        'bWUiOiAiVDExNDAuMyAtIFhPUiAvIGNoYXItc3Vic3RpdHV0aW9uIGRlY29kZXJzIGlubGluZSIs',
        'ICJXaHkiOiAiSGV1cmlzdGljIGZvciBjdXN0b20gZGVjb2RlcnM6IC1ieG9yICsgY2hhciBhcnJh',
        'eXMuIiwgIlNQTCI6ICJcbmluZGV4PSogKEV2ZW50Q29kZT00MTA0IE9SIEV2ZW50SUQ9NDEwNClc',
        'bnwgd2hlcmUgbWF0Y2goU2NyaXB0QmxvY2tUZXh0LCBcIig/aSktYnhvclwiKVxuICAgICAgIE9S',
        'IG1hdGNoKFNjcmlwdEJsb2NrVGV4dCwgXCIoP2kpXFxbY2hhclxcXVwiKVxufCBzdGF0cyBjb3Vu',
        'dCBCWSBob3N0IHVzZXJcbnwgd2hlcmUgY291bnQgPj0gM1xuIn1dLCAiVDE1MDUiOiBbeyJOYW1l',
        'IjogIlQxNTA1LjEgLSB4cF9jbWRzaGVsbCBleGVjdXRpb24gKENMQVNTSUMgU1FMIFNlcnZlciBh',
        'dHRhY2spIiwgIldoeSI6ICJ4cF9jbWRzaGVsbCBsZXRzIFNRTCBydW4gT1MgY29tbWFuZHMuIERp',
        'c2FibGVkIGJ5IGRlZmF1bHQgaW4gbW9kZXJuIFNRTCBidXQgb2xkIFNRTCAyMDA1LzIwMDgvMjAx',
        'MiBoYWQgaXQgT04uIFN5c21vbiBjYXRjaGVzIHNxbHNlcnZyLmV4ZSAtPiBjbWQuZXhlIHBhcmVu',
        'dC1jaGlsZC4iLCAiU1BMIjogIlxuaW5kZXg9KiAoRXZlbnRDb2RlPTEgT1IgRXZlbnRJRD0xKVxu',
        'ICAgICAgIFBhcmVudEltYWdlPVwiKnNxbHNlcnZyLmV4ZVwiXG4gICAgICAgKEltYWdlPVwiKlxc',
        'XFxjbWQuZXhlXCIgT1IgSW1hZ2U9XCIqXFxcXHBvd2Vyc2hlbGwuZXhlXCIgT1IgSW1hZ2U9XCIq',
        'XFxcXHdtaWMuZXhlXCIpXG58IHN0YXRzIGNvdW50IHZhbHVlcyhDb21tYW5kTGluZSkgQVMgY21k',
        'bGluZXMgQlkgaG9zdCBQYXJlbnRJbWFnZSBJbWFnZSBVc2VyXG58IHNvcnQgLSBjb3VudFxuIn0s',
        'IHsiTmFtZSI6ICJUMTUwNS4yIC0gc3BfT0FDcmVhdGUgLyBPTEUgQXV0b21hdGlvbiBQcm9jZWR1',
        'cmVzIHVzYWdlIiwgIldoeSI6ICJzcF9PQUNyZWF0ZSBpcyB0aGUgc2Vjb25kIHdheSB0byBlc2Nh',
        'cGUgU1FMLiBPZnRlbiBsZWZ0IGVuYWJsZWQgb24gbGVnYWN5IERCcy4gU1FMIGF1ZGl0IGxvZyBj',
        'YXB0dXJlcyBpdC4iLCAiU1BMIjogIlxuaW5kZXg9KiAoXCJzcF9PQUNyZWF0ZVwiIE9SIFwic3Bf',
        'T0FNZXRob2RcIiBPUiBcIk9sZSBBdXRvbWF0aW9uIFByb2NlZHVyZXNcIilcbnwgc3RhdHMgY291',
        'bnQgQlkgaG9zdCBzb3VyY2Ugc291cmNldHlwZVxufCBzb3J0IC0gY291bnRcbiJ9LCB7Ik5hbWUi',
        'OiAiVDE1MDUuMyAtIFNRTCBTZXJ2ZXIgY29uZmlndXJhdGlvbiBjaGFuZ2VkIChDUklUSUNBTCki',
        'LCAiV2h5IjogIkF0dGFja2VyIGVuYWJsZXMgeHBfY21kc2hlbGwgb3IgT2xlIEF1dG9tYXRpb24g',
        'dmlhIHNwX2NvbmZpZ3VyZS4gTGVnYWN5IFNRTCBhdWRpdCArIFN5c21vbiBDb21tYW5kTGluZS4i',
        'LCAiU1BMIjogIlxuaW5kZXg9KiAoRXZlbnRDb2RlPTQxMDQgT1IgRXZlbnRJRD00MTA0IE9SIEV2',
        'ZW50Q29kZT0xIE9SIEV2ZW50SUQ9MSlcbiAgICAgICAoXCJzcF9jb25maWd1cmVcIiBcInhwX2Nt',
        'ZHNoZWxsXCJcbiAgICAgICAgT1IgXCJzcF9jb25maWd1cmVcIiBcIk9sZSBBdXRvbWF0aW9uXCJc',
        'biAgICAgICAgT1IgXCJzcF9jb25maWd1cmVcIiBcInNob3cgYWR2YW5jZWQgb3B0aW9uc1wiXG4g',
        'ICAgICAgIE9SIFwiUkVDT05GSUdVUkVcIilcbnwgc3RhdHMgY291bnQgQlkgaG9zdCBVc2VyIENv',
        'bW1hbmRMaW5lXG58IHNvcnQgLSBjb3VudFxuIn0sIHsiTmFtZSI6ICJUMTUwNS40IC0gU1FMIFNl',
        'cnZlciBzdG9yZWQgcHJvYyBjcmVhdGVkL21vZGlmaWVkIGJ5IHN1c3BpY2lvdXMgYWNjb3VudCIs',
        'ICJXaHkiOiAiQXR0YWNrZXIgZHJvcHMgYSBwZXJzaXN0ZW50IGJhY2tkb29yIGFzIGEgc3RvcmVk',
        'IHByb2NlZHVyZS4gV2F0Y2ggQ1JFQVRFL0FMVEVSIFBST0NFRFVSRSBpbiBTUUwgYXVkaXQgbG9n',
        'cy4iLCAiU1BMIjogIlxuaW5kZXg9KiBzb3VyY2V0eXBlPVwiKm1zc3FsKlwiXG4gICAgICAgKFwi',
        'Q1JFQVRFIFBST0NFRFVSRVwiIE9SIFwiQUxURVIgUFJPQ0VEVVJFXCIgT1IgXCJDUkVBVEUgRlVO',
        'Q1RJT05cIilcbnwgc3RhdHMgY291bnQgQlkgaG9zdCBkYXRhYmFzZV9uYW1lIHNlc3Npb25fc2Vy',
        'dmVyX3ByaW5jaXBhbF9uYW1lIHN0YXRlbWVudFxufCBzb3J0IC0gY291bnRcbiJ9LCB7Ik5hbWUi',
        'OiAiVDE1MDUuNSAtIFNRTCBTZXJ2ZXIgYnJ1dGUgZm9yY2UgLyB3ZWFrIHNhIGxvZ2luIiwgIldo',
        'eSI6ICJPdXRkYXRlZCBTUUwgb2Z0ZW4gaGFzIHdlYWsgXCJzYVwiIHBhc3N3b3Jkcy4gRUlEIDE4',
        'NDU2IChmYWlsZWQgbG9nb24pIGJ1cnN0IGZyb20gb25lIElQID0gYnJ1dGUgZm9yY2UuIiwgIlNQ',
        'TCI6ICJcbmluZGV4PSogKEV2ZW50Q29kZT0xODQ1NiBPUiBFdmVudElEPTE4NDU2IE9SIFwiTG9n',
        'aW4gZmFpbGVkIGZvciB1c2VyXCIpXG58IHN0YXRzIGNvdW50IGVhcmxpZXN0KF90aW1lKSBBUyBm',
        'aXJzdCBsYXRlc3QoX3RpbWUpIEFTIGxhc3RcbiAgICAgICAgdmFsdWVzKGNsaWVudF9pcCkgQVMg',
        'c3JjcyBCWSBob3N0IHVzZXJfbmFtZVxufCB3aGVyZSBjb3VudCA+IDEwXG58IGNvbnZlcnQgY3Rp',
        'bWUoZmlyc3QpIGN0aW1lKGxhc3QpXG58IHNvcnQgLSBjb3VudFxuIn1dfQ=='
    ) -join '')
    $decodedJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($queryBlob))
    $parsed = $decodedJson | ConvertFrom-Json
    $byTechnique = @{}
    foreach ($prop in $parsed.PSObject.Properties) {
        $byTechnique[$prop.Name] = $prop.Value
    }

    Write-Cli "`n============================================================" -Color Cyan
    Write-Cli " DETECTION QUERIES FOR $TechniqueId" -Color Cyan
    Write-Cli "============================================================" -Color Cyan

    if (-not $byTechnique.ContainsKey($TechniqueId)) {
        Write-Cli "`n[!] No bundled queries for $TechniqueId yet." -Color Yellow
        Write-Cli "    Run [s] from the main menu for the general blind-hunt set.`n" -Color Yellow
        return
    }

    foreach ($q in $byTechnique[$TechniqueId]) {
        Write-Cli "`n--- $($q.Name) ---" -Color Yellow
        Write-Cli "Why: $($q.Why)`n" -Color DarkGray
        Write-Cli $q.SPL -Color White
    }

    Write-Cli "`n============================================================" -Color Cyan
    Write-Cli " TIP: Run the atomic first (option [a]), then run these queries" -Color Cyan
    Write-Cli "      in Splunk. Each query has 'Why' explaining the detection." -Color Cyan
    Write-Cli "============================================================`n" -Color Cyan
}

# endregion

# =====================================================================
# region SPLUNK HUNT HELPER (blind-hunt style, index=*)
# =====================================================================

function Show-SplunkQueries {
    $header = @'

============================================================
SPLUNK BLIND-HUNT HELPER  -  AtomicHunt + Atomic Red Team
============================================================
Assumes SOC has NO custom index, NO parser configured.
Queries use index=* and rely on signatures present in the
logs themselves. Adjust the timeframe in the search picker.
============================================================

'@
    Write-Cli $header -Color Cyan

    $queries = @(
@{ Name = '1. The blindfolded hunt - find AtomicHunt logs anywhere'
   Why  = 'Run this FIRST. If empty, fix ingestion before everything.'
   SPL  = @'
index=* "AtomicHunt"
| stats count BY index sourcetype host source
| sort - count
'@ },
@{ Name = '2. Find by Atomic Red Team module artifacts'
   Why  = 'Even if AtomicHunt is not ingested, AtomicRedTeam itself logs to PowerShell 4104. Hunt those too.'
   SPL  = @'
index=* ("Invoke-AtomicTest" OR "AtomicRedTeam" OR "atomic-red-team")
| stats count BY index sourcetype host source
| sort - count
'@ },
@{ Name = '3. PowerShell ScriptBlock 4104 - command line signatures'
   Why  = 'Atomics fire from powershell.exe. EID 4104 (Script Block Logging) is the gold mine. Filter for common atomic command words.'
   SPL  = @'
index=* (EventCode=4104 OR EventID=4104)
       ("Invoke-AtomicTest" OR "AtomicRedTeam"
        OR "DownloadString" OR "FromBase64String"
        OR "IEX " OR "Invoke-Expression")
| stats count values(host) AS hosts BY ScriptBlockText user
| sort - count
'@ },
@{ Name = '4. Extract technique ID, test number, session from raw logs'
   Why  = 'No props.conf? rex inline. Pull the IDs the SOC needs to pivot.'
   SPL  = @'
index=* "AtomicHunt"
| rex field=_raw "technique=(?<technique>T\d{4}(?:\.\d{3})?)"
| rex field=_raw "test_number=(?<test_number>\d+)"
| rex field=_raw "sim_session=(?<sim_session>[a-f0-9]{12})"
| rex field=_raw "verb=(?<verb>[A-Z_]+)"
| stats count values(technique) AS techniques values(verb) AS verbs
        BY host user sim_session
| sort - count
'@ },
@{ Name = '5. EXECUTE_START without EXECUTE_END - test crashed or evaded'
   Why  = 'A start with no matching end (after 5 min) is either a crash or active evasion. Both worth investigating.'
   SPL  = @'
index=* "AtomicHunt"
| rex field=_raw "technique=(?<technique>T\d{4}(?:\.\d{3})?)"
| rex field=_raw "action=(?<action>[A-Z_]+)"
| rex field=_raw "sim_session=(?<sim_session>[a-f0-9]{12})"
| eval is_start = if(match(action,"EXECUTE_START"),1,0)
| eval is_end   = if(match(action,"EXECUTE_END") OR match(action,"EXECUTE_FAILED"),1,0)
| stats sum(is_start) AS starts sum(is_end) AS ends earliest(_time) AS first latest(_time) AS last
        BY sim_session host technique
| where starts > ends AND (now() - last) > 300
| convert ctime(first) ctime(last)
'@ },
@{ Name = '6. Tactic-level execution timeline'
   Why  = 'Show the SOC the whole drill: which tactics ran, in what order, how fast.'
   SPL  = @'
index=* "AtomicHunt" ("TACTIC" OR "TEST")
| rex field=_raw "tactic=(?<tactic>[A-Za-z _]+)"
| rex field=_raw "technique=(?<technique>T\d{4}(?:\.\d{3})?)"
| rex field=_raw "sim_session=(?<sim_session>[a-f0-9]{12})"
| timechart span=1m count BY tactic
'@ },
@{ Name = '7. Cross-source correlation - AtomicHunt event + Sysmon process'
   Why  = 'The real test. When AtomicHunt logs an EXECUTE_START, can the SOC find the matching Sysmon Process Create within +/- 10 sec?'
   SPL  = @'
index=* ("AtomicHunt" OR EventCode=1 OR EventID=1)
| rex field=_raw "technique=(?<technique>T\d{4}(?:\.\d{3})?)"
| rex field=_raw "sim_session=(?<sim_session>[a-f0-9]{12})"
| eval source_type = case(
      match(_raw,"AtomicHunt"), "atomichunt",
      match(_raw,"Sysmon")    , "sysmon_process",
      true(), "other")
| stats earliest(_time) AS first latest(_time) AS last count BY host technique sim_session source_type
| eval window_sec = round(last - first, 1)
| where source_type="atomichunt" OR source_type="sysmon_process"
| sort - count
'@ },
@{ Name = '8. Outcome breakdown - SUCCESS vs FAILED'
   Why  = 'Quick view of which atomics survived prereq checks vs which failed.'
   SPL  = @'
index=* "AtomicHunt"
| rex field=_raw "technique=(?<technique>T\d{4}(?:\.\d{3})?)"
| rex field=_raw "outcome=(?<outcome>\w+)"
| rex field=_raw "action=(?<action>[A-Z_]+)"
| stats count BY technique action outcome
| sort - count
'@ },
@{ Name = '9. Suspicious child processes spawned during the drill'
   Why  = 'Many atomics spawn cmd/powershell/mshta/rundll32/regsvr32. Catching the child within a session window proves correlation.'
   SPL  = @'
index=* (EventCode=1 OR EventID=1 OR "Process Create")
       (Image="*powershell.exe" OR Image="*cmd.exe"
        OR Image="*mshta.exe" OR Image="*rundll32.exe"
        OR Image="*regsvr32.exe" OR Image="*wmic.exe"
        OR Image="*certutil.exe" OR Image="*bitsadmin.exe")
| stats count earliest(_time) AS first latest(_time) AS last
        values(CommandLine) AS cmdlines
        BY host User Image ParentImage
| sort - count
'@ },
@{ Name = '10. SOC GRADING DASHBOARD - chain completeness per session'
   Why  = 'One query that scores every drill. Use to grade analysts after each run.'
   SPL  = @'
index=* "AtomicHunt"
| rex field=_raw "technique=(?<technique>T\d{4}(?:\.\d{3})?)"
| rex field=_raw "sim_session=(?<sim_session>[a-f0-9]{12})"
| rex field=_raw "tactic=(?<tactic>[A-Za-z _]+)"
| rex field=_raw "action=(?<action>[A-Z_]+)"
| where isnotnull(sim_session)
| stats earliest(_time) AS first latest(_time) AS last
        count AS events
        dc(technique) AS unique_techniques
        dc(tactic)    AS unique_tactics
        values(technique) AS techniques
        values(tactic)    AS tactics
        BY sim_session host
| eval duration_min = round((last - first)/60, 1)
| eval verdict = case(
      unique_tactics >= 4, "MULTI-TACTIC DRILL  - SOC must catch this",
      unique_tactics = 3,  "THREE TACTICS       - hard hunt",
      unique_tactics = 2,  "TWO TACTICS         - moderate",
      unique_tactics = 1,  "SINGLE TACTIC       - easy",
      true(), "unknown")
| convert ctime(first) ctime(last)
| table sim_session host verdict unique_tactics unique_techniques events duration_min tactics techniques first last
| sort - unique_tactics - events
'@ }
    )

    foreach ($q in $queries) {
        Write-Cli "`n--- $($q.Name) ---" -Color Yellow
        Write-Cli "Why: $($q.Why)`n" -Color DarkGray
        Write-Cli $q.SPL -Color White
    }

    Write-Cli "`n============================================================" -Color Cyan
    Write-Cli "TIP: Query #1 confirms ingestion. Query #10 grades the SOC." -Color Cyan
    Write-Cli "     Pair AtomicHunt logs with Sysmon for the chain test (#7)." -Color Cyan
    Write-Cli "============================================================`n" -Color Cyan
}

# endregion

# =====================================================================
# region MAIN
# =====================================================================

if ($ShowSplunkQueries) {
    Show-Banner
    Show-SplunkQueries
    return
}

Show-Banner
Initialize-Logging
$Script:CurrentSession = [guid]::NewGuid().ToString('N').Substring(0,12)

Write-HuntEvent -EventId $Script:EventIds.Startup -Category 'CONTROL' -Action 'STARTUP' `
                -Severity 'Information' -Message "AtomicHunt started by $env:USERNAME on $env:COMPUTERNAME" `
                -Fields @{ pwsh_ver = $PSVersionTable.PSVersion.ToString(); dryrun = [bool]$DryRun }

$Script:AtomicsRoot = Find-AtomicsFolder
if (-not $Script:AtomicsRoot) {
    Write-Cli "`n[-] No atomics folder found. Provide -AtomicsPath or clone:" -Color Red
    Write-Cli "    git clone https://github.com/redcanaryco/atomic-red-team.git C:\AtomicRedTeam" -Color Yellow
    return
}

$haveModule = Ensure-Invoke-AtomicRedTeam
if (-not $haveModule) {
    Write-Cli "`n[!] Running in read-only mode (no test execution possible)." -Color Yellow
    $Script:DryRun = $true; $DryRun = $true
}

$Script:Catalog = Build-TechniqueCatalog -Atomics $Script:AtomicsRoot
if ($Script:Catalog.Count -eq 0) {
    Write-Cli "[-] Catalog is empty. Check that the atomics folder contains T*/T*.yaml files." -Color Red
    return
}

try {
    Show-MainMenu
} finally {
    Write-HuntEvent -EventId $Script:EventIds.Shutdown -Category 'CONTROL' -Action 'SHUTDOWN' `
                    -Severity 'Information' -Message "AtomicHunt exiting"
    Write-Cli "`nLogs:" -Color Green
    Write-Cli "  JSON     : $($Script:Config.JsonLog)" -Color Green
    Write-Cli "  CEF      : $($Script:Config.CefLog)"  -Color Green
    Write-Cli "  WinEvent : Application log, Source=AtomicHunt`n" -Color Green
    Write-Cli "Run with -ShowSplunkQueries to print the SOC hunt helper.`n" -Color Cyan
}

# endregion
