[CmdletBinding()]
param(
    [switch]$DryRun,
    [string[]]$Only,
    [switch]$NoNetwork,
    [switch]$IncludeMedium
)

$ErrorActionPreference = 'Continue'
$session = (Get-Date).ToString('yyyyMMddHHmmss')
$src = 'AtomicHuntInline'
$dir = "$env:ProgramData\AtomicHuntInline"
$tmpRoot = Join-Path $dir 'tmp'
$logFile = Join-Path $dir "results-$session.json"
$csvFile = Join-Path $dir "summary-$session.csv"
$txtFile = Join-Path $dir "table-$session.txt"
$splFile = Join-Path $dir "splunk-$session.txt"
$null = New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path $tmpRoot -Force -ErrorAction SilentlyContinue
$results = New-Object System.Collections.Generic.List[object]

try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($src)) {
        [System.Diagnostics.EventLog]::CreateEventSource($src,'Application')
        Start-Sleep -Milliseconds 300
    }
} catch { }

function Shorten {
    param([object]$Value, [int]$Max = 120)
    if ($null -eq $Value) { return 'no output' }
    $s = ($Value | Out-String).Trim()
    $s = $s -replace "`r"," " -replace "`n"," " -replace "\s+"," "
    if ([string]::IsNullOrWhiteSpace($s)) { return 'no output' }
    if ($s.Length -gt $Max) { return $s.Substring(0, $Max - 3) + '...' }
    return $s
}

function Test-MatchesOnly {
    param([string]$Tech, [string]$Name, [string]$Tactic)
    if (-not $Only) { return $true }
    foreach ($item in $Only) {
        if ($Tech -like "*$item*" -or $Name -like "*$item*" -or $Tactic -like "*$item*") { return $true }
    }
    return $false
}

function Add-Result {
    param(
        [string]$Tactic,
        [string]$Tech,
        [string]$Name,
        [string]$Status,
        [string]$Result,
        [string]$Issue
    )

    $runtimeIssue = if ($Status -in @('FAILED','BLOCKED')) { 'Yes' } else { 'No' }

    if ([string]::IsNullOrWhiteSpace($Issue)) {
        $Issue = if ($runtimeIssue -eq 'Yes') { $Result } else { 'No runtime issue' }
    }

    $rec = [pscustomobject]@{
        timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
        sim_session = $session
        tactic = $Tactic
        technique = $Tech
        test = $Name
        status = $Status
        result = $Result
        runtime_issue = $runtimeIssue
        issue = $Issue
        host = $env:COMPUTERNAME
        user = $env:USERNAME
    }

    $results.Add($rec) | Out-Null

    $color = switch ($Status) {
        'OK' { 'Green' }
        'BLOCKED' { 'Red' }
        'FAILED' { 'Yellow' }
        'DRYRUN' { 'DarkCyan' }
        'SKIPPED' { 'DarkGray' }
        default { 'Gray' }
    }

    Write-Host ("[{0,-18}] [{1,-13}] {2,-8} {3}" -f $Tactic, $Tech, $Status, $Name) -ForegroundColor $color

    $eventMessage = "AtomicHuntInline sim_session=$session tactic=$Tactic technique=$Tech test=$Name status=$Status runtime_issue=$runtimeIssue result=$Result issue=$Issue"
    $eventMessage = Shorten $eventMessage 7000

    try {
        Write-EventLog -LogName Application -Source $src -EventId 9999 -EntryType Information -Message $eventMessage -ErrorAction SilentlyContinue
    } catch { }
}

function Run-Test {
    param(
        [string]$Tactic,
        [string]$Tech,
        [string]$Name,
        [scriptblock]$Action
    )

    if (-not (Test-MatchesOnly -Tech $Tech -Name $Name -Tactic $Tactic)) { return }

    if ($DryRun) {
        Add-Result -Tactic $Tactic -Tech $Tech -Name $Name -Status 'DRYRUN' -Result 'Not executed' -Issue 'Dry run only'
        return
    }

    try {
        $out = & $Action
        $summary = Shorten $out 120
        Add-Result -Tactic $Tactic -Tech $Tech -Name $Name -Status 'OK' -Result $summary -Issue 'No runtime issue'
    } catch {
        $msg = Shorten $_.Exception.Message 120
        if ($msg -match 'malicious|blocked|antivirus|AMSI|Access is denied|UnauthorizedAccess') {
            Add-Result -Tactic $Tactic -Tech $Tech -Name $Name -Status 'BLOCKED' -Result $msg -Issue "Possible security control block: $msg"
        } else {
            Add-Result -Tactic $Tactic -Tech $Tech -Name $Name -Status 'FAILED' -Result $msg -Issue $msg
        }
    }
}


function Run-MediumTest {
    param(
        [string]$Tactic,
        [string]$Tech,
        [string]$Name,
        [scriptblock]$Action
    )

    if (-not $IncludeMedium) { return }
    Run-Test -Tactic $Tactic -Tech $Tech -Name $Name -Action $Action
}

function Run-MediumNetworkTest {
    param(
        [string]$Tactic,
        [string]$Tech,
        [string]$Name,
        [scriptblock]$Action
    )

    if (-not $IncludeMedium) { return }
    Run-NetworkTest -Tactic $Tactic -Tech $Tech -Name $Name -Action $Action
}

function Run-NetworkTest {
    param(
        [string]$Tactic,
        [string]$Tech,
        [string]$Name,
        [scriptblock]$Action
    )

    if ($NoNetwork) {
        if (Test-MatchesOnly -Tech $Tech -Name $Name -Tactic $Tactic) {
            Add-Result -Tactic $Tactic -Tech $Tech -Name $Name -Status 'SKIPPED' -Result 'Skipped because -NoNetwork was used' -Issue 'No runtime issue'
        }
        return
    }

    Run-Test -Tactic $Tactic -Tech $Tech -Name $Name -Action $Action
}

Write-Host ""
Write-Host "AtomicHunt-Inline Low-Noise Purple Team Runner" -ForegroundColor Cyan
Write-Host "Session : $session" -ForegroundColor DarkGray
Write-Host "Host    : $env:COMPUTERNAME" -ForegroundColor DarkGray
Write-Host "User    : $env:USERNAME" -ForegroundColor DarkGray
Write-Host "Output  : $dir" -ForegroundColor DarkGray
Write-Host "Mode    : Safe OS-native tests, isolated execution, clean table output" -ForegroundColor DarkGray
if ($DryRun) { Write-Host "DryRun  : Enabled" -ForegroundColor Yellow }
if ($NoNetwork) { Write-Host "Network : Skipped" -ForegroundColor Yellow }
if ($IncludeMedium) { Write-Host "Stimulus: Medium enabled" -ForegroundColor Yellow } else { Write-Host "Stimulus: Low only" -ForegroundColor DarkGray }
Write-Host ""

Write-Host "[ DISCOVERY ]" -ForegroundColor Magenta

Run-Test 'Discovery' 'T1082' 'systeminfo basics' { systeminfo | Select-Object -First 5 }
Run-Test 'Discovery' 'T1082.b' 'OS via CIM' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture }
Run-Test 'Discovery' 'T1082.c' 'BIOS information' { Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SerialNumber,SMBIOSBIOSVersion }
Run-Test 'Discovery' 'T1082.d' 'Computer model' { Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,Domain,PartOfDomain }
Run-Test 'Discovery' 'T1082.e' 'Environment variables summary' { Get-ChildItem Env: | Select-Object Name,Value -First 8 }
Run-Test 'Discovery' 'T1082.f' 'PowerShell version' { $PSVersionTable | Select-Object PSVersion,PSEdition,BuildVersion }
Run-Test 'Discovery' 'T1033' 'whoami all' { whoami /all 2>&1 | Select-Object -First 10 }
Run-Test 'Discovery' 'T1033.b' 'whoami privileges' { whoami /priv 2>&1 | Select-Object -First 12 }
Run-Test 'Discovery' 'T1033.c' 'whoami groups' { whoami /groups 2>&1 | Select-Object -First 12 }
Run-Test 'Discovery' 'T1087.001' 'Local users via net user' { net user 2>&1 | Select-Object -First 8 }
Run-Test 'Discovery' 'T1087.001.b' 'Local users via PowerShell' { Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,LastLogon -First 8 }
Run-Test 'Discovery' 'T1087.002' 'Domain groups via net' { net group /domain 2>&1 | Select-Object -First 8 }
Run-Test 'Discovery' 'T1087.002.b' 'Domain admins query' { net group "Domain Admins" /domain 2>&1 | Select-Object -First 8 }
Run-Test 'Discovery' 'T1069.001' 'Local groups' { net localgroup 2>&1 | Select-Object -First 12 }
Run-Test 'Discovery' 'T1069.001.b' 'Administrators group members' { net localgroup administrators 2>&1 | Select-Object -First 12 }
Run-Test 'Discovery' 'T1069.001.c' 'PowerShell local groups' { Get-LocalGroup -ErrorAction SilentlyContinue | Select-Object Name -First 10 }
Run-Test 'Discovery' 'T1069.002' 'Domain group listing' { net group /domain 2>&1 | Select-Object -First 10 }
Run-Test 'Discovery' 'T1482' 'Domain trust discovery' { nltest /domain_trusts 2>&1 | Select-Object -First 8 }
Run-Test 'Discovery' 'T1016' 'ipconfig all' { ipconfig /all 2>&1 | Select-Object -First 14 }
Run-Test 'Discovery' 'T1016.b' 'IPv4 route print' { route print -4 2>&1 | Select-Object -First 14 }
Run-Test 'Discovery' 'T1016.c' 'DNS cache sample' { ipconfig /displaydns 2>&1 | Select-Object -First 12 }
Run-Test 'Discovery' 'T1016.d' 'Get-NetIPConfiguration' { Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,IPv4Address,IPv4DefaultGateway,DNSServer -First 5 }
Run-Test 'Discovery' 'T1016.e' 'DNS client server addresses' { Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,ServerAddresses -First 8 }
Run-Test 'Discovery' 'T1016.f' 'Net route summary' { Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,NextHop,InterfaceAlias -First 8 }
Run-Test 'Discovery' 'T1049' 'netstat ano' { netstat -ano 2>&1 | Select-Object -First 12 }
Run-Test 'Discovery' 'T1049.b' 'netstat process mapping' { netstat -nb 2>&1 | Select-Object -First 12 }
Run-Test 'Discovery' 'T1049.c' 'Get-NetTCPConnection' { Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State -First 12 }
Run-Test 'Discovery' 'T1018' 'ARP cache' { arp -a 2>&1 | Select-Object -First 12 }
Run-Test 'Discovery' 'T1018.b' 'net view' { net view 2>&1 | Select-Object -First 8 }
Run-Test 'Discovery' 'T1018.c' 'Domain controller list' { nltest /dclist: 2>&1 | Select-Object -First 8 }
Run-Test 'Discovery' 'T1018.d' 'Neighbor cache' { Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress,LinkLayerAddress,State -First 8 }
Run-Test 'Discovery' 'T1135' 'Network shares via net share' { net share 2>&1 | Select-Object -First 10 }
Run-Test 'Discovery' 'T1135.b' 'SMB shares via PowerShell' { Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,Description -First 10 }
Run-Test 'Discovery' 'T1135.c' 'Mapped drives' { Get-SmbMapping -ErrorAction SilentlyContinue | Select-Object LocalPath,RemotePath,Status -First 8 }
Run-Test 'Discovery' 'T1057' 'tasklist' { tasklist 2>&1 | Select-Object -First 8 }
Run-Test 'Discovery' 'T1057.b' 'Get-Process basic' { Get-Process | Select-Object Name,Id,Path -First 8 }
Run-Test 'Discovery' 'T1057.c' 'tasklist services' { tasklist /svc 2>&1 | Select-Object -First 8 }
Run-Test 'Discovery' 'T1007' 'Service discovery' { Get-Service | Select-Object Name,Status,DisplayName -First 10 }
Run-Test 'Discovery' 'T1083' 'User directory enumeration' { Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | Select-Object Name }
Run-Test 'Discovery' 'T1083.b' 'System32 executable count' { (Get-ChildItem C:\Windows\System32 -Filter '*.exe' -ErrorAction SilentlyContinue).Count }
Run-Test 'Discovery' 'T1083.c' 'Desktop item sample' { Get-ChildItem "$env:USERPROFILE\Desktop" -ErrorAction SilentlyContinue | Select-Object Name -First 8 }
Run-Test 'Discovery' 'T1083.d' 'Downloads item sample' { Get-ChildItem "$env:USERPROFILE\Downloads" -ErrorAction SilentlyContinue | Select-Object Name -First 8 }
Run-Test 'Discovery' 'T1518' 'Installed software via registry' { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion -First 8 }
Run-Test 'Discovery' 'T1518.b' 'Installed software Wow6432Node' { Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion -First 8 }
Run-Test 'Discovery' 'T1518.001' 'Security software processes' { Get-Process | Where-Object { $_.ProcessName -match 'avp|kavfs|MsMpEng|Sense|klnagent|kavfsgt|McShield|CrowdStrike|Sentinel|Sophos|CarbonBlack|Defender' } | Select-Object Name,Id -First 10 }
Run-Test 'Discovery' 'T1518.001.b' 'Security software services' { Get-Service | Where-Object { $_.Name -match 'AVP|KAVFS|WinDefend|Sense|klnagent|McAfee|CSFalcon|Sentinel|Sophos|CarbonBlack' -or $_.DisplayName -match 'Kaspersky|Defender|CrowdStrike|Sentinel|Sophos|Carbon Black|McAfee' } | Select-Object Name,Status,DisplayName -First 10 }
Run-Test 'Discovery' 'T1518.001.c' 'SecurityCenter2 antivirus inventory' {
    try {
        Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,pathToSignedProductExe -First 8
    } catch {
        'SecurityCenter2 unavailable or empty'
    }
}
Run-Test 'Discovery' 'T1124' 'System time' { Get-Date; w32tm /query /status 2>&1 | Select-Object -First 5 }
Run-Test 'Discovery' 'T1010' 'Open windows' { Get-Process | Where-Object { $_.MainWindowTitle } | Select-Object Name,MainWindowTitle -First 8 }
Run-Test 'Discovery' 'T1614' 'System locale' { Get-Culture; Get-WinSystemLocale }
Run-Test 'Discovery' 'T1120' 'PnP devices sample' { Get-PnpDevice -ErrorAction SilentlyContinue | Select-Object FriendlyName,Status -First 8 }
Run-Test 'Discovery' 'T1201' 'Password policy' { net accounts 2>&1 | Select-Object -First 12 }

Write-Host ""
Write-Host "[ EXECUTION ]" -ForegroundColor Magenta

Run-Test 'Execution' 'T1059.001' 'PowerShell basic output' { Write-Output 'AtomicHunt-PS-test' }
Run-Test 'Execution' 'T1059.001.b' 'PowerShell EncodedCommand benign' {
    $c = 'Write-Output AtomicHunt-Encoded'
    $e = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($c))
    powershell.exe -NoProfile -EncodedCommand $e 2>&1
}
Run-Test 'Execution' 'T1059.001.c' 'PowerShell child process NoProfile' { powershell.exe -NoProfile -Command "Write-Output AtomicHunt-ChildPS" 2>&1 }
Run-Test 'Execution' 'T1059.001.d' 'PowerShell Get-Date child' { powershell.exe -NoProfile -Command "Get-Date" 2>&1 | Select-Object -First 2 }
Run-Test 'Execution' 'T1059.003' 'cmd echo child' { cmd.exe /c 'echo AtomicHunt-CMD-test' 2>&1 }
Run-Test 'Execution' 'T1059.003.b' 'cmd command chain benign' { cmd.exe /c 'whoami & hostname & echo done' 2>&1 }
Run-Test 'Execution' 'T1059.003.c' 'cmd environment sample' { cmd.exe /c 'set' 2>&1 | Select-Object -First 8 }
Run-Test 'Execution' 'T1059.005' 'VBScript via cscript benign' {
    $vbs = Join-Path $tmpRoot 'ah-test.vbs'
    Set-Content -Path $vbs -Value 'WScript.Echo "AtomicHunt-VBS-test"' -Encoding ASCII
    $o = cscript.exe //Nologo $vbs 2>&1 | Select-Object -First 5
    Remove-Item $vbs -ErrorAction SilentlyContinue
    $o
}
Run-Test 'Execution' 'T1059.007' 'JScript via cscript benign' {
    $js = Join-Path $tmpRoot 'ah-test.js'
    Set-Content -Path $js -Value 'WScript.Echo("AtomicHunt-JS-test");' -Encoding ASCII
    $o = cscript.exe //E:JScript //Nologo $js 2>&1 | Select-Object -First 5
    Remove-Item $js -ErrorAction SilentlyContinue
    $o
}
Run-Test 'Execution' 'T1053.005' 'Scheduled task create and delete benign' {
    schtasks.exe /Create /TN 'AtomicHuntTest' /TR 'cmd.exe /c exit' /SC ONCE /ST 23:59 /F 2>&1 | Select-Object -First 3
    schtasks.exe /Delete /TN 'AtomicHuntTest' /F 2>&1 | Select-Object -First 3
}
Run-Test 'Execution' 'T1047' 'WMI process query' { Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId -First 8 }
Run-Test 'Execution' 'T1047.b' 'WMI service query' { Get-CimInstance Win32_Service | Select-Object Name,State,StartMode -First 8 }
Run-Test 'Execution' 'T1047.c' 'WMIC OS query' { wmic os get Caption,Version 2>&1 | Select-Object -First 5 }

Write-Host ""
Write-Host "[ DEFENSE EVASION ]" -ForegroundColor Magenta

Run-Test 'Defense Evasion' 'T1218.005' 'mshta about blank spawn' {
    $p = Start-Process mshta.exe -ArgumentList 'about:blank' -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 1
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    "mshta PID $($p.Id)"
}
Run-Test 'Defense Evasion' 'T1218.011' 'rundll32 legit Control_RunDLL' {
    $p = Start-Process rundll32.exe -ArgumentList 'shell32.dll,Control_RunDLL' -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 1
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    "rundll32 PID $($p.Id)"
}
Run-Test 'Defense Evasion' 'T1218.010' 'regsvr32 silent local scrobj call' { $p = Start-Process regsvr32.exe -ArgumentList '/s','/u','/n','/i:AtomicHunt','scrobj.dll' -PassThru -Wait -WindowStyle Hidden; "exitcode=$($p.ExitCode)" }
Run-Test 'Defense Evasion' 'T1218.007' 'msiexec quiet invalid package probe' { $fake = Join-Path $tmpRoot 'missing.msi'; $p = Start-Process msiexec.exe -ArgumentList '/qn','/i',$fake -PassThru -Wait -WindowStyle Hidden; "exitcode=$($p.ExitCode)" }
Run-Test 'Defense Evasion' 'T1218.002' 'control.exe applet open close' {
    $p = Start-Process control.exe -ArgumentList '/name Microsoft.System' -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 1
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    "control PID $($p.Id)"
}
Run-Test 'Defense Evasion' 'T1218.help' 'forfiles help only' { forfiles.exe /? 2>&1 | Select-Object -First 3 }
Run-Test 'Defense Evasion' 'T1140' 'certutil decode local benign' {
    $b64 = Join-Path $tmpRoot 'ah-b64.txt'
    $dec = Join-Path $tmpRoot 'ah-dec.txt'
    Set-Content -Path $b64 -Value 'QXRvbWljSHVudC1jZXJ0dXRpbC10ZXN0' -Encoding ASCII
    $o = certutil.exe -decode $b64 $dec 2>&1 | Select-Object -First 4
    Remove-Item $b64,$dec -ErrorAction SilentlyContinue
    $o
}
Run-Test 'Defense Evasion' 'T1027' 'Base64 roundtrip local' {
    $s = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('AtomicHunt-obfuscated'))
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
}
Run-Test 'Defense Evasion' 'T1070.001' 'Event log read Application' { Get-WinEvent -LogName Application -MaxEvents 3 | Select-Object Id,ProviderName,TimeCreated }
Run-Test 'Defense Evasion' 'T1070.001.b' 'Event log read Security' { Get-WinEvent -LogName Security -MaxEvents 3 -ErrorAction SilentlyContinue | Select-Object Id,ProviderName,TimeCreated }
Run-Test 'Defense Evasion' 'T1036.005' 'Process path inspection' { Get-Process svchost -ErrorAction SilentlyContinue | Select-Object -First 5 Path,Id }
Run-Test 'Defense Evasion' 'T1564.001' 'Hidden files enumeration' { Get-ChildItem C:\ -Hidden -ErrorAction SilentlyContinue | Select-Object Name -First 8 }
Run-Test 'Defense Evasion' 'T1497' 'VM detection markers read' { Get-CimInstance Win32_ComputerSystem | Select-Object Model,Manufacturer }
Run-Test 'Defense Evasion' 'T1497.b' 'Hypervisor flag read' { Get-CimInstance Win32_ComputerSystem | Select-Object HypervisorPresent }
Run-Test 'Defense Evasion' 'T1620' 'Loaded assemblies in PowerShell' { [AppDomain]::CurrentDomain.GetAssemblies() | Select-Object FullName -First 5 }
Run-Test 'Defense Evasion' 'T1112.info' 'Registry policy keys inspect' {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,LocalAccountTokenFilterPolicy
}


if ($IncludeMedium) {
Write-Host ""
Write-Host "[ EDR STIMULUS MEDIUM SAFE ]" -ForegroundColor Magenta

Run-MediumTest 'EDR Stimulus' 'T1059.001.m1' 'PowerShell hidden window benign child' {
    $p = Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-Command','Write-Output AtomicHunt-Medium-PS' -PassThru -Wait -WindowStyle Hidden
    "powershell exitcode=$($p.ExitCode)"
}
Run-MediumTest 'EDR Stimulus' 'T1059.001.m2' 'PowerShell Invoke-Expression benign' {
    $x = 'Write-Output AtomicHunt-IEX'
    Invoke-Expression $x
}
Run-MediumTest 'EDR Stimulus' 'T1059.001.m3' 'PowerShell string assembled command benign' {
    $a = 'Get'
    $b = '-Date'
    &("$a$b")
}
Run-MediumTest 'EDR Stimulus' 'T1059.003.m1' 'cmd to PowerShell benign chain' {
    cmd.exe /c 'powershell.exe -NoProfile -Command Write-Output AtomicHunt-CmdToPS' 2>&1
}
Run-MediumTest 'EDR Stimulus' 'T1047.m1' 'WMIC local process create benign' {
    $outFile = Join-Path $tmpRoot 'wmic-create.txt'
    $cmd = "cmd.exe /c echo AtomicHunt-WMIC > $outFile"
    $o = & wmic.exe process call create $cmd 2>&1 | Select-Object -First 8
    Start-Sleep -Seconds 2
    $r = if (Test-Path $outFile) { Get-Content $outFile -ErrorAction SilentlyContinue } else { 'no output file' }
    Remove-Item $outFile -Force -ErrorAction SilentlyContinue
    $o
    $r
}
Run-MediumTest 'EDR Stimulus' 'T1053.005.m1' 'Scheduled task create run delete benign' {
    $taskName = "AtomicHuntMedium-$session"
    $outFile = Join-Path $tmpRoot 'schtask-run.txt'
    schtasks.exe /Create /TN $taskName /TR "cmd.exe /c echo AtomicHunt-Scheduled > $outFile" /SC ONCE /ST 23:59 /F 2>&1 | Select-Object -First 4
    schtasks.exe /Run /TN $taskName 2>&1 | Select-Object -First 4
    Start-Sleep -Seconds 3
    $r = if (Test-Path $outFile) { Get-Content $outFile -ErrorAction SilentlyContinue } else { 'task output not created yet' }
    schtasks.exe /Delete /TN $taskName /F 2>&1 | Select-Object -First 4
    Remove-Item $outFile -Force -ErrorAction SilentlyContinue
    $r
}
Run-MediumTest 'EDR Stimulus' 'T1547.001.m1' 'HKCU Run key create delete benign' {
    $name = "AtomicHuntMedium-$session"
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $name -Value 'cmd.exe /c echo AtomicHunt-RunKey' -PropertyType String -Force | Out-Null
    $r = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $name -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name $name -Force -ErrorAction SilentlyContinue
    if ($r) { 'HKCU Run value created and removed' } else { 'Run value not observed' }
}
Run-MediumTest 'EDR Stimulus' 'T1543.003.m1' 'Service create delete benign' {
    $svcName = "AtomicHuntSvc$session"
    $create = sc.exe create $svcName binPath= "cmd.exe /c exit" start= demand 2>&1 | Select-Object -First 6
    $query = sc.exe query $svcName 2>&1 | Select-Object -First 6
    $delete = sc.exe delete $svcName 2>&1 | Select-Object -First 6
    $create
    $query
    $delete
}
Run-MediumTest 'EDR Stimulus' 'T1218.005.m1' 'mshta local HTA benign command' {
    $hta = Join-Path $tmpRoot 'atomic-hunt.hta'
    $outFile = Join-Path $tmpRoot 'mshta-run.txt'
    $cmd = "cmd.exe /c echo AtomicHunt-MSHTA > $outFile"
    $content = "<html><head><script language=`"VBScript`">CreateObject(`"WScript.Shell`").Run `"$cmd`",0,True:close</script></head><body></body></html>"
    Set-Content -Path $hta -Value $content -Encoding ASCII
    $p = Start-Process mshta.exe -ArgumentList $hta -PassThru -Wait -WindowStyle Hidden
    $r = if (Test-Path $outFile) { Get-Content $outFile -ErrorAction SilentlyContinue } else { 'no output file' }
    Remove-Item $hta,$outFile -Force -ErrorAction SilentlyContinue
    "mshta exitcode=$($p.ExitCode)"
    $r
}
Run-MediumTest 'EDR Stimulus' 'T1218.010.m1' 'regsvr32 scrobj silent probe' {
    $p = Start-Process regsvr32.exe -ArgumentList '/s','/u','/n','/i:AtomicHuntMedium','scrobj.dll' -PassThru -Wait -WindowStyle Hidden
    "regsvr32 exitcode=$($p.ExitCode)"
}
Run-MediumTest 'EDR Stimulus' 'T1105.m1' 'BITS create cancel job no transfer' {
    $job = "AtomicHuntBITS$session"
    bitsadmin /create $job 2>&1 | Select-Object -First 6
    bitsadmin /cancel $job 2>&1 | Select-Object -First 6
}
Run-MediumNetworkTest 'EDR Stimulus' 'T1071.001.m1' 'PowerShell web request custom header benign' {
    $headers = @{ 'User-Agent' = 'AtomicHunt-Medium'; 'X-AtomicHunt' = $session }
    try {
        $r = Invoke-WebRequest -Uri 'https://www.microsoft.com' -UseBasicParsing -Headers $headers -TimeoutSec 5
        "status=$($r.StatusCode) bytes=$($r.RawContentLength)"
    } catch {
        "network error: $($_.Exception.Message)"
    }
}
Run-MediumNetworkTest 'EDR Stimulus' 'T1071.001.m2' 'curl custom user agent benign' {
    curl.exe -A "AtomicHunt-Medium-$session" -s -o NUL -w "%{http_code}" --max-time 5 https://www.microsoft.com 2>&1
}
Run-MediumTest 'EDR Stimulus' 'T1027.m1' 'Encoded command through child PowerShell benign' {
    $c = 'Write-Output AtomicHunt-Encoded-Medium'
    $e = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($c))
    powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $e 2>&1
}
Run-MediumTest 'EDR Stimulus' 'T1564.001.m1' 'Create hidden file then remove' {
    $hidden = Join-Path $tmpRoot "atomic-hidden-$session.txt"
    Set-Content -Path $hidden -Value 'AtomicHunt hidden file test'
    attrib.exe +h $hidden 2>&1 | Select-Object -First 4
    $r = Get-Item $hidden -Force -ErrorAction SilentlyContinue | Select-Object Name,Attributes
    attrib.exe -h $hidden 2>&1 | Select-Object -First 4
    Remove-Item $hidden -Force -ErrorAction SilentlyContinue
    $r
}
Run-MediumTest 'EDR Stimulus' 'T1036.005.m1' 'Copy cmd as svchost-like name run delete' {
    $fake = Join-Path $tmpRoot "svchost32-$session.exe"
    Copy-Item "$env:WINDIR\System32\cmd.exe" $fake -Force
    $p = Start-Process $fake -ArgumentList '/c','echo AtomicHunt-Masquerade' -PassThru -Wait -WindowStyle Hidden
    Remove-Item $fake -Force -ErrorAction SilentlyContinue
    "fake cmd exitcode=$($p.ExitCode)"
}
Run-MediumTest 'EDR Stimulus' 'T1112.m1' 'Benign registry value create delete' {
    $key = 'HKCU:\Software\AtomicHunt'
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "Medium$session" -Value $session -PropertyType String -Force | Out-Null
    $r = Get-ItemProperty -Path $key -Name "Medium$session" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $key -Name "Medium$session" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $key -Force -ErrorAction SilentlyContinue
    if ($r) { 'registry value created and removed' } else { 'registry value not observed' }
}
Run-MediumTest 'EDR Stimulus' 'T1070.004.m1' 'Create and delete temp artifact' {
    $f = Join-Path $tmpRoot "atomic-delete-$session.txt"
    Set-Content -Path $f -Value 'AtomicHunt delete artifact'
    Remove-Item $f -Force
    if (-not (Test-Path $f)) { 'temp artifact created and deleted' } else { 'delete failed' }
}
}

Write-Host ""
Write-Host "[ PERSISTENCE READ ONLY ]" -ForegroundColor Magenta

Run-Test 'Persistence' 'T1547.001' 'Run key inspect HKLM' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Format-List }
Run-Test 'Persistence' 'T1547.001.b' 'Run key inspect HKCU' { Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Format-List }
Run-Test 'Persistence' 'T1547.001.c' 'RunOnce key inspect' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Format-List }
Run-Test 'Persistence' 'T1547.009' 'Startup folder check' { Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name,FullName -First 8 }
Run-Test 'Persistence' 'T1543.003' 'Running services list' { Get-Service | Where-Object Status -eq 'Running' | Select-Object Name,DisplayName -First 8 }
Run-Test 'Persistence' 'T1053.005.b' 'Scheduled tasks list' { schtasks.exe /Query /FO LIST 2>&1 | Select-Object -First 10 }
Run-Test 'Persistence' 'T1546.003' 'WMI event filters check' { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name -First 8 }
Run-Test 'Persistence' 'T1546.003.b' 'WMI consumers check' { Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Select-Object Name -First 8 }
Run-Test 'Persistence' 'T1546.003.c' 'WMI bindings check' { Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter,Consumer -First 8 }
Run-Test 'Persistence' 'T1037.001' 'Logon scripts environment check' { Get-ItemProperty 'HKCU:\Environment' -ErrorAction SilentlyContinue }
Run-Test 'Persistence' 'T1547.004' 'Winlogon shell userinit inspect' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue | Select-Object Shell,Userinit,VMApplet }
Run-Test 'Persistence' 'T1546.012' 'IFEO key sample inspect' { Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | Select-Object PSChildName -First 8 }
Run-Test 'Persistence' 'T1546.010' 'AppInit DLLs inspect' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue | Select-Object AppInit_DLLs,LoadAppInit_DLLs }
Run-Test 'Persistence' 'T1547.005' 'Security packages inspect' { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue | Select-Object Security Packages,Authentication Packages }
Run-Test 'Persistence' 'T1547.012' 'Print monitors inspect' { Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue | Select-Object PSChildName -First 8 }

Write-Host ""
Write-Host "[ PRIVILEGE ESCALATION READ ONLY ]" -ForegroundColor Magenta

Run-Test 'Privilege Escalation' 'T1548.info' 'UAC configuration read' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop }
Run-Test 'Privilege Escalation' 'T1068.info' 'OS hotfix sample' { Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID,InstalledOn -First 8 }
Run-Test 'Privilege Escalation' 'T1055.info' 'Process architecture sample' { Get-Process | Select-Object Name,Id,Path,Company -First 8 }
Run-Test 'Privilege Escalation' 'T1134.info' 'Token privilege listing' { whoami /priv 2>&1 | Select-Object -First 12 }

Write-Host ""
Write-Host "[ CREDENTIAL ACCESS BENIGN PROBES ]" -ForegroundColor Magenta

Run-Test 'Credential Access' 'T1003.info' 'LSASS metadata only' {
    $l = Get-Process lsass -ErrorAction Stop
    "lsass PID=$($l.Id) Handles=$($l.Handles) Path=$($l.Path)"
}
Run-Test 'Credential Access' 'T1552.001' 'Search password keyword file names only' {
    $matches = Get-ChildItem $env:USERPROFILE -Recurse -Include *.txt,*.ini,*.config -ErrorAction SilentlyContinue | Select-String 'password|passwd|pwd' -ErrorAction SilentlyContinue
    $paths = $matches | Select-Object -ExpandProperty Path -Unique | Select-Object -First 5
    if ($paths) { $paths } else { 'no keyword matches found' }
}
Run-Test 'Credential Access' 'T1552.003' 'PowerShell history path check' {
    $p = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath
    if ($p -and (Test-Path $p)) { "history file exists: $p" } else { 'history file not present or PSReadLine unavailable' }
}
Run-Test 'Credential Access' 'T1555.003' 'Chrome credential database path check' {
    $p = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    if (Test-Path $p) { "exists: $p" } else { 'not present' }
}
Run-Test 'Credential Access' 'T1555.003.b' 'Chrome cookie database path check' {
    $p = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies"
    if (Test-Path $p) { "exists: $p" } else { 'not present' }
}
Run-Test 'Credential Access' 'T1555.004' 'Windows Credential Manager target count' {
    $o = cmdkey /list 2>&1
    $count = ($o | Select-String 'Target:' | Measure-Object).Count
    "stored credential targets count=$count"
}
Run-Test 'Credential Access' 'T1558.003' 'Kerberos tickets summary' {
    $o = klist 2>&1
    $line = $o | Select-String 'Cached Tickets' | Select-Object -First 1
    if ($line) { $line.ToString() } else { $o | Select-Object -First 5 }
}
Run-Test 'Credential Access' 'T1110.001' 'Recent failed logons count' {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 -ErrorAction SilentlyContinue
    if ($events) { $events | Select-Object TimeCreated,Id -First 5 } else { 'no recent 4625 events visible' }
}
Run-Test 'Credential Access' 'T1552.004' 'DPAPI protect directory check' {
    $p = "$env:APPDATA\Microsoft\Protect"
    if (Test-Path $p) { "exists: $p" } else { 'not present' }
}

Write-Host ""
Write-Host "[ LATERAL MOVEMENT ENUMERATION ONLY ]" -ForegroundColor Magenta

Run-Test 'Lateral Movement' 'T1021.001' 'RDP service status' { Get-Service TermService -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType }
Run-Test 'Lateral Movement' 'T1021.001.b' 'RDP registry status read' { Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue | Select-Object fDenyTSConnections }
Run-Test 'Lateral Movement' 'T1021.002' 'SMB server configuration' { Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature }
Run-Test 'Lateral Movement' 'T1021.002.b' 'SMB sessions list' { Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName,ClientUserName,NumOpens -First 8 }
Run-Test 'Lateral Movement' 'T1021.006' 'WinRM service status' { Get-Service WinRM -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType }
Run-Test 'Lateral Movement' 'T1021.006.b' 'WinRM listeners enumerate' { winrm enumerate winrm/config/listener 2>&1 | Select-Object -First 8 }
Run-Test 'Lateral Movement' 'T1570' 'Net use list' { net use 2>&1 | Select-Object -First 8 }
Run-Test 'Lateral Movement' 'T1021.info' 'Firewall remote access rules sample' { Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Remote|RDP|WinRM|File and Printer' } | Select-Object DisplayName,Enabled,Direction,Action -First 8 }

Write-Host ""
Write-Host "[ COLLECTION ]" -ForegroundColor Magenta

Run-Test 'Collection' 'T1005' 'Documents folder list' { Get-ChildItem "$env:USERPROFILE\Documents" -ErrorAction SilentlyContinue | Select-Object Name -First 8 }
Run-Test 'Collection' 'T1083.coll' 'File type hunt docx names only' { Get-ChildItem $env:USERPROFILE -Recurse -Include *.docx -ErrorAction SilentlyContinue | Select-Object Name -First 5 }
Run-Test 'Collection' 'T1083.coll.b' 'File type hunt pdf names only' { Get-ChildItem $env:USERPROFILE -Recurse -Include *.pdf -ErrorAction SilentlyContinue | Select-Object Name -First 5 }
Run-Test 'Collection' 'T1560.001' 'Compress archive benign local sample' {
    $tmp = Join-Path $tmpRoot 'ah-collect'
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    Set-Content -Path (Join-Path $tmp 'f1.txt') -Value 'test1'
    Set-Content -Path (Join-Path $tmp 'f2.txt') -Value 'test2'
    Compress-Archive -Path (Join-Path $tmp '*.txt') -DestinationPath (Join-Path $tmp 'bundle.zip') -Force
    $size = (Get-Item (Join-Path $tmp 'bundle.zip')).Length
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    "zip size=$size"
}
Run-Test 'Collection' 'T1113' 'Screen resolution probe only' { Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize }
Run-Test 'Collection' 'T1115' 'Clipboard length probe only' {
    $c = Get-Clipboard -ErrorAction SilentlyContinue
    if ($null -eq $c) { 'clipboard empty or inaccessible' } else { "clipboard characters=$((($c | Out-String).Trim()).Length)" }
}
Run-Test 'Collection' 'T1213.info' 'Cloud sync folder path check' {
    $paths = @("$env:USERPROFILE\OneDrive","$env:USERPROFILE\Dropbox","$env:USERPROFILE\Google Drive")
    foreach ($p in $paths) { if (Test-Path $p) { $p } }
}

Write-Host ""
Write-Host "[ COMMAND AND CONTROL BENIGN NETWORK PROBES ]" -ForegroundColor Magenta

Run-NetworkTest 'Command and Control' 'T1071.001' 'HTTPS GET to Microsoft' {
    try {
        $r = Invoke-WebRequest -Uri 'https://www.microsoft.com' -UseBasicParsing -TimeoutSec 5
        "status=$($r.StatusCode) bytes=$($r.RawContentLength)"
    } catch {
        "network error: $($_.Exception.Message)"
    }
}
Run-NetworkTest 'Command and Control' 'T1071.001.b' 'curl HTTPS status to Microsoft' { curl.exe -s -o NUL -w "%{http_code}" --max-time 5 https://www.microsoft.com 2>&1 }
Run-NetworkTest 'Command and Control' 'T1071.001.c' 'Test-NetConnection 443 Microsoft' { Test-NetConnection www.microsoft.com -Port 443 -WarningAction SilentlyContinue | Select-Object ComputerName,RemotePort,TcpTestSucceeded }
Run-NetworkTest 'Command and Control' 'T1071.004' 'DNS A query Microsoft' { Resolve-DnsName microsoft.com -Type A -ErrorAction SilentlyContinue | Select-Object Name,IPAddress -First 3 }
Run-NetworkTest 'Command and Control' 'T1071.004.b' 'DNS TXT query Microsoft' { Resolve-DnsName microsoft.com -Type TXT -ErrorAction SilentlyContinue | Select-Object Name,Type,Strings -First 2 }
Run-NetworkTest 'Command and Control' 'T1071.004.c' 'nslookup Microsoft' { nslookup microsoft.com 2>&1 | Select-Object -First 8 }
Run-Test 'Command and Control' 'T1105' 'BITS jobs list only' { bitsadmin /list 2>&1 | Select-Object -First 5 }
Run-Test 'Command and Control' 'T1105.b' 'PowerShell BITS transfers list' {
    if (Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue) {
        Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Select-Object DisplayName,JobState -First 8
    } else {
        'Get-BitsTransfer unavailable'
    }
}
Run-Test 'Command and Control' 'T1090' 'Proxy settings read' { Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue | Select-Object ProxyEnable,ProxyServer,AutoConfigURL }
Run-Test 'Command and Control' 'T1090.b' 'WinHTTP proxy read' { netsh winhttp show proxy 2>&1 | Select-Object -First 8 }

Write-Host ""
Write-Host "[ EXFILTRATION PROBES ONLY ]" -ForegroundColor Magenta

Run-NetworkTest 'Exfiltration' 'T1567' 'Cloud service reachability' {
    $hosts = @('dropbox.com','drive.google.com','onedrive.live.com')
    foreach ($h in $hosts) {
        try {
            $r = Test-NetConnection $h -Port 443 -WarningAction SilentlyContinue
            "$h reachable=$($r.TcpTestSucceeded)"
        } catch {
            "$h error"
        }
    }
}
Run-Test 'Exfiltration' 'T1048' 'FTP loopback port probe' { Test-NetConnection 127.0.0.1 -Port 21 -WarningAction SilentlyContinue | Select-Object ComputerName,RemotePort,TcpTestSucceeded }
Run-Test 'Exfiltration' 'T1041.info' 'Outbound DNS client config read' { Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,ServerAddresses -First 8 }

Write-Host ""
Write-Host "[ IMPACT PROBES ONLY ]" -ForegroundColor Magenta

Run-Test 'Impact' 'T1490' 'Shadow copy list no delete' { vssadmin.exe list shadows 2>&1 | Select-Object -First 8 }
Run-Test 'Impact' 'T1490.b' 'Shadow storage list no change' { vssadmin.exe list shadowstorage 2>&1 | Select-Object -First 8 }
Run-Test 'Impact' 'T1489' 'Critical service status check' { Get-Service | Where-Object { $_.Name -match 'WinDefend|MpsSvc|EventLog|BITS|VSS' } | Select-Object Name,Status -First 10 }
Run-Test 'Impact' 'T1486.info' 'BitLocker status read' {
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,ProtectionStatus,VolumeStatus
    } else {
        'Get-BitLockerVolume unavailable'
    }
}
Run-Test 'Impact' 'T1562.001.info' 'Defender status read only' {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled
    } else {
        'Get-MpComputerStatus unavailable'
    }
}
Run-Test 'Impact' 'T1562.004.info' 'Firewall profile read only' { Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction }

Write-Host ""
Write-Host "[ INITIAL ACCESS PASSIVE CHECKS ]" -ForegroundColor Magenta

Run-Test 'Initial Access' 'T1566' 'Outlook profile path check' {
    $p = "$env:LOCALAPPDATA\Microsoft\Outlook"
    if (Test-Path $p) { 'Outlook profile path exists' } else { 'not present' }
}
Run-Test 'Initial Access' 'T1133' 'External remote access port local check' { Get-NetTCPConnection -LocalPort 3389 -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,State -First 5 }
Run-Test 'Initial Access' 'T1133.b' 'Common remote tools process check' { Get-Process | Where-Object { $_.ProcessName -match 'AnyDesk|TeamViewer|RustDesk|ScreenConnect|Splashtop|VNC' } | Select-Object Name,Id -First 8 }
Run-Test 'Initial Access' 'T1190.info' 'IIS service detect' { Get-Service W3SVC -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType }

Write-Host ""
Write-Host "[ SQL SERVER LEGACY SOFTWARE DISCOVERY ]" -ForegroundColor Magenta

Run-Test 'SQL Server' 'T1505.SQL' 'SQL Server service detect' {
    $svc = Get-Service | Where-Object Name -like 'MSSQL*' -ErrorAction SilentlyContinue
    if ($svc) { $svc | Select-Object Name,Status,StartType } else { 'no MSSQL service found' }
}
Run-Test 'SQL Server' 'T1505.SQL.b' 'SQL Server version attempt' {
    $svc = Get-Service | Where-Object Name -like 'MSSQL*' -ErrorAction SilentlyContinue
    if ($svc -and (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {
        sqlcmd -E -Q "SELECT @@VERSION" 2>&1 | Select-Object -First 5
    } else {
        'sqlcmd unavailable or MSSQL service not found'
    }
}
Run-Test 'SQL Server' 'T1505.SQL.c' 'SQL ports listening check' { Get-NetTCPConnection -LocalPort 1433,1434 -ErrorAction SilentlyContinue | Select-Object LocalPort,State -First 5 }
Run-Test 'SQL Server' 'T1505.SQL.d' 'SQL browser service check' { Get-Service SQLBrowser -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType }

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$summary = $results | Group-Object status | Sort-Object Name | Select-Object Name,Count
$summary | Format-Table -AutoSize | Out-Host
Write-Host ("TOTAL : {0}" -f $results.Count) -ForegroundColor Cyan

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "CLEAN RESULT TABLE" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$clean = $results | Select-Object tactic,technique,test,status,result,runtime_issue,issue
$clean | Format-Table -AutoSize -Wrap | Out-Host

try {
    $results | ConvertTo-Json -Depth 5 | Set-Content -Path $logFile -Encoding UTF8
    $clean | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    $clean | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Set-Content -Path $txtFile -Encoding UTF8
} catch {
    Write-Host "Report write failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

$splunk = @"
index=* sourcetype="WinEventLog:Application" SourceName="AtomicHuntInline"
| rex field=Message "sim_session=(?<sim_session>\d+)"
| rex field=Message "tactic=(?<tactic>.*?) technique="
| rex field=Message "technique=(?<technique>\S+)"
| rex field=Message "test=(?<test>.*?) status="
| rex field=Message "status=(?<status>\w+)"
| rex field=Message "runtime_issue=(?<runtime_issue>\w+)"
| where sim_session="$session"
| table _time host tactic technique test status runtime_issue Message
| sort _time

index=* (EventCode=1 OR EventID=1)
(Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\wmic.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe" OR Image="*\\schtasks.exe" OR Image="*\\net.exe" OR Image="*\\netstat.exe" OR Image="*\\nltest.exe" OR Image="*\\regsvr32.exe" OR Image="*\\msiexec.exe" OR Image="*\\certutil.exe" OR Image="*\\control.exe" OR Image="*\\forfiles.exe" OR Image="*\\sc.exe" OR Image="*\\reg.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\curl.exe" OR Image="*\\wscript.exe")
| stats count values(CommandLine) AS cmds BY host User ParentImage Image
| sort - count

index=* sourcetype="WinEventLog:Application" SourceName="AtomicHuntInline"
| rex field=Message "sim_session=(?<sim_session>\d+)"
| rex field=Message "technique=(?<technique>\S+)"
| rex field=Message "status=(?<status>\w+)"
| rex field=Message "runtime_issue=(?<runtime_issue>\w+)"
| where sim_session="$session"
| stats count BY technique status runtime_issue
| sort technique
"@

try {
    Set-Content -Path $splFile -Value $splunk -Encoding UTF8
} catch { }

Write-Host ""
Write-Host "JSON report : $logFile" -ForegroundColor Green
Write-Host "CSV table   : $csvFile" -ForegroundColor Green
Write-Host "TXT table   : $txtFile" -ForegroundColor Green
Write-Host "Splunk SPL  : $splFile" -ForegroundColor Green
Write-Host "Event log   : Application source=AtomicHuntInline sim_session=$session" -ForegroundColor Green
Write-Host ""
Write-Host "Recommended Splunk import for CSV table:" -ForegroundColor Cyan
Write-Host "| inputlookup summary-$session.csv" -ForegroundColor Gray
Write-Host ""
