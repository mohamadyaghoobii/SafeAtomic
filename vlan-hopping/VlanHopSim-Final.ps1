<#
.SYNOPSIS
    Invoke-VlanHopSim - Yersinia-style VLAN hopping attack simulator for purple team / SOC detection PoC.

.DESCRIPTION
    Pure simulation tool. Writes realistic attacker artifacts to:
      - Windows Event Log (custom provider: VlanHopSim)
      - JSON line log (CIM-ish):   C:\ProgramData\VlanHopSim\vlanhop.json
      - CEF log (ArcSight-ready):  C:\ProgramData\VlanHopSim\vlanhop.cef

    NO real packets are sent. NO interface is touched. Safe to run on a
    production Windows Server. Designed so a SOC analyst has to actually
    correlate fields - not just trip a single string match.

    Techniques simulated:
      1. DTP switch spoofing                  (Yersinia: "enabling trunking")
      2. 802.1Q double tagging                (native VLAN escape)
      3. CDP flood                            (table exhaustion)
      4. DTP flood                            (bonus - matches Yersinia menu)
      5. Full attack chain                    (recon -> trunk -> hop -> exfil beacon)

.NOTES
    Author : Mohamad Yaghoobi  (Purple Team PoC)
    Target : Windows Server (PS 5.1+ / PS 7+)
    Run as : Administrator (required for custom Event Log source registration)

.EXAMPLE
    PS> .\Invoke-VlanHopSim.ps1
    Launches the interactive Yersinia-style menu.

.EXAMPLE
    PS> .\Invoke-VlanHopSim.ps1 -Mode DoubleTag -TargetVlan 99 -NativeVlan 1 -Intensity High
    Non-interactive run, useful for scheduled purple team drills.

.EXAMPLE
    PS> .\Invoke-VlanHopSim.ps1 -ShowSplunkQueries
    Prints all Splunk detection queries and exits.
#>

[CmdletBinding()]
param(
    [ValidateSet('Menu','DTPSpoof','DoubleTag','CDPFlood','DTPFlood','FullChain','ShowQueries')]
    [string]$Mode = 'Menu',

    [int]$TargetVlan = 99,
    [int]$NativeVlan = 1,
    [string]$SpoofMac,
    [string]$SpoofIp,
    [string]$VictimSwitch = 'CORE-SW-01',

    [ValidateSet('Low','Medium','High','Insane')]
    [string]$Intensity = 'Medium',

    [int]$DurationSeconds = 30,

    [switch]$ShowSplunkQueries,
    [switch]$NoBanner,
    [switch]$Quiet
)

# =====================================================================
# region GLOBAL CONFIG
# =====================================================================

$Script:Config = @{
    LogDir         = 'C:\ProgramData\VlanHopSim'
    JsonLog        = 'C:\ProgramData\VlanHopSim\vlanhop.json'
    CefLog         = 'C:\ProgramData\VlanHopSim\vlanhop.cef'
    EventLogName   = 'Application'
    EventSource    = 'VlanHopSim'
    Version        = '1.0.0'
    Vendor         = 'PurpleTeam'
    Product        = 'VlanHopSim'
}

$Script:IntensityMap = @{
    Low    = @{ MinDelayMs =  800; MaxDelayMs = 1500; PacketsPerBurst =   5 }
    Medium = @{ MinDelayMs =  150; MaxDelayMs =  400; PacketsPerBurst =  25 }
    High   = @{ MinDelayMs =   30; MaxDelayMs =  100; PacketsPerBurst = 100 }
    Insane = @{ MinDelayMs =    1; MaxDelayMs =   10; PacketsPerBurst = 500 }
}

# Event IDs - distinct per technique so SOC can pivot fast
$Script:EventIds = @{
    Startup            = 9000
    Shutdown           = 9001
    DTPSpoof           = 9101
    DTPNegotiated      = 9102
    DoubleTagInject    = 9201
    DoubleTagFrame     = 9202
    CDPFlood           = 9301
    CDPNeighborSpoof   = 9302
    DTPFlood           = 9401
    Recon              = 9501
    Beacon             = 9601
    AttackChainStep    = 9701
}

# endregion

# =====================================================================
# region UTIL: COLOR / BANNER
# =====================================================================

function Write-Cli {
    param(
        [string]$Text,
        [ConsoleColor]$Color = 'Gray',
        [switch]$NoNewline
    )
    if ($Script:Quiet) { return }
    $params = @{ Object = $Text; ForegroundColor = $Color }
    if ($NoNewline) { $params.NoNewline = $true }
    Write-Host @params
}

function Show-Banner {
    if ($NoBanner -or $Script:Quiet) { return }
    Clear-Host
    $banner = @'
  __     __                _       _
  \ \   / /__ _ __ ___  __| | __ _| | __ _   ___  ___
   \ \ / / _ \ '__/ __|/ _` |/ _` | |/ _` | / __|/ _ \
    \ V /  __/ |  \__ \ (_| | (_| | | (_| | \__ \  __/
     \_/ \___|_|  |___/\__,_|\__,_|_|\__,_| |___/\___|

   VlanHopSim  -  Purple Team PoC  -  Simulation only
   Developed by: Mohamad Yaghoobi
'@
    Write-Cli $banner -Color Cyan
    Write-Cli "   v$($Script:Config.Version)  |  No packets are sent  |  Logs only`n" -Color DarkGray
}

# endregion

# =====================================================================
# region LOGGING CORE
# =====================================================================

function Initialize-Logging {
    [CmdletBinding()]
    param()

    # Create log dir
    if (-not (Test-Path $Script:Config.LogDir)) {
        try {
            New-Item -ItemType Directory -Path $Script:Config.LogDir -Force | Out-Null
            Write-Cli "[+] Created log dir: $($Script:Config.LogDir)" -Color Green
        } catch {
            Write-Cli "[-] Failed to create log dir: $_" -Color Red
            throw
        }
    }

    # Register custom Event Log source. Requires admin once; idempotent after.
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Script:Config.EventSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource(
                $Script:Config.EventSource,
                $Script:Config.EventLogName
            )
            Write-Cli "[+] Registered Event Log source: $($Script:Config.EventSource)" -Color Green
            Start-Sleep -Milliseconds 500   # Windows needs a beat after source creation
        }
    } catch {
        Write-Cli "[!] Could not register event source (need admin first run). Continuing with file logs only." -Color Yellow
    }
}

function Write-SimEvent {
    <#
    .SYNOPSIS
        Writes a single simulated attack artifact to all three sinks
        (Event Log + JSON + CEF) with consistent correlation fields.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [int]$EventId,
        [Parameter(Mandatory)] [string]$Technique,
        [Parameter(Mandatory)] [string]$Action,
        [Parameter(Mandatory)] [string]$Message,

        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Warning',

        [hashtable]$Fields = @{},
        [string]$SessionId
    )

    if (-not $SessionId) { $SessionId = $Script:CurrentSession }

    try {
        $v_ts        = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffzzz')
        $v_hostname  = $env:COMPUTERNAME
        $v_user      = "$env:USERDOMAIN\$env:USERNAME"
        $v_processId = $PID

    # Base record
    $rec = [ordered]@{
        timestamp     = $v_ts
        host          = $v_hostname
        user          = $v_user
        process_id    = $v_processId
        process_name  = 'powershell.exe'
        sim_session   = $SessionId
        technique     = $Technique
        action        = $Action
        event_id      = $EventId
        severity      = $Severity
        message       = $Message
        vendor        = $Script:Config.Vendor
        product       = $Script:Config.Product
        product_ver   = $Script:Config.Version
    }
    foreach ($k in $Fields.Keys) { $rec[$k] = $Fields[$k] }

    # 1) JSON line
    try {
        $json = $rec | ConvertTo-Json -Compress -Depth 5
        Add-Content -Path $Script:Config.JsonLog -Value $json -Encoding UTF8
    } catch {
        Write-Cli "[-] JSON write failed: $_" -Color Red
    }

    # 2) CEF line - ArcSight / Splunk CEF TA friendly
    try {
        $cefSev = switch ($Severity) {
            'Information' { 3 }
            'Warning'     { 6 }
            'Error'       { 9 }
            default       { 5 }
        }
        $ext = ($rec.GetEnumerator() | ForEach-Object {
            $v = ($_.Value -as [string]) -replace '\\','\\\\' -replace '=','\=' -replace '\|','\|' -replace "`n",'\n'
            "$($_.Key)=$v"
        }) -join ' '
        $cef = "CEF:0|$($Script:Config.Vendor)|$($Script:Config.Product)|$($Script:Config.Version)|$EventId|$Action|$cefSev|$ext"
        Add-Content -Path $Script:Config.CefLog -Value $cef -Encoding UTF8
    } catch {
        Write-Cli "[-] CEF write failed: $_" -Color Red
    }

    # 3) Windows Event Log
    try {
        $entryType = [System.Diagnostics.EventLogEntryType]::$Severity
        $body = "$Message`n`n" + (($rec.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n")
        Write-EventLog -LogName $Script:Config.EventLogName `
                       -Source $Script:Config.EventSource `
                       -EventId $EventId `
                       -EntryType $entryType `
                       -Message $body `
                       -ErrorAction Stop
    } catch {
        # Silently swallow - JSON/CEF still captured the event
    }

    if (-not $Script:Quiet) {
        $color = switch ($Severity) {
            'Information' { 'DarkCyan' }
            'Warning'     { 'Yellow' }
            'Error'       { 'Red' }
        }
        Write-Cli "  [$v_ts] [$Technique/$Action] $Message" -Color $color
    }
    } catch {
        Write-Cli "[!] Write-SimEvent failed for ${Technique}/${Action}: $($_.Exception.Message)" -Color Red
    }
}

# endregion

# =====================================================================
# region UTIL: FAKE NETWORK ARTIFACT GENERATORS
# =====================================================================

function New-FakeMac {
    # OUIs that scream "attacker tooling" - Cisco-ish, VMware, randoms
    $ouis = @('00:0C:29','00:50:56','00:1B:21','00:E0:4C','AA:BB:CC','DE:AD:BE')
    $oui = Get-Random -InputObject $ouis
    $suffix = (1..3 | ForEach-Object { '{0:X2}' -f (Get-Random -Maximum 256) }) -join ':'
    return "$oui`:$suffix"
}

function New-FakeIp {
    param([string]$Subnet = '10.0.99')
    return "$Subnet.$(Get-Random -Minimum 2 -Maximum 254)"
}

function New-SessionId {
    return [guid]::NewGuid().ToString('N').Substring(0,12)
}

function Get-IntensityDelay {
    $cfg = $Script:IntensityMap[$Intensity]
    return (Get-Random -Minimum $cfg.MinDelayMs -Maximum $cfg.MaxDelayMs)
}

function Get-AttackerContext {
    if (-not $Script:SpoofMac) { $Script:SpoofMac = New-FakeMac }
    if (-not $Script:SpoofIp)  { $Script:SpoofIp  = New-FakeIp }
    return @{
        attacker_mac    = $Script:SpoofMac
        attacker_ip     = $Script:SpoofIp
        attacker_host   = $env:COMPUTERNAME
        victim_switch   = $VictimSwitch
        native_vlan     = $NativeVlan
        target_vlan     = $TargetVlan
    }
}

# endregion

# =====================================================================
# region TECHNIQUE 1 - DTP SWITCH SPOOFING
# =====================================================================

function Invoke-DTPSpoofSim {
    [CmdletBinding()] param()

    $ctx = Get-AttackerContext
    $burst = $Script:IntensityMap[$Intensity].PacketsPerBurst

    Write-Cli "`n[*] TECHNIQUE: DTP Switch Spoofing" -Color Magenta
    Write-Cli "    Attacker MAC : $($ctx.attacker_mac)" -Color DarkGray
    Write-Cli "    Target switch: $($ctx.victim_switch)  (port simulated)" -Color DarkGray
    Write-Cli "    Goal         : Negotiate trunk -> get tagged access to all VLANs`n" -Color DarkGray

    Write-SimEvent -EventId $Script:EventIds.DTPSpoof `
                   -Technique 'DTP_SPOOF' -Action 'INITIATE' `
                   -Severity 'Warning' `
                   -Message "DTP desirable frame burst initiated from $($ctx.attacker_mac)" `
                   -Fields ($ctx + @{
                       dtp_mode      = 'desirable'
                       dtp_type      = 'DYNAMIC_DESIRABLE'
                       burst_count   = $burst
                       eth_type      = '0x2004'   # SNAP/DTP-ish
                   })

    for ($i = 1; $i -le $burst; $i++) {
        Start-Sleep -Milliseconds (Get-IntensityDelay)
        Write-SimEvent -EventId $Script:EventIds.DTPSpoof `
                       -Technique 'DTP_SPOOF' -Action 'FRAME' `
                       -Severity 'Information' `
                       -Message "DTP frame $i/$burst transmitted (simulated)" `
                       -Fields ($ctx + @{
                           dtp_frame_id  = $i
                           dtp_neighbor  = $ctx.attacker_mac
                           dtp_type      = 'DYNAMIC_DESIRABLE'
                       })
    }

    # Simulated trunk negotiation success
    Write-SimEvent -EventId $Script:EventIds.DTPNegotiated `
                   -Technique 'DTP_SPOOF' -Action 'TRUNK_NEGOTIATED' `
                   -Severity 'Error' `
                   -Message "Trunk link 'negotiated' with $($ctx.victim_switch) - attacker now has access to all VLANs" `
                   -Fields ($ctx + @{
                       trunk_mode    = '802.1Q'
                       allowed_vlans = '1-4094'
                       outcome       = 'SUCCESS'
                   })

    Write-Cli "[+] DTP spoof simulation complete.`n" -Color Green
}

# endregion

# =====================================================================
# region TECHNIQUE 2 - 802.1Q DOUBLE TAGGING
# =====================================================================

function Invoke-DoubleTagSim {
    [CmdletBinding()] param()

    $ctx = Get-AttackerContext
    $burst = $Script:IntensityMap[$Intensity].PacketsPerBurst

    Write-Cli "`n[*] TECHNIQUE: 802.1Q Double Tagging" -Color Magenta
    Write-Cli "    Outer tag (native): VLAN $($ctx.native_vlan)" -Color DarkGray
    Write-Cli "    Inner tag (target): VLAN $($ctx.target_vlan)" -Color DarkGray
    Write-Cli "    Goal              : Hop into VLAN $($ctx.target_vlan) one-way`n" -Color DarkGray

    Write-SimEvent -EventId $Script:EventIds.DoubleTagInject `
                   -Technique 'DOUBLE_TAG' -Action 'INITIATE' `
                   -Severity 'Warning' `
                   -Message "Double-tagged 802.1Q injection starting: outer=$($ctx.native_vlan) inner=$($ctx.target_vlan)" `
                   -Fields ($ctx + @{
                       outer_tpid   = '0x8100'
                       inner_tpid   = '0x8100'
                       outer_vlan   = $ctx.native_vlan
                       inner_vlan   = $ctx.target_vlan
                       burst_count  = $burst
                   })

    for ($i = 1; $i -le $burst; $i++) {
        Start-Sleep -Milliseconds (Get-IntensityDelay)
        $dstIp = New-FakeIp -Subnet "10.$($ctx.target_vlan).0"
        Write-SimEvent -EventId $Script:EventIds.DoubleTagFrame `
                       -Technique 'DOUBLE_TAG' -Action 'FRAME' `
                       -Severity 'Information' `
                       -Message "Double-tagged frame $i/$burst forwarded to VLAN $($ctx.target_vlan)" `
                       -Fields ($ctx + @{
                           frame_id     = $i
                           outer_vlan   = $ctx.native_vlan
                           inner_vlan   = $ctx.target_vlan
                           src_ip       = $ctx.attacker_ip
                           dst_ip       = $dstIp
                           protocol     = (Get-Random -InputObject @('ICMP','TCP/445','UDP/137','TCP/3389'))
                           payload_size = (Get-Random -Minimum 64 -Maximum 1500)
                       })
    }

    Write-Cli "[+] Double-tag simulation complete.`n" -Color Green
}

# endregion

# =====================================================================
# region TECHNIQUE 3 - CDP FLOOD
# =====================================================================

function Invoke-CDPFloodSim {
    [CmdletBinding()] param()

    $ctx = Get-AttackerContext
    $burst = $Script:IntensityMap[$Intensity].PacketsPerBurst * 2  # CDP floods are typically larger

    Write-Cli "`n[*] TECHNIQUE: CDP Neighbor Flood" -Color Magenta
    Write-Cli "    Goal: Exhaust neighbor table on $($ctx.victim_switch)`n" -Color DarkGray

    Write-SimEvent -EventId $Script:EventIds.CDPFlood `
                   -Technique 'CDP_FLOOD' -Action 'INITIATE' `
                   -Severity 'Warning' `
                   -Message "CDP flood starting - $burst spoofed neighbors will be announced" `
                   -Fields ($ctx + @{
                       burst_count = $burst
                       cdp_version = 2
                   })

    $platforms = @('cisco WS-C2960-24TT-L','cisco C9300-48P','cisco N9K-C93180YC-EX','cisco WS-C3850-48P')
    for ($i = 1; $i -le $burst; $i++) {
        Start-Sleep -Milliseconds (Get-IntensityDelay)
        Write-SimEvent -EventId $Script:EventIds.CDPNeighborSpoof `
                       -Technique 'CDP_FLOOD' -Action 'NEIGHBOR_ANNOUNCE' `
                       -Severity 'Information' `
                       -Message "Spoofed CDP neighbor $i/$burst announced" `
                       -Fields ($ctx + @{
                           neighbor_id     = "FAKE-SW-{0:D5}" -f $i
                           neighbor_mac    = (New-FakeMac)
                           neighbor_ip     = (New-FakeIp -Subnet '10.99.99')
                           platform        = (Get-Random -InputObject $platforms)
                           capabilities    = 'Router Switch IGMP'
                           native_vlan_adv = $ctx.native_vlan
                       })
    }

    Write-Cli "[+] CDP flood simulation complete.`n" -Color Green
}

# endregion

# =====================================================================
# region TECHNIQUE 4 - DTP FLOOD
# =====================================================================

function Invoke-DTPFloodSim {
    [CmdletBinding()] param()

    $ctx = Get-AttackerContext
    $burst = $Script:IntensityMap[$Intensity].PacketsPerBurst * 3

    Write-Cli "`n[*] TECHNIQUE: DTP Flood" -Color Magenta
    Write-Cli "    Goal: Saturate DTP processing on $($ctx.victim_switch)`n" -Color DarkGray

    Write-SimEvent -EventId $Script:EventIds.DTPFlood `
                   -Technique 'DTP_FLOOD' -Action 'INITIATE' `
                   -Severity 'Warning' `
                   -Message "DTP flood starting - $burst frames from rotating MACs" `
                   -Fields ($ctx + @{ burst_count = $burst })

    $modes = @('DYNAMIC_DESIRABLE','DYNAMIC_AUTO','TRUNK','ACCESS')
    for ($i = 1; $i -le $burst; $i++) {
        Start-Sleep -Milliseconds (Get-IntensityDelay)
        Write-SimEvent -EventId $Script:EventIds.DTPFlood `
                       -Technique 'DTP_FLOOD' -Action 'FRAME' `
                       -Severity 'Information' `
                       -Message "DTP flood frame $i/$burst" `
                       -Fields ($ctx + @{
                           frame_id       = $i
                           src_mac        = (New-FakeMac)
                           dtp_type       = (Get-Random -InputObject $modes)
                       })
    }

    Write-Cli "[+] DTP flood simulation complete.`n" -Color Green
}

# endregion

# =====================================================================
# region TECHNIQUE 5 - FULL ATTACK CHAIN
# =====================================================================

function Invoke-FullChainSim {
    [CmdletBinding()] param()

    Write-Cli "`n[*] FULL ATTACK CHAIN: recon -> trunk -> hop -> beacon" -Color Magenta
    Write-Cli "    This is the realistic one. SOC should chain these via sim_session." -Color DarkGray
    Write-Cli "    sim_session = $Script:CurrentSession`n" -Color DarkGray

    $ctx = Get-AttackerContext

    # Step 1 - Recon
    Write-SimEvent -EventId $Script:EventIds.Recon `
                   -Technique 'CHAIN' -Action 'RECON' `
                   -Severity 'Information' `
                   -Message "Step 1/5: Passive listen for CDP/DTP/STP frames" `
                   -Fields ($ctx + @{
                       chain_step     = 1
                       recon_protocols= 'CDP,DTP,STP,LLDP'
                       duration_sec   = 15
                   })
    Start-Sleep -Seconds 2

    # Step 2 - DTP spoof (short burst)
    Write-SimEvent -EventId $Script:EventIds.AttackChainStep `
                   -Technique 'CHAIN' -Action 'STEP_BEGIN' `
                   -Severity 'Warning' `
                   -Message "Step 2/5: DTP spoofing" `
                   -Fields (@{ chain_step = 2 })
    $savedBurst = $Script:IntensityMap[$Intensity].PacketsPerBurst
    $Script:IntensityMap[$Intensity].PacketsPerBurst = [Math]::Max(3, [int]($savedBurst / 3))
    Invoke-DTPSpoofSim
    $Script:IntensityMap[$Intensity].PacketsPerBurst = $savedBurst

    # Step 3 - Double tag
    Write-SimEvent -EventId $Script:EventIds.AttackChainStep `
                   -Technique 'CHAIN' -Action 'STEP_BEGIN' `
                   -Severity 'Warning' `
                   -Message "Step 3/5: Double-tagging into VLAN $TargetVlan" `
                   -Fields (@{ chain_step = 3 })
    $Script:IntensityMap[$Intensity].PacketsPerBurst = [Math]::Max(3, [int]($savedBurst / 3))
    Invoke-DoubleTagSim
    $Script:IntensityMap[$Intensity].PacketsPerBurst = $savedBurst

    # Step 4 - Pivot beacon (looks like C2)
    Write-SimEvent -EventId $Script:EventIds.AttackChainStep `
                   -Technique 'CHAIN' -Action 'STEP_BEGIN' `
                   -Severity 'Warning' `
                   -Message "Step 4/5: Lateral beacon from hopped VLAN" `
                   -Fields (@{ chain_step = 4 })

    1..5 | ForEach-Object {
        Start-Sleep -Milliseconds (Get-IntensityDelay)
        Write-SimEvent -EventId $Script:EventIds.Beacon `
                       -Technique 'CHAIN' -Action 'BEACON' `
                       -Severity 'Error' `
                       -Message "Pivot beacon $_ from VLAN $TargetVlan toward management subnet" `
                       -Fields ($ctx + @{
                           chain_step   = 4
                           beacon_id    = $_
                           src_vlan     = $TargetVlan
                           dst_ip       = (New-FakeIp -Subnet '10.0.10')
                           dst_port     = 443
                           ja3_hash     = 'e7d705a3286e19ea42f587b344ee6865'
                       })
    }

    # Step 5 - Done
    Write-SimEvent -EventId $Script:EventIds.AttackChainStep `
                   -Technique 'CHAIN' -Action 'COMPLETE' `
                   -Severity 'Error' `
                   -Message "Step 5/5: Attack chain finished - SOC should have fired by now" `
                   -Fields (@{ chain_step = 5; outcome = 'SUCCESS' })

    Write-Cli "[+] Full chain complete. sim_session=$Script:CurrentSession`n" -Color Green
}

# endregion

# =====================================================================
# region SPLUNK DETECTION QUERIES
# =====================================================================

function Show-SplunkQueries {
    $sourcetypeNote = @'

============================================================
SPLUNK DETECTION HELPER
============================================================
Index/sourcetype assumed:
  - JSON log : index=netsec sourcetype=vlanhopsim:json   (or _json)
  - CEF log  : index=netsec sourcetype=cef
  - WinEvent : index=wineventlog source="Application" SourceName="VlanHopSim"

Adjust the index/sourcetype to whatever your TA uses.
============================================================

'@
    Write-Cli $sourcetypeNote -Color Cyan

    $queries = @(
@{
    Name = '1. Catch-all: any VlanHopSim activity'
    Why  = 'Baseline visibility. Run first to confirm ingestion.'
    SPL  = @'
index=netsec sourcetype="vlanhopsim:json"
| stats count min(_time) AS first_seen max(_time) AS last_seen values(technique) AS techniques values(action) AS actions BY host user sim_session
| convert ctime(first_seen) ctime(last_seen)
| sort - count
'@
},
@{
    Name = '2. DTP switch spoofing - desirable frame burst'
    Why  = 'Endpoint should NEVER send DTP. Any frame burst from a host = high-fi alert.'
    SPL  = @'
index=netsec sourcetype="vlanhopsim:json" technique="DTP_SPOOF"
| stats count BY host user attacker_mac dtp_type sim_session
| where count >= 5
'@
},
@{
    Name = '3. DTP -> trunk negotiated (the money alert)'
    Why  = 'Event 9102 means the attacker thinks they got a trunk. Critical, page on-call.'
    SPL  = @'
index=netsec sourcetype="vlanhopsim:json" technique="DTP_SPOOF" action="TRUNK_NEGOTIATED"
| table _time host user attacker_mac victim_switch allowed_vlans outcome sim_session
'@
},
@{
    Name = '4. Double-tagging anomaly - outer != inner VLAN'
    Why  = 'Outer tag matching native VLAN + different inner tag = textbook VLAN hop.'
    SPL  = @'
index=netsec sourcetype="vlanhopsim:json" technique="DOUBLE_TAG"
| eval mismatch=if(outer_vlan!=inner_vlan,1,0)
| where mismatch=1
| stats count BY host attacker_mac outer_vlan inner_vlan src_ip dst_ip protocol sim_session
| where count >= 10
'@
},
@{
    Name = '5. CDP/DTP flood - rate-based'
    Why  = 'Endpoint sending >50 CDP/DTP frames in 1 min is impossible without tooling.'
    SPL  = @'
index=netsec sourcetype="vlanhopsim:json" (technique="CDP_FLOOD" OR technique="DTP_FLOOD")
| bin _time span=1m
| stats count BY _time host user technique
| where count > 50
'@
},
@{
    Name = '6. MAC churn - many spoofed source MACs from one host'
    Why  = 'A real NIC has one MAC. Many MACs from one host = attacker tooling.'
    SPL  = @'
index=netsec sourcetype="vlanhopsim:json"
| stats dc(neighbor_mac) AS unique_macs dc(src_mac) AS unique_src_macs values(technique) AS techniques BY host user sim_session
| eval mac_diversity=unique_macs + unique_src_macs
| where mac_diversity >= 20
'@
},
@{
    Name = '7. Attack-chain correlation - the purple team prize'
    Why  = 'Same sim_session touches recon + trunk + hop + beacon. Chain detection > single rule.'
    SPL  = @'
index=netsec sourcetype="vlanhopsim:json"
| stats values(technique) AS techs values(action) AS actions count BY sim_session host user
| eval has_recon = if(match(actions,"RECON"),1,0)
| eval has_trunk = if(match(actions,"TRUNK_NEGOTIATED"),1,0)
| eval has_hop   = if(match(techs,"DOUBLE_TAG"),1,0)
| eval has_beacon= if(match(actions,"BEACON"),1,0)
| eval score = has_recon + has_trunk + has_hop + has_beacon
| where score >= 3
| sort - score
'@
},
@{
    Name = '8. Off-hours layer-2 activity'
    Why  = 'Adjust the date_hour window to your env. Layer-2 attack outside biz hours = suspicious.'
    SPL  = @'
index=netsec sourcetype="vlanhopsim:json"
| eval hour=strftime(_time,"%H")
| where hour < 7 OR hour > 19
| stats count BY host user technique action hour
| where count > 10
'@
},
@{
    Name = '9. Windows Event Log path (no TA for JSON yet)'
    Why  = 'Fallback if only WinEventLog is forwarded by Universal Forwarder.'
    SPL  = @'
index=wineventlog source="Application" SourceName="VlanHopSim"
| rex field=Message "technique=(?<technique>\S+)"
| rex field=Message "action=(?<action>\S+)"
| rex field=Message "sim_session=(?<sim_session>\S+)"
| stats count BY host technique action sim_session
'@
},
@{
    Name = '10. CEF path (ArcSight TA or Splunk CEF TA)'
    Why  = 'If logs are ingested via syslog/CEF.'
    SPL  = @'
index=netsec sourcetype=cef CEF_vendor=PurpleTeam CEF_product=VlanHopSim
| stats count BY src dst cs1 cs2 cs3 deviceEventClassId name
'@
}
    )

    foreach ($q in $queries) {
        Write-Cli "`n--- $($q.Name) ---" -Color Yellow
        Write-Cli "Why: $($q.Why)" -Color DarkGray
        Write-Cli ""
        Write-Cli $q.SPL -Color White
    }

    Write-Cli "`n============================================================" -Color Cyan
    Write-Cli "TIP: Start with query #1, then #7 (chain) - that's the one that" -Color Cyan
    Write-Cli "     proves SOC can correlate, not just match strings." -Color Cyan
    Write-Cli "============================================================`n" -Color Cyan
}

# endregion

# =====================================================================
# region INTERACTIVE MENU
# =====================================================================

function Show-Menu {
    Show-Banner

    while ($true) {
        Write-Cli "  Current config:" -Color DarkGray
        Write-Cli "    TargetVlan   = $TargetVlan" -Color DarkGray
        Write-Cli "    NativeVlan   = $NativeVlan" -Color DarkGray
        Write-Cli "    Intensity    = $Intensity" -Color DarkGray
        Write-Cli "    VictimSwitch = $VictimSwitch" -Color DarkGray
        Write-Cli "    Session      = $Script:CurrentSession`n" -Color DarkGray

        Write-Cli "  [1]  DTP switch spoofing"           -Color White
        Write-Cli "  [2]  802.1Q double tagging"          -Color White
        Write-Cli "  [3]  CDP flood"                      -Color White
        Write-Cli "  [4]  DTP flood"                      -Color White
        Write-Cli "  [5]  FULL attack chain  (recommended for purple)" -Color Green
        Write-Cli ""
        Write-Cli "  [c]  Change config (vlan, intensity, switch...)" -Color Cyan
        Write-Cli "  [s]  Show Splunk detection queries"  -Color Cyan
        Write-Cli "  [t]  Tail recent log entries"        -Color Cyan
        Write-Cli "  [n]  New session id"                 -Color Cyan
        Write-Cli "  [q]  Quit`n"                         -Color Cyan

        $choice = Read-Host "  Choice"

        try {
            switch -Regex ($choice) {
                '^1$' { Invoke-DTPSpoofSim }
                '^2$' { Invoke-DoubleTagSim }
                '^3$' { Invoke-CDPFloodSim }
                '^4$' { Invoke-DTPFloodSim }
                '^5$' { Invoke-FullChainSim }
                '^c$' { Set-MenuConfig }
                '^s$' { Show-SplunkQueries }
                '^t$' { Show-RecentLog }
                '^n$' {
                    $Script:CurrentSession = New-SessionId
                    Write-Cli "[+] New session id: $Script:CurrentSession" -Color Green
                }
                '^q$' { return }
                default { Write-Cli "  ? Invalid choice" -Color Red }
            }
        } catch {
            Write-Cli "`n[!] Technique failed: $($_.Exception.Message)" -Color Red
            Write-Cli "    At: $($_.InvocationInfo.PositionMessage)" -Color DarkGray
            Write-Cli "    Returning to menu...`n" -Color Yellow
        }
    }
}

function Set-MenuConfig {
    $newTv  = Read-Host "  TargetVlan ($TargetVlan)"
    if ($newTv -match '^\d+$') { $Script:TargetVlan = [int]$newTv }
    $newNv  = Read-Host "  NativeVlan ($NativeVlan)"
    if ($newNv -match '^\d+$') { $Script:NativeVlan = [int]$newNv }
    $newSw  = Read-Host "  VictimSwitch ($VictimSwitch)"
    if ($newSw) { $Script:VictimSwitch = $newSw }
    $newIn  = Read-Host "  Intensity Low/Medium/High/Insane ($Intensity)"
    if ($newIn -in @('Low','Medium','High','Insane')) { $Script:Intensity = $newIn }
    Write-Cli "[+] Config updated.`n" -Color Green
}

function Show-RecentLog {
    if (Test-Path $Script:Config.JsonLog) {
        Write-Cli "`n--- Last 10 JSON events ---" -Color Yellow
        Get-Content $Script:Config.JsonLog -Tail 10 | ForEach-Object {
            try {
                $obj = $_ | ConvertFrom-Json
                Write-Cli ("  {0}  [{1}/{2}]  {3}" -f $obj.timestamp, $obj.technique, $obj.action, $obj.message) -Color DarkCyan
            } catch {
                Write-Cli "  $_" -Color DarkGray
            }
        }
        Write-Cli ""
    } else {
        Write-Cli "[-] No log yet at $($Script:Config.JsonLog)" -Color Yellow
    }
}

# endregion

# =====================================================================
# region MAIN
# =====================================================================

# Handle ShowQueries early - no init needed
if ($Mode -eq 'ShowQueries' -or $ShowSplunkQueries) {
    Show-Banner
    Show-SplunkQueries
    return
}

# Init
Initialize-Logging
$Script:CurrentSession = New-SessionId

Write-SimEvent -EventId $Script:EventIds.Startup `
               -Technique 'CONTROL' -Action 'STARTUP' `
               -Severity 'Information' `
               -Message "VlanHopSim started by $env:USERNAME on $env:COMPUTERNAME mode=$Mode intensity=$Intensity" `
               -Fields @{
                   mode      = $Mode
                   intensity = $Intensity
                   pwsh_ver  = $PSVersionTable.PSVersion.ToString()
               }

try {
    switch ($Mode) {
        'Menu'      { Show-Menu }
        'DTPSpoof'  { Show-Banner; Invoke-DTPSpoofSim }
        'DoubleTag' { Show-Banner; Invoke-DoubleTagSim }
        'CDPFlood'  { Show-Banner; Invoke-CDPFloodSim }
        'DTPFlood'  { Show-Banner; Invoke-DTPFloodSim }
        'FullChain' { Show-Banner; Invoke-FullChainSim }
    }
} finally {
    Write-SimEvent -EventId $Script:EventIds.Shutdown `
                   -Technique 'CONTROL' -Action 'SHUTDOWN' `
                   -Severity 'Information' `
                   -Message "VlanHopSim exiting"

    Write-Cli "`nLogs written to:" -Color Green
    Write-Cli "  JSON     : $($Script:Config.JsonLog)" -Color Green
    Write-Cli "  CEF      : $($Script:Config.CefLog)"  -Color Green
    Write-Cli "  WinEvent : Application log, Source=VlanHopSim`n" -Color Green

    if ($Mode -ne 'Menu') {
        Write-Cli "Tip: run with -ShowSplunkQueries to print detection SPL.`n" -Color Cyan
    }
}

# endregion
