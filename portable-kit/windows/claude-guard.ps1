# Claude 持久化安全锁 · Windows 双锁核心引擎
# 双锁模型:
#   - 锁 1 (直连切换锁):
#       * lock-cn     (国内直连放行): 放行中国大陆直连 + 局域网 + 代理入口 + TUN; 0ms 死锁 Claude(ASN+域名IP) + 目标应用进程 + 一切海外公网 + 公网 IPv6 + STUN
#       * lock-strict (全封闭模式):   仅放行代理入口 + 局域网(非DNS) + TUN; 0ms 死锁全部物理公网(含国内+海外+Claude+IPv6+STUN)
#   - 锁 2 (持久化硬锁总开关):
#       * Windows 防火墙规则天然持久化 (代理退出/本软件被杀/死机/断网/重启后依然生效)
#       * 仅当用户确认不再使用 Claude 并手动执行 unlock-all 时才彻底撤销规则组并恢复原生网络
#   - 验收实证: 开启三档防火墙 LogBlocked=True -> pfirewall.log，verify-firewall 直接查验规则与真实 DROP 流量日志
param(
    [Parameter(Position = 0)]
    [ValidateSet('init', 'set-nodes', 'lock', 'lock-cn', 'lock-strict', 'unlock', 'unlock-all', 'verify-firewall', 'status', 'check', 'export-report')]
    [string]$Action = 'status',
    [Parameter(Position = 1)]
    [string]$Nodes = '',
    [Parameter(Position = 2)]
    [string]$ManualCountry = ''
)

$ErrorActionPreference = 'Stop'
$FW_GROUP = 'ClaudeGuard-KillSwitch'
$APP_DIR = Join-Path $env:USERPROFILE '.claude-guard'
$CFG_FILE = Join-Path $APP_DIR 'config.json'
$HOSTS_FILE = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$PFW_LOG = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
$HOSTS_BEGIN = '# BEGIN claude-guard-hosts'
$HOSTS_END = '# END claude-guard-hosts'

$ANTHROPIC_ASN_V4 = '160.79.104.0/21'
$ANTHROPIC_ASN_V6 = '2607:6bc0::/48'
$ANTHROPIC_DOMAINS = @('claude.ai', 'claude.com', 'api.anthropic.com', 'claudeusercontent.com', 'platform.claude.com', 'console.anthropic.com', 'statsig.anthropic.com')

New-Item -ItemType Directory -Force -Path $APP_DIR | Out-Null

$COUNTRY_TZ = @{
    'US' = 'Eastern Standard Time'; 'JP' = 'Tokyo Standard Time'; 'TW' = 'Taipei Standard Time'
    'HK' = 'China Standard Time'; 'SG' = 'Singapore Standard Time'; 'GB' = 'GMT Standard Time'
    'DE' = 'W. Europe Standard Time'; 'FR' = 'Romance Standard Time'; 'KR' = 'Korea Standard Time'
    'AU' = 'AUS Eastern Standard Time'; 'CA' = 'Eastern Standard Time'; 'MY' = 'Singapore Standard Time'
}
$IANA_TO_WIN = @{
    'America/New_York' = 'Eastern Standard Time'; 'America/Chicago' = 'Central Standard Time'
    'America/Denver' = 'Mountain Standard Time'; 'America/Los_Angeles' = 'Pacific Standard Time'
    'America/Toronto' = 'Eastern Standard Time'; 'America/Vancouver' = 'Pacific Standard Time'
    'Asia/Singapore' = 'Singapore Standard Time'; 'Asia/Tokyo' = 'Tokyo Standard Time'
    'Asia/Seoul' = 'Korea Standard Time'; 'Asia/Taipei' = 'Taipei Standard Time'
    'Asia/Hong_Kong' = 'China Standard Time'; 'Europe/London' = 'GMT Standard Time'
    'Europe/Berlin' = 'W. Europe Standard Time'; 'Europe/Paris' = 'Romance Standard Time'
    'Australia/Sydney' = 'AUS Eastern Standard Time'; 'Asia/Kuala_Lumpur' = 'Singapore Standard Time'
}
$COUNTRY_LOCALE = @{
    'US' = 'en-US'; 'JP' = 'ja-JP'; 'TW' = 'zh-TW'; 'HK' = 'zh-HK'
    'SG' = 'en-SG'; 'GB' = 'en-GB'; 'DE' = 'de-DE'; 'FR' = 'fr-FR'
    'KR' = 'ko-KR'; 'AU' = 'en-AU'; 'CA' = 'en-CA'; 'MY' = 'ms-MY'
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Load-Config {
    $cfg = [ordered]@{
        entryNodes = ''
        countryTarget = ''
        tzTarget = ''
        localeTarget = ''
        allowLanDns = $false
        lockMode = 'off'
    }
    if (Test-Path -LiteralPath $CFG_FILE) {
        try {
            $raw = Get-Content -LiteralPath $CFG_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($raw.entryNodes) { $cfg.entryNodes = [string]$raw.entryNodes }
            if ($raw.countryTarget) { $cfg.countryTarget = [string]$raw.countryTarget }
            if ($raw.tzTarget) { $cfg.tzTarget = [string]$raw.tzTarget }
            if ($raw.localeTarget) { $cfg.localeTarget = [string]$raw.localeTarget }
            if ($null -ne $raw.allowLanDns) { $cfg.allowLanDns = [bool]$raw.allowLanDns }
            if ($raw.lockMode) { $cfg.lockMode = [string]$raw.lockMode }
        } catch {}
    }
    return $cfg
}

function Save-Config($cfg) {
    $json = $cfg | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($CFG_FILE, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
}

# ---- IPv4 整数与合法单播区间运算 (严格限定 1.0.0.0 - 223.255.255.255) ----
function ConvertTo-UInt32Ip([string]$Ip) {
    $addr = [System.Net.IPAddress]::Parse($Ip)
    $b = $addr.GetAddressBytes()
    return ([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3]
}

function ConvertFrom-UInt32Ip([uint32]$Val) {
    return "{0}.{1}.{2}.{3}" -f (($Val -shr 24) -band 255), (($Val -shr 16) -band 255), (($Val -shr 8) -band 255), ($Val -band 255)
}

function Convert-CidrToRange([string]$Cidr) {
    $parts = $Cidr -split '/'
    $base = ConvertTo-UInt32Ip $parts[0]
    $prefix = if ($parts.Count -gt 1) { [int]$parts[1] } else { 32 }
    if ($prefix -lt 0 -or $prefix -gt 32) { throw "无效 CIDR: $Cidr" }
    $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32](([uint64]0xFFFFFFFF -shl (32 - $prefix)) -band 0xFFFFFFFF) }
    $start = $base -band $mask
    $end = $start -bor (([uint32]0xFFFFFFFF) -bxor $mask)
    return [pscustomobject]@{ Start = [uint64]$start; End = [uint64]$end }
}

function Get-ComplementIpv4Ranges([string[]]$ExcludeCidrs) {
    $minIp = [uint64](ConvertTo-UInt32Ip '1.0.0.0')
    $maxIp = [uint64](ConvertTo-UInt32Ip '223.255.255.255')
    $intervals = New-Object System.Collections.Generic.List[object]

    foreach ($c in $ExcludeCidrs) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $r = Convert-CidrToRange $c.Trim()
        $s = [Math]::Max($minIp, $r.Start)
        $e = [Math]::Min($maxIp, $r.End)
        if ($s -le $e) { $intervals.Add([pscustomobject]@{ Start = $s; End = $e }) }
    }

    $sorted = @($intervals | Sort-Object Start, End)
    $merged = New-Object System.Collections.Generic.List[object]
    foreach ($iv in $sorted) {
        if ($merged.Count -eq 0 -or $iv.Start -gt ($merged[$merged.Count - 1].End + 1)) {
            $merged.Add([pscustomobject]@{ Start = $iv.Start; End = $iv.End })
        } elseif ($iv.End -gt $merged[$merged.Count - 1].End) {
            $merged[$merged.Count - 1].End = $iv.End
        }
    }

    $result = New-Object System.Collections.Generic.List[string]
    $cursor = $minIp
    foreach ($iv in $merged) {
        if ($cursor -lt $iv.Start) {
            $sStr = ConvertFrom-UInt32Ip ([uint32]$cursor)
            $eStr = ConvertFrom-UInt32Ip ([uint32]($iv.Start - 1))
            if ($sStr -eq $eStr) { $result.Add($sStr) } else { $result.Add("$sStr-$eStr") }
        }
        $cursor = $iv.End + 1
    }
    if ($cursor -le $maxIp) {
        $sStr = ConvertFrom-UInt32Ip ([uint32]$cursor)
        $eStr = ConvertFrom-UInt32Ip ([uint32]$maxIp)
        if ($sStr -eq $eStr) { $result.Add($sStr) } else { $result.Add("$sStr-$eStr") }
    }
    return @($result)
}

# 从预计算的海外公网补集区间表中精准挖空白名单代理入口 IP/CIDR
function Subtract-CidrsFromRanges([string[]]$BaseRanges, [string[]]$WhitelistCidrs) {
    if (-not $WhitelistCidrs -or $WhitelistCidrs.Count -eq 0) { return $BaseRanges }
    $exList = New-Object System.Collections.Generic.List[object]
    foreach ($c in $WhitelistCidrs) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $exList.Add((Convert-CidrToRange $c.Trim()))
    }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in $BaseRanges) {
        $sLine = $line.Trim()
        if (-not $sLine -or $sLine.StartsWith('#')) { continue }
        $parts = $sLine -split '-'
        $curList = New-Object System.Collections.Generic.List[object]
        $st = [uint64](ConvertTo-UInt32Ip $parts[0])
        $en = if ($parts.Count -gt 1) { [uint64](ConvertTo-UInt32Ip $parts[1]) } else { $st }
        $curList.Add([pscustomobject]@{ Start = $st; End = $en })
        foreach ($ex in $exList) {
            $nextList = New-Object System.Collections.Generic.List[object]
            foreach ($seg in $curList) {
                if ($ex.End -lt $seg.Start -or $ex.Start -gt $seg.End) {
                    $nextList.Add($seg)
                } else {
                    if ($seg.Start -lt $ex.Start) { $nextList.Add([pscustomobject]@{ Start = $seg.Start; End = ($ex.Start - 1) }) }
                    if ($seg.End -gt $ex.End) { $nextList.Add([pscustomobject]@{ Start = ($ex.End + 1); End = $seg.End }) }
                }
            }
            $curList = $nextList
            if ($curList.Count -eq 0) { break }
        }
        foreach ($seg in $curList) {
            $a = ConvertFrom-UInt32Ip ([uint32]$seg.Start)
            $b = ConvertFrom-UInt32Ip ([uint32]$seg.End)
            if ($a -eq $b) { $out.Add($a) } else { $out.Add("$a-$b") }
        }
    }
    return @($out)
}

function Find-OverseasRangesFile {
    $candidates = @(
        (Join-Path $PSScriptRoot '..\data\overseas-ipv4-ranges.txt'),
        (Join-Path $PSScriptRoot 'overseas-ipv4-ranges.txt')
    )
    foreach ($p in $candidates) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

function Resolve-EntryNodes([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return [pscustomobject]@{ Cidrs = @(); Hosts = @() } }
    $tokens = @($Raw -split '[\s,;，；]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $cidrs = New-Object System.Collections.Generic.List[string]
    $hostsMap = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]

    foreach ($tok in $tokens) {
        $clean = $tok.Trim() -replace '^[a-zA-Z0-9+.-]+://', ''
        $clean = ($clean -split '/')[0]
        if ($clean -match '^([^:]+):\d+$' -and $tok -notmatch '/\d+$') { $clean = $Matches[1] }

        if ($tok.Trim() -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
            $parsed = $null
            if ([System.Net.IPAddress]::TryParse($Matches[1], [ref]$parsed) -and [int]$Matches[2] -ge 0 -and [int]$Matches[2] -le 32) {
                $val = "$($Matches[1])/$($Matches[2])"
                if ($seen.Add($val)) { $cidrs.Add($val) }
                continue
            }
        }
        $parsedIp = $null
        if ([System.Net.IPAddress]::TryParse($clean, [ref]$parsedIp) -and $parsedIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $val = "$($parsedIp.IPAddressToString)/32"
            if ($seen.Add($val)) { $cidrs.Add($val) }
            continue
        }
        try {
            $addrs = @([System.Net.Dns]::GetHostAddresses($clean) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
            if ($addrs.Count -gt 0) {
                $hostsMap.Add("$($addrs[0].IPAddressToString) $clean")
                foreach ($a in $addrs) {
                    $val = "$($a.IPAddressToString)/32"
                    if ($seen.Add($val)) { $cidrs.Add($val) }
                }
            }
        } catch {}
    }
    return [pscustomobject]@{ Cidrs = @($cidrs); Hosts = @($hostsMap) }
}

function Resolve-ClaudeBlockV4([string[]]$WhitelistCidrs) {
    $wlIps = @($WhitelistCidrs | ForEach-Object { ($_ -split '/')[0] })
    $list = New-Object System.Collections.Generic.List[string]
    $list.Add($ANTHROPIC_ASN_V4)
    foreach ($d in $ANTHROPIC_DOMAINS) {
        try {
            $recs = Resolve-DnsName -Name $d -Type A -ErrorAction SilentlyContinue
            foreach ($r in $recs) {
                $ip = [string]$r.IPAddress
                if (-not $ip -or $ip -like '198.18.*' -or $ip -like '198.19.*' -or $ip -like '127.*' -or $ip -like '10.*' -or $ip -like '192.168.*') { continue }
                if (($wlIps -notcontains $ip) -and (-not $list.Contains($ip))) { $list.Add($ip) }
            }
        } catch {}
    }
    return @($list)
}

function Get-ProtectedClaudeExes {
    $exes = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in @(
        "$env:LOCALAPPDATA\AnthropicClaude\Claude.exe",
        "$env:LOCALAPPDATA\Programs\Claude\Claude.exe",
        "$env:USERPROFILE\.local\bin\claude.exe",
        "$env:LOCALAPPDATA\Programs\claude\claude.exe"
    )) {
        if (Test-Path -LiteralPath $p) { $null = $exes.Add($p) }
    }
    try {
        $pkg = Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pkg -and $pkg.InstallLocation) {
            foreach ($f in @(Get-ChildItem -LiteralPath $pkg.InstallLocation -Filter 'Claude.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 3)) {
                $null = $exes.Add($f.FullName)
            }
        }
    } catch {}
    try {
        $cmd = Get-Command 'claude.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) { $null = $exes.Add($cmd.Source) }
    } catch {}
    return @($exes)
}

function Update-HostsManagedBlock([string[]]$Lines) {
    $existing = if (Test-Path -LiteralPath $HOSTS_FILE) { @(Get-Content -LiteralPath $HOSTS_FILE -Encoding UTF8 -ErrorAction SilentlyContinue) } else { @() }
    $out = New-Object System.Collections.Generic.List[string]
    $skip = $false
    foreach ($line in $existing) {
        if ($line -like "*$HOSTS_BEGIN*") { $skip = $true; continue }
        if ($skip -and $line -like "*$HOSTS_END*") { $skip = $false; continue }
        if (-not $skip) { $out.Add($line) }
    }
    while ($out.Count -gt 0 -and [string]::IsNullOrWhiteSpace($out[$out.Count - 1])) { $out.RemoveAt($out.Count - 1) }
    if ($Lines -and $Lines.Count -gt 0) {
        $out.Add('')
        $out.Add($HOSTS_BEGIN)
        foreach ($l in $Lines) { $out.Add($l) }
        $out.Add($HOSTS_END)
    }
    [System.IO.File]::WriteAllLines($HOSTS_FILE, $out, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-TunInfo {
    $tunIps = New-Object System.Collections.Generic.List[string]
    $tunIndices = New-Object System.Collections.Generic.List[int]
    foreach ($ipObj in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        if ($ipObj.IPAddress -like '198.18.*' -or $ipObj.IPAddress -like '198.19.*' -or $ipObj.IPAddress -like '172.19.*' -or $ipObj.IPAddress -like '172.18.*') {
            $tunIps.Add($ipObj.IPAddress); $tunIndices.Add([int]$ipObj.InterfaceIndex)
        }
    }
    foreach ($nic in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'TAP|TUN|WireGuard|Wintun|VPN|Tailscale|Sing-Box|Mihomo' -or $_.Name -match 'singbox_tun|sing-tun|v2rayN|Mihomo|Meta|utun')
    })) {
        $tunIndices.Add([int]$nic.ifIndex)
        foreach ($ipObj in @(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)) { $tunIps.Add($ipObj.IPAddress) }
    }
    $uniqueIdx = @($tunIndices | Select-Object -Unique)
    $uniqueIps = @($tunIps | Select-Object -Unique)
    $routeViaTun = $false; $bestAlias = ''
    try {
        $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        if ($routes.Count -gt 0) {
            $best = $routes | Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric } | Select-Object -First 1
            if ($best) {
                $bestAlias = [string]$best.InterfaceAlias
                if ($uniqueIdx -contains [int]$best.InterfaceIndex) { $routeViaTun = $true }
            }
        }
    } catch {}
    return [pscustomobject]@{ Up = ($uniqueIdx.Count -gt 0); RouteViaTun = $routeViaTun; BestAlias = $bestAlias; TunIps = $uniqueIps }
}

function Stop-ClaudeSafely {
    $desktop = Get-Process -Name 'Claude' -ErrorAction SilentlyContinue
    if ($desktop) {
        foreach ($p in $desktop) { try { $null = $p.CloseMainWindow() } catch {} }
        for ($i = 0; $i -lt 5; $i++) { if (-not (Get-Process -Name 'Claude' -ErrorAction SilentlyContinue)) { break }; Start-Sleep 1 }
        Get-Process -Name 'Claude' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    try {
        Get-Process -Name 'claude' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        foreach ($np in @(Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='bun.exe'" -ErrorAction SilentlyContinue)) {
            if ($np.CommandLine -and ($np.CommandLine -match '@anthropic-ai[/\\]claude-code[/\\](bin[/\\]claude(\.exe)?|cli\.js)')) {
                Stop-Process -Id ([int]$np.ProcessId) -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

function Set-ClaudeDesktopEnglish {
    $targets = New-Object System.Collections.Generic.List[string]
    $targets.Add("$env:APPDATA\Claude\config.json")
    try {
        foreach ($d in @(Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\Claude-Data" -Directory -Filter 'claude_*' -ErrorAction SilentlyContinue)) {
            $targets.Add((Join-Path $d.FullName 'config.json'))
        }
    } catch {}
    foreach ($f in $targets) {
        if (-not (Test-Path -LiteralPath (Split-Path -Parent $f))) { continue }
        try {
            $obj = if (Test-Path -LiteralPath $f) { Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json } else { [pscustomobject]@{} }
            if ($obj.PSObject.Properties['locale']) { $obj.locale = 'en-US' } else { $obj | Add-Member -NotePropertyName 'locale' -NotePropertyValue 'en-US' -Force }
            [System.IO.File]::WriteAllText($f, ($obj | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
        } catch {}
    }
}

function Get-GeoInfo {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ua = 'claude-guard/1.0'
    foreach ($s in @(
        @{ Url = 'https://ipinfo.io/json'; Country = 'country'; Tz = 'timezone'; Ip = 'ip' },
        @{ Url = 'https://ipapi.co/json/'; Country = 'country_code'; Tz = 'timezone'; Ip = 'ip' },
        @{ Url = 'https://ifconfig.co/json'; Country = 'country_iso'; Tz = 'timezone'; Ip = 'ip' }
    )) {
        try {
            $d = Invoke-RestMethod -Uri $s.Url -UserAgent $ua -TimeoutSec 6 -ErrorAction Stop
            $cc = ([string]$d.$($s.Country)).Trim().ToUpperInvariant()
            if ($cc -match '^[A-Z]{2}$') { return [pscustomobject]@{ Country = $cc; IanaTz = [string]$d.$($s.Tz); Ip = [string]$d.$($s.Ip) } }
        } catch {}
    }
    try {
        $t = Invoke-WebRequest -Uri 'https://www.cloudflare.com/cdn-cgi/trace' -UserAgent $ua -TimeoutSec 6 -UseBasicParsing -ErrorAction Stop
        $cc = ''; $ip = ''
        foreach ($line in ($t.Content -split "`r?`n")) {
            if ($line -match '^loc=([A-Za-z]{2})$') { $cc = $Matches[1].ToUpperInvariant() }
            if ($line -match '^ip=(\S+)$') { $ip = $Matches[1] }
        }
        if ($cc -match '^[A-Z]{2}$') { return [pscustomobject]@{ Country = $cc; IanaTz = ''; Ip = $ip } }
    } catch {}
    return [pscustomobject]@{ Country = ''; IanaTz = ''; Ip = '' }
}

function Invoke-Lock($cfg, [string]$Mode = 'cn') {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:开启持久化硬锁需要管理员权限，请通过「Claude安全锁控制台.bat」运行'
        exit 1
    }
    $resolved = Resolve-EntryNodes $cfg.entryNodes
    if ($Mode -eq 'strict' -and $resolved.Cidrs.Count -eq 0) {
        Write-Output 'FAIL:开启「全封闭模式」前请先填写第一跳代理入口 IP 或域名'
        exit 1
    }

    $tun = Get-TunInfo
    $localExcludes = New-Object System.Collections.Generic.List[string]
    $localExcludes.Add('127.0.0.0/8'); $localExcludes.Add('172.18.0.0/15'); $localExcludes.Add('198.18.0.0/15')
    foreach ($tip in $tun.TunIps) { $localExcludes.Add("$tip/32") }
    $nonTunLocalV4 = Get-ComplementIpv4Ranges @($localExcludes)
    $publicRemoteV4 = Get-ComplementIpv4Ranges @('10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15')
    $claudeV4 = Resolve-ClaudeBlockV4 $resolved.Cidrs

    # 强制启用 Windows Defender 防火墙三档并开启阻断流量日志 (pfirewall.log) 供验收核查
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -LogBlocked True -LogFileName $PFW_LOG -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue

    Update-HostsManagedBlock $resolved.Hosts
    # Zero-Gap 原子切换: 先记录旧规则，待全部新规则创建生效后再删除旧规则，切换锁1模式期间 0ms 无空窗
    $oldRules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue)
    $gen = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()

    # 1. 最高优先级: 物理网卡阻断 Claude/Anthropic 官方 ASN(AS399358) 与生态域名 IP (IPv4 + IPv6)
    New-NetFirewallRule -DisplayName 'ClaudeGuard: 死锁 Claude/Anthropic ASN 与域名 IP (IPv4)' `
        -Name "ClaudeGuard-Block-Claude-ASN-V4-$gen" `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -LocalAddress $nonTunLocalV4 -RemoteAddress $claudeV4 | Out-Null

    New-NetFirewallRule -DisplayName 'ClaudeGuard: 死锁全部公网 IPv6 与 Anthropic IPv6' `
        -Name "ClaudeGuard-Block-All-Public-V6-$gen" `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -RemoteAddress @($ANTHROPIC_ASN_V6, '2000::/3') | Out-Null

    # 2. 物理网卡阻断 STUN / WebRTC UDP (3478/5349/19302)
    New-NetFirewallRule -DisplayName 'ClaudeGuard: 阻断物理网卡 STUN/WebRTC UDP' `
        -Name "ClaudeGuard-Block-STUN-UDP-$gen" `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -Protocol UDP -RemotePort @('3478', '5349', '19302') -LocalAddress $nonTunLocalV4 | Out-Null

    # 3. 目标应用进程绝对硬锁: 无论国内还是海外，Claude.exe / claude.exe 绝不允许走物理网卡直连公网
    $appIdx = 0
    foreach ($exe in (Get-ProtectedClaudeExes)) {
        $appIdx++
        New-NetFirewallRule -DisplayName "ClaudeGuard: 死锁目标应用物理直连 #$appIdx (IPv4)" `
            -Name "ClaudeGuard-Block-TargetApp-V4-$appIdx-$gen" `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -Program $exe -LocalAddress $nonTunLocalV4 -RemoteAddress $publicRemoteV4 | Out-Null
        New-NetFirewallRule -DisplayName "ClaudeGuard: 死锁目标应用物理直连 #$appIdx (IPv6)" `
            -Name "ClaudeGuard-Block-TargetApp-V6-$appIdx-$gen" `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -Program $exe -RemoteAddress '2000::/3' | Out-Null
    }

    # 4. 海外服务全封(cn模式) vs 全部公网全封(strict模式)
    $shardCount = 0
    if ($Mode -eq 'strict') {
        $remoteExcludes = New-Object System.Collections.Generic.List[string]
        foreach ($lan in @('10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15')) { $remoteExcludes.Add($lan) }
        foreach ($c in $resolved.Cidrs) { $remoteExcludes.Add($c) }
        $blockedAll = Get-ComplementIpv4Ranges @($remoteExcludes)
        New-NetFirewallRule -DisplayName 'ClaudeGuard: 全封闭模式仅放行白名单入口 (IPv4)' `
            -Name "ClaudeGuard-Block-Strict-All-V4-$gen" `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -LocalAddress $nonTunLocalV4 -RemoteAddress $blockedAll | Out-Null
        if (-not $cfg.allowLanDns) {
            New-NetFirewallRule -DisplayName 'ClaudeGuard: 阻断物理网卡裸 DNS (UDP 53)' `
                -Name "ClaudeGuard-Block-Phys-DNS-UDP-$gen" `
                -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
                -Protocol UDP -RemotePort '53' -LocalAddress $nonTunLocalV4 | Out-Null
            New-NetFirewallRule -DisplayName 'ClaudeGuard: 阻断物理网卡裸 DNS (TCP 53)' `
                -Name "ClaudeGuard-Block-Phys-DNS-TCP-$gen" `
                -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
                -Protocol TCP -RemotePort '53' -LocalAddress $nonTunLocalV4 | Out-Null
        }
        $shardCount = 1
    } else {
        $ovFile = Find-OverseasRangesFile
        if (-not $ovFile) {
            Write-Output 'FAIL:找不到海外公网补集区间表 (data\overseas-ipv4-ranges.txt)，已中止'
            exit 1
        }
        $baseOverseas = @(Get-Content -LiteralPath $ovFile -Encoding UTF8)
        $overseasBlocked = Subtract-CidrsFromRanges $baseOverseas $resolved.Cidrs
        # 每片 400 个区间写入一条 WFP 规则 (~12 条规则，避免超单条上限)
        $chunkSize = 400
        for ($off = 0; $off -lt $overseasBlocked.Count; $off += $chunkSize) {
            $shardCount++
            $endIdx = [Math]::Min($off + $chunkSize - 1, $overseasBlocked.Count - 1)
            $slice = @($overseasBlocked[$off..$endIdx])
            New-NetFirewallRule -DisplayName "ClaudeGuard: 死锁一切海外公网服务 分片#$shardCount (放行国内直连)" `
                -Name "ClaudeGuard-Block-Overseas-V4-Part$shardCount-$gen" `
                -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
                -LocalAddress $nonTunLocalV4 -RemoteAddress $slice | Out-Null
        }
    }

    # 全部新规则均已落盘生效，安全移除上一代旧规则 (0ms 空窗)
    if ($oldRules.Count -gt 0) {
        $oldRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }

    $cfg.lockMode = $Mode
    Save-Config $cfg
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    $modeLabel = if ($Mode -eq 'strict') { '全封闭模式(仅海外TUN)' } else { '国内直连放行(死锁Claude与一切海外)' }
    Write-Output "OK:持久化硬锁已生效 [$modeLabel] | 目标应用锁=$appIdx | 封锁规则分片=$shardCount | 已开启 pfirewall.log 丢包日志 (代理/软件退出及重启后仍持续生效)"
}

function Invoke-UnlockAll {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:解开持久化硬锁需要管理员权限'
        exit 1
    }
    Write-Output '正在安全退出 Claude 桌面版与 Claude Code CLI...'
    Stop-ClaudeSafely
    Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Update-HostsManagedBlock @()
    $cfg = Load-Config
    $cfg.lockMode = 'off'
    Save-Config $cfg
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Output 'OK:【锁2】持久化硬锁已完全解开，电脑已恢复原生直连状态。⚠️ 切记：此刻严禁启动任何 Claude 服务！'
}

function Invoke-VerifyFirewall {
    Write-Output '=== 操作系统防火墙与流量拦截日志验收 (Windows Defender Firewall) ==='
    Write-Output ("时间: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Write-Output ('-' * 64)

    $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $allEnabled = $true; $allLogged = $true
    Write-Output '[1] 系统防火墙配置文件状态 (Domain / Private / Public):'
    foreach ($p in $profiles) {
        Write-Output ("    - {0,-8}: Enabled={1}, LogBlocked={2}, LogFile={3}" -f $p.Name, $p.Enabled, $p.LogBlocked, $p.LogFileName)
        if (-not $p.Enabled) { $allEnabled = $false }
        if (-not $p.LogBlocked) { $allLogged = $false }
    }

    $rules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    $asnCnt = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Claude-*' }).Count
    $appCnt = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-TargetApp-*' }).Count
    $ovCnt  = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Overseas-*' -or $_.Name -like 'ClaudeGuard-Block-Strict-*' }).Count
    $v6Cnt  = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-All-Public-V6*' }).Count
    $stunCnt = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-STUN-UDP*' }).Count

    Write-Output "[2] 持久化硬锁规则组 ($FW_GROUP): 共 $($rules.Count) 条启用中的 Block 规则"
    Write-Output "    - Claude ASN/域名 IP 死锁规则: $asnCnt 条"
    Write-Output "    - 目标应用(Claude.exe/claude.exe)进程死锁: $appCnt 条"
    Write-Output "    - 海外公网/全封闭封锁分片: $ovCnt 条"
    Write-Output "    - 公网 IPv6 死锁: $v6Cnt 条 | STUN/WebRTC 死锁: $stunCnt 条"

    Write-Output "[3] 操作系统防火墙真实拦截流量日志 ($PFW_LOG 最近 12 条 DROP):"
    if (Test-Path -LiteralPath $PFW_LOG) {
        $drops = @(Get-Content -LiteralPath $PFW_LOG -Tail 200 -ErrorAction SilentlyContinue | Where-Object { $_ -match '\sDROP\s' } | Select-Object -Last 12)
        if ($drops.Count -gt 0) {
            foreach ($d in $drops) { Write-Output "    $d" }
        } else {
            Write-Output '    (日志文件存在，暂无新 DROP 记录 —— 可断开代理后尝试访问 claude.ai 再点本按钮查看实时 DROP 记录)'
        }
    } else {
        Write-Output '    (日志文件路径尚未产生数据，产生首次拦截后系统自动生成)'
    }

    Write-Output ('-' * 64)
    if ($allEnabled -and $rules.Count -ge 4 -and $asnCnt -ge 1 -and $ovCnt -ge 1) {
        Write-Output '验收结论: [✓] Windows 持久化硬锁已生效 (代理/软件退出及重启后依然阻断 Claude 与海外直连)'
        exit 0
    } else {
        Write-Output '验收结论: [✗] 操作系统防火墙持久化硬锁未处于完整锁定状态'
        exit 1
    }
}

function Invoke-Init([string]$InputNodes, [string]$InputCountry) {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:一键初始化需要管理员权限'
        exit 1
    }
    $cfg = Load-Config
    if (-not [string]::IsNullOrWhiteSpace($InputNodes)) { $cfg.entryNodes = $InputNodes.Trim() }

    $cc = ''; $winTz = ''; $ip = '手动指定'
    if (-not [string]::IsNullOrWhiteSpace($InputCountry)) {
        $cc = $InputCountry.Trim().ToUpperInvariant()
        $winTz = if ($COUNTRY_TZ.ContainsKey($cc)) { $COUNTRY_TZ[$cc] } else { 'Eastern Standard Time' }
    } else {
        $geo = Get-GeoInfo
        $cc = $geo.Country
        $ip = if ($geo.Ip) { $geo.Ip } else { '未知' }
        if (-not $cc -or $cc -in @('CN', 'HK', 'MO')) {
            Write-Output "FAIL:当前出口为 $(if ($cc) { $cc } else { '未知' })($ip)，属于不支持地区！请先打开 Clash Verge / v2rayN「全局 + TUN」切至海外支持地区后再初始化"
            exit 1
        }
        if ($geo.IanaTz -and $IANA_TO_WIN.ContainsKey($geo.IanaTz)) { $winTz = $IANA_TO_WIN[$geo.IanaTz] }
        elseif ($COUNTRY_TZ.ContainsKey($cc)) { $winTz = $COUNTRY_TZ[$cc] }
        else { $winTz = 'Eastern Standard Time' }
    }
    $locale = if ($COUNTRY_LOCALE.ContainsKey($cc)) { $COUNTRY_LOCALE[$cc] } else { 'en-US' }

    $cfg.countryTarget = $cc; $cfg.tzTarget = $winTz; $cfg.localeTarget = $locale
    Save-Config $cfg

    Set-TimeZone -Id $winTz
    try { Set-Culture -CultureInfo $locale -ErrorAction SilentlyContinue } catch {}
    Set-ClaudeDesktopEnglish
    Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Enabled } | Disable-NetAdapterBinding -Confirm:$false -ErrorAction SilentlyContinue

    # 默认扣死持久化硬锁 (国内直连放行 + 死锁 Claude 与一切海外)
    Invoke-Lock $cfg 'cn'
    Write-Output "OK:一键初始化完成 | 出口=$cc($ip) | 时区=$winTz | 地区=$locale | Claude语言=en-US | 全网卡IPv6=已关闭"
}

function Invoke-Status {
    $cfg = Load-Config
    $rules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
    $lockState = if ($rules.Count -ge 4) { 'on' } else { 'off' }
    $lockMode = 'off'
    if ($lockState -eq 'on') {
        $isStrict = [bool]($rules | Where-Object { $_.Name -eq 'ClaudeGuard-Block-Strict-All-V4' })
        $lockMode = if ($isStrict) { 'strict' } else { 'cn' }
    }
    Write-Output "LOCK=$lockState"
    Write-Output "LOCK_MODE=$lockMode"
    Write-Output "PERSISTENT_LOCK=$lockState"
    Write-Output "ENTRY_NODES=$(if ($cfg.entryNodes) { $cfg.entryNodes } else { '未配置' })"
    Write-Output "COUNTRY_TARGET=$(if ($cfg.countryTarget) { $cfg.countryTarget } else { '未配置' })"
    Write-Output "TZ_TARGET=$(if ($cfg.tzTarget) { $cfg.tzTarget } else { '未配置' })"
    Write-Output "LOCALE_TARGET=$(if ($cfg.localeTarget) { $cfg.localeTarget } else { '未配置' })"
}

function Invoke-Check([string]$ExportFile = '') {
    $auditScript = Join-Path $PSScriptRoot 'env-audit.ps1'
    if (Test-Path -LiteralPath $auditScript) {
        $auditArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $auditScript, '-ConfigPath', $CFG_FILE)
        if ($ExportFile) { $auditArgs += @('-ExportPath', $ExportFile) }
        & powershell.exe @auditArgs
        exit $LASTEXITCODE
    }
    Write-Output 'FAIL:找不到 env-audit.ps1 深度体检引擎'
    exit 1
}

switch ($Action) {
    'set-nodes' {
        $cfg = Load-Config
        if ([string]::IsNullOrWhiteSpace($Nodes)) {
            $cfg.entryNodes = ''
            Save-Config $cfg
            Write-Output 'OK:已清空海外入口白名单(国内中转机自动放行)'
        } else {
            $r = Resolve-EntryNodes $Nodes
            if ($r.Cidrs.Count -eq 0) { Write-Output "FAIL:无法解析任何有效 IPv4: $Nodes"; exit 1 }
            $cfg.entryNodes = $Nodes.Trim()
            Save-Config $cfg
            Write-Output "OK:已保存入口节点 ($($cfg.entryNodes))，解析出 $($r.Cidrs.Count) 个 IPv4"
        }
    }
    'init'            { Invoke-Init $Nodes $ManualCountry }
    'lock'            { Invoke-Lock (Load-Config) 'cn' }
    'lock-cn'         { Invoke-Lock (Load-Config) 'cn' }
    'lock-strict'     { Invoke-Lock (Load-Config) 'strict' }
    'unlock'          { Invoke-UnlockAll }
    'unlock-all'      { Invoke-UnlockAll }
    'verify-firewall' { Invoke-VerifyFirewall }
    'check'           { Invoke-Check $Nodes }
    'export-report'   {
        $outF = if ($Nodes) { $Nodes } else { Join-Path ([Environment]::GetFolderPath('Desktop')) ("claude-env-report-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt') }
        Invoke-Check $outF
    }
    default           { Invoke-Status }
}
