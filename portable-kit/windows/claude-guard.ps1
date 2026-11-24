# Claude 安全锁 · Windows 极简核心引擎 (方案 A: 固定代理入口白名单 Kill-Switch)
# 特点:
#   - 零外部依赖 (仅 Windows 10/11 自带 PowerShell 5.1)
#   - 兼容 Clash Verge (服务模式+TUN) / v2rayN (管理员+启用Tun) / FlClash / sing-box 等任意全局+TUN 客户端
#   - 使用精确 IPv4 补集区间算法: 物理网卡仅放行局域网与白名单入口 IP (支持链式代理第一跳多 IP/域名), 其余公网 IPv4 + 全部公网 IPv6 + 物理裸 DNS 53 全部 0ms 内核 DROP
#   - 不修改 Windows 全局默认出站策略, 一键恢复直连只需删除 ClaudeGuard-KillSwitch 规则组, 0.3 秒无痕还原
param(
    [Parameter(Position = 0)]
    [ValidateSet('init', 'set-nodes', 'lock', 'unlock', 'status', 'check', 'export-report')]
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
$HOSTS_BEGIN = '# BEGIN claude-guard-hosts'
$HOSTS_END = '# END claude-guard-hosts'

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
    }
    if (Test-Path -LiteralPath $CFG_FILE) {
        try {
            $raw = Get-Content -LiteralPath $CFG_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($raw.entryNodes) { $cfg.entryNodes = [string]$raw.entryNodes }
            if ($raw.countryTarget) { $cfg.countryTarget = [string]$raw.countryTarget }
            if ($raw.tzTarget) { $cfg.tzTarget = [string]$raw.tzTarget }
            if ($raw.localeTarget) { $cfg.localeTarget = [string]$raw.localeTarget }
            if ($null -ne $raw.allowLanDns) { $cfg.allowLanDns = [bool]$raw.allowLanDns }
        } catch {}
    }
    return $cfg
}

function Save-Config($cfg) {
    $json = $cfg | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($CFG_FILE, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
}

# ---- IPv4 整数与精确补集区间算法 (100% 合法单播范围 1.0.0.0 - 223.255.255.255，绝不出现 0.0.0.0 / 255.255.255.255) ----
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
    $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32]([uint64]0xFFFFFFFF -shl (32 - $prefix) -band 0xFFFFFFFF) }
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
        if ($s -le $e) {
            $intervals.Add([pscustomobject]@{ Start = $s; End = $e })
        }
    }

    $sorted = @($intervals | Sort-Object Start, End)
    $merged = New-Object System.Collections.Generic.List[object]
    foreach ($iv in $sorted) {
        if ($merged.Count -eq 0 -or $iv.Start -gt ($merged[$merged.Count - 1].End + 1)) {
            $merged.Add([pscustomobject]@{ Start = $iv.Start; End = $iv.End })
        } else {
            if ($iv.End -gt $merged[$merged.Count - 1].End) {
                $merged[$merged.Count - 1].End = $iv.End
            }
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

# 解析用户输入的代理入口节点 (支持 IP / CIDR / 域名，逗号或空格分隔)
function Resolve-EntryNodes([string]$Raw) {
    $tokens = @($Raw -split '[\s,;，；]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $cidrs = New-Object System.Collections.Generic.List[string]
    $hostsMap = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]

    foreach ($tok in $tokens) {
        $clean = $tok.Trim() -replace '^[a-zA-Z0-9+.-]+://', ''
        $clean = ($clean -split '/')[0]
        if ($clean -match '^([^:]+):\d+$' -and $tok -notmatch '/\d+$') { $clean = $Matches[1] }

        # CIDR 格式如 203.0.113.0/24
        if ($tok.Trim() -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
            $parsed = $null
            if ([System.Net.IPAddress]::TryParse($Matches[1], [ref]$parsed) -and [int]$Matches[2] -ge 0 -and [int]$Matches[2] -le 32) {
                $val = "$($Matches[1])/$($Matches[2])"
                if ($seen.Add($val)) { $cidrs.Add($val) }
                continue
            }
        }

        # 纯 IPv4
        $parsedIp = $null
        if ([System.Net.IPAddress]::TryParse($clean, [ref]$parsedIp) -and $parsedIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $val = "$($parsedIp.IPAddressToString)/32"
            if ($seen.Add($val)) { $cidrs.Add($val) }
            continue
        }

        # 域名解析 A 记录并写入 hosts 托管映射
        try {
            $addrs = @([System.Net.Dns]::GetHostAddresses($clean) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
            if ($addrs.Count -gt 0) {
                $firstIp = $addrs[0].IPAddressToString
                $hostsMap.Add("$firstIp $clean")
                foreach ($a in $addrs) {
                    $val = "$($a.IPAddressToString)/32"
                    if ($seen.Add($val)) { $cidrs.Add($val) }
                }
            }
        } catch {}
    }

    return [pscustomobject]@{
        Cidrs = @($cidrs)
        Hosts = @($hostsMap)
    }
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
    while ($out.Count -gt 0 -and [string]::IsNullOrWhiteSpace($out[$out.Count - 1])) {
        $out.RemoveAt($out.Count - 1)
    }
    if ($Lines -and $Lines.Count -gt 0) {
        $out.Add('')
        $out.Add($HOSTS_BEGIN)
        foreach ($l in $Lines) { $out.Add($l) }
        $out.Add($HOSTS_END)
    }
    [System.IO.File]::WriteAllLines($HOSTS_FILE, $out, (New-Object System.Text.UTF8Encoding($false)))
}

# 探测当前活跃的 TUN 虚拟网卡 IP 与默认路由状态
function Get-TunInfo {
    $tunIps = New-Object System.Collections.Generic.List[string]
    $tunIndices = New-Object System.Collections.Generic.List[int]

    foreach ($ipObj in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
        if ($ipObj.IPAddress -like '198.18.*' -or $ipObj.IPAddress -like '198.19.*' -or $ipObj.IPAddress -like '172.19.*' -or $ipObj.IPAddress -like '172.18.*') {
            $tunIps.Add($ipObj.IPAddress)
            $tunIndices.Add([int]$ipObj.InterfaceIndex)
        }
    }
    foreach ($nic in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'TAP|TUN|WireGuard|Wintun|VPN|Tailscale|Sing-Box|Mihomo' -or $_.Name -match 'singbox_tun|sing-tun|v2rayN|Mihomo|Meta|utun')
    })) {
        $tunIndices.Add([int]$nic.ifIndex)
        foreach ($ipObj in @(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
            $tunIps.Add($ipObj.IPAddress)
        }
    }

    $uniqueIdx = @($tunIndices | Select-Object -Unique)
    $uniqueIps = @($tunIps | Select-Object -Unique)
    $routeViaTun = $false
    $bestAlias = ''
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

    return [pscustomobject]@{
        Up = ($uniqueIdx.Count -gt 0)
        RouteViaTun = $routeViaTun
        BestAlias = $bestAlias
        TunIps = $uniqueIps
    }
}

function Stop-ClaudeSafely {
    $desktop = Get-Process -Name 'Claude' -ErrorAction SilentlyContinue
    if ($desktop) {
        foreach ($p in $desktop) { try { $null = $p.CloseMainWindow() } catch {} }
        for ($i = 0; $i -lt 5; $i++) {
            if (-not (Get-Process -Name 'Claude' -ErrorAction SilentlyContinue)) { break }
            Start-Sleep 1
        }
        Get-Process -Name 'Claude' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    try {
        Get-Process -Name 'claude' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        $nodeProcs = Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='bun.exe'" -ErrorAction SilentlyContinue
        foreach ($np in $nodeProcs) {
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
        $msixDirs = @(Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\Claude-Data" -Directory -Filter 'claude_*' -ErrorAction SilentlyContinue)
        foreach ($d in $msixDirs) { $targets.Add((Join-Path $d.FullName 'config.json')) }
    } catch {}
    foreach ($f in $targets) {
        $dir = Split-Path -Parent $f
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        try {
            $obj = if (Test-Path -LiteralPath $f) {
                Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json
            } else {
                [pscustomobject]@{}
            }
            if ($obj.PSObject.Properties['locale']) {
                $obj.locale = 'en-US'
            } else {
                $obj | Add-Member -NotePropertyName 'locale' -NotePropertyValue 'en-US' -Force
            }
            [System.IO.File]::WriteAllText($f, ($obj | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
        } catch {}
    }
}

function Get-GeoInfo {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ua = 'claude-guard/1.0'
    $sources = @(
        @{ Url = 'https://ipinfo.io/json'; Country = 'country'; Tz = 'timezone'; Ip = 'ip' },
        @{ Url = 'https://ipapi.co/json/'; Country = 'country_code'; Tz = 'timezone'; Ip = 'ip' },
        @{ Url = 'https://ifconfig.co/json'; Country = 'country_iso'; Tz = 'timezone'; Ip = 'ip' }
    )
    foreach ($s in $sources) {
        try {
            $d = Invoke-RestMethod -Uri $s.Url -UserAgent $ua -TimeoutSec 6 -ErrorAction Stop
            $cc = ([string]$d.$($s.Country)).Trim().ToUpperInvariant()
            if ($cc -match '^[A-Z]{2}$') {
                return [pscustomobject]@{ Country = $cc; IanaTz = [string]$d.$($s.Tz); Ip = [string]$d.$($s.Ip) }
            }
        } catch {}
    }
    try {
        $t = Invoke-WebRequest -Uri 'https://www.cloudflare.com/cdn-cgi/trace' -UserAgent $ua -TimeoutSec 6 -UseBasicParsing -ErrorAction Stop
        $cc = ''; $ip = ''
        foreach ($line in ($t.Content -split "`r?`n")) {
            if ($line -match '^loc=([A-Za-z]{2})$') { $cc = $Matches[1].ToUpperInvariant() }
            if ($line -match '^ip=(\S+)$') { $ip = $Matches[1] }
        }
        if ($cc -match '^[A-Z]{2}$') {
            return [pscustomobject]@{ Country = $cc; IanaTz = ''; Ip = $ip }
        }
    } catch {}
    return [pscustomobject]@{ Country = ''; IanaTz = ''; Ip = '' }
}

function Invoke-Lock($cfg) {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:开启安全锁需要管理员权限，请通过「Claude安全锁控制台.bat」运行'
        exit 1
    }
    if ([string]::IsNullOrWhiteSpace($cfg.entryNodes)) {
        Write-Output 'FAIL:尚未配置代理入口节点 IP/域名，请先填写入口节点'
        exit 1
    }

    $resolved = Resolve-EntryNodes $cfg.entryNodes
    if ($resolved.Cidrs.Count -eq 0) {
        Write-Output "FAIL:未能解析出有效入口 IPv4，请检查输入: $($cfg.entryNodes)"
        exit 1
    }

    $tun = Get-TunInfo
    # 本地非 TUN 源地址区间: 排除 127.0.0.0/8, 172.18.0.0/15, 198.18.0.0/15 及当前活跃 TUN 精确 IP
    $localExcludes = New-Object System.Collections.Generic.List[string]
    $localExcludes.Add('127.0.0.0/8')
    $localExcludes.Add('172.18.0.0/15')
    $localExcludes.Add('198.18.0.0/15')
    foreach ($tip in $tun.TunIps) { $localExcludes.Add("$tip/32") }
    $nonTunLocalV4 = Get-ComplementIpv4Ranges @($localExcludes)

    # 远程封锁目标区间: 1.0.0.0-223.255.255.255 减去 (局域网 + 回环 + 链路本地 + FakeIP + 用户白名单入口 IP)
    $remoteExcludes = New-Object System.Collections.Generic.List[string]
    foreach ($lan in @('10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15')) {
        $remoteExcludes.Add($lan)
    }
    foreach ($c in $resolved.Cidrs) { $remoteExcludes.Add($c) }
    $blockedRemoteV4 = Get-ComplementIpv4Ranges @($remoteExcludes)

    # 写入入口域名 hosts 托管块 (防止封死物理 DNS 53 后域名节点断网重连失败)
    Update-HostsManagedBlock $resolved.Hosts

    # 幂等重建 ClaudeGuard-KillSwitch 防火墙规则组
    Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

    # 1. 封锁物理网卡除白名单入口 IP 与局域网外的所有公网 IPv4 (含 Anthropic / WebRTC STUN / 裸 DNS)
    New-NetFirewallRule -DisplayName 'ClaudeGuard: 物理网卡仅放行白名单入口节点 (IPv4)' `
        -Name 'ClaudeGuard-Block-NonWhitelist-V4' `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -LocalAddress $nonTunLocalV4 -RemoteAddress $blockedRemoteV4 | Out-Null

    # 2. 封锁物理网卡全部公网 IPv6 出站 (根治手机热点强推 IPv6)
    New-NetFirewallRule -DisplayName 'ClaudeGuard: 阻断全部公网 IPv6 出站' `
        -Name 'ClaudeGuard-Block-All-Public-V6' `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -RemoteAddress '2000::/3' | Out-Null

    # 3. 默认封锁物理网卡向局域网路由器/网关发送裸 DNS 53 查询
    if (-not $cfg.allowLanDns) {
        New-NetFirewallRule -DisplayName 'ClaudeGuard: 阻断物理网卡裸 DNS (UDP 53)' `
            -Name 'ClaudeGuard-Block-Phys-DNS-UDP' `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -Protocol UDP -RemotePort '53' -LocalAddress $nonTunLocalV4 | Out-Null
        New-NetFirewallRule -DisplayName 'ClaudeGuard: 阻断物理网卡裸 DNS (TCP 53)' `
            -Name 'ClaudeGuard-Block-Phys-DNS-TCP' `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -Protocol TCP -RemotePort '53' -LocalAddress $nonTunLocalV4 | Out-Null
    }

    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Output "OK:安全锁已开启 (白名单入口=$($resolved.Cidrs.Count)个, 其余物理公网/IPv6/WebRTC/裸DNS已全部阻断)"
}

function Invoke-Unlock {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:恢复直连模式需要管理员权限'
        exit 1
    }
    Write-Output '正在安全退出 Claude 桌面版与 Claude Code CLI...'
    Stop-ClaudeSafely
    Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Update-HostsManagedBlock @()
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Output 'OK:已恢复直连模式 (防火墙安全锁与 hosts 托管项已彻底清除)'
}

function Invoke-Init([string]$InputNodes, [string]$InputCountry) {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:一键初始化需要管理员权限'
        exit 1
    }
    $cfg = Load-Config
    if (-not [string]::IsNullOrWhiteSpace($InputNodes)) { $cfg.entryNodes = $InputNodes.Trim() }
    if ([string]::IsNullOrWhiteSpace($cfg.entryNodes)) {
        Write-Output 'FAIL:请先填写代理入口节点 IP 或域名'
        exit 1
    }

    $cc = ''; $winTz = ''; $ip = '手动指定'
    if (-not [string]::IsNullOrWhiteSpace($InputCountry)) {
        $cc = $InputCountry.Trim().ToUpperInvariant()
        $winTz = if ($COUNTRY_TZ.ContainsKey($cc)) { $COUNTRY_TZ[$cc] } else { 'Eastern Standard Time' }
    } else {
        $geo = Get-GeoInfo
        $cc = $geo.Country
        $ip = if ($geo.Ip) { $geo.Ip } else { '未知' }
        if (-not $cc -or $cc -eq 'CN') {
            Write-Output "FAIL:当前出口为 $(if ($cc) { $cc } else { '未知' })($ip)，请先打开 Clash Verge / v2rayN「全局 + TUN」后再初始化"
            exit 1
        }
        if ($geo.IanaTz -and $IANA_TO_WIN.ContainsKey($geo.IanaTz)) { $winTz = $IANA_TO_WIN[$geo.IanaTz] }
        elseif ($COUNTRY_TZ.ContainsKey($cc)) { $winTz = $COUNTRY_TZ[$cc] }
        else { $winTz = 'Eastern Standard Time' }
    }
    $locale = if ($COUNTRY_LOCALE.ContainsKey($cc)) { $COUNTRY_LOCALE[$cc] } else { 'en-US' }

    $cfg.countryTarget = $cc
    $cfg.tzTarget = $winTz
    $cfg.localeTarget = $locale
    Save-Config $cfg

    # 1. 锁定时区 / 地区 / Claude 英文语言 / 关闭全网卡 IPv6
    Set-TimeZone -Id $winTz
    try { Set-Culture -CultureInfo $locale -ErrorAction SilentlyContinue } catch {}
    Set-ClaudeDesktopEnglish
    Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Enabled } | Disable-NetAdapterBinding -Confirm:$false -ErrorAction SilentlyContinue

    # 2. 开启方案 A 严格白名单安全锁
    Invoke-Lock $cfg
    Write-Output "OK:一键初始化完成 | 出口=$cc($ip) | 时区=$winTz | 地区=$locale | Claude语言=en-US | 全网卡IPv6=已关闭"
}

function Invoke-Status {
    $cfg = Load-Config
    $rules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
    $lockState = if ($rules.Count -ge 2) { 'on' } else { 'off' }
    Write-Output "LOCK=$lockState"
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
        if ([string]::IsNullOrWhiteSpace($Nodes)) { Write-Output 'FAIL:请输入入口节点 IP 或域名'; exit 1 }
        $r = Resolve-EntryNodes $Nodes
        if ($r.Cidrs.Count -eq 0) { Write-Output "FAIL:无法解析任何有效 IPv4: $Nodes"; exit 1 }
        $cfg.entryNodes = $Nodes.Trim()
        Save-Config $cfg
        Write-Output "OK:已保存入口节点 ($($cfg.entryNodes))，解析出 $($r.Cidrs.Count) 个 IPv4"
    }
    'init'   { Invoke-Init $Nodes $ManualCountry }
    'lock'   { Invoke-Lock (Load-Config) }
    'unlock' { Invoke-Unlock }
    'check'  { Invoke-Check $Nodes }
    'export-report' {
        $outF = if ($Nodes) { $Nodes } else { Join-Path ([Environment]::GetFolderPath('Desktop')) ("claude-env-report-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt') }
        Invoke-Check $outF
    }
    default  { Invoke-Status }
}
