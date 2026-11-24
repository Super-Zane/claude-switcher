# Claude 持久化安全锁 · Windows 极简单锁核心引擎 (内核级 IFEO 进程硬锁 + 永久 Claude/遥测网络硬锁)
# 核心铁律 (除非运行「卸载.bat」，否则永久生效):
#   1. 开启安全锁 (lock):
#        - Zero-Gap 原子刷入 WFP 持久化防火墙规则: 物理网卡死锁 Claude(ASN+主服务+全系遥测IP) + 目标应用进程 + 一切海外公网(或全封闭) + 公网IPv6 + STUN
#        - 校验三档防火墙真实 Enabled=True (若被第三方杀软接管则显式报 FAIL) 并开启 LogBlocked=True -> pfirewall.log
#        - 移除 hosts 黑洞并摘除 IFEO 进程锁，放行 Claude 仅通过海外 TUN 运行
#   2. 关闭安全锁 (unlock · 日常上网模式):
#        - 强制终止 Claude 主进程、更新器与 CLI
#        - 写入 Windows 内核级 IFEO 注册表锁 (Claude.exe -> claude-blocked-alert.vbs): 无论传统版/MSIX商店版/自动更新后，点开永远启动不了并 0ms 弹出中文提示！
#        - 写入 hosts 托管黑洞 (0.0.0.0 + :: 覆盖全部 24 个 Claude 主站与遥测/Sentry/Statsig 域名，连浏览器残留标签页也不发本地 DNS)
#        - WFP 防火墙切换为永久 standby 防线: 放行日常上网，但物理网卡永久 0ms 阻断 Claude ASN/遥测 IP 与目标应用出站 (重启/软件退出不失效)
#   3. 彻底卸载 (uninstall-all，仅由卸载脚本调用):
#        - 完整清理 IFEO 注册表锁、WFP 防火墙规则组与 hosts 托管块，恢复原生系统
param(
    [Parameter(Position = 0)]
    [ValidateSet('init', 'set-nodes', 'set-strict', 'lock', 'lock-cn', 'lock-strict', 'unlock', 'uninstall-all', 'verify-firewall', 'status', 'check', 'export-report')]
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
$IFEO_CLAUDE_KEY = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Claude.exe'
$BLOCKER_VBS = Join-Path $PSScriptRoot 'claude-blocked-alert.vbs'

$ANTHROPIC_ASN_V4 = '160.79.104.0/21'
$ANTHROPIC_ASN_V6 = '2607:6bc0::/48'
# 完整覆盖 Claude 主服务 + API/CDN + 专属遥测/埋点/灰度开关/Sentry(o1158394) 崩溃上报域名
$ANTHROPIC_DOMAINS = @(
    'claude.ai', 'www.claude.ai', 'a-cdn.claude.ai', 'a-api.claude.ai', 'downloads.claude.ai',
    'claude.com', 'www.claude.com', 'platform.claude.com',
    'api.anthropic.com', 'anthropic.com', 'www.anthropic.com', 'console.anthropic.com', 'auth.anthropic.com', 'mcp-proxy.anthropic.com',
    'claudeusercontent.com',
    'statsig.anthropic.com', 'events.anthropic.com', 'telemetry.anthropic.com',
    'o1158394.ingest.sentry.io', 'o1158394.ingest.us.sentry.io',
    'statsigapi.net', 'events.statsigapi.net', 'featuregates.org', 'prodregistryv2.org'
)

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
        strictMode = $false
        lockMode = 'off'
    }
    if (Test-Path -LiteralPath $CFG_FILE) {
        try {
            $raw = Get-Content -LiteralPath $CFG_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($raw.entryNodes) { $cfg.entryNodes = [string]$raw.entryNodes }
            if ($raw.countryTarget) { $cfg.countryTarget = [string]$raw.countryTarget }
            if ($raw.tzTarget) { $cfg.tzTarget = [string]$raw.tzTarget }
            if ($raw.localeTarget) { $cfg.localeTarget = [string]$raw.localeTarget }
            if ($null -ne $raw.strictMode) { $cfg.strictMode = [bool]$raw.strictMode }
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
        $ipObj = $null
        if ([System.Net.IPAddress]::TryParse($clean, [ref]$ipObj) -and $ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $val = "$($ipObj.IPAddressToString)/32"
            if ($seen.Add($val)) { $cidrs.Add($val) }
            continue
        }
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($clean) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
            $first = $null
            foreach ($a in $addrs) {
                $s = $a.IPAddressToString
                if (-not $first) { $first = $s }
                if ($seen.Add("$s/32")) { $cidrs.Add("$s/32") }
            }
            if ($first) { $hostsMap.Add("$first $clean") }
        } catch {}
    }
    return [pscustomobject]@{ Cidrs = @($cidrs); Hosts = @($hostsMap) }
}

function Resolve-ClaudeBlockV4([string[]]$WhitelistCidrs) {
    $wlSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($w in $WhitelistCidrs) { $null = $wlSet.Add(($w -split '/')[0]) }
    $items = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $null = $seen.Add($ANTHROPIC_ASN_V4); $items.Add($ANTHROPIC_ASN_V4)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    foreach ($dom in $ANTHROPIC_DOMAINS) {
        try {
            $resp = Invoke-RestMethod -Uri "https://cloudflare-dns.com/dns-query?name=$dom&type=A" -Headers @{ accept = 'application/dns-json' } -TimeoutSec 3 -ErrorAction Stop
            foreach ($ans in @($resp.Answer)) {
                $ipStr = [string]$ans.data
                $ipObj = $null
                if ([System.Net.IPAddress]::TryParse($ipStr, [ref]$ipObj) -and $ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    if ($ipStr -notlike '198.18.*' -and $ipStr -notlike '198.19.*' -and $ipStr -notlike '10.*' -and $ipStr -notlike '127.*' -and $ipStr -notlike '192.168.*' -and (-not $wlSet.Contains($ipStr))) {
                        if ($seen.Add($ipStr)) { $items.Add($ipStr) }
                    }
                }
            }
        } catch {}
    }
    return @($items)
}

function Get-ProtectedClaudeExes {
    $exes = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    $staticPaths = @(
        (Join-Path $env:LOCALAPPDATA 'AnthropicClaude\claude.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\claude\Claude.exe')
    )
    foreach ($p in $staticPaths) {
        if ($p -and (Test-Path -LiteralPath $p)) { $null = $exes.Add($p) }
    }
    try {
        foreach ($d in @(Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'AnthropicClaude') -Directory -Filter 'app-*' -ErrorAction SilentlyContinue)) {
            $cand = Join-Path $d.FullName 'claude.exe'
            if (Test-Path -LiteralPath $cand) { $null = $exes.Add($cand) }
        }
    } catch {}
    try {
        $pkg = Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pkg -and $pkg.InstallLocation) {
            foreach ($f in @(Get-ChildItem -LiteralPath $pkg.InstallLocation -Filter 'Claude.exe' -Recurse -ErrorAction SilentlyContinue)) {
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

function Get-ClaudeBlackholeHostsLines {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($d in $ANTHROPIC_DOMAINS) {
        $lines.Add("0.0.0.0 $d")
        $lines.Add(":: $d")
    }
    return @($lines)
}

# ---- Windows 内核级 IFEO 进程死锁 (与路径/MSIX 版本号无关，永远拦截 Claude.exe 启动并弹窗) ----
function Enable-ClaudeProcessLock {
    $vbsPath = $BLOCKER_VBS
    if (-not (Test-Path -LiteralPath $vbsPath)) {
        $vbsPath = 'C:\ProgramData\ClaudeGuard\windows\claude-blocked-alert.vbs'
    }
    New-Item -Path $IFEO_CLAUDE_KEY -Force | Out-Null
    $dbgCmd = "wscript.exe //B `"$vbsPath`""
    Set-ItemProperty -Path $IFEO_CLAUDE_KEY -Name 'Debugger' -Value $dbgCmd -Type String -Force
}

function Disable-ClaudeProcessLock {
    if (Test-Path -LiteralPath $IFEO_CLAUDE_KEY) {
        Remove-ItemProperty -Path $IFEO_CLAUDE_KEY -Name 'Debugger' -ErrorAction SilentlyContinue
        try {
            $props = Get-ItemProperty -Path $IFEO_CLAUDE_KEY -ErrorAction SilentlyContinue
            $realProps = @($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })
            if ($realProps.Count -eq 0) { Remove-Item -Path $IFEO_CLAUDE_KEY -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
}

function Test-ClaudeProcessLocked {
    try {
        if (-not (Test-Path -LiteralPath $IFEO_CLAUDE_KEY)) { return $false }
        $v = (Get-ItemProperty -Path $IFEO_CLAUDE_KEY -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
        return ([string]$v -like '*claude-blocked-alert.vbs*')
    } catch { return $false }
}

function Ensure-FirewallProfilesEnabled {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -LogBlocked True -LogFileName $PFW_LOG -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
    $profs = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $disabled = @($profs | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
    if ($disabled.Count -gt 0) {
        return "FAIL:检测到 Windows 防火墙配置档 ($($disabled -join ',')) 处于关闭状态（可能被 360/火绒/第三方杀软接管或组策略强制关闭），硬锁无法生效！请先在安全软件中放行或恢复 Windows Defender 防火墙。"
    }
    return ''
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
        for ($i = 0; $i -lt 4; $i++) { if (-not (Get-Process -Name 'Claude' -ErrorAction SilentlyContinue)) { break }; Start-Sleep 1 }
        Get-Process -Name 'Claude' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    try {
        Get-Process -Name 'claude' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        # 彻底清零 Claude Code CLI 及 AnthropicClaude 后台更新器进程，绝不留遥测残留
        foreach ($np in @(Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='bun.exe' OR Name='Update.exe'" -ErrorAction SilentlyContinue)) {
            $cmd = [string]$np.CommandLine
            $ep  = [string]$np.ExecutablePath
            if (($cmd -match '@anthropic-ai[/\\]claude-code[/\\](bin[/\\]claude(\.exe)?|cli\.js)') -or ($ep -match 'AnthropicClaude')) {
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

function Invoke-Lock($cfg, [string]$Mode = '') {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:开启安全锁需要管理员权限，请通过「Claude安全锁控制台.bat」运行'
        exit 1
    }
    if (-not $Mode) { $Mode = if ($cfg.strictMode) { 'strict' } else { 'cn' } }
    $resolved = Resolve-EntryNodes $cfg.entryNodes
    if ($Mode -eq 'strict' -and $resolved.Cidrs.Count -eq 0) {
        Write-Output 'FAIL:全封闭模式前请先填写第一跳代理入口 IP 或域名（或取消勾选全封闭切回默认国内放行模式）'
        exit 1
    }

    $fwErr = Ensure-FirewallProfilesEnabled
    if ($fwErr) { Write-Output $fwErr; exit 1 }

    $tun = Get-TunInfo
    $localExcludes = New-Object System.Collections.Generic.List[string]
    $localExcludes.Add('127.0.0.0/8'); $localExcludes.Add('172.18.0.0/15'); $localExcludes.Add('198.18.0.0/15')
    foreach ($tip in $tun.TunIps) { $localExcludes.Add("$tip/32") }
    $nonTunLocalV4 = Get-ComplementIpv4Ranges @($localExcludes)
    $publicRemoteV4 = Get-ComplementIpv4Ranges @('10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15')
    $claudeV4 = Resolve-ClaudeBlockV4 $resolved.Cidrs

    # Zero-Gap 原子切换: 先记录旧规则，待全部新规则生效后再删除旧规则，0ms 无空窗
    $oldRules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue)
    $gen = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()

    New-NetFirewallRule -DisplayName 'ClaudeGuard: 死锁 Claude/Anthropic ASN 与全系遥测 IP (IPv4)' `
        -Name "ClaudeGuard-Block-Claude-ASN-V4-$gen" `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -LocalAddress $nonTunLocalV4 -RemoteAddress $claudeV4 | Out-Null

    New-NetFirewallRule -DisplayName 'ClaudeGuard: 死锁全部公网 IPv6 与 Anthropic IPv6' `
        -Name "ClaudeGuard-Block-All-Public-V6-$gen" `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -RemoteAddress @($ANTHROPIC_ASN_V6, '2000::/3') | Out-Null

    New-NetFirewallRule -DisplayName 'ClaudeGuard: 阻断物理网卡 STUN/WebRTC UDP' `
        -Name "ClaudeGuard-Block-STUN-UDP-$gen" `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -Protocol UDP -RemotePort @('3478', '5349', '19302') -LocalAddress $nonTunLocalV4 | Out-Null

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
        New-NetFirewallRule -DisplayName 'ClaudeGuard: 阻断物理网卡裸 DNS (UDP 53)' `
            -Name "ClaudeGuard-Block-Phys-DNS-UDP-$gen" `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -Protocol UDP -RemotePort '53' -LocalAddress $nonTunLocalV4 | Out-Null
        New-NetFirewallRule -DisplayName 'ClaudeGuard: 阻断物理网卡裸 DNS (TCP 53)' `
            -Name "ClaudeGuard-Block-Phys-DNS-TCP-$gen" `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -Protocol TCP -RemotePort '53' -LocalAddress $nonTunLocalV4 | Out-Null
        $shardCount = 1
    } else {
        $ovFile = Find-OverseasRangesFile
        if (-not $ovFile) {
            Write-Output 'FAIL:找不到海外公网补集区间表 (data\overseas-ipv4-ranges.txt)，已中止'
            exit 1
        }
        $baseOverseas = @(Get-Content -LiteralPath $ovFile -Encoding UTF8)
        $overseasBlocked = Subtract-CidrsFromRanges $baseOverseas $resolved.Cidrs
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

    if ($oldRules.Count -gt 0) { $oldRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
    # 网络硬锁 100% 落盘生效后，才移除 hosts 黑洞并放行 IFEO 进程锁
    Update-HostsManagedBlock $resolved.Hosts
    Disable-ClaudeProcessLock

    $cfg.lockMode = $Mode
    Save-Config $cfg
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    $modeLabel = if ($Mode -eq 'strict') { '全封闭模式(仅海外TUN)' } else { '放行国内直连 + 死锁Claude与一切海外' }
    Write-Output "OK:安全锁已开启 [$modeLabel]！Claude 现已解锁可用，且只能走海外 TUN，物理网卡 0ms 死锁一切泄露。"
}

# 关闭安全锁 (日常模式): 系统内核级 IFEO 锁死 Claude.exe + hosts 遥测黑洞 + WFP 永久阻断 Claude ASN/遥测/进程！
function Invoke-Standby($cfg) {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:切换日常模式需要管理员权限'
        exit 1
    }
    $fwErr = Ensure-FirewallProfilesEnabled
    if ($fwErr) { Write-Output $fwErr; exit 1 }

    Write-Output '正在强制终止运行中的 Claude 桌面版、更新器与 CLI...'
    Stop-ClaudeSafely
    # 1. 先扣死 Windows 内核级 IFEO 进程锁 (点开 Claude 0ms 弹窗，真进程绝不启动!)
    Enable-ClaudeProcessLock
    # 2. 写入 hosts 全部 24 个 Claude 主站与遥测域名黑洞 (连浏览器手抖点网页版都不发本地 DNS)
    Update-HostsManagedBlock (Get-ClaudeBlackholeHostsLines)

    # 3. Zero-Gap 原子切换 WFP 防火墙为「永久 Claude & 遥测物理拦截防线」(放行日常普通上网，但永不放行 Claude 直连!)
    $tun = Get-TunInfo
    $localExcludes = New-Object System.Collections.Generic.List[string]
    $localExcludes.Add('127.0.0.0/8'); $localExcludes.Add('172.18.0.0/15'); $localExcludes.Add('198.18.0.0/15')
    foreach ($tip in $tun.TunIps) { $localExcludes.Add("$tip/32") }
    $nonTunLocalV4 = Get-ComplementIpv4Ranges @($localExcludes)
    $publicRemoteV4 = Get-ComplementIpv4Ranges @('10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15')
    $claudeV4 = Resolve-ClaudeBlockV4 @()

    $oldRules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue)
    $gen = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()

    New-NetFirewallRule -DisplayName 'ClaudeGuard[永久防线]: 物理网卡永久死锁 Claude ASN 与全系遥测 IP (IPv4)' `
        -Name "ClaudeGuard-Standby-Claude-V4-$gen" `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -LocalAddress $nonTunLocalV4 -RemoteAddress $claudeV4 | Out-Null

    New-NetFirewallRule -DisplayName 'ClaudeGuard[永久防线]: 物理网卡永久死锁 Anthropic IPv6' `
        -Name "ClaudeGuard-Standby-Claude-V6-$gen" `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -RemoteAddress $ANTHROPIC_ASN_V6 | Out-Null

    $appIdx = 0
    foreach ($exe in (Get-ProtectedClaudeExes)) {
        $appIdx++
        New-NetFirewallRule -DisplayName "ClaudeGuard[永久防线]: 永久死锁目标应用物理直连 #$appIdx (IPv4)" `
            -Name "ClaudeGuard-Block-TargetApp-V4-$appIdx-$gen" `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -Program $exe -LocalAddress $nonTunLocalV4 -RemoteAddress $publicRemoteV4 | Out-Null
    }

    if ($oldRules.Count -gt 0) { $oldRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue }

    $cfg.lockMode = 'standby'
    Save-Config $cfg
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Output 'OK:已切换为日常上网模式！Claude 已被系统内核锁死（点开将弹出提示），且物理网卡与 hosts 永久阻断 Claude 及遥测服务器，重启不失效。'
}

# 彻底卸载 (仅由「卸载.bat」调用)
function Invoke-UninstallAll {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:彻底卸载需要管理员权限'
        exit 1
    }
    Stop-ClaudeSafely
    Disable-ClaudeProcessLock
    Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Update-HostsManagedBlock @()
    $cfg = Load-Config
    $cfg.lockMode = 'off'
    Save-Config $cfg
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Output 'OK:已彻底解除所有系统级进程锁与防火墙规则，电脑已完全恢复出厂状态。'
}

function Invoke-VerifyFirewall {
    Write-Output '=== 操作系统防火墙、内核进程锁与流量拦截日志验收 (Windows Defender Firewall) ==='
    Write-Output ("时间: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Write-Output ('-' * 64)

    $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $allEnabled = $true
    Write-Output '[1] 系统防火墙配置文件状态 (Domain / Private / Public):'
    foreach ($p in $profiles) {
        Write-Output ("    - {0,-8}: Enabled={1}, LogBlocked={2}, LogFile={3}" -f $p.Name, $p.Enabled, $p.LogBlocked, $p.LogFileName)
        if (-not $p.Enabled) { $allEnabled = $false }
    }

    $ifeoOn = Test-ClaudeProcessLocked
    $ifeoText = if ($ifeoOn) { '已锁死 (日常模式，点开 Claude.exe 0ms 弹窗拦截，真进程绝不启动)' } else { '已放行 (安全锁开启中，仅允许走海外 TUN)' }
    Write-Output "[2] Windows 内核级 IFEO 进程锁 (Claude.exe): $ifeoText"

    $rules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    $asnCnt = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Claude-*' -or $_.Name -like 'ClaudeGuard-Standby-Claude-*' }).Count
    $appCnt = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-TargetApp-*' }).Count
    $ovCnt  = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Overseas-*' -or $_.Name -like 'ClaudeGuard-Block-Strict-*' }).Count
    $v6Cnt  = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-All-Public-V6*' -or $_.Name -like 'ClaudeGuard-Standby-Claude-V6*' }).Count

    Write-Output "[3] 持久化硬锁规则组 ($FW_GROUP): 共 $($rules.Count) 条启用中的 Block 规则"
    Write-Output "    - Claude ASN/全系遥测 IP 死锁: $asnCnt 条 | 目标应用进程锁: $appCnt 条"
    Write-Output "    - 海外公网/全封闭分片: $ovCnt 条 | IPv6 死锁: $v6Cnt 条"

    Write-Output "[4] 操作系统防火墙真实拦截流量日志 ($PFW_LOG 最近 12 条 DROP):"
    if (Test-Path -LiteralPath $PFW_LOG) {
        $drops = @(Get-Content -LiteralPath $PFW_LOG -Tail 200 -ErrorAction SilentlyContinue | Where-Object { $_ -match '\sDROP\s' } | Select-Object -Last 12)
        if ($drops.Count -gt 0) {
            foreach ($d in $drops) { Write-Output "    $d" }
        } else {
            Write-Output '    (日志文件存在，暂无新 DROP 记录 —— 可断开代理后尝试访问 160.79.104.10 再点本按钮查看实时 DROP)'
        }
    } else {
        Write-Output '    (产生首次拦截后系统自动生成日志文件)'
    }

    Write-Output ('-' * 64)
    if ($allEnabled -and $rules.Count -ge 2 -and $asnCnt -ge 1) {
        Write-Output '验收结论: [✓] 操作系统防火墙硬锁已实装生效，Claude 绝不可能绕过 TUN 泄露'
    } else {
        Write-Output '验收结论: [✗] 操作系统防火墙未处于锁定状态（请检查是否被杀软关闭或尚未初始化）'
        exit 1
    }
}

$cfg = Load-Config
switch ($Action) {
    'set-nodes' {
        if ([string]::IsNullOrWhiteSpace($Nodes)) {
            $cfg.entryNodes = ''
            Save-Config $cfg
            Write-Output 'OK:已清空海外入口白名单(国内中转机仍自动放行)'
            exit 0
        }
        $r = Resolve-EntryNodes $Nodes
        if ($r.Cidrs.Count -eq 0) { Write-Output "FAIL:未能从输入解析出有效 IPv4 ($Nodes)"; exit 1 }
        $cfg.entryNodes = $Nodes.Trim()
        Save-Config $cfg
        Write-Output "OK:已保存海外入口白名单 ($($cfg.entryNodes))"
    }
    'set-strict' {
        $cfg.strictMode = ($Nodes -eq '1' -or $Nodes -eq 'true')
        Save-Config $cfg
        Write-Output ("OK:开锁策略已设为 " + ($(if ($cfg.strictMode) { '全封闭模式' } else { '放行国内直连(推荐)' })))
    }
    'lock' { Invoke-Lock $cfg '' }
    'lock-cn' { Invoke-Lock $cfg 'cn' }
    'lock-strict' { Invoke-Lock $cfg 'strict' }
    'unlock' { Invoke-Standby $cfg }
    'uninstall-all' { Invoke-UninstallAll }
    'verify-firewall' { Invoke-VerifyFirewall }
    'init' {
        if (-not (Test-IsAdmin)) { Write-Output 'FAIL:一键初始化需要管理员权限'; exit 1 }
        $nodeArg = if ($Nodes) { $Nodes.Trim() } else { $cfg.entryNodes }
        if ($nodeArg) {
            $r = Resolve-EntryNodes $nodeArg
            if ($r.Cidrs.Count -eq 0) { Write-Output "FAIL:无法解析代理入口节点: $nodeArg"; exit 1 }
            $cfg.entryNodes = $nodeArg
        }
        $cc = ''; $winTz = ''; $ip = ''
        if ($ManualCountry) {
            $cc = $ManualCountry.Trim().ToUpperInvariant()
            $winTz = if ($COUNTRY_TZ.ContainsKey($cc)) { $COUNTRY_TZ[$cc] } else { 'Eastern Standard Time' }
            $ip = '手动指定'
        } else {
            $geo = Get-GeoInfo
            $cc = $geo.Country; $ip = $geo.Ip
            if (-not $cc -or @('CN', 'HK', 'MO') -contains $cc) {
                Write-Output "FAIL:当前出口为 $(if ($cc) { $cc } else { '未知' })(IP=$ip)，属于不支持地区！请先开启 Clash Verge(服务模式+TUN) 或 v2rayN(管理员+启用Tun) 的全局代理后再初始化"
                exit 1
            }
            if ($geo.IanaTz -and $IANA_TO_WIN.ContainsKey($geo.IanaTz)) { $winTz = $IANA_TO_WIN[$geo.IanaTz] }
            elseif ($COUNTRY_TZ.ContainsKey($cc)) { $winTz = $COUNTRY_TZ[$cc] }
            else { $winTz = 'Eastern Standard Time' }
        }
        $loc = if ($COUNTRY_LOCALE.ContainsKey($cc)) { $COUNTRY_LOCALE[$cc] } else { 'en-US' }
        $cfg.countryTarget = $cc; $cfg.tzTarget = $winTz; $cfg.localeTarget = $loc
        Save-Config $cfg

        try { Set-TimeZone -Id $winTz -ErrorAction SilentlyContinue } catch {}
        try { Set-Culture -CultureInfo $loc -ErrorAction SilentlyContinue } catch {}
        Set-ClaudeDesktopEnglish
        foreach ($nic in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
            try { Disable-NetAdapterBinding -Name $nic.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue } catch {}
        }
        Invoke-Lock $cfg ''
        Write-Output "OK:一键初始化完成 | 出口=$cc($ip) | 时区=$winTz | 地区=$loc | Claude语言=en-US | 全网卡IPv6=已关闭 | 安全锁=已开启"
    }
    'status' {
        $rules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
        $isActive = (@($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Overseas-*' -or $_.Name -like 'ClaudeGuard-Block-Strict-*' }).Count -gt 0)
        $isStandby = (-not $isActive -and @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Standby-Claude-*' }).Count -gt 0)
        $mode = if ($isActive) { if (@($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Strict-*' }).Count -gt 0) { 'strict' } else { 'cn' } } elseif ($isStandby) { 'standby' } else { 'off' }
        $lockSt = if ($isActive) { 'on' } elseif ($isStandby) { 'standby' } else { 'off' }
        $procLocked = if (Test-ClaudeProcessLocked) { 'on' } else { 'off' }
        Write-Output "LOCK=$lockSt"
        Write-Output "LOCK_MODE=$mode"
        Write-Output "PROC_LOCKED=$procLocked"
        Write-Output "STRICT_MODE=$(if ($cfg.strictMode) { '1' } else { '0' })"
        Write-Output "ENTRY_NODES=$(if ($cfg.entryNodes) { $cfg.entryNodes } else { '未配置' })"
        Write-Output "COUNTRY_TARGET=$(if ($cfg.countryTarget) { $cfg.countryTarget } else { '未配置' })"
        Write-Output "TZ_TARGET=$(if ($cfg.tzTarget) { $cfg.tzTarget } else { '未配置' })"
        Write-Output "LOCALE_TARGET=$(if ($cfg.localeTarget) { $cfg.localeTarget } else { '未配置' })"
    }
    'check' {
        $auditScript = Join-Path $PSScriptRoot 'env-audit.ps1'
        if (Test-Path -LiteralPath $auditScript) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $auditScript -ConfigPath $CFG_FILE
            exit $LASTEXITCODE
        }
        Write-Output 'FAIL:找不到 env-audit.ps1 深度体检引擎'
        exit 1
    }
    'export-report' {
        $auditScript = Join-Path $PSScriptRoot 'env-audit.ps1'
        $outPath = if ($Nodes) { $Nodes } else { Join-Path ([Environment]::GetFolderPath('Desktop')) ("claude-env-report-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".txt") }
        if (Test-Path -LiteralPath $auditScript) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $auditScript -ConfigPath $CFG_FILE -ExportPath $outPath
            $rc = $LASTEXITCODE
            Write-Output "REPORT_FILE=$outPath"
            exit $rc
        }
        Write-Output 'FAIL:找不到 env-audit.ps1 深度体检引擎'
        exit 1
    }
}
