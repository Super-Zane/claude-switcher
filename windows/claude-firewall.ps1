# Claude 切换器 Windows 内核级防直连防火墙管理器 (Windows Defender Firewall / WFP)
# 作用:
#   1. 基于非 TUN 源地址区间 (排除 127.0.0.0/8, 198.18.0.0/15, 172.18.0.0/15) 在内核层 0ms 拦截物理网卡直连
#   2. 覆盖场景: (1) TUN 忘开 (2) VPS 掉线代理回落 DIRECT (3) 手机热点新网卡与 IPv6 (4) 断网与重连毫秒窗口
#   3. 双重防线: 全系统 Anthropic 目标段/IP 物理阻断 + Claude.exe / claude.exe 进程级非隧道公网出站封锁 + STUN UDP 物理阻断
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'enable', 'refresh', 'disable')]
    [string]$Action = 'status',
    [switch]$Resolve,
    [switch]$StrictAppBlock = $true
)

$ErrorActionPreference = 'Stop'
$FW_GROUP = 'ClaudeSwitcher-KillSwitch'
$BASE = Join-Path $env:USERPROFILE '.claude-switcher'
$CACHE_DIR = Join-Path $BASE 'firewall'

# Anthropic 官方专属段 (AS399358)，不误伤正常国内网站与常规 VPS
$STATIC_BLOCKED_V4 = @('160.79.104.0/21')
$STATIC_BLOCKED_V6 = @('2607:6bc0::/48')
$ANTHROPIC_DOMAINS = @('claude.ai', 'api.anthropic.com', 'claudeusercontent.com', 'statsig.anthropic.com', 'claude.com')

# 排除 127.0.0.0/8 (本机回环代理)、172.18.0.0/15 (v2rayN/sing-box TUN)、198.18.0.0/15 (Clash Fake-IP TUN)
# 所有 Wi-Fi / 有线 / iPhone 热点 (172.20.10.x) / Android 热点 (192.168.x.x) 物理接口 IP 均落在此区间内
$NON_TUN_LOCAL_V4 = @(
    '0.0.0.0-126.255.255.255',
    '128.0.0.0-172.17.255.255',
    '172.20.0.0-198.17.255.255',
    '198.20.0.0-255.255.255.255'
)

# 排除 Loopback / RFC1918 私网 / Link-Local 后的公网 IPv4 范围 (用于 Claude 进程级非隧道公网封锁)
$PUBLIC_REMOTE_V4 = @(
    '1.0.0.0-9.255.255.255',
    '11.0.0.0-100.63.255.255',
    '100.128.0.0-126.255.255.255',
    '128.0.0.0-169.253.255.255',
    '169.255.0.0-172.15.255.255',
    '172.32.0.0-192.167.255.255',
    '192.169.0.0-198.17.255.255',
    '198.20.0.0-223.255.255.255'
)

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-IsGlobalIpv4([string]$Ip) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $parsed.GetAddressBytes()
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19)) { return $false }
    if ($b[0] -ge 224) { return $false }
    return $true
}

# 提取本机 v2rayN / Clash Verge 配置中的代理服务器公网 IPv4 作为白名单，防止 CDN 中转节点与目标 IP 重合被误封
function Get-ProxyServerWhitelist {
    $ips = New-Object System.Collections.Generic.HashSet[string]
    $candidates = @(
        "$env:APPDATA\v2rayN\guiConfigs\config.json",
        "$env:APPDATA\v2rayN\guiConfigs\guiNConfig.json",
        "$env:LOCALAPPDATA\v2rayN\guiConfigs\config.json",
        "$env:APPDATA\io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml",
        "$env:LOCALAPPDATA\io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml"
    )
    # 若正在运行的 v2rayN 为绿色便携版，从其进程路径推导同目录 guiConfigs
    try {
        $v2p = Get-Process -Name 'v2rayN' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($v2p -and $v2p.Path) {
            $dir = Split-Path -Parent $v2p.Path
            $candidates += (Join-Path $dir 'guiConfigs\config.json')
            $candidates += (Join-Path $dir 'guiConfigs\guiNConfig.json')
        }
    } catch {}

    foreach ($p in $candidates) {
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        try {
            $raw = Get-Content -LiteralPath $p -Raw -Encoding UTF8 -ErrorAction Stop
            foreach ($m in [regex]::Matches($raw, '(?:"(?:address|server|host)"\s*:\s*"|server:\s*["'']?)(\d{1,3}(?:\.\d{1,3}){3})')) {
                $ip = $m.Groups[1].Value
                if ((Test-IsGlobalIpv4 $ip) -and ($ip -notlike '160.79.104.*') -and ($ip -notlike '160.79.105.*') -and ($ip -notlike '160.79.106.*') -and ($ip -notlike '160.79.107.*') -and ($ip -notlike '160.79.108.*') -and ($ip -notlike '160.79.109.*') -and ($ip -notlike '160.79.110.*') -and ($ip -notlike '160.79.111.*')) {
                    $null = $ips.Add($ip)
                }
            }
        } catch {}
    }
    return @($ips)
}

# 收集本机受保护的 Claude Desktop (含 MSIX) 与 Claude Code CLI 可执行路径
function Get-ProtectedClaudeExecutables {
    $exes = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $staticPaths = @(
        "$env:LOCALAPPDATA\AnthropicClaude\Claude.exe",
        "$env:LOCALAPPDATA\Programs\Claude\Claude.exe",
        "$env:USERPROFILE\.local\bin\claude.exe",
        "$env:LOCALAPPDATA\Programs\claude\claude.exe"
    )
    foreach ($p in $staticPaths) {
        if (Test-Path -LiteralPath $p) { $null = $exes.Add($p) }
    }
    # 探测 MSIX / Appx 安装目录的 Claude.exe
    try {
        $pkg = Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pkg -and $pkg.InstallLocation) {
            $found = Get-ChildItem -LiteralPath $pkg.InstallLocation -Filter 'Claude.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 3
            foreach ($f in $found) { $null = $exes.Add($f.FullName) }
        }
    } catch {}
    # 探测 PATH 中的 claude.exe
    try {
        $cmd = Get-Command 'claude.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) {
            $null = $exes.Add($cmd.Source)
        }
    } catch {}
    # 若正在运行 Claude.exe，收集其真实路径
    try {
        Get-Process -Name 'Claude','claude' -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Path -and (Test-Path -LiteralPath $_.Path)) { $null = $exes.Add($_.Path) }
        }
    } catch {}
    return @($exes)
}

function Resolve-DynamicAnthropicIps {
    $v4 = New-Object System.Collections.Generic.HashSet[string]
    $v6 = New-Object System.Collections.Generic.HashSet[string]
    $wl = Get-ProxyServerWhitelist
    foreach ($d in $ANTHROPIC_DOMAINS) {
        try {
            $records = Resolve-DnsName -Name $d -Type A -ErrorAction SilentlyContinue
            foreach ($r in $records) {
                if ($r.IPAddress -and (Test-IsGlobalIpv4 $r.IPAddress) -and ($wl -notcontains $r.IPAddress)) {
                    $null = $v4.Add($r.IPAddress)
                }
            }
        } catch {}
        try {
            $records6 = Resolve-DnsName -Name $d -Type AAAA -ErrorAction SilentlyContinue
            foreach ($r in $records6) {
                if ($r.IPAddress -and $r.IPAddress -match ':' -and $r.IPAddress -ne '::1') {
                    $null = $v6.Add($r.IPAddress)
                }
            }
        } catch {}
    }
    return [pscustomobject]@{ V4 = @($v4); V6 = @($v6) }
}

function Enable-KillSwitchFirewall([switch]$WithResolve) {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:启用 Windows 防直连防火墙需要管理员权限'
        exit 1
    }
    New-Item -ItemType Directory -Force -Path $CACHE_DIR | Out-Null

    $v4Targets = New-Object System.Collections.Generic.List[string]
    $v6Targets = New-Object System.Collections.Generic.List[string]
    foreach ($c in $STATIC_BLOCKED_V4) { $v4Targets.Add($c) }
    foreach ($c in $STATIC_BLOCKED_V6) { $v6Targets.Add($c) }

    if ($WithResolve) {
        $dyn = Resolve-DynamicAnthropicIps
        foreach ($ip in $dyn.V4) { if (-not $v4Targets.Contains($ip)) { $v4Targets.Add($ip) } }
        foreach ($ip in $dyn.V6) { if (-not $v6Targets.Contains($ip)) { $v6Targets.Add($ip) } }
    }

    # 先幂等清理旧分组规则，再重建
    Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

    # 1. 全系统物理网卡直连 Anthropic 目的 IPv4 封锁 (防忘开TUN / VPS掉线回落DIRECT / 手机热点 / 断网重连窗口)
    New-NetFirewallRule -DisplayName 'ClaudeSwitcher: 阻断物理网卡直连 Anthropic (IPv4)' `
        -Name 'ClaudeSwitcher-Block-Anthropic-V4' `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -LocalAddress $NON_TUN_LOCAL_V4 -RemoteAddress @($v4Targets) | Out-Null

    # 2. 全系统阻断 Anthropic IPv6 出站 (防运营商手机热点强推 IPv6)
    New-NetFirewallRule -DisplayName 'ClaudeSwitcher: 阻断直连 Anthropic (IPv6)' `
        -Name 'ClaudeSwitcher-Block-Anthropic-V6' `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -RemoteAddress @($v6Targets) | Out-Null

    # 3. 阻断非隧道物理网卡的 STUN/TURN UDP 探测端口 (防切网/热点瞬间 WebRTC 泄露)
    New-NetFirewallRule -DisplayName 'ClaudeSwitcher: 阻断物理网卡 STUN UDP (IPv4)' `
        -Name 'ClaudeSwitcher-Block-STUN-UDP-V4' `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -Protocol UDP -RemotePort @('3478', '5349', '19302') -LocalAddress $NON_TUN_LOCAL_V4 | Out-Null

    New-NetFirewallRule -DisplayName 'ClaudeSwitcher: 阻断物理网卡 STUN UDP (IPv6)' `
        -Name 'ClaudeSwitcher-Block-STUN-UDP-V6' `
        -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
        -Protocol UDP -RemotePort @('3478', '5349', '19302') -RemoteAddress '2000::/3' | Out-Null

    # 4. 进程级非隧道公网出站封锁 (即便 Anthropic/Cloudflare 更换 IP，Claude.exe / claude.exe 也无法走物理网卡直连)
    $appCount = 0
    if ($StrictAppBlock) {
        $exes = Get-ProtectedClaudeExecutables
        $idx = 0
        foreach ($exe in $exes) {
            $idx++
            New-NetFirewallRule -DisplayName "ClaudeSwitcher: 禁止进程物理网卡直连公网 #$idx (IPv4)" `
                -Name "ClaudeSwitcher-Block-App-Direct-V4-$idx" `
                -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
                -Program $exe -LocalAddress $NON_TUN_LOCAL_V4 -RemoteAddress $PUBLIC_REMOTE_V4 | Out-Null
            New-NetFirewallRule -DisplayName "ClaudeSwitcher: 禁止进程物理网卡直连公网 #$idx (IPv6)" `
                -Name "ClaudeSwitcher-Block-App-Direct-V6-$idx" `
                -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
                -Program $exe -RemoteAddress '2000::/3' | Out-Null
            $appCount++
        }
    }

    $meta = [ordered]@{
        updatedAt = (Get-Date).ToString('o')
        v4Count   = $v4Targets.Count
        v6Count   = $v6Targets.Count
        appCount  = $appCount
    }
    [System.IO.File]::WriteAllText((Join-Path $CACHE_DIR 'state.json'), ($meta | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))
    Write-Output "OK:Windows 防直连防火墙已启用(IPv4目标=$($v4Targets.Count), 受保护程序=$appCount)"
}

function Disable-KillSwitchFirewall {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:停用 Windows 防直连防火墙需要管理员权限'
        exit 1
    }
    Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $CACHE_DIR 'state.json') -Force -ErrorAction SilentlyContinue
    Write-Output 'OK:Windows 防直连防火墙规则已全部移除'
}

function Get-KillSwitchFirewallStatus {
    $rules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    if ($rules.Count -eq 0) {
        Write-Output 'warn:未启用(建议运行一键修复开启 Windows 防火墙内核防直连)'
        exit 1
    }
    $hasV4 = [bool]($rules | Where-Object { $_.Name -eq 'ClaudeSwitcher-Block-Anthropic-V4' })
    $hasStun = [bool]($rules | Where-Object { $_.Name -eq 'ClaudeSwitcher-Block-STUN-UDP-V4' })
    if (-not $hasV4 -or -not $hasStun) {
        Write-Output "warn:规则不完整(仅 $($rules.Count) 条,建议重新运行一键修复)"
        exit 1
    }
    $appRules = @($rules | Where-Object { $_.Name -like 'ClaudeSwitcher-Block-App-Direct-V4-*' }).Count
    Write-Output "ok:Windows防火墙已生效($($rules.Count)条阻断规则/进程锁定=$appRules)"
    exit 0
}

switch ($Action) {
    'enable'  { Enable-KillSwitchFirewall -WithResolve:$Resolve }
    'refresh' { Enable-KillSwitchFirewall -WithResolve }
    'disable' { Disable-KillSwitchFirewall }
    default   { Get-KillSwitchFirewallStatus }
}
