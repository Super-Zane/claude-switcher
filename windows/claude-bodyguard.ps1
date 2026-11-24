# Claude 保镖 (Windows 事件驱动增强版) —— 代理/TUN/默认路由异常时立即关闭 Claude 桌面版与 Claude Code CLI
# 由安装器注册为计划任务(已解除 72h 时长与电池模式限制),登录自动常驻运行
# 设计原则: 零外发网络探测、无重试退避,依靠 NetworkChange 事件毫秒级感知断网/重连/手机热点切网 + 2 秒兜底巡检
$ErrorActionPreference = 'SilentlyContinue'
$BASE = Join-Path $env:USERPROFILE ".claude-switcher"
$LOG = Join-Path $BASE "bodyguard.log"
New-Item -ItemType Directory -Force -Path $BASE | Out-Null

# 代理模式:优先读脚本同目录,其次读安装器写入的 proxy-mode.txt;缺失时按旧版 Clash Verge 行为
$modeFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "proxy-mode.txt" } else { '' }
if (-not $modeFile -or -not (Test-Path $modeFile)) { $modeFile = Join-Path $BASE "proxy-mode.txt" }
$PROXY_MODE = if (Test-Path $modeFile) { Get-Content $modeFile -Raw } else { '' }
if ($PROXY_MODE) { $PROXY_MODE = $PROXY_MODE.Trim() }
if (-not $PROXY_MODE) { $PROXY_MODE = 'clash-verge' }

function Write-GuardLog([string]$Message) {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message" | Out-File -Append -Encoding utf8 $LOG
}

# TUN 在线 + 默认路由归属判定:
#   1. 兼容 Clash 198.18/198.19 假IP段、v2rayN/sing-box 172.18/172.19 TUN 段及 Up 状态虚拟网卡
#   2. 核验最高优先级 0.0.0.0/0 默认路由是否指向 TUN 网卡(防手机热点 USB/Wi-Fi 抢占默认路由或断网瞬间)
function Get-TunStatus {
    $tunIndices = @()
    $detail = ''

    $fakeIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '198.18.*' -or $_.IPAddress -like '198.19.*' })
    if ($fakeIps.Count -gt 0) {
        $tunIndices += @($fakeIps | ForEach-Object { $_.InterfaceIndex })
        $detail = '198.18 假IP段'
    }
    $v2Ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '172.19.*' -or $_.IPAddress -like '172.18.*' })
    if ($v2Ips.Count -gt 0) {
        $tunIndices += @($v2Ips | ForEach-Object { $_.InterfaceIndex })
        if (-not $detail) { $detail = 'v2rayN/sing-box TUN网段' }
    }
    $nics = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'TAP|TUN|WireGuard|Wintun|VPN|Tailscale|Sing-Box|Mihomo' -or $_.Name -match 'singbox_tun|sing-tun|v2rayN|Mihomo|Meta|utun')
    })
    if ($nics.Count -gt 0) {
        $tunIndices += @($nics | ForEach-Object { $_.ifIndex })
        if (-not $detail) { $detail = '通用虚拟网卡' }
    }

    $tunIndices = @($tunIndices | Select-Object -Unique)
    if ($tunIndices.Count -eq 0) {
        return @{ up = $false; detail = 'TUN网卡不在线' }
    }

    # 默认路由核验: 断网时无 0.0.0.0/0 路由; 切到手机热点时物理接口可能抢占最低 Metric
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue)
    if ($routes.Count -eq 0) {
        return @{ up = $false; detail = '网络断开(无默认路由)' }
    }
    $best = $routes | Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric } | Select-Object -First 1
    if ($best -and ($tunIndices -notcontains $best.InterfaceIndex)) {
        return @{ up = $false; detail = "默认路由被物理网卡($($best.InterfaceAlias))抢占" }
    }
    return @{ up = $true; detail = $detail }
}

# 客户端进程/服务在线判定:auto 与 other 只依赖 TUN,不要求特定进程(避免误杀)
function Test-ClientAlive {
    switch ($PROXY_MODE) {
        'clash-verge' { return [bool](Get-Process -Name 'verge-mihomo' -ErrorAction SilentlyContinue) }
        'flclash'     { return [bool](Get-Process -Name 'FlClashCore','FlClash' -ErrorAction SilentlyContinue) }
        'v2rayn'      { return [bool](Get-Process -Name 'v2rayN','xray','v2ray','sing-box','mihomo' -ErrorAction SilentlyContinue) }
        'sing-box'    { return [bool](Get-Process -Name 'sing-box' -ErrorAction SilentlyContinue) }
        'clashx'      { return [bool](Get-Process -Name 'ClashX' -ErrorAction SilentlyContinue) }
        'surge'       { return [bool](Get-Process -Name 'Surge' -ErrorAction SilentlyContinue) }
        'wireguard'   { return [bool](Get-Service -Name 'WireGuardTunnel*' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running') }
        'auto'        { return $true }
        'other'       { return $true }
        default       { return [bool](Get-Process -Name 'verge-mihomo' -ErrorAction SilentlyContinue) }
    }
}

# 终止 Claude 桌面版以及当前用户的 Claude Code CLI 进程 (native claude.exe 及 npm/bun 的 @anthropic-ai/claude-code)
function Stop-ProtectedClaudeProcesses([string]$Reason) {
    $desktop = Get-Process -Name 'Claude' -ErrorAction SilentlyContinue
    if ($desktop) {
        $desktop | Stop-Process -Force
        Write-GuardLog "${Reason},已自动关闭 Claude 桌面版"
    }

    $cliIds = @()
    try {
        $curSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $nativeCli = Get-Process -Name 'claude' -ErrorAction SilentlyContinue
        foreach ($proc in $nativeCli) { $cliIds += $proc.Id }
        $nodeProcs = Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='bun.exe'" -ErrorAction SilentlyContinue
        foreach ($np in $nodeProcs) {
            if ($np.CommandLine -and ($np.CommandLine -match '@anthropic-ai[/\\]claude-code[/\\](bin[/\\]claude(\.exe)?|cli\.js)')) {
                $ownerSid = $null
                try {
                    $sidObj = Invoke-CimMethod -InputObject $np -MethodName GetOwnerSid -ErrorAction SilentlyContinue
                    if ($sidObj) { $ownerSid = $sidObj.Sid }
                } catch {}
                if (-not $ownerSid -or $ownerSid -eq $curSid) {
                    $cliIds += [int]$np.ProcessId
                }
            }
        }
    } catch {}

    $cliIds = @($cliIds | Select-Object -Unique)
    if ($cliIds.Count -gt 0) {
        foreach ($cid in $cliIds) {
            Stop-Process -Id $cid -Force -ErrorAction SilentlyContinue
        }
        Write-GuardLog "${Reason},已自动关闭 Claude Code CLI (PID=$($cliIds -join ','))"
    }
}

# 注册 .NET 网络地址与可用性事件: 断网那一刻、重连那一刻、插入手机热点那一刻毫秒级唤醒主循环
$netAddrSub = $null
$netAvailSub = $null
try {
    $netAddrSub = Register-ObjectEvent -InputObject ([System.Net.NetworkInformation.NetworkChange]) -EventName 'NetworkAddressChanged' -SourceIdentifier 'ClaudeBgNetAddr' -ErrorAction SilentlyContinue
    $netAvailSub = Register-ObjectEvent -InputObject ([System.Net.NetworkInformation.NetworkChange]) -EventName 'NetworkAvailabilityChanged' -SourceIdentifier 'ClaudeBgNetAvail' -ErrorAction SilentlyContinue
} catch {}

Write-GuardLog "保镖已启动(模式=$PROXY_MODE, 事件驱动=NetworkChange, 兜底轮询=2s)"

$offline = $false
$stableStreak = 2

try {
    while ($true) {
        if (Test-Path $modeFile) {
            $currentMode = (Get-Content $modeFile -Raw).Trim()
            if ($currentMode) { $script:PROXY_MODE = $currentMode }
        }
        $tun = Get-TunStatus
        $clientUp = Test-ClientAlive
        $alive = $tun.up -and $clientUp

        if (-not $alive) {
            $stableStreak = 0
            $clientState = if ($PROXY_MODE -eq 'auto' -or $PROXY_MODE -eq 'other') { '跳过(仅TUN)' } elseif ($clientUp) { '在线' } else { '离线' }
            $reason = "代理离线(模式=$PROXY_MODE, TUN=$($tun.detail), 客户端=$clientState)"
            if (-not $offline) {
                Write-GuardLog $reason
                $offline = $true
            }
            Stop-ProtectedClaudeProcesses $reason
        } else {
            if ($offline) {
                $stableStreak++
                if ($stableStreak -lt 2) {
                    # 重连冷却窗口: 刚重连但尚未连续 2 轮稳定,防止 Claude 抢跑
                    Stop-ProtectedClaudeProcesses '网络重连冷却期(等待TUN路由稳定)'
                } else {
                    $offline = $false
                    Write-GuardLog "隧道与默认路由已恢复稳定(TUN=$($tun.detail)),解除急停锁定"
                }
            }
        }

        # 毫秒级响应网络变更事件,无事件时 2 秒自动兜底巡检
        $ev = Wait-Event -Timeout 2 -ErrorAction SilentlyContinue
        if ($ev) {
            Get-Event -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
            if (-not [System.Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()) {
                $offline = $true
                $stableStreak = 0
                Stop-ProtectedClaudeProcesses '检测到网络断开事件(NetworkChange)'
            }
        }
    }
} finally {
    if ($netAddrSub) { Unregister-Event -SourceIdentifier 'ClaudeBgNetAddr' -ErrorAction SilentlyContinue }
    if ($netAvailSub) { Unregister-Event -SourceIdentifier 'ClaudeBgNetAvail' -ErrorAction SilentlyContinue }
}
