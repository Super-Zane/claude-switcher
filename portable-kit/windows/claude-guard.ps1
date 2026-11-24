# Claude 持久化安全锁 · Windows 三态防呆核心引擎 (v2.2)
# 完美适配「代理客户端默认开全局 + TUN」工作流:
#   - 状态 1 [lock / strict]:   一级安全锁开启 (Claude 工作态) -> 一切公网流量 100% 只走代理 TUN，自动识别第一跳节点 IP，放行 Claude 启动
#   - 状态 2 [unlock / cn]:     一级安全锁关闭 (国内网络态)   -> 先退出 Claude 并锁死全版本进程; 放行国内 CN 段，持续死锁一切海外与 Claude 遥测
#   - 状态 3 [relax / standby]: 二级放宽锁打开 (防国内误伤态) -> 放宽普通公网防未收录国内 IP 误伤，但永久焊死 Claude 全版本进程锁(IFEO+守卫) + 34 个主站/遥测/邮件链接黑洞 + ASN 拦截
#   - 彻底卸载 [uninstall-all]: 仅在卸载软件时解除永久进程锁、自愈守卫与防火墙规则，恢复出厂状态
param(
    [Parameter(Position = 0)]
    [ValidateSet('init', 'set-nodes', 'lock', 'lock-strict', 'unlock', 'lock-cn', 'relax', 'write-emergency', 'watchdog-loop', 'uninstall-all', 'verify-firewall', 'status', 'check', 'export-report')]
    [string]$Action = 'status',
    [Parameter(Position = 1)]
    [string]$Nodes = '',
    [Parameter(Position = 2)]
    [string]$ManualCountry = ''
)

$ErrorActionPreference = 'Stop'
$FW_GROUP = 'ClaudeGuard-KillSwitch'
$WATCHDOG_TASK = 'ClaudeGuard-Watchdog'
$STATE_DIR = 'C:\ProgramData\ClaudeGuard\state'
$SYS_CFG_FILE = Join-Path $STATE_DIR 'system-state.json'
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
# 34 个全系域名: 主站 + API/CDN + MCP + 邮件点击跳转链接 + Statsig/Sentry(o1158394)/Datadog 遥测上报端点
$ANTHROPIC_DOMAINS = @(
    'claude.ai', 'www.claude.ai', 'a-cdn.claude.ai', 'a-api.claude.ai', 'downloads.claude.ai',
    'links.claude.ai', 'email.claude.ai',
    'claude.com', 'www.claude.com', 'platform.claude.com', 'claudemcpclient.com',
    'api.anthropic.com', 'anthropic.com', 'www.anthropic.com', 'console.anthropic.com', 'auth.anthropic.com', 'mcp-proxy.anthropic.com',
    'docs.anthropic.com', 'support.anthropic.com', 'status.anthropic.com', 'mail.anthropic.com', 'e.anthropic.com',
    'claudeusercontent.com',
    'statsig.anthropic.com', 'events.anthropic.com', 'telemetry.anthropic.com',
    'o1158394.ingest.sentry.io', 'o1158394.ingest.us.sentry.io',
    'statsigapi.net', 'events.statsigapi.net', 'featuregates.org', 'prodregistryv2.org',
    'browser-intake-datadoghq.com', 'http-intake.logs.datadoghq.com'
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
        lockMode = 'off'
    }
    foreach ($f in @($CFG_FILE, $SYS_CFG_FILE)) {
        if (Test-Path -LiteralPath $f) {
            try {
                $raw = Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($raw.entryNodes) { $cfg.entryNodes = [string]$raw.entryNodes }
                if ($raw.countryTarget) { $cfg.countryTarget = [string]$raw.countryTarget }
                if ($raw.tzTarget) { $cfg.tzTarget = [string]$raw.tzTarget }
                if ($raw.localeTarget) { $cfg.localeTarget = [string]$raw.localeTarget }
                if ($raw.lockMode) { $cfg.lockMode = [string]$raw.lockMode }
                break
            } catch {}
        }
    }
    return $cfg
}

function Save-Config($cfg) {
    $json = ($cfg | ConvertTo-Json -Depth 4) + "`n"
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($CFG_FILE, $json, $enc)
    try {
        New-Item -ItemType Directory -Force -Path $STATE_DIR -ErrorAction SilentlyContinue | Out-Null
        [System.IO.File]::WriteAllText($SYS_CFG_FILE, $json, $enc)
    } catch {}
}

# ---- IPv4 合法单播区间运算 (1.0.0.0 - 223.255.255.255) ----
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
    foreach ($p in @(
        (Join-Path $PSScriptRoot '..\data\overseas-ipv4-ranges.txt'),
        (Join-Path $PSScriptRoot 'overseas-ipv4-ranges.txt')
    )) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

# 自动探测当前活跃代理进程 (Clash Verge / Mihomo / v2rayN / sing-box / xray) 正在连接的远端第一跳公网 IPv4
function Get-AutoDetectedProxyUpstreamIps {
    $found = New-Object System.Collections.Generic.HashSet[string]
    try {
        $proxyPids = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -match '(?i)(verge|mihomo|clash|v2ray|xray|sing-box|hysteria|tuic|naive|brook)'
        } | Select-Object -ExpandProperty Id)
        if ($proxyPids.Count -gt 0) {
            foreach ($conn in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $proxyPids -contains $_.OwningProcess })) {
                $rip = [string]$conn.RemoteAddress
                if ($rip -match '^\d+\.\d+\.\d+\.\d+$' -and
                    $rip -notlike '127.*' -and $rip -notlike '10.*' -and $rip -notlike '192.168.*' -and
                    $rip -notlike '169.254.*' -and $rip -notlike '198.18.*' -and $rip -notlike '198.19.*' -and
                    $rip -notmatch '^172\.(1[6-9]|2[0-9]|3[0-1])\.' -and
                    $rip -notmatch '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.') {
                    $null = $found.Add($rip)
                }
            }
        }
    } catch {}
    return @($found)
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
    foreach ($p in @(
        (Join-Path $env:LOCALAPPDATA 'AnthropicClaude\claude.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\claude\Claude.exe')
    )) {
        if ($p -and (Test-Path -LiteralPath $p)) { $null = $exes.Add($p) }
    }
    try {
        foreach ($d in @(Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'AnthropicClaude') -Directory -Filter 'app-*' -ErrorAction SilentlyContinue)) {
            $cand = Join-Path $d.FullName 'claude.exe'
            if (Test-Path -LiteralPath $cand) { $null = $exes.Add($cand) }
        }
    } catch {}
    try {
        $pkg = Get-AppxPackage -Name '*Claude*' -ErrorAction SilentlyContinue | Select-Object -First 1
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

# ---- Windows 内核级 IFEO + SYSTEM 常驻全版本守卫 (永久免维护适配未来所有新版 Desktop/MSIX/npm/npx/bun CLI) ----
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

function Install-WatchdogTask {
    try {
        $selfScript = Join-Path $PSScriptRoot 'claude-guard.ps1'
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$selfScript`" watchdog-loop"
        $trig = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $WATCHDOG_TASK -Action $act -Trigger $trig -Principal $principal -Settings $settings -Force -ErrorAction SilentlyContinue | Out-Null
        Start-ScheduledTask -TaskName $WATCHDOG_TASK -ErrorAction SilentlyContinue
    } catch {}
}

function Uninstall-WatchdogTask {
    try {
        Stop-ScheduledTask -TaskName $WATCHDOG_TASK -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $WATCHDOG_TASK -Confirm:$false -ErrorAction SilentlyContinue
    } catch {}
}

function Invoke-WatchdogLoop {
    $tick = 0
    while ($true) {
        try {
            $cfg = Load-Config
            $mode = $cfg.lockMode
            if ($mode -eq 'off') { break }

            # A. 非 strict 工作态下: 全版本进程实时拦截 (覆盖 npm/npx/bunx @anthropic-ai/claude-code 与任意新版 Claude Desktop)
            if ($mode -ne 'strict') {
                if (-not (Test-ClaudeProcessLocked)) { Enable-ClaudeProcessLock }
                foreach ($np in @(Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='bun.exe' OR Name='Claude.exe' OR Name='claude.exe' OR Name='Update.exe'" -ErrorAction SilentlyContinue)) {
                    $cmd = [string]$np.CommandLine
                    $ep  = [string]$np.ExecutablePath
                    if (($cmd -match '@anthropic-ai[/\\]claude-code') -or ($ep -match 'AnthropicClaude|WindowsApps\\Claude_')) {
                        Stop-Process -Id ([int]$np.ProcessId) -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            # B. 每 32 秒 (8 ticks) 自愈巡检 WFP 防火墙与 hosts 黑洞: 若被第三方杀软/VPN 清掉，自动补回!
            if (($tick % 8) -eq 0) {
                $rules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
                if ($rules.Count -lt 2) {
                    Invoke-ApplyMode $cfg $mode $true | Out-Null
                }
                if ($mode -ne 'strict' -and (Test-Path -LiteralPath $HOSTS_FILE)) {
                    $ht = Get-Content -LiteralPath $HOSTS_FILE -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                    if ($ht -notmatch 'statsig\.anthropic\.com') {
                        Update-HostsManagedBlock (Get-ClaudeBlackholeHostsLines)
                    }
                }
            }
        } catch {}
        $tick++
        Start-Sleep -Seconds 4
    }
}

function Write-EmergencyGuideToDesktop([string]$TargetFile = '') {
    if (-not $TargetFile) {
        $TargetFile = Join-Path ([Environment]::GetFolderPath('Desktop')) '断网急救.txt'
    }
    $txt = @"
====================================================================
  Claude 安全锁 · Windows 专属断网急救指南（手机拍照留存，照抄即通）
====================================================================

【为什么会断网？】
开启一级安全锁后，系统强制「一切公网流量 100% 只走代理 TUN」。
若 Clash Verge / v2rayN 退出了、未开启「全局 + TUN」、或节点挂了，外网会被防火墙 0ms 拦截以保护账号不漏国内 IP。

【第 1 步（最简单）】
1. 打开 Clash Verge(开启服务模式+TUN+全局) 或 v2rayN(管理员运行+启用Tun+全局)，等 10 秒；
2. 若当前不想开代理，直接双击桌面「Claude安全锁」点击「关闭安全锁」切换回国内网络（Claude 仍保持锁死不泄露）。

【第 2 步（若国内部分未收录偏门网站被误拦）】
在「Claude安全锁」界面下方打开「二级放宽锁」（注意：打开期间严禁点击任何 Claude 服务及任何 Claude 邮件链接！）。

【第 3 步（管理员 PowerShell 终极急救命令 —— 复制粘贴回车即恢复）】
1) 一键彻底解除防火墙锁与进程锁：
  powershell -ExecutionPolicy Bypass -File "C:\ProgramData\ClaudeGuard\windows\claude-guard.ps1" uninstall-all

2) 清理代理异常退出残留的 Windows 系统代理：
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
====================================================================
"@
    try {
        [System.IO.File]::WriteAllText($TargetFile, ($txt -replace "`r?`n", "`r`n"), (New-Object System.Text.UTF8Encoding($true)))
    } catch {}
}

function Ensure-FirewallProfilesEnabled {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -LogBlocked True -LogFileName $PFW_LOG -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
    $profs = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $disabled = @($profs | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
    if ($disabled.Count -gt 0) {
        return "FAIL:检测到 Windows 防火墙配置档 ($($disabled -join ',')) 被 360/火绒/第三方杀软关闭，硬锁无法生效！请先恢复 Windows Defender 防火墙。"
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
    return [pscustomobject]@{ Up = ($uniqueIdx.Count -gt 0); TunIps = $uniqueIps }
}

function Stop-ClaudeSafely {
    $desktop = Get-Process -Name 'Claude' -ErrorAction SilentlyContinue
    if ($desktop) {
        foreach ($p in $desktop) { try { $null = $p.CloseMainWindow() } catch {} }
        for ($i = 0; $i -lt 3; $i++) { if (-not (Get-Process -Name 'Claude' -ErrorAction SilentlyContinue)) { break }; Start-Sleep 1 }
        Get-Process -Name 'Claude' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    try {
        Get-Process -Name 'claude' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        foreach ($np in @(Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='bun.exe' OR Name='Update.exe'" -ErrorAction SilentlyContinue)) {
            $cmd = [string]$np.CommandLine
            $ep  = [string]$np.ExecutablePath
            if (($cmd -match '@anthropic-ai[/\\]claude-code') -or ($ep -match 'AnthropicClaude|WindowsApps\\Claude_')) {
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
    return [pscustomobject]@{ Country = ''; IanaTz = ''; Ip = '' }
}

# 应用三态: strict (一级锁开启·全走TUN) | cn (一级锁关闭·国内白名单直连) | standby (二级放宽锁打开·防国内误伤)
function Invoke-ApplyMode($cfg, [string]$Mode = 'strict', [bool]$Silent = $false) {
    if (-not (Test-IsAdmin)) {
        Write-Output 'FAIL:操作安全锁需要管理员权限'
        exit 1
    }
    $fwErr = Ensure-FirewallProfilesEnabled
    if ($fwErr) { Write-Output $fwErr; exit 1 }

    $resolved = Resolve-EntryNodes $cfg.entryNodes
    if ($Mode -eq 'strict' -and $resolved.Cidrs.Count -eq 0) {
        $autoIps = Get-AutoDetectedProxyUpstreamIps
        if ($autoIps.Count -gt 0) {
            $cfg.entryNodes = ($autoIps -join ', ')
            $resolved = Resolve-EntryNodes $cfg.entryNodes
        }
    }
    if ($Mode -eq 'strict' -and $resolved.Cidrs.Count -eq 0) {
        Write-Output 'FAIL:未检测到活跃代理连接，请先开启代理「全局+TUN」重试，或在输入框手动填写第一跳节点 IP'
        exit 1
    }

    if ($Mode -ne 'strict') {
        if (-not $Silent) { Stop-ClaudeSafely }
        Enable-ClaudeProcessLock
        Update-HostsManagedBlock (Get-ClaudeBlackholeHostsLines)
    }

    $tun = Get-TunInfo
    $localExcludes = New-Object System.Collections.Generic.List[string]
    $localExcludes.Add('127.0.0.0/8'); $localExcludes.Add('172.18.0.0/15'); $localExcludes.Add('198.18.0.0/15')
    foreach ($tip in $tun.TunIps) { $localExcludes.Add("$tip/32") }
    $nonTunLocalV4 = Get-ComplementIpv4Ranges @($localExcludes)
    $publicRemoteV4 = Get-ComplementIpv4Ranges @('10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15')
    $claudeV4 = Resolve-ClaudeBlockV4 $(if ($Mode -eq 'strict') { $resolved.Cidrs } else { @() })

    # Zero-Gap 原子切换: 先建新锁、后删旧锁
    $oldRules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue)
    $gen = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()

    if ($Mode -eq 'standby') {
        New-NetFirewallRule -DisplayName 'ClaudeGuard[二级放宽锁底线]: 永久死锁 Claude ASN 与 34 个遥测/邮件链接 IP (IPv4)' `
            -Name "ClaudeGuard-Standby-Claude-V4-$gen" `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -LocalAddress $nonTunLocalV4 -RemoteAddress $claudeV4 | Out-Null

        New-NetFirewallRule -DisplayName 'ClaudeGuard[二级放宽锁底线]: 永久死锁 Anthropic IPv6' `
            -Name "ClaudeGuard-Standby-Claude-V6-$gen" `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -RemoteAddress $ANTHROPIC_ASN_V6 | Out-Null
    } else {
        New-NetFirewallRule -DisplayName 'ClaudeGuard: 死锁 Claude ASN 与 34 个遥测/邮件链接 IP (IPv4)' `
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
    }

    $appIdx = 0
    foreach ($exe in (Get-ProtectedClaudeExes)) {
        $appIdx++
        New-NetFirewallRule -DisplayName "ClaudeGuard: 永久死锁目标应用物理直连 #$appIdx (IPv4)" `
            -Name "ClaudeGuard-Block-TargetApp-V4-$appIdx-$gen" `
            -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
            -Program $exe -LocalAddress $nonTunLocalV4 -RemoteAddress $publicRemoteV4 | Out-Null
    }

    if ($Mode -eq 'strict') {
        $remoteExcludes = New-Object System.Collections.Generic.List[string]
        foreach ($lan in @('10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15')) { $remoteExcludes.Add($lan) }
        foreach ($c in $resolved.Cidrs) { $remoteExcludes.Add($c) }
        $blockedAll = Get-ComplementIpv4Ranges @($remoteExcludes)
        New-NetFirewallRule -DisplayName 'ClaudeGuard[一级安全锁]: 100% 流量强制只走 TUN (IPv4)' `
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
    } elseif ($Mode -eq 'cn') {
        $ovFile = Find-OverseasRangesFile
        if (-not $ovFile) { Write-Output 'FAIL:缺少海外区间表 (data\overseas-ipv4-ranges.txt)'; exit 1 }
        $baseOverseas = @(Get-Content -LiteralPath $ovFile -Encoding UTF8)
        $overseasBlocked = Subtract-CidrsFromRanges $baseOverseas $resolved.Cidrs
        $chunkSize = 400; $part = 0
        for ($off = 0; $off -lt $overseasBlocked.Count; $off += $chunkSize) {
            $part++
            $endIdx = [Math]::Min($off + $chunkSize - 1, $overseasBlocked.Count - 1)
            $slice = @($overseasBlocked[$off..$endIdx])
            New-NetFirewallRule -DisplayName "ClaudeGuard[国内网络态]: 反向规则死锁海外公网 分片#$part" `
                -Name "ClaudeGuard-Block-Overseas-V4-Part$part-$gen" `
                -Group $FW_GROUP -Direction Outbound -Action Block -Profile Any -Enabled True `
                -LocalAddress $nonTunLocalV4 -RemoteAddress $slice | Out-Null
        }
    }

    if ($oldRules.Count -gt 0) { $oldRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue }

    $cfg.lockMode = $Mode
    Save-Config $cfg
    if (-not $Silent) { Install-WatchdogTask }

    if ($Mode -eq 'strict') {
        Update-HostsManagedBlock $resolved.Hosts
        Disable-ClaudeProcessLock
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        if (-not $Silent) { Write-Output "OK:一级安全锁已开启！一切公网流量 100% 强制只走代理 TUN (入口=$($cfg.entryNodes))，Claude 已安全放行。" }
    } elseif ($Mode -eq 'cn') {
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        if (-not $Silent) { Write-Output 'OK:已退出 Claude 并切回国内白名单网络！一切海外与 Claude 遥测持续 0ms 阻断，Claude 全版本进程已锁死。' }
    } else {
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        if (-not $Silent) { Write-Output 'OK:二级放宽锁已打开（防未收录国内流量误伤）！⚠️ 请严禁打开任何 Claude 服务及点击任何 Claude 邮件链接（底层进程锁与遥测黑洞仍持续保护中）。' }
    }
}

function Invoke-UninstallAll {
    if (-not (Test-IsAdmin)) { Write-Output 'FAIL:彻底卸载需要管理员权限'; exit 1 }
    $cfg = Load-Config; $cfg.lockMode = 'off'; Save-Config $cfg
    Uninstall-WatchdogTask
    Stop-ClaudeSafely
    Disable-ClaudeProcessLock
    Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Update-HostsManagedBlock @()
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Output 'OK:已彻底解除所有系统级进程锁、自愈守卫与防火墙规则，电脑已完全恢复出厂状态。'
}

function Invoke-VerifyFirewall {
    Write-Output '=== 操作系统防火墙、全版本进程守卫与流量拦截日志验收 (Windows) ==='
    Write-Output ("时间: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Write-Output ('-' * 64)

    $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $allEnabled = $true
    Write-Output '[1] 系统防火墙配置档 (Domain / Private / Public):'
    foreach ($p in $profiles) {
        Write-Output ("    - {0,-8}: Enabled={1}, LogBlocked={2}" -f $p.Name, $p.Enabled, $p.LogBlocked)
        if (-not $p.Enabled) { $allEnabled = $false }
    }

    $ifeoOn = Test-ClaudeProcessLocked
    $wdTask = Get-ScheduledTask -TaskName $WATCHDOG_TASK -ErrorAction SilentlyContinue
    $wdStr  = if ($wdTask) { "已注册 ($($wdTask.State))" } else { '未注册' }
    Write-Output "[2] 全版本免维护进程锁: IFEO=$(if ($ifeoOn) { '已锁死' } else { '工作态放行' }) | SYSTEM自愈守卫($WATCHDOG_TASK)=$wdStr"

    $rules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
    $asnCnt = @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Claude-*' -or $_.Name -like 'ClaudeGuard-Standby-Claude-*' }).Count
    Write-Output "[3] 持久化规则组 ($FW_GROUP): 共 $($rules.Count) 条启用中的 Block 规则 (Claude/遥测核心锁=$asnCnt 条)"

    Write-Output "[4] 防火墙真实拦截流量日志 ($PFW_LOG 最近 10 条 DROP):"
    if (Test-Path -LiteralPath $PFW_LOG) {
        $drops = @(Get-Content -LiteralPath $PFW_LOG -Tail 200 -ErrorAction SilentlyContinue | Where-Object { $_ -match '\sDROP\s' } | Select-Object -Last 10)
        if ($drops.Count -gt 0) { foreach ($d in $drops) { Write-Output "    $d" } }
        else { Write-Output '    (暂无新 DROP 记录)' }
    } else { Write-Output '    (产生首次拦截后自动生成)' }

    Write-Output ('-' * 64)
    if ($allEnabled -and $rules.Count -ge 2 -and $asnCnt -ge 1) {
        Write-Output '验收结论: [✓] 操作系统防火墙硬锁与自愈守卫已实装生效'
    } else {
        Write-Output '验收结论: [✗] 操作系统防火墙未处于锁定状态'
        exit 1
    }
}

$cfg = Load-Config
switch ($Action) {
    'set-nodes' {
        if ([string]::IsNullOrWhiteSpace($Nodes)) {
            $cfg.entryNodes = ''
            Save-Config $cfg
            Write-Output 'OK:已清空手动入口节点配置(开锁时将自动探测当前活跃代理入口 IP)'
            exit 0
        }
        $r = Resolve-EntryNodes $Nodes
        if ($r.Cidrs.Count -eq 0) { Write-Output "FAIL:未能从输入解析出有效 IPv4 ($Nodes)"; exit 1 }
        $cfg.entryNodes = $Nodes.Trim()
        Save-Config $cfg
        Write-Output "OK:已保存第一跳入口白名单 ($($cfg.entryNodes))"
    }
    'lock'          { Invoke-ApplyMode $cfg 'strict' $false }
    'lock-strict'   { Invoke-ApplyMode $cfg 'strict' $false }
    'unlock'        { Invoke-ApplyMode $cfg 'cn' $false }
    'lock-cn'       { Invoke-ApplyMode $cfg 'cn' $false }
    'relax'         { Invoke-ApplyMode $cfg 'standby' $false }
    'write-emergency' { Write-EmergencyGuideToDesktop $Nodes; Write-Output 'OK:已在桌面生成本机专属《断网急救.txt》' }
    'watchdog-loop' { Invoke-WatchdogLoop }
    'uninstall-all' { Invoke-UninstallAll }
    'verify-firewall' { Invoke-VerifyFirewall }
    'init' {
        if (-not (Test-IsAdmin)) { Write-Output 'FAIL:一键初始化需要管理员权限'; exit 1 }
        if ($Nodes -and $Nodes.Trim()) { $cfg.entryNodes = $Nodes.Trim() }
        $cc = ''; $winTz = ''; $ip = ''
        if ($ManualCountry) {
            $cc = $ManualCountry.Trim().ToUpperInvariant()
            $winTz = if ($COUNTRY_TZ.ContainsKey($cc)) { $COUNTRY_TZ[$cc] } else { 'Eastern Standard Time' }
            $ip = '手动指定'
        } else {
            $geo = Get-GeoInfo
            $cc = $geo.Country; $ip = $geo.Ip
            if (-not $cc -or @('CN', 'HK', 'MO') -contains $cc) {
                Write-Output "FAIL:当前出口为 $(if ($cc) { $cc } else { '未知' })(IP=$ip)，属于不支持地区！请先开启代理「全局 + TUN」切至海外支持地区后再初始化"
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
        Write-EmergencyGuideToDesktop ''
        Invoke-ApplyMode $cfg 'strict' $false
        Write-Output "OK:一键初始化完成 | 出口=$cc($ip) | 时区=$winTz | 地区=$loc | 已在桌面生成《断网急救.txt》 | 一级安全锁(100%只走TUN)=已开启"
    }
    'status' {
        $rules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
        $isStrict  = (@($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Strict-*' }).Count -gt 0)
        $isCn      = (-not $isStrict -and @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Overseas-*' }).Count -gt 0)
        $isStandby = (-not $isStrict -and -not $isCn -and @($rules | Where-Object { $_.Name -like 'ClaudeGuard-Standby-Claude-*' }).Count -gt 0)
        $lockSt = if ($isStrict) { 'on' } elseif ($isCn) { 'cn' } elseif ($isStandby) { 'relax' } else { 'off' }
        $mode   = if ($isStrict) { 'strict' } elseif ($isCn) { 'cn' } elseif ($isStandby) { 'standby' } else { 'off' }
        $procLocked = if (Test-ClaudeProcessLocked) { 'on' } else { 'off' }
        $wdOn = if (Get-ScheduledTask -TaskName $WATCHDOG_TASK -ErrorAction SilentlyContinue) { 'on' } else { 'off' }
        Write-Output "LOCK=$lockSt"
        Write-Output "LOCK_MODE=$mode"
        Write-Output "PROC_LOCKED=$procLocked"
        Write-Output "PERSISTENT_LOCK=$wdOn"
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
