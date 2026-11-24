# Claude 安全锁 · Windows 14 维度深度本地环境体检引擎 (纯 PowerShell 5.1 + .NET，零外部依赖)
# 整合参考:
#   - TZZ520/claude-environment-check: 本地 DNS 大陆信号、代理环境变量/系统代理/PAC 脱敏检测、TLS 证书与 MITM 校验、WebSocket、Claude Code 安装检测
#   - betaer/AiSignalGuard: 多源出口 IP 共识、路由/ASN 风险标签、严格语义(未知不冒充通过)与证据覆盖率
#   - Nooobhh/claude-analysis: 受限地区黑名单(含 CN/HK/MO 等)、IP 机房/代理/VPN/Tor 画像、多 STUN WebRTC 探测、多端点延迟
param(
    [string]$ConfigPath = (Join-Path $env:USERPROFILE '.claude-guard\config.json'),
    [string]$ExportPath = '',
    [switch]$Json,
    [switch]$Offline
)

$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$FW_GROUP = 'ClaudeGuard-KillSwitch'
$RESTRICTED_COUNTRIES = @('CN', 'HK', 'MO', 'RU', 'BY', 'KP', 'IR', 'SY', 'CU')
$CN_DNS_SERVERS = @(
    '114.114.114.114', '114.114.115.115',
    '223.5.5.5', '223.6.6.6',
    '119.29.29.29', '182.254.116.116',
    '180.76.76.76', '1.2.4.8', '210.2.4.8',
    '101.226.4.6', '218.30.118.6'
)
$SUSPICIOUS_MITM = @('charles', 'fiddler', 'mitmproxy', 'burp', 'proxyman', 'zscaler', 'netskope', 'kaspersky', 'avast', 'sangfor', 'qianxin')
$COUNTRY_WIN_TZ = @{
    'US' = @('Eastern Standard Time', 'Central Standard Time', 'Mountain Standard Time', 'Pacific Standard Time', 'Alaskan Standard Time', 'Hawaiian Standard Time')
    'CA' = @('Eastern Standard Time', 'Central Standard Time', 'Mountain Standard Time', 'Pacific Standard Time', 'Atlantic Standard Time')
    'JP' = @('Tokyo Standard Time')
    'SG' = @('Singapore Standard Time')
    'TW' = @('Taipei Standard Time')
    'GB' = @('GMT Standard Time')
    'DE' = @('W. Europe Standard Time')
    'FR' = @('Romance Standard Time')
    'KR' = @('Korea Standard Time')
    'AU' = @('AUS Eastern Standard Time', 'E. Australia Standard Time', 'Cen. Australia Standard Time', 'W. Australia Standard Time')
    'MY' = @('Singapore Standard Time')
}

$items = New-Object System.Collections.Generic.List[object]
function Add-AuditItem([string]$Id, [string]$Name, [string]$State, [string]$Detail) {
    $items.Add([pscustomobject]@{ id = $Id; name = $Name; state = $State; detail = $Detail })
}

function Hide-ProxyCreds([string]$Val) {
    if (-not $Val) { return '' }
    return [regex]::Replace($Val, '://([^:@/\s]+):([^@/\s]+)@', '://$1:***@')
}

function Invoke-WebProbe([string]$Url, [int]$TimeoutSec = 6) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'
        $req.UserAgent = 'claude-guard-audit/1.0'
        $req.Timeout = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $sr.ReadToEnd()
        $code = [int]$resp.StatusCode
        $sr.Close(); $resp.Close(); $sw.Stop()
        return [pscustomobject]@{ Code = $code; Body = $body; Ms = [int]$sw.ElapsedMilliseconds; Error = '' }
    } catch [System.Net.WebException] {
        $sw.Stop()
        $code = 0
        try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch {}
        return [pscustomobject]@{ Code = $code; Body = ''; Ms = [int]$sw.ElapsedMilliseconds; Error = $_.Exception.Status.ToString() }
    } catch {
        $sw.Stop()
        return [pscustomobject]@{ Code = 0; Body = ''; Ms = [int]$sw.ElapsedMilliseconds; Error = $_.Exception.GetType().Name }
    }
}

function Test-StunServer([string]$ServerHost, [int]$Port, [int]$TimeoutMs = 2000) {
    $udp = $null
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($ServerHost) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
        if (-not $ips) { return $null }
        $ep = New-Object System.Net.IPEndPoint($ips[0], $Port)
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Client.SendTimeout = $TimeoutMs
        $req = New-Object byte[] 20
        $req[0] = 0x00; $req[1] = 0x01; $req[2] = 0x00; $req[3] = 0x00
        $req[4] = 0x21; $req[5] = 0x12; $req[6] = 0xA4; $req[7] = 0x42
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $txn = New-Object byte[] 12
        $rng.GetBytes($txn)
        [Array]::Copy($txn, 0, $req, 8, 12)
        $null = $udp.Send($req, 20, $ep)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $data = $udp.Receive([ref]$remote)
        if ($data.Length -lt 20 -or $data[0] -ne 0x01 -or $data[1] -ne 0x01) { return $null }
        $pos = 20
        while (($pos + 4) -le $data.Length) {
            $atype = ([int]$data[$pos] -shl 8) -bor [int]$data[$pos + 1]
            $alen  = ([int]$data[$pos + 2] -shl 8) -bor [int]$data[$pos + 3]
            if (($pos + 4 + $alen) -gt $data.Length) { break }
            if ($atype -eq 0x0020 -and $alen -ge 8 -and $data[$pos + 5] -eq 0x01) {
                $b0 = $data[$pos + 8] -bxor 0x21; $b1 = $data[$pos + 9] -bxor 0x12
                $b2 = $data[$pos + 10] -bxor 0xA4; $b3 = $data[$pos + 11] -bxor 0x42
                return "$b0.$b1.$b2.$b3"
            }
            if ($atype -eq 0x0001 -and $alen -ge 8 -and $data[$pos + 5] -eq 0x01) {
                return "$($data[$pos + 8]).$($data[$pos + 9]).$($data[$pos + 10]).$($data[$pos + 11])"
            }
            $pad = (4 - ($alen % 4)) % 4
            $pos += 4 + $alen + $pad
        }
    } catch {} finally {
        if ($udp) { $udp.Close() }
    }
    return $null
}

function Test-TlsEndpoint([string]$TargetHost, [int]$Port = 443, [int]$TimeoutMs = 6000) {
    $tcp = $null; $ssl = $null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar = $tcp.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { throw 'Timeout' }
        $tcp.EndConnect($ar)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
        $ssl.ReadTimeout = $TimeoutMs
        $ssl.AuthenticateAsClient($TargetHost)
        $sw.Stop()
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $issuer = [string]$cert.Issuer
        $isMitm = $false
        foreach ($tok in $SUSPICIOUS_MITM) {
            if ($issuer.ToLowerInvariant().Contains($tok)) { $isMitm = $true; break }
        }
        return [pscustomobject]@{ Ok = $true; Protocol = $ssl.SslProtocol.ToString(); Issuer = $issuer; Mitm = $isMitm; Ms = [int]$sw.ElapsedMilliseconds }
    } catch {
        return [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message }
    } finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Close() }
    }
}

function Test-WssUpgrade([string]$TargetHost = 'claude.ai', [int]$Port = 443, [int]$TimeoutMs = 6000) {
    $tcp = $null; $ssl = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar = $tcp.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { throw 'Timeout' }
        $tcp.EndConnect($ar)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
        $ssl.ReadTimeout = $TimeoutMs
        $ssl.AuthenticateAsClient($TargetHost)
        $rawReq = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`nSec-WebSocket-Version: 13`r`nUser-Agent: claude-guard-audit/1.0`r`n`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($rawReq)
        $ssl.Write($bytes, 0, $bytes.Length); $ssl.Flush()
        $buf = New-Object byte[] 512
        $n = $ssl.Read($buf, 0, $buf.Length)
        $head = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
        $first = ($head -split "`r?`n")[0]
        if ($first -match 'HTTP/\d(?:\.\d)?\s+(\d{3})') {
            return [pscustomobject]@{ Ok = $true; Status = [int]$Matches[1] }
        }
        return [pscustomobject]@{ Ok = $false; Error = 'InvalidHTTPResponse' }
    } catch {
        return [pscustomobject]@{ Ok = $false; Error = $_.Exception.GetType().Name }
    } finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Close() }
    }
}

# 读取配置
$cfg = @{ entryNodes = ''; countryTarget = ''; tzTarget = ''; localeTarget = ''; lockMode = '' }
if (Test-Path -LiteralPath $ConfigPath) {
    try {
        $j = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($j.entryNodes) { $cfg.entryNodes = [string]$j.entryNodes }
        if ($j.countryTarget) { $cfg.countryTarget = [string]$j.countryTarget }
        if ($j.tzTarget) { $cfg.tzTarget = [string]$j.tzTarget }
        if ($j.localeTarget) { $cfg.localeTarget = [string]$j.localeTarget }
        if ($j.lockMode) { $cfg.lockMode = [string]$j.lockMode }
    } catch {}
}

# 1. 持久化安全锁 (WFP) + 内核 IFEO 进程锁与拦截日志验收
$fwRules = @(Get-NetFirewallRule -Group $FW_GROUP -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
$fwProfs = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
$fwAllOn = ($fwProfs.Count -gt 0 -and (@($fwProfs | Where-Object { -not $_.Enabled }).Count -eq 0))
$fwLogOn = ($fwProfs.Count -gt 0 -and (@($fwProfs | Where-Object { -not $_.LogBlocked }).Count -eq 0))
$isActive = (@($fwRules | Where-Object { $_.Name -like 'ClaudeGuard-Block-Overseas-*' -or $_.Name -like 'ClaudeGuard-Block-Strict-*' }).Count -gt 0)
$isStandby = (-not $isActive -and @($fwRules | Where-Object { $_.Name -like 'ClaudeGuard-Standby-Claude-*' }).Count -gt 0)
$lockOn = ($isActive -and $fwAllOn)
$modeLabel = if ($cfg.lockMode -eq 'strict') { '全封闭模式' } else { '放行国内 · 死锁Claude与海外' }
if ($isActive -and $fwAllOn) {
    $logStr = if ($fwLogOn) { '拦截日志已开' } else { '拦截日志未全开' }
    Add-AuditItem 'killswitch' '持久化安全锁 (WFP 防火墙)' 'ok' "安全锁已开启 · $modeLabel ($($fwRules.Count)条规则, $logStr, 入口=$($cfg.entryNodes))"
} elseif ($isStandby -and $fwAllOn) {
    Add-AuditItem 'killswitch' '持久化安全锁 (WFP 防火墙)' 'warn' "当前为日常上网模式 (Claude 已被 IFEO 内核锁死且永久阻断遥测，使用 Claude 前请先点「开启安全锁」)"
} elseif ($fwRules.Count -ge 2) {
    Add-AuditItem 'killswitch' '持久化安全锁 (WFP 防火墙)' 'fail' "已写入 $($fwRules.Count) 条规则，但 Windows 防火墙配置档被第三方安全软件或系统策略关闭！"
} else {
    Add-AuditItem 'killswitch' '持久化安全锁 (WFP 防火墙)' 'fail' '尚未初始化安全锁，请先点「一键初始化环境」或「开启安全锁」'
}

# 2. TUN 虚拟网卡与默认路由归属
$tunIdx = @(); $tunIps = @()
foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
    if ($a.IPAddress -like '198.18.*' -or $a.IPAddress -like '198.19.*' -or $a.IPAddress -like '172.18.*' -or $a.IPAddress -like '172.19.*') {
        $tunIdx += [int]$a.InterfaceIndex; $tunIps += $a.IPAddress
    }
}
foreach ($nic in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'TAP|TUN|WireGuard|Wintun|VPN|Tailscale|Sing-Box|Mihomo' -or $_.Name -match 'singbox_tun|sing-tun|v2rayN|Mihomo|Meta') })) {
    $tunIdx += [int]$nic.ifIndex
}
$tunIdx = @($tunIdx | Select-Object -Unique)
$bestRoute = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object { [int]$_.RouteMetric + [int]$_.InterfaceMetric } | Select-Object -First 1)
if ($tunIdx.Count -gt 0 -and $bestRoute.Count -gt 0 -and ($tunIdx -contains [int]$bestRoute[0].InterfaceIndex)) {
    Add-AuditItem 'tun' '全局 TUN 与默认路由' 'ok' "在线 (默认路由=$($bestRoute[0].InterfaceAlias), IP=$(($tunIps | Select-Object -Unique) -join ','))"
} elseif ($tunIdx.Count -gt 0) {
    $al = if ($bestRoute.Count -gt 0) { $bestRoute[0].InterfaceAlias } else { '无' }
    Add-AuditItem 'tun' '全局 TUN 与默认路由' 'fail' "虚拟网卡在，但默认路由被 $al 抢占(疑似手机热点/未开全局)"
} else {
    Add-AuditItem 'tun' '全局 TUN 与默认路由' 'fail' '未检测到 TUN (Clash Verge 需开服务模式+TUN; v2rayN 需管理员+启用Tun)'
}

# 3. 本地与上游 DNS 泄露审计 (大陆 DNS 信号 + claude.ai 解析 + isp.ac 上游实测)
$dnsList = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
$cnDns = @($dnsList | Where-Object { $CN_DNS_SERVERS -contains $_ })
$claudeDns = ''
try { $claudeDns = [string]((Resolve-DnsName claude.ai -Type A -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress) } catch {}
$upCn = @(); $upNote = ''
if (-not $Offline) {
    $dl = Invoke-WebProbe 'https://isp.ac/dns-leak-test' 5
    if ($dl.Code -eq 200 -and $dl.Body) {
        try {
            $dj = $dl.Body | ConvertFrom-Json
            $arr = if ($dj -is [System.Array]) { $dj } elseif ($dj.servers) { @($dj.servers) } else { @($dj) }
            $ccs = @()
            foreach ($e in $arr) {
                $cv = ([string](if ($e.country_code) { $e.country_code } else { $e.country })).ToUpperInvariant()
                if ($cv) {
                    $ccs += $cv
                    if ($cv -eq 'CN' -or $cv -eq 'CHINA') { $upCn += $(if ($e.ip) { [string]$e.ip } else { $cv }) }
                }
            }
            if ($ccs.Count -gt 0) { $upNote = '; 上游DNS=' + (($ccs | Select-Object -Unique | Select-Object -First 3) -join ',') }
        } catch {}
    }
}
if ($upCn.Count -gt 0) {
    Add-AuditItem 'dns' '本地与上游 DNS 泄露' 'fail' "上游 DNS 出口检出中国大陆服务器($($upCn -join ','))"
} elseif ($cnDns.Count -gt 0 -and -not ($claudeDns -like '198.18.*' -or $claudeDns -like '198.19.*')) {
    Add-AuditItem 'dns' '本地与上游 DNS 泄露' 'fail' "发现大陆 DNS($($cnDns -join ',')) 且 claude.ai 解析=$claudeDns$upNote"
} elseif ($claudeDns -like '198.18.*' -or $claudeDns -like '198.19.*') {
    Add-AuditItem 'dns' '本地与上游 DNS 泄露' 'ok' "Fake-IP 隧道接管 (claude.ai=$claudeDns$upNote)"
} elseif ($claudeDns) {
    $st = if ($cnDns.Count -gt 0) { 'warn' } else { 'ok' }
    Add-AuditItem 'dns' '本地与上游 DNS 泄露' $st "Real-IP 解析 ($claudeDns$upNote)"
} else {
    Add-AuditItem 'dns' '本地与上游 DNS 泄露' 'unknown' "未能解析 claude.ai (系统DNS=$($dnsList -join ','))"
}

# 4. 代理环境变量与 Windows 系统代理/PAC 检测 (脱敏)
$envHits = @()
foreach ($k in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')) {
    $v = [Environment]::GetEnvironmentVariable($k)
    if ($v) { $envHits += "$k=$(Hide-ProxyCreds $v)" }
}
$inetKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$pacUrl = ''
try { $pacUrl = [string](Get-ItemProperty -Path $inetKey -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL } catch {}
if ($envHits.Count -gt 0) {
    Add-AuditItem 'proxy_env' '代理环境变量与 PAC' 'warn' "检测到代理环境变量($($envHits -join ', '))，请确认与 TUN 不冲突"
} elseif ($pacUrl) {
    Add-AuditItem 'proxy_env' '代理环境变量与 PAC' 'warn' '检测到系统 PAC 脚本，建议全局+TUN 下关闭 PAC 以免分流直连'
} else {
    Add-AuditItem 'proxy_env' '代理环境变量与 PAC' 'ok' '无冲突代理环境变量或 PAC'
}

# 5 & 6 & 7. 多源出口 IP 共识 + 受限地区合规 + IP 纯净度/ASN 画像
$egress = @()
$riskSignals = $null
if (-not $Offline) {
    $p1 = Invoke-WebProbe 'https://ipinfo.io/json'
    if ($p1.Code -eq 200 -and $p1.Body) {
        try {
            $j = $p1.Body | ConvertFrom-Json
            if ($j.ip) { $egress += [pscustomobject]@{ Src = 'ipinfo'; Ip = [string]$j.ip; Cc = ([string]$j.country).ToUpperInvariant(); Org = [string]$j.org } }
        } catch {}
    }
    $p2 = Invoke-WebProbe 'https://ipwho.is/'
    if ($p2.Code -eq 200 -and $p2.Body) {
        try {
            $j = $p2.Body | ConvertFrom-Json
            if ($j.ip -and $j.success -ne $false) {
                $org = if ($j.connection -and $j.connection.asn) { "AS$($j.connection.asn) $($j.connection.isp)" } else { '' }
                $egress += [pscustomobject]@{ Src = 'ipwho.is'; Ip = [string]$j.ip; Cc = ([string]$j.country_code).ToUpperInvariant(); Org = $org }
            }
        } catch {}
    }
    $p3 = Invoke-WebProbe 'https://www.cloudflare.com/cdn-cgi/trace'
    if ($p3.Code -eq 200 -and $p3.Body) {
        $cfIp = ''; $cfCc = ''
        foreach ($l in ($p3.Body -split "`r?`n")) {
            if ($l -match '^ip=(\S+)$') { $cfIp = $Matches[1] }
            if ($l -match '^loc=([A-Za-z]{2})$') { $cfCc = $Matches[1].ToUpperInvariant() }
        }
        if ($cfIp -and $cfCc) { $egress += [pscustomobject]@{ Src = 'cloudflare'; Ip = $cfIp; Cc = $cfCc; Org = '' } }
    }
    $p4 = Invoke-WebProbe 'https://api.ipapi.is/'
    if ($p4.Code -eq 200 -and $p4.Body) {
        try {
            $j = $p4.Body | ConvertFrom-Json
            if ($j.ip) {
                $cc = if ($j.location -and $j.location.country_code) { ([string]$j.location.country_code).ToUpperInvariant() } else { '' }
                $org = if ($j.asn -and $j.asn.asn) { "AS$($j.asn.asn) $($j.asn.org)" } else { '' }
                $egress += [pscustomobject]@{ Src = 'ipapi.is'; Ip = [string]$j.ip; Cc = $cc; Org = $org }
                $riskSignals = [pscustomobject]@{
                    Datacenter = ($j.is_datacenter -eq $true)
                    Proxy = ($j.is_proxy -eq $true)
                    Vpn = ($j.is_vpn -eq $true)
                    Tor = ($j.is_tor -eq $true)
                    Abuser = ($j.is_abuser -eq $true)
                    AsnType = if ($j.asn -and $j.asn.type) { [string]$j.asn.type } else { 'unknown' }
                }
            }
        } catch {}
    }
}

$consensusIp = ''; $consensusCc = ''; $consensusOrg = ''
if ($Offline) {
    Add-AuditItem 'egress' '多源出口 IP 共识' 'unknown' '离线演练模式'
    Add-AuditItem 'region_policy' 'Anthropic 地区合规性' 'unknown' '离线演练模式'
    Add-AuditItem 'ip_risk' 'IP 纯净度与 ASN 画像' 'unknown' '离线演练模式'
} elseif ($egress.Count -eq 0) {
    Add-AuditItem 'egress' '多源出口 IP 共识' 'fail' '全部 4 个出口探测源均失败 (请检查节点与入口白名单 IP)'
    Add-AuditItem 'region_policy' 'Anthropic 地区合规性' 'fail' '无法确认出口国家'
    Add-AuditItem 'ip_risk' 'IP 纯净度与 ASN 画像' 'unknown' '无可用情报源'
} else {
    $uniqIps = @($egress | ForEach-Object { $_.Ip } | Where-Object { $_ } | Select-Object -Unique)
    $uniqCcs = @($egress | ForEach-Object { $_.Cc } | Where-Object { $_ } | Select-Object -Unique)
    $consensusIp = $uniqIps[0]
    $consensusCc = if ($uniqCcs.Count -gt 0) { $uniqCcs[0] } else { '' }
    $consensusOrg = ($egress | Where-Object { $_.Org } | Select-Object -First 1).Org

    if ($uniqCcs.Count -gt 1) {
        Add-AuditItem 'egress' '多源出口 IP 共识' 'fail' "多源国家分歧($($uniqCcs -join ','))，存在分流不一致风险"
    } elseif ($uniqIps.Count -gt 1) {
        Add-AuditItem 'egress' '多源出口 IP 共识' 'warn' "同国($consensusCc)但多源 IP 不同($($uniqIps -join ','))"
    } else {
        Add-AuditItem 'egress' '多源出口 IP 共识' 'ok' "$consensusIp / $consensusCc ($($egress.Count) 源完全一致)"
    }

    if ($RESTRICTED_COUNTRIES -contains $consensusCc) {
        Add-AuditItem 'region_policy' 'Anthropic 地区合规性' 'fail' "出口 $consensusCc 属于 Anthropic 不支持地区，严禁登录使用！"
    } elseif ($cfg.countryTarget -and $consensusCc -ne $cfg.countryTarget) {
        Add-AuditItem 'region_policy' 'Anthropic 地区合规性' 'warn' "出口 $consensusCc 与初始化目标 $($cfg.countryTarget) 不一致"
    } else {
        Add-AuditItem 'region_policy' 'Anthropic 地区合规性' 'ok' "出口地区 $consensusCc 属于支持地区"
    }

    if ($riskSignals) {
        $flags = @()
        if ($riskSignals.Datacenter) { $flags += '机房' }
        if ($riskSignals.Proxy) { $flags += '公开代理' }
        if ($riskSignals.Vpn) { $flags += 'VPN' }
        if ($riskSignals.Tor) { $flags += 'Tor' }
        if ($riskSignals.Abuser) { $flags += '滥用记录' }
        if ($flags.Count -gt 0) {
            Add-AuditItem 'ip_risk' 'IP 纯净度与 ASN 画像' 'warn' "命中风险标签[$($flags -join ',')] | 类型=$($riskSignals.AsnType) | $consensusOrg"
        } else {
            Add-AuditItem 'ip_risk' 'IP 纯净度与 ASN 画像' 'ok' "无代理/机房/滥用标记 | 类型=$($riskSignals.AsnType) | $consensusOrg"
        }
    } elseif ($consensusOrg) {
        Add-AuditItem 'ip_risk' 'IP 纯净度与 ASN 画像' 'warn' "仅获取到 ASN($consensusOrg)，第三方风险标签源未响应"
    } else {
        Add-AuditItem 'ip_risk' 'IP 纯净度与 ASN 画像' 'unknown' '未能获取 ASN 与风险画像'
    }
}

# 8. WebRTC / STUN 泄露探测
if ($Offline) {
    Add-AuditItem 'webrtc' 'WebRTC / STUN 泄露' 'unknown' '离线演练模式'
} else {
    $stunHits = @()
    foreach ($pair in @(@('stun.miwifi.com', 3478), @('stun.chat.bilibili.com', 3478), @('stun.l.google.com', 19302), @('stun.cloudflare.com', 3478))) {
        $resIp = Test-StunServer $pair[0] $pair[1]
        if ($resIp -and ($stunHits -notcontains $resIp)) { $stunHits += $resIp }
    }
    if ($stunHits.Count -eq 0) {
        if ($lockOn) {
            Add-AuditItem 'webrtc' 'WebRTC / STUN 泄露' 'ok' '无 STUN 响应 (物理网卡 STUN 已被安全锁内核阻断，零泄露)'
        } else {
            Add-AuditItem 'webrtc' 'WebRTC / STUN 泄露' 'warn' 'STUN 无响应 (节点未开 UDP 或被拦截；建议开启安全锁兜底)'
        }
    } else {
        $leaks = @($stunHits | Where-Object { $consensusIp -and $_ -ne $consensusIp })
        if ($leaks.Count -gt 0) {
            Add-AuditItem 'webrtc' 'WebRTC / STUN 泄露' 'fail' "严重泄露！STUN 暴露非出口 IP: $($leaks -join ',') (出口=$consensusIp)"
        } else {
            Add-AuditItem 'webrtc' 'WebRTC / STUN 泄露' 'ok' "仅返回代理出口 IP ($($stunHits -join ','))"
        }
    }
}

# 9. 时区 / 地区 / 客户端语言一致性
$curTz = (Get-TimeZone).Id
$curCult = [System.Globalization.CultureInfo]::CurrentCulture.Name
$tzIssues = @()
if ($curTz -eq 'China Standard Time') { $tzIssues += '仍为中国标准时间' }
elseif ($consensusCc -and $COUNTRY_WIN_TZ.ContainsKey($consensusCc) -and ($COUNTRY_WIN_TZ[$consensusCc] -notcontains $curTz)) {
    $tzIssues += "时区($curTz)与出口国($consensusCc)不匹配"
}
if ($curCult -ieq 'zh-CN') { $tzIssues += '系统地区仍为 zh-CN' }
if ($tzIssues.Count -gt 0) {
    Add-AuditItem 'locale_tz' '时区/地区/语言一致性' 'fail' ($tzIssues -join '; ')
} else {
    Add-AuditItem 'locale_tz' '时区/地区/语言一致性' 'ok' "时区=$curTz, 地区=$curCult"
}

# 10. 全网卡 IPv6 封锁
$v6On = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Enabled })
if ($v6On.Count -eq 0) {
    Add-AuditItem 'ipv6' '全网卡 IPv6 封锁' 'ok' ("全部网卡已关闭 IPv6" + $(if ($lockOn) { ' + 防火墙封锁 2000::/3' } else { '' }))
} elseif ($lockOn) {
    Add-AuditItem 'ipv6' '全网卡 IPv6 封锁' 'warn' "有 $($v6On.Count) 张网卡未关 IPv6，但安全锁已内核阻断全部公网 IPv6"
} else {
    Add-AuditItem 'ipv6' '全网卡 IPv6 封锁' 'fail' "有 $($v6On.Count) 张网卡开启 IPv6 且安全锁未开"
}

# 11. Anthropic 多端点连通性与延迟
if ($Offline) {
    Add-AuditItem 'endpoints' 'Anthropic 多端点连通' 'unknown' '离线演练模式'
} else {
    $okList = @(); $failList = @(); $blockList = @()
    foreach ($ep in @(@('claude.ai', 'https://claude.ai/'), @('api', 'https://api.anthropic.com/v1/models'), @('platform', 'https://platform.claude.com/'))) {
        $r = Invoke-WebProbe $ep[1] 6
        if ($r.Code -eq 0) { $failList += "$($ep[0]):$($r.Error)" }
        elseif ($r.Code -eq 451) { $blockList += "$($ep[0]):HTTP451(地区封锁)" }
        else { $okList += "$($ep[0]):$($r.Code)($($r.Ms)ms)" }
    }
    if ($blockList.Count -gt 0) { Add-AuditItem 'endpoints' 'Anthropic 多端点连通' 'fail' ("遭遇地区封锁: " + ($blockList -join ', ')) }
    elseif ($failList.Count -gt 0) { Add-AuditItem 'endpoints' 'Anthropic 多端点连通' 'fail' ("端点不可达: " + ($failList -join ', ')) }
    else { Add-AuditItem 'endpoints' 'Anthropic 多端点连通' 'ok' ($okList -join ', ') }
}

# 12. TLS 证书完整性与 MITM 校验
if ($Offline) {
    Add-AuditItem 'tls' 'TLS 证书与 MITM 校验' 'unknown' '离线演练模式'
} else {
    $tls = Test-TlsEndpoint 'api.anthropic.com'
    if (-not $tls.Ok) { Add-AuditItem 'tls' 'TLS 证书与 MITM 校验' 'fail' "TLS 握手失败($($tls.Error))" }
    elseif ($tls.Mitm) { Add-AuditItem 'tls' 'TLS 证书与 MITM 校验' 'fail' "疑似中间人劫持证书! Issuer=$($tls.Issuer)" }
    else { Add-AuditItem 'tls' 'TLS 证书与 MITM 校验' 'ok' "$($tls.Protocol) / $($tls.Issuer) ($($tls.Ms)ms)" }
}

# 13. WebSocket 隧道能力
if ($Offline) {
    Add-AuditItem 'ws' 'WebSocket 隧道能力' 'unknown' '离线演练模式'
} else {
    $ws = Test-WssUpgrade 'claude.ai'
    if ($ws.Ok) { Add-AuditItem 'ws' 'WebSocket 隧道能力' 'ok' "WSS 升级请求已达源站 (HTTP $($ws.Status))" }
    else { Add-AuditItem 'ws' 'WebSocket 隧道能力' 'warn' "WSS 握手异常 ($($ws.Error))" }
}

# 14. Claude 客户端与认证环境变量污染检查
$hasDesktop = (Test-Path "$env:LOCALAPPDATA\AnthropicClaude\Claude.exe") -or (Test-Path "$env:LOCALAPPDATA\Programs\Claude\Claude.exe") -or [bool](Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue)
$cliCmd = Get-Command 'claude' -ErrorAction SilentlyContinue
$cliInfo = if ($cliCmd) { '已装' } else { '未装' }
$overrideHits = @()
foreach ($k in @('ANTHROPIC_BASE_URL', 'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_VERTEX')) {
    if ([Environment]::GetEnvironmentVariable($k)) { $overrideHits += $k }
}
$cDesc = "Desktop=$(if ($hasDesktop) { '已装' } else { '未装' }), CLI=$cliInfo"
if ($overrideHits.Count -gt 0) {
    Add-AuditItem 'client_env' 'Claude 客户端与环境变量' 'warn' "$cDesc; 检测到覆盖变量($($overrideHits -join ','))"
} else {
    Add-AuditItem 'client_env' 'Claude 客户端与环境变量' 'ok' "$cDesc; 无第三方覆盖变量"
}

# 统计与覆盖率
$okN = @($items | Where-Object { $_.state -eq 'ok' }).Count
$warnN = @($items | Where-Object { $_.state -eq 'warn' }).Count
$failN = @($items | Where-Object { $_.state -eq 'fail' }).Count
$unkN = @($items | Where-Object { $_.state -eq 'unknown' }).Count
$total = $items.Count
$verified = $total - $unkN
$cov = if ($total -gt 0) { [int][Math]::Round(($verified / $total) * 100) } else { 0 }

$report = [ordered]@{
    timestamp = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    platform = "Windows $([System.Environment]::OSVersion.Version.ToString())"
    coverage_percent = $cov
    summary = [ordered]@{ ok = $okN; warn = $warnN; fail = $failN; unknown = $unkN }
    items = @($items)
}

if ($Json) {
    $outText = $report | ConvertTo-Json -Depth 5
} else {
    $iconMap = @{ ok = '[✓]'; warn = '[!]'; fail = '[✗]'; unknown = '[?]' }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("=== Claude 14 维度深度本地环境体检 ($($report.platform)) ===")
    $lines.Add("时间: $($report.timestamp) | 证据覆盖率: $cov% ($verified/$total 已核实)")
    $lines.Add(('-' * 58))
    $i = 0
    foreach ($it in $items) {
        $i++
        $lines.Add(("{0:D2}. {1} {2}: {3}" -f $i, $iconMap[$it.state], $it.name, $it.detail))
    }
    $lines.Add(('-' * 58))
    $lines.Add("统计: 通过=$okN | 警告=$warnN | 失败=$failN | 未知=$unkN")
    if ($failN -eq 0 -and $unkN -eq 0) { $lines.Add('结论: 核心环境全部核实通过，可以放心交付/使用 Claude') }
    elseif ($failN -eq 0) { $lines.Add('结论: 已核实项无失败（存在未知或警告项，请结合明细确认）') }
    else { $lines.Add("结论: 有 $failN 项未通过，请先修复后再使用 Claude") }
    $outText = $lines -join "`n"
}

if ($ExportPath) {
    [System.IO.File]::WriteAllText($ExportPath, $outText + "`n", (New-Object System.Text.UTF8Encoding($false)))
}
Write-Output $outText
if ($failN -gt 0) { exit 1 } else { exit 0 }
