#!/bin/bash
# Claude 安全锁 · macOS 极简核心引擎 (方案 A: 固定代理入口白名单 Kill-Switch)
# 特点:
#   - 零外部依赖 (仅系统自带 bash / pfctl / networksetup / osascript / python3)
#   - 兼容 Stash / Shadowrocket / Clash Verge / FlClash / v2rayN / V2RayU 等任意全局+TUN 客户端
#   - 支持链式代理: 只需填入「第一跳入口节点」的 IP 或域名 (多个用逗号/空格分隔)
#   - 开启安全锁后: 物理网卡仅放行入口节点 IP + 局域网(非DNS) + DHCP + TUN, 其余 IPv4/IPv6/WebRTC/裸DNS 全部 0ms DROP
#   - 一键恢复直连: 自动先关闭 Claude 桌面版与 CLI, 再无痕移除 pf 锚点与 hosts 托管块

set -u
export LC_ALL=en_US.UTF-8

APP_DIR="${CLAUDE_GUARD_DIR:-$HOME/.claude-guard}"
CFG_FILE="$APP_DIR/config.env"
PF_ANCHOR_NAME="${CLAUDE_GUARD_ANCHOR:-com.claude-guard}"
PF_CONF="${CLAUDE_GUARD_PF_CONF:-/etc/pf.conf}"
PF_ANCHOR_FILE="${CLAUDE_GUARD_ANCHOR_FILE:-/etc/pf.anchors/${PF_ANCHOR_NAME}}"
PF_CN_FILE="${CLAUDE_GUARD_CN_FILE:-/etc/pf.anchors/${PF_ANCHOR_NAME}.cn.txt}"
PF_BOOT_LABEL="com.claude-guard.pfboot"
PF_BOOT_PLIST="${CLAUDE_GUARD_BOOT_PLIST:-/Library/LaunchDaemons/${PF_BOOT_LABEL}.plist}"
HOSTS_FILE="${CLAUDE_GUARD_HOSTS:-/etc/hosts}"

ANTHROPIC_ASN_V4="160.79.104.0/21"
ANTHROPIC_ASN_V6="2607:6bc0::/48"
ANTHROPIC_DOMAINS="claude.ai claude.com api.anthropic.com claudeusercontent.com platform.claude.com console.anthropic.com statsig.anthropic.com"

PF_BEGIN="# BEGIN claude-guard-pf"
PF_END="# END claude-guard-pf"
HOSTS_BEGIN="# BEGIN claude-guard-hosts"
HOSTS_END="# END claude-guard-hosts"

mkdir -p "$APP_DIR"

# ---- 默认配置 ----
ENTRY_NODES=""       # 入口节点 IP 或域名，逗号分隔（链式代理填第一跳入口）
COUNTRY_TARGET=""    # 期望出口国家码，如 US / JP / SG
TZ_TARGET=""         # 期望 IANA 时区，如 America/New_York
LOCALE_TARGET=""     # 期望地区格式，如 en_US
ALLOW_LAN_DNS="0"    # 默认封死物理网卡 53 端口裸 DNS (入口域名由 hosts 托管块解析)
PERSISTENT_LOCK="0"  # 持久化防直连硬锁开关 (1=开启: 代理退出/软件退出/重启后仍阻断直连，直到手动关闭)

load_cfg() {
    [ -f "$CFG_FILE" ] && source "$CFG_FILE" 2>/dev/null || true
}

save_cfg() {
    mkdir -p "$APP_DIR"
    cat > "$CFG_FILE" <<EOF
ENTRY_NODES="${ENTRY_NODES}"
COUNTRY_TARGET="${COUNTRY_TARGET}"
TZ_TARGET="${TZ_TARGET}"
LOCALE_TARGET="${LOCALE_TARGET}"
ALLOW_LAN_DNS="${ALLOW_LAN_DNS}"
PERSISTENT_LOCK="${PERSISTENT_LOCK}"
EOF
    chmod 600 "$CFG_FILE" 2>/dev/null || true
}

default_tz_for() {
    case "$1" in
        US) echo America/New_York ;; JP) echo Asia/Tokyo ;; TW) echo Asia/Taipei ;;
        HK) echo Asia/Hong_Kong ;; SG) echo Asia/Singapore ;; GB) echo Europe/London ;;
        DE) echo Europe/Berlin ;; FR) echo Europe/Paris ;; KR) echo Asia/Seoul ;;
        AU) echo Australia/Sydney ;; CA) echo America/Toronto ;; MY) echo Asia/Kuala_Lumpur ;;
        *) echo America/New_York ;;
    esac
}

default_locale_for() {
    case "$1" in
        US) echo en_US ;; JP) echo ja_JP ;; TW) echo zh_TW ;; HK) echo zh_HK ;;
        SG) echo en_SG ;; GB) echo en_GB ;; DE) echo de_DE ;; FR) echo fr_FR ;;
        KR) echo ko_KR ;; AU) echo en_AU ;; CA) echo en_CA ;; MY) echo ms_MY ;;
        *) echo en_US ;;
    esac
}

# 将用户输入的入口节点列表（支持 IP、CIDR、域名，逗号/空格/换行分隔）解析为 IPv4 列表 + hosts 映射
resolve_entries() {
    local raw="$1"
    python3 - "$raw" <<'PY'
import ipaddress, re, socket, sys

raw = sys.argv[1]
tokens = [t.strip() for t in re.split(r'[\s,;，；]+', raw) if t.strip()]
ips = []
seen = set()
hosts = []

def add_entry(val):
    if val not in seen:
        seen.add(val)
        ips.append(val)

for tok in tokens:
    # 去掉可能误粘贴的协议前缀与端口 (例如 vless:// 或 1.2.3.4:443)
    tok = re.sub(r'^[a-zA-Z0-9+.-]+://', '', tok).split('/')[0]
    if ':' in tok and tok.count(':') == 1 and not tok.startswith('['):
        tok = tok.split(':', 1)[0]
    # 1. 纯 IPv4 或 IPv4 CIDR
    try:
        net = ipaddress.ip_network(tok, strict=False)
        if net.version == 4:
            add_entry(str(net.network_address) if net.prefixlen == 32 else str(net))
            continue
    except ValueError:
        pass
    # 2. 域名: 解析所有 IPv4 A 记录并输出 hosts 映射，避免封死物理 DNS 后无法连接域名节点
    try:
        infos = socket.getaddrinfo(tok, None, socket.AF_INET)
        resolved = []
        for info in infos:
            ip = info[4][0]
            if ip not in resolved:
                resolved.append(ip)
            add_entry(ip)
        if resolved:
            hosts.append((resolved[0], tok))
        else:
            print(f"ERR:无法解析域名 {tok}", file=sys.stderr)
    except Exception:
        print(f"ERR:无法解析节点 {tok}", file=sys.stderr)

for ip in ips:
    print(f"IP:{ip}")
for ip, host in hosts:
    print(f"HOST:{ip} {host}")
PY
}

# 探测当前承担默认路由的代理 TUN 接口与 IPv4 网段
detect_tun_info() {
    local iface ip
    iface=$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2; exit}')
    case "$iface" in
        utun[0-9]*)
            ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2; exit}')
            echo "${iface}|${ip}"
            return 0 ;;
    esac
    # 回退检查常见 TUN 网段
    ip=$(ifconfig 2>/dev/null | awk '/inet (198\.18\.|198\.19\.|172\.18\.|172\.19\.)/{print $2; exit}')
    if [ -n "$ip" ]; then
        echo "|${ip}"
        return 0
    fi
    echo "|"
    return 1
}

# 动态解析 Claude/Anthropic 生态域名公网 IPv4 (用于叠加锁定，自动跳过 Fake-IP 与白名单入口 IP)
resolve_claude_ips() {
    local whitelist_csv="${1:-}"
    python3 - "$ANTHROPIC_ASN_V4" "$ANTHROPIC_DOMAINS" "$whitelist_csv" <<'PY' 2>/dev/null || echo "$ANTHROPIC_ASN_V4"
import ipaddress, json, re, subprocess, sys

asn_v4, domains_s, wl_csv = sys.argv[1], sys.argv[2], sys.argv[3]
wl = {x.strip() for x in re.split(r'[\s,]+', wl_csv) if x.strip()}
items = [asn_v4]
seen = {asn_v4}

for dom in domains_s.split():
    try:
        out = subprocess.check_output(
            ["curl", "-s", "--max-time", "4", "-H", "accept: application/dns-json",
             f"https://cloudflare-dns.com/dns-query?name={dom}&type=A"],
            stderr=subprocess.DEVNULL, text=True, timeout=5
        )
        for ans in (json.loads(out).get("Answer") or []):
            ip_s = str(ans.get("data", "")).strip()
            try:
                ip = ipaddress.ip_address(ip_s)
            except ValueError:
                continue
            if ip.version == 4 and ip.is_global and ip not in ipaddress.ip_network("198.18.0.0/15"):
                if str(ip) not in wl and str(ip) not in seen:
                    seen.add(str(ip))
                    items.append(str(ip))
    except Exception:
        pass
print(", ".join(items))
PY
}

find_cn_list_src() {
    local self_dir
    self_dir="$(cd "$(dirname "$0")" && pwd)"
    for p in "${self_dir}/../data/cn-ipv4.txt" "${self_dir}/cn-ipv4.txt"; do
        if [ -r "$p" ]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

# 生成持久化防直连硬锁 pf 锚点规则:
#   mode=cn     (锁1·国内直连放行): 放行国内 CN 段 + 局域网 + 代理入口 + TUN; 0ms 死锁 Claude(ASN+域名IP) + 一切海外 + IPv6 + STUN
#   mode=strict (锁1·全封闭模式):   仅放行代理入口 + 局域网(非DNS) + DHCP + TUN; 0ms 死锁全部公网(含国内+海外+Claude+IPv6+STUN)
render_pf_rules() {
    local ip_csv="${1:-}"
    local tun_if="${2:-}"
    local tun_ip="${3:-}"
    local allow_lan_dns="${4:-0}"
    local cn_file="${5:-$PF_CN_FILE}"
    local claude_v4="${6:-$ANTHROPIC_ASN_V4}"
    local lock_mode="${7:-cn}"

    if [ "$lock_mode" = "strict" ] && [ -z "$ip_csv" ]; then
        echo "FAIL:全封闭模式必须先配置代理入口节点 IP/域名，否则会无法连接代理" >&2
        return 1
    fi

    # 汇总 TUN 放行源网段（兼容 Stash/小火箭/Clash 198.18.0.0/15、v2rayN/sing-box 172.18.0.0/15，及当前 TUN 精确 IP）
    local tun_sources="198.18.0.0/15, 172.18.0.0/15"
    if [ -n "$tun_ip" ]; then
        case "$tun_ip" in
            198.18.*|198.19.*|172.18.*|172.19.*) ;;
            *) tun_sources="${tun_sources}, ${tun_ip}" ;;
        esac
    fi

    cat <<EOF
# Claude 持久化防直连硬锁 (pf Anchor: ${PF_ANCHOR_NAME}, mode=${lock_mode})
# 策略: 代理退出/软件被杀/系统死机重启后依然内核生效，直到用户再次打开软件解开锁2
table <claude_blocked_v4> persist { ${claude_v4} }
table <claude_blocked_v6> persist { ${ANTHROPIC_ASN_V6} }
table <claude_guard_lan> const { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }
EOF
    if [ -n "$ip_csv" ]; then
        echo "table <claude_guard_entries> persist { ${ip_csv} }"
    else
        echo "table <claude_guard_entries> persist"
    fi
    if [ "$lock_mode" = "cn" ] && [ -n "$cn_file" ] && [ -r "$cn_file" ]; then
        echo "table <claude_guard_cn> persist file \"${cn_file}\""
    else
        echo "table <claude_guard_cn> persist"
    fi

    cat <<EOF

# 0. 封死所有物理网卡公网 IPv6 出站并记录内核丢包日志 (根治运营商手机热点强推 IPv6 泄露)
pass out quick on lo0 inet6 all
pass out quick inet6 to fe80::/10
block drop out log quick inet6 to <claude_blocked_v6>
block drop out log quick inet6 all

# 1. 放行本机回环 + DHCP + 代理 TUN 虚拟网段 (开全局+TUN 时 Claude 与海外服务全速走隧道)
pass out quick on lo0 all
pass out quick inet proto udp from any port 68 to any port 67
pass out quick inet from { ${tun_sources} } to any
EOF
    if [ -n "$tun_if" ]; then
        echo "# 1b. 同步放行当前承载默认路由的代理接口"
        echo "pass out quick on ${tun_if} all"
    fi

    cat <<EOF

# 2. 放行白名单代理入口节点 IP (第一跳海外 VPS / 链式代理入口; 国内中转机在 cn 模式下也自动放行)
pass out quick inet to <claude_guard_entries>

# 3. 物理网卡最高优先级硬锁: 阻断 Claude/Anthropic 官方 ASN 与生态域名 IP (全协议)，以及非隧道 STUN/WebRTC UDP 端口
block drop out log quick inet to <claude_blocked_v4>
block drop out log quick inet proto udp to any port { 3478, 5349, 19302 }
EOF

    if [ "$lock_mode" = "strict" ]; then
        if [ "$allow_lan_dns" != "1" ]; then
            cat <<EOF

# 4. 全封闭模式: 阻断物理网卡向局域网路由器/运营商发送裸 DNS 查询 (入口域名由本机 hosts 托管)
block drop out log quick inet proto { tcp, udp } to <claude_guard_lan> port 53
EOF
        fi
        cat <<EOF

# 5. 仅放行局域网常规通信，其余全部物理公网(含国内+海外) 0ms DROP 并记 pflog0 日志
pass out quick inet to <claude_guard_lan>
block drop out log quick inet all
EOF
    else
        cat <<EOF

# 4. 国内直连放行模式: 放行局域网与中国大陆直连服务(关代理/退软件时国内正常上网不受影响)
pass out quick inet to <claude_guard_lan>
pass out quick inet to <claude_guard_cn>

# 5. 默认兜底硬锁: 阻断一切其他海外公网服务直连并记录 pflog0 拦截日志 (直至手动解开锁2)
block drop out log quick inet all
EOF
    fi
}

write_managed_block() {
    local file="$1" begin_m="$2" end_m="$3" body="$4"
    [ -f "$file" ] || touch "$file"
    if [ ! -f "${file}.claude-guard.bak" ]; then
        cp -p "$file" "${file}.claude-guard.bak" 2>/dev/null || true
    fi
    python3 - "$file" "$begin_m" "$end_m" "$body" <<'PY'
import sys
path, begin_m, end_m, body = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
lines = open(path, encoding="utf-8", errors="ignore").readlines()
out = []
skip = False
for line in lines:
    if begin_m in line:
        skip = True
        continue
    if skip and end_m in line:
        skip = False
        continue
    if not skip:
        out.append(line)
while out and out[-1].strip() == "":
    out.pop()
if out:
    out.append("\n")
if body.strip():
    out.append(begin_m + "\n")
    out.append(body.rstrip("\n") + "\n")
    out.append(end_m + "\n")
open(path, "w", encoding="utf-8").writelines(out)
PY
}

remove_managed_block() {
    local file="$1" begin_m="$2" end_m="$3"
    [ -f "$file" ] || return 0
    write_managed_block "$file" "$begin_m" "$end_m" ""
}

# 枚举所有已启用的活跃网络服务中未关闭 IPv6 的服务
ipv6_enabled_services() {
    local svcs svc info
    svcs=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*') || return 0
    while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        info=$(networksetup -getinfo "$svc" 2>/dev/null)
        if printf '%s\n' "$info" | grep -qi '^IPv6:' && ! printf '%s\n' "$info" | grep -qi '^IPv6:.*off'; then
            echo "$svc"
        fi
    done <<< "$svcs"
}

# 温和退出 Claude 桌面版与当前用户的 Claude Code CLI (恢复直连前必做，防切回直连瞬间泄露)
stop_claude_safely() {
    if pgrep -f '/Applications/Claude.app/Contents/MacOS/Claude' >/dev/null 2>&1; then
        osascript -e 'tell application "Claude" to quit' >/dev/null 2>&1 || true
        for _ in 1 2 3 4 5; do
            pgrep -f '/Applications/Claude.app/Contents/MacOS/Claude' >/dev/null 2>&1 || break
            sleep 1
        done
        pkill -f '/Applications/Claude.app/Contents/MacOS/Claude' 2>/dev/null || true
    fi
    local uid pids
    uid=$(id -u)
    pids=$(ps -axo pid=,uid=,comm=,args= | awk -v uid="$uid" '
        $2 == uid && ($3 ~ /(^|\/)(claude|claude\.exe)$/ ||
        ($3 ~ /(^|\/)(node|bun)$/ && $5 ~ /(^|\/)@anthropic-ai\/claude-code\/(bin\/claude(\.exe)?|cli\.js)$/)) { print $1 }')
    if [ -n "$pids" ]; then
        kill -TERM $pids 2>/dev/null || true
        sleep 1
    fi
}

# 探测当前出口国家与推荐时区
detect_geo() {
    python3 - <<'PY' 2>/dev/null || true
import json, subprocess, sys

sources = [
    ("https://ipinfo.io/json", "country", "timezone", "ip"),
    ("https://ipapi.co/json/", "country_code", "timezone", "ip"),
    ("https://ifconfig.co/json", "country_iso", "timezone", "ip"),
]
for url, cf, tf, ipf in sources:
    try:
        out = subprocess.check_output(["curl", "-s", "--max-time", "6", url], text=True, timeout=8)
        d = json.loads(out)
        cc = str(d.get(cf, "")).upper()
        tz = str(d.get(tf, ""))
        ip = str(d.get(ipf, ""))
        if len(cc) == 2 and cc.isalpha():
            print(f"{cc}|{tz}|{ip}")
            sys.exit(0)
    except Exception:
        pass
try:
    out = subprocess.check_output(["curl", "-s", "--max-time", "6", "https://www.cloudflare.com/cdn-cgi/trace"], text=True, timeout=8)
    cc = ip = ""
    for line in out.splitlines():
        if line.startswith("loc="): cc = line.split("=", 1)[1].strip().upper()
        if line.startswith("ip="): ip = line.split("=", 1)[1].strip()
    if len(cc) == 2 and cc.isalpha():
        print(f"{cc}||{ip}")
        sys.exit(0)
except Exception:
    pass
print("||")
PY
}

# ---- 内部 root 执行动作 (通过 osascript 一次提权调用) ----
_apply_lock_root() {
    local ip_csv="$1"
    local hosts_lines="$2"
    local tun_if="$3"
    local tun_ip="$4"
    local allow_dns="$5"
    local tz_to_set="${6:-}"
    local disable_v6="${7:-0}"
    local cn_src="${8:-}"
    local claude_v4="${9:-$ANTHROPIC_ASN_V4}"
    local lock_mode="${10:-cn}"

    local cn_target="$PF_CN_FILE"
    if [ "$lock_mode" = "cn" ]; then
        if [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ]; then
            cn_target="$cn_src"
        else
            mkdir -p "$(dirname "$PF_ANCHOR_FILE")" || { echo "FAIL:无法创建锚点目录"; return 1; }
            if [ -n "$cn_src" ] && [ -r "$cn_src" ]; then
                cp "$cn_src" "$PF_CN_FILE" || { echo "FAIL:无法安装中国大陆直连 IP 表"; return 1; }
                chmod 644 "$PF_CN_FILE"
            else
                echo "FAIL:缺少中国大陆直连 IP 表(cn-ipv4.txt)，已中止以防误断国内直连"
                return 1
            fi
        fi
    else
        cn_target=""
    fi

    local tmp_anchor
    tmp_anchor=$(mktemp "${TMPDIR:-/tmp}/claude-guard-pf.XXXXXX") || { echo "FAIL:无法创建临时文件"; return 1; }
    if ! render_pf_rules "$ip_csv" "$tun_if" "$tun_ip" "$allow_dns" "$cn_target" "$claude_v4" "$lock_mode" > "$tmp_anchor"; then
        rm -f "$tmp_anchor"
        return 1
    fi
    if ! pfctl -nvf "$tmp_anchor" >/dev/null 2>&1; then
        echo "FAIL:pf 规则语法校验失败，已中止"
        rm -f "$tmp_anchor"
        return 1
    fi

    if [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ]; then
        cat "$tmp_anchor"
        rm -f "$tmp_anchor"
        echo "OK:持久化硬锁演练通过 (mode=${lock_mode})"
        return 0
    fi

    mkdir -p "$(dirname "$PF_ANCHOR_FILE")" || { rm -f "$tmp_anchor"; echo "FAIL:无法创建锚点目录"; return 1; }
    mv "$tmp_anchor" "$PF_ANCHOR_FILE"
    chmod 644 "$PF_ANCHOR_FILE"

    write_managed_block "$PF_CONF" "$PF_BEGIN" "$PF_END" "anchor \"${PF_ANCHOR_NAME}\"
load anchor \"${PF_ANCHOR_NAME}\" from \"${PF_ANCHOR_FILE}\""

    if [ -n "$hosts_lines" ]; then
        write_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END" "$hosts_lines"
    else
        remove_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END"
    fi

    if [ -n "$tz_to_set" ]; then
        /usr/sbin/systemsetup -settimezone "$tz_to_set" >/dev/null 2>&1 || true
    fi

    if [ "$disable_v6" = "1" ]; then
        local svc
        while IFS= read -r svc; do
            [ -n "$svc" ] || continue
            networksetup -setv6off "$svc" >/dev/null 2>&1 || true
        done < <(ipv6_enabled_services)
    fi

    if ! pfctl -f "$PF_CONF" >/dev/null 2>&1; then
        echo "FAIL:pfctl 加载配置失败"
        return 1
    fi
    pfctl -e >/dev/null 2>&1 || true

    # 安装开机持久化 LaunchDaemon: 确保代理退出、软件退出、甚至系统重启后 pf 硬锁依然持续生效，直到用户手动关闭
    mkdir -p "$(dirname "$PF_BOOT_PLIST")" 2>/dev/null || true
    cat > "$PF_BOOT_PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>${PF_BOOT_LABEL}</string>
    <key>ProgramArguments</key><array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>/sbin/pfctl -f ${PF_CONF} &amp;&amp; /sbin/pfctl -e</string>
    </array>
    <key>RunAtLoad</key><true/>
</dict></plist>
PLISTEOF
    /usr/bin/xattr -d com.apple.quarantine "$PF_BOOT_PLIST" 2>/dev/null || true
    chown root:wheel "$PF_BOOT_PLIST" 2>/dev/null || true
    chmod 644 "$PF_BOOT_PLIST" 2>/dev/null || true
    launchctl bootout "system/${PF_BOOT_LABEL}" 2>/dev/null || true
    launchctl bootstrap system "$PF_BOOT_PLIST" 2>/dev/null || true

    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true

    echo "OK:持久化防直连硬锁已启用 (代理退出/本软件退出/重启后仍生效，已开启 pflog 丢包日志)"
}

_apply_unlock_root() {
    if [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ]; then
        echo "OK:直连模式演练通过"
        return 0
    fi
    launchctl bootout "system/${PF_BOOT_LABEL}" 2>/dev/null || true
    rm -f "$PF_BOOT_PLIST" 2>/dev/null || true
    pfctl -a "$PF_ANCHOR_NAME" -F all >/dev/null 2>&1 || true
    rm -f "$PF_ANCHOR_FILE" "$PF_CN_FILE" 2>/dev/null || true
    remove_managed_block "$PF_CONF" "$PF_BEGIN" "$PF_END"
    remove_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END"
    pfctl -f "$PF_CONF" >/dev/null 2>&1 || true
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    echo "OK:持久化防直连硬锁已关闭，已恢复直连模式 (防火墙锚点、开机守护与 hosts 托管项已彻底清除)"
}

_verify_firewall_root() {
    echo "=== 操作系统防火墙与内核流量拦截日志验收 (macOS pf) ==="
    echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "----------------------------------------------------------"

    local pf_status="未知"
    local info_out
    info_out=$(pfctl -s info 2>&1 || true)
    if printf '%s\n' "$info_out" | grep -qi 'Status: Enabled'; then
        pf_status="Enabled (内核防火墙运行中)"
    elif printf '%s\n' "$info_out" | grep -qi 'Status: Disabled'; then
        pf_status="Disabled (未启用)"
    fi
    echo "[1] pf 内核总开关状态: ${pf_status}"

    if [ -f "$PF_BOOT_PLIST" ]; then
        local ld_state="已落盘(重启自动加载)"
        launchctl print "system/${PF_BOOT_LABEL}" >/dev/null 2>&1 && ld_state="已注册并生效(代理/软件退出及重启后均持续锁定)"
        echo "[2] 开机持久化守护 (${PF_BOOT_LABEL}): ${ld_state}"
    else
        echo "[2] 开机持久化守护 (${PF_BOOT_LABEL}): 未安装 (重启后防火墙不会自动开启)"
    fi

    echo "[3] 内核内存白名单表 (<claude_guard_entries>):"
    local tbl_out
    tbl_out=$(pfctl -a "$PF_ANCHOR_NAME" -t claude_guard_entries -T show 2>/dev/null || true)
    if [ -n "$tbl_out" ]; then
        printf '%s\n' "$tbl_out" | sed 's/^/    /'
    else
        echo "    (空 / 锚点未加载)"
    fi

    echo "[4] 内核阻断规则与实时丢包计数 (pfctl -a ${PF_ANCHOR_NAME} -sr -v):"
    local rules_v
    rules_v=$(pfctl -a "$PF_ANCHOR_NAME" -sr -v 2>/dev/null || true)
    if [ -n "$rules_v" ]; then
        printf '%s\n' "$rules_v" | sed 's/^/    /'
    else
        echo "    (无活动规则)"
    fi

    echo "[5] 实时抓取内核拦截数据包日志命令 (验收时可在终端直接观察被 DROP 的包):"
    echo "    sudo tcpdump -n -e -ttt -i pflog0"
    echo "----------------------------------------------------------"
    if [ "$pf_status" = "Enabled (内核防火墙运行中)" ] && printf '%s\n' "$rules_v" | grep -q 'block drop out log quick'; then
        echo "验收结论: [✓] 操作系统防火墙硬锁已实装生效，代理与软件退出后仍持续阻断直连"
        return 0
    else
        echo "验收结论: [✗] 操作系统防火墙硬锁未处于完全锁定状态"
        return 1
    fi
}

run_as_admin() {
    local cmd_str="$1"
    local prompt="${2:-Claude 安全锁需要管理员权限}"
    if [ "$(id -u)" -eq 0 ] || [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ]; then
        eval "$cmd_str"
        return $?
    fi
    osascript - "$cmd_str" "$prompt" <<'ASEOF'
on run argv
    set cmd to item 1 of argv
    set p to item 2 of argv
    do shell script cmd with prompt p with administrator privileges
end run
ASEOF
}

cmd_set_nodes() {
    load_cfg
    local raw="${1:-}"
    if [ -z "$raw" ]; then
        ENTRY_NODES=""
        save_cfg
        echo "OK:已清空海外入口白名单(国内中转机仍自动放行)"
        return 0
    fi
    local parsed ips
    parsed=$(resolve_entries "$raw")
    ips=$(printf '%s\n' "$parsed" | sed -n 's/^IP://p')
    [ -n "$ips" ] || { echo "FAIL:未能从输入中解析出任何有效 IPv4，请检查输入: $raw"; return 1; }
    ENTRY_NODES="$raw"
    save_cfg
    echo "OK:已保存入口节点配置 ($raw)"
}

cmd_lock() {
    load_cfg
    local tz_set="${1:-}"
    local dis_v6="${2:-0}"
    local lock_mode="${3:-cn}"
    local cn_src=""
    if [ "$lock_mode" = "cn" ]; then
        cn_src=$(find_cn_list_src) || { echo "FAIL:找不到中国大陆直连 IP 表 (portable-kit/data/cn-ipv4.txt)"; return 1; }
    fi

    local parsed="" ip_csv="" hosts_lines="" tun_info tun_if tun_ip claude_v4
    if [ -n "$ENTRY_NODES" ]; then
        parsed=$(resolve_entries "$ENTRY_NODES")
        ip_csv=$(printf '%s\n' "$parsed" | sed -n 's/^IP://p' | paste -sd ',' - | sed 's/,/, /g')
        hosts_lines=$(printf '%s\n' "$parsed" | sed -n 's/^HOST://p')
    fi
    if [ "$lock_mode" = "strict" ] && [ -z "$ip_csv" ]; then
        echo "FAIL:开启「全封闭模式」前请先配置第一跳代理入口 IP 或域名"
        return 1
    fi
    tun_info=$(detect_tun_info || true)
    tun_if="${tun_info%%|*}"
    tun_ip="${tun_info#*|}"
    if [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ] || [ "${CLAUDE_GUARD_OFFLINE:-0}" = "1" ]; then
        claude_v4="$ANTHROPIC_ASN_V4"
    else
        claude_v4=$(resolve_claude_ips "$ip_csv")
    fi

    local self_path
    self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    # 用 base64 安全传递含换行的 hosts_lines，避免 shell 转义问题
    local hosts_b64
    hosts_b64=$(printf '%s' "$hosts_lines" | base64 | tr -d '\n')
    local root_cmd
    root_cmd="CLAUDE_GUARD_DRY_RUN='${CLAUDE_GUARD_DRY_RUN:-0}' CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_CN_FILE='${PF_CN_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' CLAUDE_GUARD_HOSTS='${HOSTS_FILE}' /bin/bash '${self_path}' _root-lock '${ip_csv}' '${hosts_b64}' '${tun_if}' '${tun_ip}' '${ALLOW_LAN_DNS}' '${tz_set}' '${dis_v6}' '${cn_src}' '${claude_v4}' '${lock_mode}'"
    if run_as_admin "$root_cmd" "Claude 安全锁需要管理员权限以开启持久化防直连硬锁"; then
        PERSISTENT_LOCK="$lock_mode"
        save_cfg
        return 0
    fi
    return 1
}

cmd_unlock() {
    load_cfg
    echo "正在安全关闭 Claude 桌面版与 Claude Code CLI（防止切回直连瞬间泄露）..."
    stop_claude_safely
    local self_path
    self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    local root_cmd
    root_cmd="CLAUDE_GUARD_DRY_RUN='${CLAUDE_GUARD_DRY_RUN:-0}' CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' CLAUDE_GUARD_HOSTS='${HOSTS_FILE}' /bin/bash '${self_path}' _root-unlock"
    if run_as_admin "$root_cmd" "Claude 安全锁需要管理员权限以关闭持久化防直连硬锁并恢复直连"; then
        PERSISTENT_LOCK="0"
        save_cfg
        return 0
    fi
    return 1
}

cmd_verify_firewall() {
    local self_path
    self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    local root_cmd
    root_cmd="CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' /bin/bash '${self_path}' _root-verify-firewall"
    run_as_admin "$root_cmd" "验收需要管理员权限以读取操作系统 pf 防火墙状态与内核丢包日志计数"
}

cmd_init() {
    load_cfg
    local nodes="${1:-$ENTRY_NODES}"
    local manual_country="${2:-}"

    local geo cc tz ip
    if [ -n "$manual_country" ]; then
        cc=$(printf '%s' "$manual_country" | tr 'a-z' 'A-Z')
        tz=$(default_tz_for "$cc")
        ip="手动指定"
    else
        geo=$(detect_geo)
        cc=$(printf '%s' "$geo" | cut -d'|' -f1)
        tz=$(printf '%s' "$geo" | cut -d'|' -f2)
        ip=$(printf '%s' "$geo" | cut -d'|' -f3)
        if [ -z "$cc" ] || [ "$cc" = "CN" ] || [ "$cc" = "HK" ] || [ "$cc" = "MO" ]; then
            echo "FAIL:当前出口为 ${cc:-未知}(IP=${ip:-无})，属于不支持地区！请先打开代理客户端「全局 + TUN」切至海外支持地区后再初始化"
            return 1
        fi
        [ -n "$tz" ] || tz=$(default_tz_for "$cc")
    fi

    local locale
    locale=$(default_locale_for "$cc")
    ENTRY_NODES="$nodes"
    COUNTRY_TARGET="$cc"
    TZ_TARGET="$tz"
    LOCALE_TARGET="$locale"
    save_cfg

    # 用户态配置: 地区格式 + Claude 客户端语言强制英文 (无需管理员)
    defaults write -g AppleLocale "$LOCALE_TARGET" 2>/dev/null || true
    defaults write com.anthropic.claudefordesktop AppleLanguages -array en-US 2>/dev/null || true

    # 默认开启「国内直连放行 + 硬锁 Claude 与海外」持久化硬锁 (如填写了入口且需要全封闭，可随时在锁1切换)
    cmd_lock "$TZ_TARGET" "1" "cn" || return 1
    echo "OK:一键初始化完成 | 出口=${cc}(${ip}) | 时区=${TZ_TARGET} | 地区=${LOCALE_TARGET} | Claude语言=en-US | 全接口IPv6=已关闭 | 持久化硬锁(放行国内/死锁Claude与海外)=已开启"
}

cmd_status() {
    load_cfg
    local lock_state="off"
    local lock_mode="off"
    local boot_persist="off"
    if [ -f "$PF_ANCHOR_FILE" ] && grep -Fq "$PF_BEGIN" "$PF_CONF" 2>/dev/null; then
        lock_state="on"
        if grep -Fq 'mode=strict' "$PF_ANCHOR_FILE" 2>/dev/null; then
            lock_mode="strict"
        else
            lock_mode="cn"
        fi
    fi
    if [ -f "$PF_BOOT_PLIST" ]; then
        boot_persist="on"
    fi
    echo "LOCK=${lock_state}"
    echo "LOCK_MODE=${lock_mode}"
    echo "PERSISTENT_LOCK=${boot_persist}"
    echo "ENTRY_NODES=${ENTRY_NODES:-未配置}"
    echo "COUNTRY_TARGET=${COUNTRY_TARGET:-未配置}"
    echo "TZ_TARGET=${TZ_TARGET:-未配置}"
    echo "LOCALE_TARGET=${LOCALE_TARGET:-未配置}"
}

cmd_check() {
    local self_dir audit_py export_path="${1:-}"
    self_dir="$(cd "$(dirname "$0")" && pwd)"
    audit_py="$self_dir/env-audit.py"
    if [ -r "$audit_py" ]; then
        local extra=()
        [ -n "$export_path" ] && extra+=(--export "$export_path")
        [ "${CLAUDE_GUARD_OFFLINE:-0}" = "1" ] && extra+=(--offline)
        python3 "$audit_py" --config "$CFG_FILE" --pf-conf "$PF_CONF" --pf-anchor "$PF_ANCHOR_FILE" --pf-boot-plist "$PF_BOOT_PLIST" "${extra[@]}"
        return $?
    fi
    load_cfg
    echo "FAIL:找不到 env-audit.py 深度体检引擎"
    return 1
}

cmd="${1:-status}"
shift || true
case "$cmd" in
    init)        cmd_init "${1:-}" "${2:-}" ;;
    set-nodes)   cmd_set_nodes "${1:-}" ;;
    lock|lock-cn) cmd_lock "${1:-}" "${2:-0}" "cn" ;;
    lock-strict) cmd_lock "${1:-}" "${2:-0}" "strict" ;;
    unlock|unlock-all) cmd_unlock ;;
    status)      cmd_status ;;
    check)       cmd_check "${1:-}" ;;
    verify-firewall) cmd_verify_firewall ;;
    export-report)
        out_f="${1:-$HOME/Desktop/claude-env-report-$(date +%Y%m%d-%H%M%S).txt}"
        cmd_check "$out_f"
        rc=$?
        echo "REPORT_FILE=$out_f"
        exit "$rc" ;;
    render)      render_pf_rules "$@" ;;
    _root-lock)
        ip_csv="${1:-}"
        hosts_b64="${2:-}"
        tun_if="${3:-}"
        tun_ip="${4:-}"
        allow_dns="${5:-0}"
        tz_set="${6:-}"
        dis_v6="${7:-0}"
        cn_src="${8:-}"
        claude_v4="${9:-$ANTHROPIC_ASN_V4}"
        lock_mode="${10:-cn}"
        hosts_decoded=""
        if [ -n "$hosts_b64" ]; then
            hosts_decoded=$(printf '%s' "$hosts_b64" | base64 -D 2>/dev/null || printf '%s' "$hosts_b64" | base64 -d 2>/dev/null || true)
        fi
        _apply_lock_root "$ip_csv" "$hosts_decoded" "$tun_if" "$tun_ip" "$allow_dns" "$tz_set" "$dis_v6" "$cn_src" "$claude_v4" "$lock_mode" ;;
    _root-unlock)
        _apply_unlock_root ;;
    _root-verify-firewall)
        _verify_firewall_root ;;
    *)
        echo "用法: claude-guard.sh init <入口IP或域名> [国家码] | set-nodes <入口IP或域名> | lock | unlock | verify-firewall | status | check | export-report [文件]"
        exit 2 ;;
esac
