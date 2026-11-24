#!/bin/bash
# Claude 持久化安全锁 · macOS 三态防呆核心引擎 (v2.2)
# 完美适配「代理客户端默认开全局 + TUN」工作流:
#   - 状态 1 [lock / strict]:  一级安全锁开启 (Claude 工作态) -> 一切公网流量 100% 只走代理 TUN，放行 Claude 启动
#   - 状态 2 [unlock / cn]:    一级安全锁关闭 (国内网络态)   -> 先退出 Claude 并锁死进程; 放行国内 CN 段，但持续死锁一切海外与 Claude 遥测
#   - 状态 3 [relax / standby]: 二级放宽锁打开 (防国内误伤态) -> 放宽普通公网防未收录国内 IP 误伤，但永久焊死 Claude 全版本进程锁 + 34 个主站/遥测/邮件链接黑洞 + ASN 拦截
#   - 彻底卸载 [uninstall-all]: 仅在卸载软件时解除永久进程锁与遥测硬锁，恢复出厂状态
#   - 免维护全版本自愈守护 (com.claude-guard.pfboot, KeepAlive):
#       * 运行时若 pf 规则或 hosts 黑洞被其他 VPN/软件或系统更新冲掉，自动秒级补回;
#       * 非 lock 状态下，若用户安装/升级了新版 Claude.app 或通过 npm/npx/bun 启动新版 claude CLI，自动接管锁死并强杀弹窗，永久免维护！

set -u
export LC_ALL=en_US.UTF-8

APP_DIR="${CLAUDE_GUARD_DIR:-$HOME/.claude-guard}"
CFG_FILE="$APP_DIR/config.env"
PF_ANCHOR_NAME="${CLAUDE_GUARD_ANCHOR:-com.claude-guard}"
PF_CONF="${CLAUDE_GUARD_PF_CONF:-/etc/pf.conf}"
PF_ANCHOR_FILE="${CLAUDE_GUARD_ANCHOR_FILE:-/etc/pf.anchors/${PF_ANCHOR_NAME}}"
PF_CN_FILE="${CLAUDE_GUARD_CN_FILE:-/etc/pf.anchors/${PF_ANCHOR_NAME}.cn.txt}"
PF_STATE_FILE="${CLAUDE_GUARD_STATE_FILE:-/etc/pf.anchors/${PF_ANCHOR_NAME}.state}"
PF_BOOT_LABEL="com.claude-guard.pfboot"
PF_BOOT_PLIST="${CLAUDE_GUARD_BOOT_PLIST:-/Library/LaunchDaemons/${PF_BOOT_LABEL}.plist}"
PF_BOOT_SCRIPT="${CLAUDE_GUARD_BOOT_SCRIPT:-/etc/pf.anchors/${PF_ANCHOR_NAME}.daemon.sh}"
HOSTS_FILE="${CLAUDE_GUARD_HOSTS:-/etc/hosts}"

CLAUDE_APP_PATH="${CLAUDE_GUARD_CLAUDE_APP:-/Applications/Claude.app}"
CLAUDE_HIDDEN_APP="${CLAUDE_GUARD_HIDDEN_APP:-$(dirname "$CLAUDE_APP_PATH")/.Claude-Locked.app}"
CLAUDE_BLOCKER_MARK=".claude-guard-blocker"
CLI_LOCK_STATE="${CLAUDE_GUARD_CLI_STATE:-$APP_DIR/locked-cli-paths.txt}"

ANTHROPIC_ASN_V4="160.79.104.0/21"
ANTHROPIC_ASN_V6="2607:6bc0::/48"
# 34 个全系域名: 主站 + API/CDN + MCP + 邮件点击跳转链接 + Statsig/Sentry(o1158394)/Datadog 遥测上报端点
ANTHROPIC_DOMAINS="claude.ai www.claude.ai a-cdn.claude.ai a-api.claude.ai downloads.claude.ai links.claude.ai email.claude.ai claude.com www.claude.com platform.claude.com claudemcpclient.com api.anthropic.com anthropic.com www.anthropic.com console.anthropic.com auth.anthropic.com mcp-proxy.anthropic.com docs.anthropic.com support.anthropic.com status.anthropic.com mail.anthropic.com e.anthropic.com claudeusercontent.com statsig.anthropic.com events.anthropic.com telemetry.anthropic.com o1158394.ingest.sentry.io o1158394.ingest.us.sentry.io statsigapi.net events.statsigapi.net featuregates.org prodregistryv2.org browser-intake-datadoghq.com http-intake.logs.datadoghq.com"

PF_BEGIN="# BEGIN claude-guard-pf"
PF_END="# END claude-guard-pf"
HOSTS_BEGIN="# BEGIN claude-guard-hosts"
HOSTS_END="# END claude-guard-hosts"

mkdir -p "$APP_DIR"

ENTRY_NODES=""
COUNTRY_TARGET=""
TZ_TARGET=""
LOCALE_TARGET=""
LOCK_STATE="off"     # active(一级锁开·全走TUN) | cn(一级锁关·国内白名单直连) | relax(二级放宽锁开·仅锁死Claude与遥测)

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
LOCK_STATE="${LOCK_STATE}"
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

# 自动探测当前活跃代理进程 (Stash / Shadowrocket / Clash / Mihomo / sing-box / xray / v2ray) 正在连接的远端第一跳服务器 IPv4
auto_detect_proxy_Upstream_ips() {
    lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk '
        BEGIN { IGNORECASE = 1 }
        $1 ~ /(stash|shadowrocket|verge|mihomo|clash|sing-box|v2ray|xray|hysteria|tuic|brook|naive)/ {
            # 格式: 192.168.1.5:54321->203.0.113.10:443
            n = split($9, arr, "->")
            if (n == 2) {
                split(arr[2], hp, ":")
                ip = hp[1]
                if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ &&
                    ip !~ /^(127\.|10\.|192\.168\.|169\.254\.|198\.18\.|198\.19\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)/ &&
                    ip !~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./) {
                    print ip
                }
            }
        }
    ' | sort -u | paste -sd ',' - | sed 's/,/, /g'
}

resolve_entries() {
    local raw="$1"
    python3 - "$raw" <<'PY'
import ipaddress, re, socket, sys

raw = sys.argv[1]
tokens = [t.strip() for t in re.split(r'[\s,;，；]+', raw) if t.strip()]
ips, seen, hosts = [], set(), []

def add_entry(val):
    if val not in seen:
        seen.add(val)
        ips.append(val)

for tok in tokens:
    tok = re.sub(r'^[a-zA-Z0-9+.-]+://', '', tok).split('/')[0]
    if ':' in tok and tok.count(':') == 1 and not tok.startswith('['):
        tok = tok.split(':', 1)[0]
    try:
        net = ipaddress.ip_network(tok, strict=False)
        if net.version == 4:
            add_entry(str(net.network_address) if net.prefixlen == 32 else str(net))
            continue
    except ValueError:
        pass
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

detect_tun_info() {
    local iface ip
    iface=$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2; exit}')
    case "$iface" in
        utun[0-9]*)
            ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2; exit}')
            echo "${iface}|${ip}"
            return 0 ;;
    esac
    ip=$(ifconfig 2>/dev/null | awk '/inet (198\.18\.|198\.19\.|172\.18\.|172\.19\.)/{print $2; exit}')
    if [ -n "$ip" ]; then
        echo "|${ip}"
        return 0
    fi
    echo "|"
    return 1
}

resolve_claude_ips() {
    local whitelist_csv="${1:-}"
    python3 - "$ANTHROPIC_ASN_V4" "$ANTHROPIC_DOMAINS" "$whitelist_csv" <<'PY' 2>/dev/null || echo "$ANTHROPIC_ASN_V4"
import ipaddress, json, re, subprocess, sys

asn_v4, domains_s, wl_csv = sys.argv[1], sys.argv[2], sys.argv[3]
wl = {x.strip() for x in re.split(r'[\s,]+', wl_csv) if x.strip()}
items, seen = [asn_v4], {asn_v4}

for dom in domains_s.split():
    try:
        out = subprocess.check_output(
            ["curl", "-s", "--max-time", "3", "-H", "accept: application/dns-json",
             f"https://cloudflare-dns.com/dns-query?name={dom}&type=A"],
            stderr=subprocess.DEVNULL, text=True, timeout=4
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

# 生成三态 pf 锚点规则:
#   mode=strict  (状态1 · 一级安全锁开启): 一切公网流量 100% 只走代理 TUN! 物理网卡仅放行代理入口 + 局域网(非DNS) + DHCP + TUN
#   mode=cn      (状态2 · 一级安全锁关闭): 反向规则放行国内 7,456 段 + 局域网; 持续 0ms 死锁一切海外 IP + Claude/全系遥测 + IPv6 + STUN
#   mode=standby (状态3 · 二级放宽锁打开): 放宽普通公网防国内误伤; 但物理网卡永久 0ms 死锁 Claude ASN 与 34 个主站/遥测/邮件追踪 IP
render_pf_rules() {
    local ip_csv="${1:-}"
    local tun_if="${2:-}"
    local tun_ip="${3:-}"
    local allow_lan_dns="${4:-0}"
    local cn_file="${5:-$PF_CN_FILE}"
    local claude_v4="${6:-$ANTHROPIC_ASN_V4}"
    local lock_mode="${7:-strict}"

    if [ "$lock_mode" = "strict" ] && [ -z "$ip_csv" ]; then
        echo "FAIL:开启安全锁(一切流量只走TUN)需要第一跳代理入口 IP/域名，请先开启代理自动识别或在输入框填入第一跳节点 IP" >&2
        return 1
    fi

    local tun_sources="198.18.0.0/15, 172.18.0.0/15"
    if [ -n "$tun_ip" ]; then
        case "$tun_ip" in
            198.18.*|198.19.*|172.18.*|172.19.*) ;;
            *) tun_sources="${tun_sources}, ${tun_ip}" ;;
        esac
    fi

    if [ "$lock_mode" = "standby" ]; then
        cat <<EOF
# Claude 二级放宽锁底层防线 (pf Anchor: ${PF_ANCHOR_NAME}, mode=standby)
# 说明: 普通公网已放宽防误伤，但物理网卡永久 0ms 死锁 Claude/Anthropic 官方 ASN 与 34 个遥测/邮件链接 IP (除非彻底卸载)
table <claude_blocked_v4> persist { ${claude_v4} }
table <claude_blocked_v6> persist { ${ANTHROPIC_ASN_V6} }

pass out quick on lo0 all
pass out quick inet from { ${tun_sources} } to any
EOF
        if [ -n "$tun_if" ]; then
            echo "pass out quick on ${tun_if} all"
        fi
        cat <<EOF
block drop out log quick inet to <claude_blocked_v4>
block drop out log quick inet6 to <claude_blocked_v6>
EOF
        return 0
    fi

    cat <<EOF
# Claude 持久化安全锁 (pf Anchor: ${PF_ANCHOR_NAME}, mode=${lock_mode})
table <claude_blocked_v4> persist { ${claude_v4} }
table <claude_blocked_v6> persist { ${ANTHROPIC_ASN_V6} }
table <claude_guard_lan> const { 127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }
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

# 0. 封死所有物理网卡公网 IPv6 出站并记日志
pass out quick on lo0 inet6 all
pass out quick inet6 to fe80::/10
block drop out log quick inet6 to <claude_blocked_v6>
block drop out log quick inet6 all

# 1. 放行回环 + DHCP + 代理 TUN 虚拟网段
pass out quick on lo0 all
pass out quick inet proto udp from any port 68 to any port 67
pass out quick inet from { ${tun_sources} } to any
EOF
    if [ -n "$tun_if" ]; then
        echo "pass out quick on ${tun_if} all"
    fi

    cat <<EOF

# 2. 放行白名单第一跳代理入口节点 IP
pass out quick inet to <claude_guard_entries>

# 3. 物理网卡最高优先级硬锁: 死锁 Claude/Anthropic ASN 与全系遥测 IP，以及非隧道 STUN/WebRTC UDP
block drop out log quick inet to <claude_blocked_v4>
block drop out log quick inet proto udp to any port { 3478, 5349, 19302 }
EOF

    if [ "$lock_mode" = "strict" ]; then
        if [ "$allow_lan_dns" != "1" ]; then
            cat <<EOF

# 4. 一级安全锁开启(全走TUN): 阻断物理网卡裸 DNS 53 查询
block drop out log quick inet proto { tcp, udp } to <claude_guard_lan> port 53
EOF
        fi
        cat <<EOF

# 5. 仅放行局域网保留段，其余一切公网(国内+海外) 0ms DROP，强制 100% 流量只走代理 TUN!
pass out quick inet to <claude_guard_lan>
block drop out log quick inet all
EOF
    else
        cat <<EOF

# 4. 一级安全锁关闭(国内白名单直连): 放行局域网与中国大陆 7,456 条 IP 段，但死锁一切海外与 Claude 遥测
pass out quick inet to <claude_guard_lan>
pass out quick inet to <claude_guard_cn>
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
out, skip = [], False
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

render_claude_hosts_blackhole() {
    local d
    for d in $ANTHROPIC_DOMAINS; do
        printf '0.0.0.0 %s\n:: %s\n' "$d" "$d"
    done
}

# 生成针对本机真实网络服务名的桌面《断网急救.txt》(修复差异项 #4)
write_emergency_guide_to_desktop() {
    local target_file="${1:-$HOME/Desktop/断网急救.txt}"
    local svcs_cmds="" svc
    while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        svcs_cmds="${svcs_cmds}  networksetup -setwebproxystate \"${svc}\" off && networksetup -setsecurewebproxystate \"${svc}\" off && networksetup -setsocksfirewallproxystate \"${svc}\" off\n"
    done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*')
    [ -n "$svcs_cmds" ] || svcs_cmds='  networksetup -setwebproxystate "Wi-Fi" off && networksetup -setsecurewebproxystate "Wi-Fi" off'

    mkdir -p "$(dirname "$target_file")" 2>/dev/null || true
    cat > "$target_file" <<EMGEOF
====================================================================
  Claude 安全锁 · 本机专属断网急救指南（手机拍照留存，断网照抄即通）
====================================================================

【为什么会断网？】
开启一级安全锁后，系统强制「一切公网流量 100% 只走代理 TUN」。
若代理客户端退出了、未开启「全局 + TUN」、或节点挂了，外网会被防火墙 0ms 拦截保护账号不漏 IP。

【第 1 步（最简单）】
1. 打开你的代理客户端（Stash / 小火箭 / Clash Verge / v2rayN），确认开启「全局 + TUN」，等 10 秒；
2. 若当前不想用代理，直接打开「Claude安全锁.app」点击「关闭安全锁」切换回国内网络（Claude 仍保持锁死不泄露）。

【第 2 步（若国内部分偏门网站被误拦）】
在「Claude安全锁.app」下方打开「二级放宽锁」（注意：打开期间严禁点击任何 Claude 服务及 Claude 邮件链接！）。

【第 3 步（终端终极急救命令 —— 复制粘贴到「终端」回车）】
1) 一键彻底卸载并解除全部防火墙规则：
  sudo launchctl bootout system/${PF_BOOT_LABEL} 2>/dev/null; sudo pfctl -a ${PF_ANCHOR_NAME} -F all 2>/dev/null; sudo rm -f ${PF_ANCHOR_FILE} ${PF_BOOT_PLIST} ${PF_BOOT_SCRIPT}; sudo pfctl -f /etc/pf.conf

2) 清理代理客户端异常退出残留的系统代理（已匹配你这台电脑的实际网卡名）：
$(printf '%b' "$svcs_cmds")
====================================================================
EMGEOF
}

# ---- 系统级无损进程硬锁 (支持未来任意新版自动接管) ----
lock_claude_apps_root() {
    local console_app="/Applications/Claude安全锁.app"
    if [ -d "$CLAUDE_APP_PATH" ] && [ ! -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ]; then
        if [ -d "$CLAUDE_HIDDEN_APP" ]; then
            chmod -R u+w "$CLAUDE_HIDDEN_APP" 2>/dev/null || true
            rm -rf "$CLAUDE_HIDDEN_APP" 2>/dev/null || true
        fi
        if [ -f "$CLAUDE_APP_PATH/Contents/MacOS/Claude" ]; then
            chmod a-x "$CLAUDE_APP_PATH/Contents/MacOS/Claude" 2>/dev/null || true
        fi
        mv "$CLAUDE_APP_PATH" "$CLAUDE_HIDDEN_APP" || return 1
    fi

    if [ -d "$CLAUDE_HIDDEN_APP" ] && [ ! -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ]; then
        rm -rf "$CLAUDE_APP_PATH" 2>/dev/null || true
        mkdir -p "$CLAUDE_APP_PATH/Contents/MacOS" "$CLAUDE_APP_PATH/Contents/Resources"
        local icon_file=""
        for ic in "$CLAUDE_HIDDEN_APP/Contents/Resources/"*.icns; do
            if [ -f "$ic" ]; then
                cp -f "$ic" "$CLAUDE_APP_PATH/Contents/Resources/app.icns" 2>/dev/null || true
                icon_file="app.icns"
                break
            fi
        done
        cat > "$CLAUDE_APP_PATH/Contents/Info.plist" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
    <key>CFBundleExecutable</key><string>Claude</string>
    <key>CFBundleIdentifier</key><string>com.claude-guard.claude-blocker</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>Claude</string>
    <key>CFBundleDisplayName</key><string>Claude</string>
    <key>CFBundleIconFile</key><string>${icon_file}</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
PLISTEOF
        cat > "$CLAUDE_APP_PATH/Contents/MacOS/Claude" <<BLOCKEREOF
#!/bin/bash
BTN=\$(/usr/bin/osascript <<'ASEOF' 2>/dev/null
try
    set r to display dialog "🔒 Claude 安全锁当前未开启，系统已禁止启动 Claude！

为防止暴露国内直连 IP 或向遥测服务器上报导致封号，在未开启一级安全锁期间 Claude 已被系统从底层锁死。

请按以下步骤操作：
1. 先打开代理客户端并开启「全局 + TUN」；
2. 打开「Claude安全锁」点击「开启安全锁」后再使用 Claude。" with title "⚠️ 已拦截 Claude 启动（防封号保护）" with icon stop buttons {"我知道了", "打开 Claude安全锁"} default button "打开 Claude安全锁"
    return button returned of r
on error
    return "我知道了"
end try
ASEOF
)
if [ "\$BTN" = "打开 Claude安全锁" ]; then
    open "${console_app}" 2>/dev/null || open "\$HOME/Desktop/Claude安全锁.app" 2>/dev/null || true
fi
exit 0
BLOCKEREOF
        chmod 755 "$CLAUDE_APP_PATH/Contents/MacOS/Claude"
        touch "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK"
        /usr/bin/xattr -dr com.apple.quarantine "$CLAUDE_APP_PATH" 2>/dev/null || true
    fi

    # 扫描全局与所有常见包管理器路径下的 claude CLI (含 Homebrew / npm / Volta / fnm / ~/.local/bin)
    local cand real_cli
    for cand in /usr/local/bin/claude /opt/homebrew/bin/claude "${CLAUDE_GUARD_EXTRA_CLI:-}"; do
        [ -n "$cand" ] || continue
        if [ -e "$cand" ] && ! grep -q 'CLAUDE_GUARD_CLI_BLOCKER' "$cand" 2>/dev/null; then
            real_cli="$(dirname "$cand")/.claude-guard-real-claude"
            [ -e "$real_cli" ] && rm -f "$real_cli" 2>/dev/null || true
            mv "$cand" "$real_cli" 2>/dev/null || continue
            chmod a-x "$real_cli" 2>/dev/null || true
            cat > "$cand" <<'CLIEOF'
#!/bin/bash
# CLAUDE_GUARD_CLI_BLOCKER
echo "" >&2
echo "================================================================" >&2
echo "  🔒 [已拦截] Claude 安全锁未开启，已禁止启动 Claude Code CLI！" >&2
echo "  请先开启代理（全局+TUN），并在「Claude安全锁」中开启一级安全锁。" >&2
echo "================================================================" >&2
echo "" >&2
/usr/bin/osascript -e 'display dialog "🔒 安全锁未开启，已禁止启动 Claude Code CLI！\n\n请先开启代理（全局+TUN）并在「Claude安全锁」中开启一级安全锁。" with title "⚠️ 已拦截 Claude 启动" with icon stop buttons {"我知道了"} default button "我知道了"' >/dev/null 2>&1 &
exit 1
CLIEOF
            chmod 755 "$cand" 2>/dev/null || true
            mkdir -p "$(dirname "$CLI_LOCK_STATE")" 2>/dev/null || true
            grep -Fqx "$cand" "$CLI_LOCK_STATE" 2>/dev/null || echo "$cand" >> "$CLI_LOCK_STATE"
        fi
    done
    return 0
}

unlock_claude_apps_root() {
    if [ -d "$CLAUDE_HIDDEN_APP" ]; then
        if [ -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ] || [ ! -e "$CLAUDE_APP_PATH" ]; then
            rm -rf "$CLAUDE_APP_PATH" 2>/dev/null || true
            mv "$CLAUDE_HIDDEN_APP" "$CLAUDE_APP_PATH" || return 1
        fi
    fi
    if [ -f "$CLAUDE_APP_PATH/Contents/MacOS/Claude" ] && [ ! -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ]; then
        chmod a+x "$CLAUDE_APP_PATH/Contents/MacOS/Claude" 2>/dev/null || true
    fi

    local cand real_cli
    for cand in /usr/local/bin/claude /opt/homebrew/bin/claude "${CLAUDE_GUARD_EXTRA_CLI:-}"; do
        [ -n "$cand" ] || continue
        real_cli="$(dirname "$cand")/.claude-guard-real-claude"
        if [ -e "$real_cli" ]; then
            rm -f "$cand" 2>/dev/null || true
            mv "$real_cli" "$cand" 2>/dev/null || true
            chmod a+x "$cand" 2>/dev/null || true
        fi
    done
    rm -f "$CLI_LOCK_STATE" 2>/dev/null || true
    return 0
}

# 安装 KeepAlive 常驻全版本自愈守护进程:
#   1) 每 5 秒巡检: 在非 active 状态下，若用户更新/重装了未来新版 Claude.app 或用 npx/bunx/nvm 启动任何新版 claude-code，立即强杀并自动接管锁死 (永久免维护!)
#   2) 每 30 秒巡检: 若 pf 锚点规则或 /etc/hosts 遥测黑洞被第三方 VPN/安全软件清掉或被系统升级重置，自动秒级补回!
install_pf_boot_daemon_root() {
    local mode="$1"
    local self_path
    self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    mkdir -p "$(dirname "$PF_BOOT_SCRIPT")" "$(dirname "$PF_BOOT_PLIST")" 2>/dev/null || true
    echo "$mode" > "$PF_STATE_FILE"
    chmod 644 "$PF_STATE_FILE" 2>/dev/null || true

    cat > "$PF_BOOT_SCRIPT" <<BOOTEOF
#!/bin/bash
PF_CONF="${PF_CONF}"
ANCHOR_NAME="${PF_ANCHOR_NAME}"
ANCHOR_FILE="${PF_ANCHOR_FILE}"
STATE_FILE="${PF_STATE_FILE}"
HOSTS_FILE="${HOSTS_FILE}"
CLAUDE_APP="${CLAUDE_APP_PATH}"
BLOCKER_MARK="${CLAUDE_BLOCKER_MARK}"
GUARD_SH="${self_path}"

tick=0
while true; do
    cur_mode=\$(cat "\$STATE_FILE" 2>/dev/null || echo "strict")

    # A. 非一级开锁状态下: 全版本进程守卫 (适配未来任意新版 Claude.app / npx / nvm / bunx CLI)
    if [ "\$cur_mode" != "strict" ]; then
        # 1. 若发现任意真实 Claude Desktop / Helper 或任何 @anthropic-ai/claude-code 进程偷跑，立即 SIGKILL 并弹窗
        killed=0
        if pgrep -f '/Claude\.app/Contents/MacOS/Claude ' >/dev/null 2>&1 || pgrep -f 'Claude Helper' >/dev/null 2>&1; then
            pkill -9 -f 'Claude Helper' 2>/dev/null || true
            pkill -9 -f '/\.Claude-Locked\.app/' 2>/dev/null || true
            killed=1
        fi
        cli_pids=\$(ps -axo pid=,comm=,args= | awk '
            \$2 !~ /claude-guard/ && (\$2 ~ /(^|\/)(claude|claude\.exe)\$/ || \$0 ~ /@anthropic-ai\/claude-code/) && \$0 !~ /CLAUDE_GUARD_CLI_BLOCKER/ { print \$1 }
        ')
        if [ -n "\$cli_pids" ]; then
            kill -9 \$cli_pids 2>/dev/null || true
            killed=1
        fi
        # 2. 若用户刚覆盖安装了新版 Claude.app (无 blocker 标记)，自动调用无损接管锁死!
        if [ -d "\$CLAUDE_APP" ] && [ ! -f "\$CLAUDE_APP/\$BLOCKER_MARK" ] && [ -x "\$GUARD_SH" ]; then
            CLAUDE_GUARD_CLAUDE_APP="\$CLAUDE_APP" /bin/bash "\$GUARD_SH" _root-relock-apps >/dev/null 2>&1 || true
        fi
    fi

    # B. 每 30 秒 (6 ticks) 自愈巡检 pf 内核防火墙与 hosts 遥测黑洞，被别的软件清掉自动补回
    if [ \$((tick % 6)) -eq 0 ] && [ -f "\$ANCHOR_FILE" ]; then
        need_reload=0
        if ! grep -Fq "anchor \"\${ANCHOR_NAME}\"" "\$PF_CONF" 2>/dev/null; then
            printf '\n# BEGIN claude-guard-pf\nanchor "%s"\nload anchor "%s" from "%s"\n# END claude-guard-pf\n' "\$ANCHOR_NAME" "\$ANCHOR_NAME" "\$ANCHOR_FILE" >> "\$PF_CONF"
            need_reload=1
        fi
        if ! /sbin/pfctl -s info 2>/dev/null | grep -qi 'Status: Enabled'; then
            need_reload=1
        elif ! /sbin/pfctl -a "\$ANCHOR_NAME" -sr 2>/dev/null | grep -q 'block drop out log quick'; then
            need_reload=1
        fi
        if [ "\$need_reload" = "1" ]; then
            /sbin/pfctl -f "\$PF_CONF" >/dev/null 2>&1 || true
            /sbin/pfctl -e >/dev/null 2>&1 || true
        fi
        if [ "\$cur_mode" != "strict" ] && ! grep -Fq "statsig.anthropic.com" "\$HOSTS_FILE" 2>/dev/null && [ -x "\$GUARD_SH" ]; then
            /bin/bash "\$GUARD_SH" _root-restore-blackhole >/dev/null 2>&1 || true
        fi
    fi

    tick=\$((tick + 1))
    sleep 5
done
BOOTEOF
    chmod 755 "$PF_BOOT_SCRIPT"
    chown root:wheel "$PF_BOOT_SCRIPT" 2>/dev/null || true

    cat > "$PF_BOOT_PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>${PF_BOOT_LABEL}</string>
    <key>ProgramArguments</key><array>
        <string>/bin/bash</string>
        <string>${PF_BOOT_SCRIPT}</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict></plist>
PLISTEOF
    /usr/bin/xattr -d com.apple.quarantine "$PF_BOOT_PLIST" 2>/dev/null || true
    chown root:wheel "$PF_BOOT_PLIST" 2>/dev/null || true
    chmod 644 "$PF_BOOT_PLIST" 2>/dev/null || true
    launchctl bootout "system/${PF_BOOT_LABEL}" 2>/dev/null || true
    launchctl bootstrap system "$PF_BOOT_PLIST" 2>/dev/null || true
}

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

stop_claude_safely() {
    if pgrep -f '/Claude\.app/' >/dev/null 2>&1; then
        osascript -e 'tell application "Claude" to quit' >/dev/null 2>&1 || true
        for _ in 1 2 3 4; do
            pgrep -f '/Claude\.app/' >/dev/null 2>&1 || break
            sleep 1
        done
        pkill -9 -f '/Claude\.app/' 2>/dev/null || true
    fi
    pkill -9 -f 'Claude Helper' 2>/dev/null || true
    local uid pids
    uid=$(id -u)
    pids=$(ps -axo pid=,uid=,comm=,args= | awk -v uid="$uid" '
        $2 == uid && ($3 ~ /(^|\/)(claude|claude\.exe)$/ || $0 ~ /@anthropic-ai\/claude-code/) && $0 !~ /claude-guard/ { print $1 }')
    if [ -n "$pids" ]; then
        kill -TERM $pids 2>/dev/null || true
        sleep 1
        kill -KILL $pids 2>/dev/null || true
    fi
}

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
        cc, tz, ip = str(d.get(cf, "")).upper(), str(d.get(tf, "")), str(d.get(ipf, ""))
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

# ---- 内部 root 应用三态 ----
_apply_mode_root() {
    local ip_csv="$1"
    local hosts_lines="$2"
    local tun_if="$3"
    local tun_ip="$4"
    local allow_dns="$5"
    local tz_to_set="${6:-}"
    local disable_v6="${7:-0}"
    local cn_src="${8:-}"
    local claude_v4="${9:-$ANTHROPIC_ASN_V4}"
    local lock_mode="${10:-strict}"  # strict | cn | standby

    local cn_target="$PF_CN_FILE"
    if [ "$lock_mode" = "cn" ]; then
        if [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ]; then
            cn_target="$cn_src"
        else
            mkdir -p "$(dirname "$PF_ANCHOR_FILE")" || { echo "FAIL:无法创建锚点目录"; return 1; }
            if [ -n "$cn_src" ] && [ -r "$cn_src" ]; then
                cp "$cn_src" "$PF_CN_FILE" || { echo "FAIL:无法安装中国大陆 IP 表"; return 1; }
                chmod 644 "$PF_CN_FILE"
            else
                echo "FAIL:缺少中国大陆直连 IP 表(cn-ipv4.txt)"
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
        if [ "$lock_mode" = "strict" ]; then
            unlock_claude_apps_root || return 1
            if [ -n "$hosts_lines" ]; then
                write_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END" "$hosts_lines"
            else
                remove_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END"
            fi
        else
            lock_claude_apps_root || return 1
            write_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END" "$(render_claude_hosts_blackhole)"
        fi
        echo "OK:安全锁演练通过 (mode=${lock_mode})"
        return 0
    fi

    # 若不是 strict 工作态，必须先锁死 Claude 进程并写入 34 个主站/遥测/邮件链接黑洞!
    if [ "$lock_mode" != "strict" ]; then
        lock_claude_apps_root || true
        write_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END" "$(render_claude_hosts_blackhole)"
    fi

    mkdir -p "$(dirname "$PF_ANCHOR_FILE")" || { rm -f "$tmp_anchor"; echo "FAIL:无法创建锚点目录"; return 1; }
    mv "$tmp_anchor" "$PF_ANCHOR_FILE"
    chmod 644 "$PF_ANCHOR_FILE"

    write_managed_block "$PF_CONF" "$PF_BEGIN" "$PF_END" "anchor \"${PF_ANCHOR_NAME}\"
load anchor \"${PF_ANCHOR_NAME}\" from \"${PF_ANCHOR_FILE}\""

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
    install_pf_boot_daemon_root "$lock_mode"

    # 仅在一级安全锁(strict 全走 TUN) 100% 生效后，才移除遥测黑洞并放行 Claude 进程!
    if [ "$lock_mode" = "strict" ]; then
        if [ -n "$hosts_lines" ]; then
            write_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END" "$hosts_lines"
        else
            remove_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END"
        fi
        unlock_claude_apps_root || true
        dscacheutil -flushcache 2>/dev/null || true
        killall -HUP mDNSResponder 2>/dev/null || true
        echo "OK:一级安全锁已开启！一切公网流量 100% 强制只走代理 TUN，Claude 已安全放行。"
    elif [ "$lock_mode" = "cn" ]; then
        dscacheutil -flushcache 2>/dev/null || true
        killall -HUP mDNSResponder 2>/dev/null || true
        echo "OK:已退出 Claude 并切回国内白名单网络！一切海外与 Claude 遥测服务器持续 0ms 阻断，Claude 进程已锁死。"
    else
        dscacheutil -flushcache 2>/dev/null || true
        killall -HUP mDNSResponder 2>/dev/null || true
        echo "OK:二级放宽锁已打开（防未收录国内流量误伤）！⚠️ 请严禁打开任何 Claude 服务及点击 Claude 邮件链接（底层 Claude 进程锁与遥测黑洞仍持续保护中）。"
    fi
}

_apply_uninstall_root() {
    if [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ]; then
        unlock_claude_apps_root || return 1
        remove_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END"
        echo "OK:彻底卸载演练通过"
        return 0
    fi
    unlock_claude_apps_root || true
    launchctl bootout "system/${PF_BOOT_LABEL}" 2>/dev/null || true
    rm -f "$PF_BOOT_PLIST" "$PF_BOOT_SCRIPT" "$PF_STATE_FILE" 2>/dev/null || true
    pfctl -a "$PF_ANCHOR_NAME" -F all >/dev/null 2>&1 || true
    rm -f "$PF_ANCHOR_FILE" "$PF_CN_FILE" 2>/dev/null || true
    remove_managed_block "$PF_CONF" "$PF_BEGIN" "$PF_END"
    remove_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END"
    pfctl -f "$PF_CONF" >/dev/null 2>&1 || true
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    echo "OK:已彻底解除所有系统级进程锁与防火墙规则，电脑已完全恢复出厂状态。"
}

_verify_firewall_root() {
    echo "=== 操作系统防火墙、全版本进程守卫与丢包日志验收 (macOS pf) ==="
    echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "----------------------------------------------------------"

    local pf_status="未知" info_out
    info_out=$(pfctl -s info 2>&1 || true)
    if printf '%s\n' "$info_out" | grep -qi 'Status: Enabled'; then
        pf_status="Enabled (内核防火墙运行中)"
    elif printf '%s\n' "$info_out" | grep -qi 'Status: Disabled'; then
        pf_status="Disabled (未启用)"
    fi
    echo "[1] pf 内核总开关状态: ${pf_status}"

    if [ -f "$PF_BOOT_PLIST" ] && [ -x "$PF_BOOT_SCRIPT" ]; then
        echo "[2] KeepAlive 全版本进程锁与自愈守护 (${PF_BOOT_LABEL}): 运行中 (每5秒拦截偷跑进程/新版App，每30秒自愈防火墙)"
    else
        echo "[2] KeepAlive 全版本进程锁与自愈守护 (${PF_BOOT_LABEL}): 未安装"
    fi

    if [ -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ]; then
        echo "[3] Claude 进程系统级死锁: 已锁死 (非工作态，双击 Claude 仅弹窗不启动真进程)"
    elif [ -d "$CLAUDE_APP_PATH" ]; then
        echo "[3] Claude 进程系统级死锁: 已放行 (一级安全锁开启中，100% 流量只走 TUN)"
    else
        echo "[3] Claude 进程系统级死锁: 未检测到 /Applications/Claude.app (未来安装时守护将自动接管)"
    fi

    echo "[4] 内核阻断规则与实时丢包计数 (pfctl -a ${PF_ANCHOR_NAME} -sr -v):"
    local rules_v
    rules_v=$(pfctl -a "$PF_ANCHOR_NAME" -sr -v 2>/dev/null || true)
    if [ -n "$rules_v" ]; then
        printf '%s\n' "$rules_v" | sed 's/^/    /'
    else
        echo "    (无活动规则)"
    fi

    echo "[5] 实时抓取内核拦截数据包日志命令:"
    echo "    sudo tcpdump -n -e -ttt -i pflog0"
    echo "----------------------------------------------------------"
    if [ "$pf_status" = "Enabled (内核防火墙运行中)" ] && printf '%s\n' "$rules_v" | grep -q 'block drop out log quick'; then
        echo "验收结论: [✓] 操作系统防火墙硬锁与自愈守护已实装生效"
        return 0
    else
        echo "验收结论: [✗] 操作系统防火墙未处于锁定状态"
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
        echo "OK:已清空手动入口节点配置(开锁时将自动探测当前活跃代理入口 IP)"
        return 0
    fi
    local parsed ips
    parsed=$(resolve_entries "$raw")
    ips=$(printf '%s\n' "$parsed" | sed -n 's/^IP://p')
    [ -n "$ips" ] || { echo "FAIL:未能从输入中解析出有效 IPv4: $raw"; return 1; }
    ENTRY_NODES="$raw"
    save_cfg
    echo "OK:已保存第一跳入口节点白名单 ($raw)"
}

# 状态 1: 开启一级安全锁 (默认且强制 strict: 一切公网流量 100% 只走 TUN!)
cmd_lock() {
    load_cfg
    local tz_set="${1:-}"
    local dis_v6="${2:-0}"
    local lock_mode="${3:-strict}"

    local cn_src=""
    if [ "$lock_mode" = "cn" ]; then
        cn_src=$(find_cn_list_src) || { echo "FAIL:找不到中国大陆直连 IP 表 (data/cn-ipv4.txt)"; return 1; }
    fi

    local parsed="" ip_csv="" hosts_lines="" tun_info tun_if tun_ip claude_v4
    if [ -n "$ENTRY_NODES" ]; then
        parsed=$(resolve_entries "$ENTRY_NODES")
        ip_csv=$(printf '%s\n' "$parsed" | sed -n 's/^IP://p' | paste -sd ',' - | sed 's/,/, /g')
        hosts_lines=$(printf '%s\n' "$parsed" | sed -n 's/^HOST://p')
    fi
    # 若用户未手动填写第一跳入口 IP，自动从当前活跃代理进程 (Stash/小火箭/Clash/v2rayN) 抓取正在连接的服务器 IP!
    if [ -z "$ip_csv" ]; then
        ip_csv=$(auto_detect_proxy_Upstream_ips || true)
        if [ -n "$ip_csv" ]; then
            ENTRY_NODES="$ip_csv"
            save_cfg
        fi
    fi
    if [ "$lock_mode" = "strict" ] && [ -z "$ip_csv" ]; then
        echo "FAIL:未检测到活跃代理连接，请在代理软件开启「全局+TUN」重试，或在「代理入口白名单」手动填入第一跳节点 IP"
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

    local self_path hosts_b64 root_cmd
    self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    hosts_b64=$(printf '%s' "$hosts_lines" | base64 | tr -d '\n')
    root_cmd="CLAUDE_GUARD_DRY_RUN='${CLAUDE_GUARD_DRY_RUN:-0}' CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_CN_FILE='${PF_CN_FILE}' CLAUDE_GUARD_STATE_FILE='${PF_STATE_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' CLAUDE_GUARD_BOOT_SCRIPT='${PF_BOOT_SCRIPT}' CLAUDE_GUARD_HOSTS='${HOSTS_FILE}' CLAUDE_GUARD_CLAUDE_APP='${CLAUDE_APP_PATH}' CLAUDE_GUARD_HIDDEN_APP='${CLAUDE_HIDDEN_APP}' CLAUDE_GUARD_EXTRA_CLI='${CLAUDE_GUARD_EXTRA_CLI:-}' CLAUDE_GUARD_CLI_STATE='${CLI_LOCK_STATE}' /bin/bash '${self_path}' _root-apply '${ip_csv}' '${hosts_b64}' '${tun_if}' '${tun_ip}' '0' '${tz_set}' '${dis_v6}' '${cn_src}' '${claude_v4}' '${lock_mode}'"
    if run_as_admin "$root_cmd" "Claude 安全锁需要管理员权限以启用全走 TUN 硬锁"; then
        if [ "$lock_mode" = "strict" ]; then LOCK_STATE="active"; else LOCK_STATE="cn"; fi
        save_cfg
        return 0
    fi
    return 1
}

# 状态 2: 关闭一级安全锁 -> 退出 Claude + 反向白名单放行国内网络 + 持续死锁海外与 Claude 遥测 + 锁死进程!
cmd_unlock() {
    load_cfg
    echo "正在安全退出 Claude 桌面版、所有 Helper 与 Claude Code CLI..."
    stop_claude_safely
    cmd_lock "" "0" "cn"
}

# 状态 3: 打开二级放宽锁 -> 放宽普通公网防未收录国内 IP 误伤，但持续锁死 Claude 全版本进程与 34 个遥测/邮件链接黑洞!
cmd_relax() {
    load_cfg
    echo "正在确保所有 Claude 进程已彻底退出..."
    stop_claude_safely
    local tun_info tun_if tun_ip claude_v4
    tun_info=$(detect_tun_info || true)
    tun_if="${tun_info%%|*}"
    tun_ip="${tun_info#*|}"
    if [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ] || [ "${CLAUDE_GUARD_OFFLINE:-0}" = "1" ]; then
        claude_v4="$ANTHROPIC_ASN_V4"
    else
        claude_v4=$(resolve_claude_ips "")
    fi
    local self_path root_cmd
    self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    root_cmd="CLAUDE_GUARD_DRY_RUN='${CLAUDE_GUARD_DRY_RUN:-0}' CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_STATE_FILE='${PF_STATE_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' CLAUDE_GUARD_BOOT_SCRIPT='${PF_BOOT_SCRIPT}' CLAUDE_GUARD_HOSTS='${HOSTS_FILE}' CLAUDE_GUARD_CLAUDE_APP='${CLAUDE_APP_PATH}' CLAUDE_GUARD_HIDDEN_APP='${CLAUDE_HIDDEN_APP}' CLAUDE_GUARD_EXTRA_CLI='${CLAUDE_GUARD_EXTRA_CLI:-}' CLAUDE_GUARD_CLI_STATE='${CLI_LOCK_STATE}' /bin/bash '${self_path}' _root-apply '' '' '${tun_if}' '${tun_ip}' '0' '' '0' '' '${claude_v4}' 'standby'"
    if run_as_admin "$root_cmd" "打开二级放宽锁需要管理员权限（底层 Claude 进程与遥测黑洞将继续锁定）"; then
        LOCK_STATE="relax"
        save_cfg
        return 0
    fi
    return 1
}

cmd_uninstall_all() {
    load_cfg
    stop_claude_safely
    local self_path root_cmd
    self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    root_cmd="CLAUDE_GUARD_DRY_RUN='${CLAUDE_GUARD_DRY_RUN:-0}' CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_STATE_FILE='${PF_STATE_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' CLAUDE_GUARD_BOOT_SCRIPT='${PF_BOOT_SCRIPT}' CLAUDE_GUARD_HOSTS='${HOSTS_FILE}' CLAUDE_GUARD_CLAUDE_APP='${CLAUDE_APP_PATH}' CLAUDE_GUARD_HIDDEN_APP='${CLAUDE_HIDDEN_APP}' CLAUDE_GUARD_EXTRA_CLI='${CLAUDE_GUARD_EXTRA_CLI:-}' CLAUDE_GUARD_CLI_STATE='${CLI_LOCK_STATE}' /bin/bash '${self_path}' _root-uninstall"
    run_as_admin "$root_cmd" "彻底卸载需要管理员权限以还原 Claude 与系统防火墙配置"
}

cmd_verify_firewall() {
    local self_path root_cmd
    self_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    root_cmd="CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' CLAUDE_GUARD_BOOT_SCRIPT='${PF_BOOT_SCRIPT}' CLAUDE_GUARD_CLAUDE_APP='${CLAUDE_APP_PATH}' /bin/bash '${self_path}' _root-verify-firewall"
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
    [ -n "$nodes" ] && ENTRY_NODES="$nodes"
    COUNTRY_TARGET="$cc"
    TZ_TARGET="$tz"
    LOCALE_TARGET="$locale"
    save_cfg

    defaults write -g AppleLocale "$LOCALE_TARGET" 2>/dev/null || true
    defaults write com.anthropic.claudefordesktop AppleLanguages -array en-US 2>/dev/null || true

    # 自动在客户桌面生成匹配本机实际网卡名的《断网急救.txt》
    write_emergency_guide_to_desktop "$HOME/Desktop/断网急救.txt" 2>/dev/null || true

    cmd_lock "$TZ_TARGET" "1" "strict" || return 1
    echo "OK:一键初始化完成 | 出口=${cc}(${ip}) | 时区=${TZ_TARGET} | 地区=${LOCALE_TARGET} | 已在桌面生成《断网急救.txt》 | 一级安全锁(100%只走TUN)=已开启"
}

cmd_status() {
    load_cfg
    local lock_state="off"
    local lock_mode="off"
    local boot_persist="off"
    local proc_locked="off"
    if [ -f "$PF_ANCHOR_FILE" ] && grep -Fq "$PF_BEGIN" "$PF_CONF" 2>/dev/null; then
        if grep -Fq 'mode=strict' "$PF_ANCHOR_FILE" 2>/dev/null; then
            lock_state="on"
            lock_mode="strict"
        elif grep -Fq 'mode=cn' "$PF_ANCHOR_FILE" 2>/dev/null; then
            lock_state="cn"
            lock_mode="cn"
        elif grep -Fq 'mode=standby' "$PF_ANCHOR_FILE" 2>/dev/null; then
            lock_state="relax"
            lock_mode="standby"
        fi
    fi
    [ -f "$PF_BOOT_PLIST" ] && boot_persist="on"
    [ -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ] && proc_locked="on"
    echo "LOCK=${lock_state}"
    echo "LOCK_MODE=${lock_mode}"
    echo "PROC_LOCKED=${proc_locked}"
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
    echo "FAIL:找不到 env-audit.py 深度体检引擎"
    return 1
}

cmd="${1:-status}"
shift || true
case "$cmd" in
    init)            cmd_init "${1:-}" "${2:-}" ;;
    set-nodes)       cmd_set_nodes "${1:-}" ;;
    lock|lock-strict) cmd_lock "${1:-}" "${2:-0}" "strict" ;;
    unlock|lock-cn)  cmd_unlock ;;
    relax)           cmd_relax ;;
    write-emergency) write_emergency_guide_to_desktop "${1:-$HOME/Desktop/断网急救.txt}" && echo "OK:已在桌面生成本机专属《断网急救.txt》" ;;
    uninstall-all)   cmd_uninstall_all ;;
    status)          cmd_status ;;
    check)           cmd_check "${1:-}" ;;
    verify-firewall) cmd_verify_firewall ;;
    export-report)
        out_f="${1:-$HOME/Desktop/claude-env-report-$(date +%Y%m%d-%H%M%S).txt}"
        cmd_check "$out_f"
        rc=$?
        echo "REPORT_FILE=$out_f"
        exit "$rc" ;;
    render)          render_pf_rules "$@" ;;
    _root-apply)
        hosts_decoded=""
        if [ -n "${2:-}" ]; then
            hosts_decoded=$(printf '%s' "${2}" | base64 -D 2>/dev/null || printf '%s' "${2}" | base64 -d 2>/dev/null || true)
        fi
        _apply_mode_root "${1:-}" "$hosts_decoded" "${3:-}" "${4:-}" "${5:-0}" "${6:-}" "${7:-0}" "${8:-}" "${9:-$ANTHROPIC_ASN_V4}" "${10:-strict}" ;;
    _root-relock-apps)
        lock_claude_apps_root ;;
    _root-restore-blackhole)
        write_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END" "$(render_claude_hosts_blackhole)" ;;
    _root-uninstall)
        _apply_uninstall_root ;;
    _root-verify-firewall)
        _verify_firewall_root ;;
    *)
        echo "用法: claude-guard.sh init [入口IP] | set-nodes <入口IP> | lock | unlock | relax | write-emergency | uninstall-all | verify-firewall | status | check | export-report"
        exit 2 ;;
esac
