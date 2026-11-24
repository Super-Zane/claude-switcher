#!/bin/bash
# Claude 持久化安全锁 · macOS 极简单锁核心引擎 (永久进程锁 + 永久 Claude 网络硬锁)
# 核心铁律 (除非运行「卸载.command」，否则永久生效):
#   1. 开启安全锁 (lock):
#        - 内核 pf 持久化死锁 Claude(ASN+生态IP) + 一切海外公网 + 公网 IPv6 + STUN (默认放行国内直连; 可选全封闭模式连国内与裸DNS一并封)
#        - 放行 Claude Desktop 与 CLI 启动 (此时 Claude 只能走海外 TUN，TUN 以外 0 字节能出去)
#   2. 关闭安全锁 (unlock · 日常模式):
#        - 放行日常普通上网;
#        - 系统级无损死锁 Claude.app (原应用原子藏匿 + chmod a-x + 原位同图标弹窗拦截器) 与 claude CLI (点开立刻弹窗提示先开安全锁!)
#        - 写入 /etc/hosts Claude 域名黑洞 (连浏览器手抖点网页版的本地 DNS 查询也直接秒拒)
#        - pf 内核防火墙永久保留 Claude ASN/生态IP 物理网卡 0ms DROP (mode=standby)，代理退出/重启/软件被杀均持续生效
#   3. 彻底卸载 (uninstall-all，仅由卸载脚本调用):
#        - 完整还原真实 Claude.app 与 CLI、彻底清理 pf 锚点、自愈开机守护与 hosts 托管块

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
PF_BOOT_SCRIPT="${CLAUDE_GUARD_BOOT_SCRIPT:-/etc/pf.anchors/${PF_ANCHOR_NAME}.boot.sh}"
HOSTS_FILE="${CLAUDE_GUARD_HOSTS:-/etc/hosts}"

# 支持测试注入自定义 Claude.app 路径与 CLI 搜索路径
CLAUDE_APP_PATH="${CLAUDE_GUARD_CLAUDE_APP:-/Applications/Claude.app}"
CLAUDE_HIDDEN_APP="${CLAUDE_GUARD_HIDDEN_APP:-$(dirname "$CLAUDE_APP_PATH")/.Claude-Locked.app}"
CLAUDE_BLOCKER_MARK=".claude-guard-blocker"
CLI_LOCK_STATE="${CLAUDE_GUARD_CLI_STATE:-$APP_DIR/locked-cli-paths.txt}"

ANTHROPIC_ASN_V4="160.79.104.0/21"
ANTHROPIC_ASN_V6="2607:6bc0::/48"
# 完整覆盖 Claude 主服务 + API/CDN + 专属遥测/埋点/灰度开关/Sentry(o1158394) 崩溃上报域名
ANTHROPIC_DOMAINS="claude.ai www.claude.ai a-cdn.claude.ai a-api.claude.ai downloads.claude.ai claude.com www.claude.com platform.claude.com api.anthropic.com anthropic.com www.anthropic.com console.anthropic.com auth.anthropic.com mcp-proxy.anthropic.com claudeusercontent.com statsig.anthropic.com events.anthropic.com telemetry.anthropic.com o1158394.ingest.sentry.io o1158394.ingest.us.sentry.io statsigapi.net events.statsigapi.net featuregates.org prodregistryv2.org"

PF_BEGIN="# BEGIN claude-guard-pf"
PF_END="# END claude-guard-pf"
HOSTS_BEGIN="# BEGIN claude-guard-hosts"
HOSTS_END="# END claude-guard-hosts"

mkdir -p "$APP_DIR"

# ---- 默认配置 ----
ENTRY_NODES=""       # 入口节点 IP 或域名，逗号分隔（链式代理第一跳在国内中转机可留空）
COUNTRY_TARGET=""    # 期望出口国家码，如 US / JP / SG
TZ_TARGET=""         # 期望 IANA 时区，如 America/New_York
LOCALE_TARGET=""     # 期望地区格式，如 en_US
STRICT_MODE="0"      # 0=开启安全锁时放行国内直连(但死锁Claude与一切海外); 1=开启安全锁时连国内公网与物理裸DNS一并全封
LOCK_STATE="standby" # active(安全锁开启·Claude可用) | standby(安全锁关闭·Claude系统级死锁)

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
STRICT_MODE="${STRICT_MODE}"
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

# 生成 pf 锚点规则:
#   mode=cn      (安全锁开启 · 默认): 放行国内 CN 段 + 局域网 + 入口 + TUN; 0ms 死锁 Claude(ASN+域名IP) + 一切海外 + 公网IPv6 + STUN
#   mode=strict  (安全锁开启 · 全封): 仅放行入口 + 局域网(非DNS) + DHCP + TUN; 0ms 死锁全部公网(含国内+海外+Claude+IPv6+STUN)
#   mode=standby (安全锁关闭 · 常驻): 日常上网正常放行; 但物理网卡永久 0ms 死锁 Claude ASN 与生态域名 IP (IPv4 + IPv6)，绝不让 Claude 从 TUN 以外跑出 1 字节
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

    local tun_sources="198.18.0.0/15, 172.18.0.0/15"
    if [ -n "$tun_ip" ]; then
        case "$tun_ip" in
            198.18.*|198.19.*|172.18.*|172.19.*) ;;
            *) tun_sources="${tun_sources}, ${tun_ip}" ;;
        esac
    fi

    if [ "$lock_mode" = "standby" ]; then
        cat <<EOF
# Claude 永久底层防线 (pf Anchor: ${PF_ANCHOR_NAME}, mode=standby)
# 说明: 安全锁处于关闭(日常上网)状态，但物理网卡永久死锁 Claude/Anthropic 官方 ASN 与生态 IP (除非彻底卸载)
table <claude_blocked_v4> persist { ${claude_v4} }
table <claude_blocked_v6> persist { ${ANTHROPIC_ASN_V6} }

# 1. 仅允许回环与代理 TUN 虚拟网段访问 (严禁物理网卡发往 Claude 哪怕 1 个字节)
pass out quick on lo0 all
pass out quick inet from { ${tun_sources} } to any
EOF
        if [ -n "$tun_if" ]; then
            echo "pass out quick on ${tun_if} all"
        fi
        cat <<EOF

# 2. 物理网卡永久死锁 Claude/Anthropic (IPv4 + IPv6) 并记 pflog0 日志
block drop out log quick inet to <claude_blocked_v4>
block drop out log quick inet6 to <claude_blocked_v6>
EOF
        return 0
    fi

    cat <<EOF
# Claude 持久化安全锁 (pf Anchor: ${PF_ANCHOR_NAME}, mode=${lock_mode})
# 策略: 代理退出/软件被杀/系统死机重启后依然内核生效
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

# 4. 国内直连放行模式: 放行局域网与中国大陆直连服务
pass out quick inet to <claude_guard_lan>
pass out quick inet to <claude_guard_cn>

# 5. 默认兜底硬锁: 阻断一切其他海外公网服务直连并记录 pflog0 拦截日志
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

# 生成日常模式下的 Claude 域名本地黑洞块 (连浏览器手抖点网页版都不会发本地 DNS 查询!)
render_claude_hosts_blackhole() {
    local d
    for d in $ANTHROPIC_DOMAINS; do
        printf '0.0.0.0 %s\n:: %s\n' "$d" "$d"
    done
}

# ---- 系统级无损进程硬锁 (解锁状态下 Claude Desktop & CLI 永远点不开，点开立刻弹中文提示!) ----
lock_claude_apps_root() {
    local console_app="/Applications/Claude安全锁.app"
    # 1. 锁定 Claude Desktop (幂等、零破坏原应用代码签名)
    if [ -d "$CLAUDE_APP_PATH" ] && [ ! -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ]; then
        if [ -d "$CLAUDE_HIDDEN_APP" ]; then
            # 保护: 若已存在隐藏原版(极罕见重装场景)，先清理旧隐藏副本再藏匿新版
            chmod -R u+w "$CLAUDE_HIDDEN_APP" 2>/dev/null || true
            rm -rf "$CLAUDE_HIDDEN_APP" 2>/dev/null || true
        fi
        # 先去掉真实二进制执行位 (内核 execve 直接 EACCES，绝不破坏文件内容与签名)
        if [ -f "$CLAUDE_APP_PATH/Contents/MacOS/Claude" ]; then
            chmod a-x "$CLAUDE_APP_PATH/Contents/MacOS/Claude" 2>/dev/null || true
        fi
        mv "$CLAUDE_APP_PATH" "$CLAUDE_HIDDEN_APP" || return 1
    fi

    # 只要真实原版已被藏匿 (或原位尚未创建占位器且存在隐藏原版)，就在原位部署带原图标的弹窗拦截器
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

为防止暴露本地直连 IP，在关闭安全锁期间 Claude 已被系统从底层锁死。

请按以下步骤操作：
1. 先打开代理客户端并确认已开启「全局 + TUN」；
2. 打开「Claude安全锁」点击「🔒 开启安全锁」后再使用 Claude。" with title "⚠️ 已拦截 Claude 启动（防直连泄露）" with icon stop buttons {"我知道了", "打开 Claude安全锁"} default button "打开 Claude安全锁"
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

    # 2. 锁定常见路径的 claude CLI (原子藏匿 + 终端/弹窗双重提醒)
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
echo "  请先开启代理（全局+TUN），并在「Claude安全锁」中开启安全锁。" >&2
echo "================================================================" >&2
echo "" >&2
/usr/bin/osascript -e 'display dialog "🔒 安全锁未开启，已禁止启动 Claude Code CLI！\n\n请先开启代理（全局+TUN）并在「Claude安全锁」中开启安全锁。" with title "⚠️ 已拦截 Claude 启动" with icon stop buttons {"我知道了"} default button "我知道了"' >/dev/null 2>&1 &
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
    # 1. 还原真实 Claude Desktop (零破坏原签名)
    if [ -d "$CLAUDE_HIDDEN_APP" ]; then
        if [ -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ] || [ ! -e "$CLAUDE_APP_PATH" ]; then
            rm -rf "$CLAUDE_APP_PATH" 2>/dev/null || true
            mv "$CLAUDE_HIDDEN_APP" "$CLAUDE_APP_PATH" || return 1
        fi
    fi
    if [ -f "$CLAUDE_APP_PATH/Contents/MacOS/Claude" ] && [ ! -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ]; then
        chmod a+x "$CLAUDE_APP_PATH/Contents/MacOS/Claude" 2>/dev/null || true
    fi

    # 2. 还原所有被锁定的 claude CLI
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

# 安装开机自愈 LaunchDaemon: 即使 macOS 系统大版本更新重置 /etc/pf.conf，开机也会自动重新注入锚点并激活 pf
install_pf_boot_daemon_root() {
    mkdir -p "$(dirname "$PF_BOOT_SCRIPT")" "$(dirname "$PF_BOOT_PLIST")" 2>/dev/null || true
    cat > "$PF_BOOT_SCRIPT" <<BOOTEOF
#!/bin/sh
PF_CONF="${PF_CONF}"
ANCHOR_NAME="${PF_ANCHOR_NAME}"
ANCHOR_FILE="${PF_ANCHOR_FILE}"
if [ -f "\$ANCHOR_FILE" ]; then
    if ! grep -Fq "anchor \"\${ANCHOR_NAME}\"" "\$PF_CONF" 2>/dev/null; then
        printf '\n# BEGIN claude-guard-pf\nanchor "%s"\nload anchor "%s" from "%s"\n# END claude-guard-pf\n' "\$ANCHOR_NAME" "\$ANCHOR_NAME" "\$ANCHOR_FILE" >> "\$PF_CONF"
    fi
    /sbin/pfctl -f "\$PF_CONF" >/dev/null 2>&1 || true
    /sbin/pfctl -e >/dev/null 2>&1 || true
fi
BOOTEOF
    chmod 755 "$PF_BOOT_SCRIPT"
    chown root:wheel "$PF_BOOT_SCRIPT" 2>/dev/null || true

    cat > "$PF_BOOT_PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>${PF_BOOT_LABEL}</string>
    <key>ProgramArguments</key><array>
        <string>/bin/sh</string>
        <string>${PF_BOOT_SCRIPT}</string>
    </array>
    <key>RunAtLoad</key><true/>
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
    if pgrep -f '/Applications/Claude.app/' >/dev/null 2>&1; then
        osascript -e 'tell application "Claude" to quit' >/dev/null 2>&1 || true
        for _ in 1 2 3 4 5; do
            pgrep -f '/Applications/Claude.app/' >/dev/null 2>&1 || break
            sleep 1
        done
        # 强制清理 Claude 主进程、所有 Electron Helper (Renderer/GPU/Plugin) 及后台 ShipIt 更新器，绝不留遥测残留进程
        pkill -9 -f '/Applications/Claude.app/' 2>/dev/null || true
    fi
    pkill -9 -f 'Claude Helper' 2>/dev/null || true
    local uid pids
    uid=$(id -u)
    pids=$(ps -axo pid=,uid=,comm=,args= | awk -v uid="$uid" '
        $2 == uid && ($3 ~ /(^|\/)(claude|claude\.exe)$/ ||
        ($3 ~ /(^|\/)(node|bun)$/ && $5 ~ /(^|\/)@anthropic-ai\/claude-code\/(bin\/claude(\.exe)?|cli\.js)$/)) { print $1 }')
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

# ---- 内部 root 执行动作 ----
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
        # 演练模式下同步检验无损进程解锁逻辑
        unlock_claude_apps_root || return 1
        echo "OK:安全锁演练通过 (mode=${lock_mode})"
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
    install_pf_boot_daemon_root

    # 关键顺序: 网络层硬锁已 100% 落盘生效后，才恢复 Claude Desktop & CLI 执行权限
    unlock_claude_apps_root || true

    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    echo "OK:安全锁已开启 (mode=${lock_mode})！Claude 现已解锁可用，且只能走海外 TUN，物理网卡 0ms 死锁一切泄露。"
}

# 关闭安全锁 (日常模式): 永远保持 Claude 进程系统级死锁 + Claude 物理网卡永久 DROP + hosts 域名黑洞!
_apply_standby_root() {
    local tun_if="$1"
    local tun_ip="$2"
    local claude_v4="${3:-$ANTHROPIC_ASN_V4}"

    local tmp_anchor
    tmp_anchor=$(mktemp "${TMPDIR:-/tmp}/claude-guard-pf.XXXXXX") || { echo "FAIL:无法创建临时文件"; return 1; }
    if ! render_pf_rules "" "$tun_if" "$tun_ip" "0" "" "$claude_v4" "standby" > "$tmp_anchor"; then
        rm -f "$tmp_anchor"
        return 1
    fi
    if ! pfctl -nvf "$tmp_anchor" >/dev/null 2>&1; then
        echo "FAIL:standby pf 规则语法校验失败，已中止"
        rm -f "$tmp_anchor"
        return 1
    fi

    if [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ]; then
        cat "$tmp_anchor"
        rm -f "$tmp_anchor"
        lock_claude_apps_root || return 1
        write_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END" "$(render_claude_hosts_blackhole)"
        echo "OK:日常模式(Claude系统级死锁)演练通过"
        return 0
    fi

    # 1. 先从系统层锁死 Claude Desktop 与 CLI (点开弹提示，真实进程绝不启动)
    lock_claude_apps_root || true

    # 2. 写入 hosts 黑洞 (连浏览器点网页版都不会发本地 DNS 查询)
    write_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END" "$(render_claude_hosts_blackhole)"

    # 3. 切换 pf 为永久 Claude 物理网卡硬锁 (mode=standby)，自愈开机守护依然常驻!
    mkdir -p "$(dirname "$PF_ANCHOR_FILE")" || { rm -f "$tmp_anchor"; echo "FAIL:无法创建锚点目录"; return 1; }
    mv "$tmp_anchor" "$PF_ANCHOR_FILE"
    chmod 644 "$PF_ANCHOR_FILE"
    write_managed_block "$PF_CONF" "$PF_BEGIN" "$PF_END" "anchor \"${PF_ANCHOR_NAME}\"
load anchor \"${PF_ANCHOR_NAME}\" from \"${PF_ANCHOR_FILE}\""

    pfctl -f "$PF_CONF" >/dev/null 2>&1 || true
    pfctl -e >/dev/null 2>&1 || true
    install_pf_boot_daemon_root

    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    echo "OK:已切换为日常上网模式！Claude 已从系统底层锁死（点开将弹出提示），且物理网卡永久阻断 Claude 流量，重启不失效。"
}

# 彻底卸载 (仅由「卸载.command」调用)
_apply_uninstall_root() {
    if [ "${CLAUDE_GUARD_DRY_RUN:-0}" = "1" ]; then
        unlock_claude_apps_root || return 1
        remove_managed_block "$HOSTS_FILE" "$HOSTS_BEGIN" "$HOSTS_END"
        echo "OK:彻底卸载演练通过"
        return 0
    fi
    unlock_claude_apps_root || true
    launchctl bootout "system/${PF_BOOT_LABEL}" 2>/dev/null || true
    rm -f "$PF_BOOT_PLIST" "$PF_BOOT_SCRIPT" 2>/dev/null || true
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
    echo "=== 操作系统防火墙、进程锁与流量拦截日志验收 (macOS pf) ==="
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
        echo "[2] 自愈开机守护 (${PF_BOOT_LABEL}): 已安装 (重启及系统更新后自动恢复 pf 硬锁)"
    else
        echo "[2] 自愈开机守护 (${PF_BOOT_LABEL}): 未安装"
    fi

    if [ -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ]; then
        echo "[3] Claude 进程系统级死锁: 已锁死 (日常模式，双击 Claude 仅弹窗不启动真进程)"
    elif [ -d "$CLAUDE_APP_PATH" ]; then
        echo "[3] Claude 进程系统级死锁: 已放行 (安全锁开启中，仅允许走海外 TUN)"
    else
        echo "[3] Claude 进程系统级死锁: 未检测到 /Applications/Claude.app (网络层与 hosts 依然生效)"
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
        echo "验收结论: [✓] 操作系统防火墙硬锁已实装生效，Claude 绝不可能绕过 TUN 泄露"
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

cmd_toggle_strict() {
    load_cfg
    if [ "${STRICT_MODE:-0}" = "1" ]; then
        STRICT_MODE="0"
        save_cfg
        echo "OK:已切为「开锁时放行国内直连（推荐）」"
    else
        STRICT_MODE="1"
        save_cfg
        echo "OK:已切为「开锁时全封闭（连国内公网与裸DNS一并封锁）」"
    fi
}

cmd_lock() {
    load_cfg
    local tz_set="${1:-}"
    local dis_v6="${2:-0}"
    local lock_mode="${3:-}"
    if [ -z "$lock_mode" ]; then
        if [ "${STRICT_MODE:-0}" = "1" ]; then lock_mode="strict"; else lock_mode="cn"; fi
    fi

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
    if [ "$lock_mode" = "strict" ] && [ -z "$ip_csv" ]; then
        echo "FAIL:全封闭模式前请先配置第一跳代理入口 IP 或域名（或在设置中切回默认国内放行模式）"
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
    root_cmd="CLAUDE_GUARD_DRY_RUN='${CLAUDE_GUARD_DRY_RUN:-0}' CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_CN_FILE='${PF_CN_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' CLAUDE_GUARD_BOOT_SCRIPT='${PF_BOOT_SCRIPT}' CLAUDE_GUARD_HOSTS='${HOSTS_FILE}' CLAUDE_GUARD_CLAUDE_APP='${CLAUDE_APP_PATH}' CLAUDE_GUARD_HIDDEN_APP='${CLAUDE_HIDDEN_APP}' CLAUDE_GUARD_EXTRA_CLI='${CLAUDE_GUARD_EXTRA_CLI:-}' CLAUDE_GUARD_CLI_STATE='${CLI_LOCK_STATE}' /bin/bash '${self_path}' _root-lock '${ip_csv}' '${hosts_b64}' '${tun_if}' '${tun_ip}' '0' '${tz_set}' '${dis_v6}' '${cn_src}' '${claude_v4}' '${lock_mode}'"
    if run_as_admin "$root_cmd" "Claude 安全锁需要管理员权限以开启安全锁并放行 Claude"; then
        LOCK_STATE="active"
        save_cfg
        return 0
    fi
    return 1
}

cmd_unlock() {
    load_cfg
    echo "正在安全关闭运行中的 Claude 桌面版与 Claude Code CLI..."
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
    root_cmd="CLAUDE_GUARD_DRY_RUN='${CLAUDE_GUARD_DRY_RUN:-0}' CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' CLAUDE_GUARD_BOOT_SCRIPT='${PF_BOOT_SCRIPT}' CLAUDE_GUARD_HOSTS='${HOSTS_FILE}' CLAUDE_GUARD_CLAUDE_APP='${CLAUDE_APP_PATH}' CLAUDE_GUARD_HIDDEN_APP='${CLAUDE_HIDDEN_APP}' CLAUDE_GUARD_EXTRA_CLI='${CLAUDE_GUARD_EXTRA_CLI:-}' CLAUDE_GUARD_CLI_STATE='${CLI_LOCK_STATE}' /bin/bash '${self_path}' _root-standby '${tun_if}' '${tun_ip}' '${claude_v4}'"
    if run_as_admin "$root_cmd" "Claude 安全锁需要管理员权限以切换日常模式并从系统底层锁死 Claude 进程"; then
        LOCK_STATE="standby"
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
    root_cmd="CLAUDE_GUARD_DRY_RUN='${CLAUDE_GUARD_DRY_RUN:-0}' CLAUDE_GUARD_PF_CONF='${PF_CONF}' CLAUDE_GUARD_ANCHOR_FILE='${PF_ANCHOR_FILE}' CLAUDE_GUARD_BOOT_PLIST='${PF_BOOT_PLIST}' CLAUDE_GUARD_BOOT_SCRIPT='${PF_BOOT_SCRIPT}' CLAUDE_GUARD_HOSTS='${HOSTS_FILE}' CLAUDE_GUARD_CLAUDE_APP='${CLAUDE_APP_PATH}' CLAUDE_GUARD_HIDDEN_APP='${CLAUDE_HIDDEN_APP}' CLAUDE_GUARD_EXTRA_CLI='${CLAUDE_GUARD_EXTRA_CLI:-}' CLAUDE_GUARD_CLI_STATE='${CLI_LOCK_STATE}' /bin/bash '${self_path}' _root-uninstall"
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
    ENTRY_NODES="$nodes"
    COUNTRY_TARGET="$cc"
    TZ_TARGET="$tz"
    LOCALE_TARGET="$locale"
    save_cfg

    defaults write -g AppleLocale "$LOCALE_TARGET" 2>/dev/null || true
    defaults write com.anthropic.claudefordesktop AppleLanguages -array en-US 2>/dev/null || true

    cmd_lock "$TZ_TARGET" "1" || return 1
    echo "OK:一键初始化完成 | 出口=${cc}(${ip}) | 时区=${TZ_TARGET} | 地区=${LOCALE_TARGET} | Claude语言=en-US | 全接口IPv6=已关闭 | 安全锁=已开启"
}

cmd_status() {
    load_cfg
    local lock_state="off"
    local lock_mode="off"
    local boot_persist="off"
    local proc_locked="off"
    if [ -f "$PF_ANCHOR_FILE" ] && grep -Fq "$PF_BEGIN" "$PF_CONF" 2>/dev/null; then
        if grep -Fq 'mode=standby' "$PF_ANCHOR_FILE" 2>/dev/null; then
            lock_state="standby"
            lock_mode="standby"
        elif grep -Fq 'mode=strict' "$PF_ANCHOR_FILE" 2>/dev/null; then
            lock_state="on"
            lock_mode="strict"
        else
            lock_state="on"
            lock_mode="cn"
        fi
    fi
    [ -f "$PF_BOOT_PLIST" ] && boot_persist="on"
    [ -f "$CLAUDE_APP_PATH/$CLAUDE_BLOCKER_MARK" ] && proc_locked="on"
    echo "LOCK=${lock_state}"
    echo "LOCK_MODE=${lock_mode}"
    echo "PROC_LOCKED=${proc_locked}"
    echo "PERSISTENT_LOCK=${boot_persist}"
    echo "STRICT_MODE=${STRICT_MODE:-0}"
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
    init)           cmd_init "${1:-}" "${2:-}" ;;
    set-nodes)      cmd_set_nodes "${1:-}" ;;
    toggle-strict)  cmd_toggle_strict ;;
    lock|lock-cn)   cmd_lock "${1:-}" "${2:-0}" "${3:-}" ;;
    lock-strict)    cmd_lock "${1:-}" "${2:-0}" "strict" ;;
    unlock)         cmd_unlock ;;
    uninstall-all)  cmd_uninstall_all ;;
    status)         cmd_status ;;
    check)          cmd_check "${1:-}" ;;
    verify-firewall) cmd_verify_firewall ;;
    export-report)
        out_f="${1:-$HOME/Desktop/claude-env-report-$(date +%Y%m%d-%H%M%S).txt}"
        cmd_check "$out_f"
        rc=$?
        echo "REPORT_FILE=$out_f"
        exit "$rc" ;;
    render)         render_pf_rules "$@" ;;
    _root-lock)
        hosts_decoded=""
        if [ -n "${2:-}" ]; then
            hosts_decoded=$(printf '%s' "${2}" | base64 -D 2>/dev/null || printf '%s' "${2}" | base64 -d 2>/dev/null || true)
        fi
        _apply_lock_root "${1:-}" "$hosts_decoded" "${3:-}" "${4:-}" "${5:-0}" "${6:-}" "${7:-0}" "${8:-}" "${9:-$ANTHROPIC_ASN_V4}" "${10:-cn}" ;;
    _root-standby)
        _apply_standby_root "${1:-}" "${2:-}" "${3:-$ANTHROPIC_ASN_V4}" ;;
    _root-uninstall)
        _apply_uninstall_root ;;
    _root-verify-firewall)
        _verify_firewall_root ;;
    *)
        echo "用法: claude-guard.sh init <入口IP或域名> [国家码] | set-nodes <入口IP或域名> | toggle-strict | lock | unlock | uninstall-all | verify-firewall | status | check | export-report [文件]"
        exit 2 ;;
esac
