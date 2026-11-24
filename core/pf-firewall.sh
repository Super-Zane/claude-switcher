#!/bin/bash
# Claude Switcher macOS 内核级 pf 防直连锚点管理器
# 作用: 在内核层阻断所有非隧道物理网卡(含 Wi-Fi / 有线 / 手机热点 / 断网重连窗口)直连 Anthropic 生态
#       以及非隧道 STUN/WebRTC UDP 泄露; 允许 lo0 本地代理与代理 TUN 虚拟网段通行。
# 支持环境变量覆盖路径以便离线测试:
#   CLAUDE_PF_CONF, CLAUDE_PF_ANCHOR_FILE, CLAUDE_PF_ANCHOR_NAME, CLAUDE_PF_CACHE_DIR, CLAUDE_PF_DRY_RUN

set -u

ANCHOR_NAME="${CLAUDE_PF_ANCHOR_NAME:-com.claude-switcher}"
PF_CONF="${CLAUDE_PF_CONF:-/etc/pf.conf}"
ANCHOR_FILE="${CLAUDE_PF_ANCHOR_FILE:-/etc/pf.anchors/${ANCHOR_NAME}}"
CACHE_DIR="${CLAUDE_PF_CACHE_DIR:-/Library/Application Support/claude-switcher/pf}"
USER_CACHE_DIR="${HOME:-/tmp}/.claude-switcher/pf"
BEGIN_MARK="# BEGIN claude-switcher-pf"
END_MARK="# END claude-switcher-pf"

# Anthropic 官方专属段 (AS399358)，永远不会误伤国内正常流量或用户常规 VPS
STATIC_V4_CIDRS="160.79.104.0/21"
STATIC_V6_CIDRS="2607:6bc0::/48"

# 需要动态解析保护的核心域名 (仅在确认通过安全代理路径时解析)
ANTHROPIC_DOMAINS="claude.ai api.anthropic.com claudeusercontent.com statsig.anthropic.com claude.com"

# 代理 TUN 常见私网/假 IP 网段
TUN_NETS_V4="198.18.0.0/15, 172.18.0.0/15"

_read_list_file() {
    local f="$1"
    [ -r "$f" ] || return 0
    grep -Ev '^[[:space:]]*(#|$)' "$f" 2>/dev/null | tr -d '\r' | sort -u
}

# 从常见代理配置中提取用户 VPS 服务器 IPv4 加入白名单，避免 CDN 中转节点与 claude.ai IP 冲突
collect_proxy_server_ips() {
    python3 - "${HOME:-}" <<'PY' 2>/dev/null || true
import ipaddress
import json
import os
import re
import sys

home = sys.argv[1]
if not home or not os.path.isdir(home):
    sys.exit(0)

candidates = [
    os.path.join(home, ".V2RayU", "config.json"),
    os.path.join(home, "Library", "Application Support", "v2rayN", "guiConfigs", "config.json"),
    os.path.join(home, "Library", "Application Support", "v2rayN", "guiConfigs", "guiNConfig.json"),
    os.path.join(home, "Library", "Application Support", "io.github.clash-verge-rev.clash-verge-rev", "clash-verge.yaml"),
]

ips = set()

def maybe_add_ip(val):
    if not isinstance(val, str):
        return
    val = val.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(val)
    except ValueError:
        return
    if ip.version == 4 and ip.is_global:
        # 绝不将 Anthropic 官方段误加白名单
        if ip not in ipaddress.ip_network("160.79.104.0/21"):
            ips.add(str(ip))

def walk_json(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("address", "server", "host", "ip") and isinstance(v, str):
                maybe_add_ip(v)
            else:
                walk_json(v)
    elif isinstance(obj, list):
        for item in obj:
            walk_json(item)

for path in candidates:
    if not os.path.isfile(path):
        continue
    try:
        raw = open(path, "r", encoding="utf-8", errors="ignore").read()
    except OSError:
        continue
    if path.endswith(".json"):
        try:
            walk_json(json.loads(raw))
        except Exception:
            pass
    else:
        for m in re.finditer(r'(?m)^\s*(?:-\s*)?server:\s*["\']?([0-9.]+)["\']?', raw):
            maybe_add_ip(m.group(1))

for ip in sorted(ips):
    print(ip)
PY
}

# 严格在代理链路安全时通过 DoH (经由本地代理/TUN) 解析目标域名最新公网 IP，绝不走裸 DNS
resolve_anthropic_ips() {
    local proxy_url="${1:-}"
    python3 - "$proxy_url" "$ANTHROPIC_DOMAINS" <<'PY' 2>/dev/null || true
import ipaddress
import json
import subprocess
import sys

proxy_url = sys.argv[1].strip()
domains = sys.argv[2].split()
v4_set = set()
v6_set = set()

def is_safe_public(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    if ip.version == 4:
        if not ip.is_global:
            return None
        if ip in ipaddress.ip_network("198.18.0.0/15"):
            return None
        return ("v4", str(ip))
    else:
        if not ip.is_global:
            return None
        return ("v6", str(ip))

for domain in domains:
    for rtype in ("A", "AAAA"):
        cmd = [
            "curl", "-s", "--max-time", "5",
            "-H", "accept: application/dns-json",
        ]
        if proxy_url:
            cmd.extend(["--proxy", proxy_url])
        cmd.append(f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}")
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=7)
            data = json.loads(out)
        except Exception:
            continue
        for ans in data.get("Answer") or []:
            res = is_safe_public(str(ans.get("data", "")).strip())
            if not res:
                continue
            ver, addr = res
            if ver == "v4":
                v4_set.add(addr)
            else:
                v6_set.add(addr)

for ip in sorted(v4_set):
    print(f"V4:{ip}")
for ip in sorted(v6_set):
    print(f"V6:{ip}")
PY
}

# 探测当前承担默认路由的代理 utun 接口名 (避免把系统自带的 iCloud utun0 误当代理)
detect_active_tun_if() {
    local iface
    iface=$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2; exit}')
    case "$iface" in
        utun[0-9]*) echo "$iface" ;;
        *) echo "" ;;
    esac
}

# 生成完整 pf 锚点文本 (纯文本输出，不改系统，便于单元测试与 pfctl -nvf 校验)
render_rules() {
    local extra_v4_file="${1:-}"
    local extra_v6_file="${2:-}"
    local whitelist_file="${3:-}"
    local active_tun_if="${4:-}"

    local v4_items v6_items wl_items
    v4_items=$(python3 - "$STATIC_V4_CIDRS" "$extra_v4_file" "$whitelist_file" <<'PY'
import ipaddress, os, sys
static_raw, extra_f, wl_f = sys.argv[1], sys.argv[2], sys.argv[3]
wl = set()
if wl_f and os.path.isfile(wl_f):
    for line in open(wl_f, encoding="utf-8", errors="ignore"):
        s = line.strip()
        if s and not s.startswith("#"):
            wl.add(s)
items = []
seen = set()
def add(entry):
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return
    if net.version != 4:
        return
    # 若某精确单 IP 在用户代理白名单中，跳过不封
    if net.prefixlen == 32 and str(net.network_address) in wl:
        return
    key = str(net.network_address) if net.prefixlen == 32 else str(net)
    if key not in seen:
        seen.add(key)
        items.append(key)
for s in static_raw.split():
    add(s)
if extra_f and os.path.isfile(extra_f):
    for line in open(extra_f, encoding="utf-8", errors="ignore"):
        add(line)
print(", ".join(items))
PY
)
    v6_items=$(python3 - "$STATIC_V6_CIDRS" "$extra_v6_file" <<'PY'
import ipaddress, os, sys
static_raw, extra_f = sys.argv[1], sys.argv[2]
items = []
seen = set()
def add(entry):
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return
    if net.version != 6:
        return
    key = str(net.network_address) if net.prefixlen == 128 else str(net)
    if key not in seen:
        seen.add(key)
        items.append(key)
for s in static_raw.split():
    add(s)
if extra_f and os.path.isfile(extra_f):
    for line in open(extra_f, encoding="utf-8", errors="ignore"):
        add(line)
print(", ".join(items))
PY
)
    wl_items=$(python3 - "$whitelist_file" <<'PY'
import ipaddress, os, sys
wl_f = sys.argv[1]
items = []
seen = set()
if wl_f and os.path.isfile(wl_f):
    for line in open(wl_f, encoding="utf-8", errors="ignore"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            continue
        if ip.version == 4 and ip.is_global and str(ip) not in seen:
            seen.add(str(ip))
            items.append(str(ip))
print(", ".join(items))
PY
)

    cat <<EOF
# Claude Switcher Fail-Closed PF Anchor (${ANCHOR_NAME})
# 内核级防直连兜底: 覆盖 TUN 忘开 / VPS 掉线回落 DIRECT / 手机热点新接口与 IPv6 / 断网与重连毫秒窗口
table <anthropic_blocked_v4> persist { ${v4_items} }
table <anthropic_blocked_v6> persist { ${v6_items} }
EOF
    if [ -n "$wl_items" ]; then
        echo "table <claude_proxy_whitelist> persist { ${wl_items} }"
    else
        echo "table <claude_proxy_whitelist> persist"
    fi

    cat <<EOF

# 1. 放行本机回环接口 (支持 V2RayU / v2rayN / Clash 本地 HTTP/SOCKS 代理端口)
pass out quick on lo0 all

# 2. 放行代理 TUN 虚拟网段流量 (兼容 Clash 198.18.0.0/15 与 v2rayN/sing-box 172.18.0.0/15)
pass out quick inet from { ${TUN_NETS_V4} } to any
EOF
    if [ -n "$active_tun_if" ]; then
        echo "# 2b. 放行当前承载默认路由的代理 TUN 接口"
        echo "pass out quick on ${active_tun_if} all"
    fi

    cat <<EOF

# 3. 放行用户代理服务器 IP (防止 Cloudflare CDN 节点与目标域名同 IP 被误封)
pass out quick inet to <claude_proxy_whitelist>

# 4. 阻断所有物理接口(含 Wi-Fi/以太网/USB或Wi-Fi手机热点)直连 Anthropic 生态 (IPv4 + IPv6)
block drop out quick inet proto { tcp, udp } to <anthropic_blocked_v4>
block drop out quick inet6 proto { tcp, udp } to <anthropic_blocked_v6>

# 5. 阻断非隧道物理接口的 STUN/TURN UDP 探测端口 (防止切网/热点瞬间 WebRTC 泄露)
block drop out quick inet proto udp to any port { 3478, 5349, 19302 }
block drop out quick inet6 proto udp to any port { 3478, 5349, 19302 }
EOF
}

# 将锚点挂接到 /etc/pf.conf (幂等 + 改前备份)
ensure_pf_conf_hook() {
    [ -f "$PF_CONF" ] || { echo "FAIL:找不到 pf 配置文件: $PF_CONF" >&2; return 1; }
    if grep -Fq "$BEGIN_MARK" "$PF_CONF"; then
        return 0
    fi
    cp -p "$PF_CONF" "${PF_CONF}.claude-switcher.bak" || {
        echo "FAIL:无法备份 $PF_CONF" >&2
        return 1
    }
    cat >> "$PF_CONF" <<EOF

${BEGIN_MARK}
anchor "${ANCHOR_NAME}"
load anchor "${ANCHOR_NAME}" from "${ANCHOR_FILE}"
${END_MARK}
EOF
}

remove_pf_conf_hook() {
    [ -f "$PF_CONF" ] || return 0
    grep -Fq "$BEGIN_MARK" "$PF_CONF" || return 0
    python3 - "$PF_CONF" "$BEGIN_MARK" "$END_MARK" <<'PY'
import sys
path, start_m, end_m = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path, encoding="utf-8").readlines()
out = []
skip = False
for line in lines:
    if start_m in line:
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
open(path, "w", encoding="utf-8").writelines(out)
PY
}

enable_firewall() {
    local resolve_flag=0
    local proxy_url=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --resolve) resolve_flag=1 ;;
            --proxy) shift; proxy_url="${1:-}" ;;
        esac
        shift || true
    done

    local cdir="$CACHE_DIR"
    mkdir -p "$cdir" 2>/dev/null || { cdir="$USER_CACHE_DIR"; mkdir -p "$cdir" 2>/dev/null || cdir="/tmp/claude-switcher-pf"; mkdir -p "$cdir"; }

    local v4_file="$cdir/dynamic_v4.txt"
    local v6_file="$cdir/dynamic_v6.txt"
    local wl_file="$cdir/whitelist_v4.txt"

    collect_proxy_server_ips > "$wl_file"

    if [ "$resolve_flag" -eq 1 ]; then
        local resolved
        resolved=$(resolve_anthropic_ips "$proxy_url")
        if [ -n "$resolved" ]; then
            printf '%s\n' "$resolved" | sed -n 's/^V4://p' > "$v4_file"
            printf '%s\n' "$resolved" | sed -n 's/^V6://p' > "$v6_file"
        fi
    fi

    local tun_if
    tun_if=$(detect_active_tun_if)

    local tmp_anchor
    tmp_anchor=$(mktemp "${TMPDIR:-/tmp}/claude-pf.XXXXXX") || { echo "FAIL:无法创建临时文件"; return 1; }
    render_rules "$v4_file" "$v6_file" "$wl_file" "$tun_if" > "$tmp_anchor"

    # 上线前必须通过 pfctl 语法校验
    if ! pfctl -nvf "$tmp_anchor" >/dev/null 2>&1; then
        echo "FAIL:生成的 pf 锚点规则语法校验失败，已中止"
        rm -f "$tmp_anchor"
        return 1
    fi

    if [ "${CLAUDE_PF_DRY_RUN:-0}" = "1" ]; then
        cat "$tmp_anchor"
        rm -f "$tmp_anchor"
        echo "OK:pf 规则校验通过(演练模式)"
        return 0
    fi

    mkdir -p "$(dirname "$ANCHOR_FILE")" || { rm -f "$tmp_anchor"; echo "FAIL:无法创建锚点目录"; return 1; }
    mv "$tmp_anchor" "$ANCHOR_FILE" || { rm -f "$tmp_anchor"; echo "FAIL:无法写入 $ANCHOR_FILE"; return 1; }
    chmod 644 "$ANCHOR_FILE" 2>/dev/null || true

    ensure_pf_conf_hook || return 1

    if ! pfctl -f "$PF_CONF" >/dev/null 2>&1; then
        echo "FAIL:pfctl 加载主配置失败"
        return 1
    fi
    # pfctl -E 会持有引用计数确保 pf 开启; 若已启用也安全幂等
    pfctl -e >/dev/null 2>&1 || true

    local v4_cnt
    v4_cnt=$(pfctl -a "$ANCHOR_NAME" -t anthropic_blocked_v4 -T show 2>/dev/null | grep -c . || echo 0)
    echo "OK:pf 防直连锚点已启用(${ANCHOR_NAME}, 拦截IPv4条目=${v4_cnt}${tun_if:+, TUN接口=${tun_if}})"
}

disable_firewall() {
    if [ "${CLAUDE_PF_DRY_RUN:-0}" = "1" ]; then
        echo "OK:pf 锚点已停用(演练模式)"
        return 0
    fi
    pfctl -a "$ANCHOR_NAME" -F all >/dev/null 2>&1 || true
    rm -f "$ANCHOR_FILE" 2>/dev/null || true
    remove_pf_conf_hook || true
    pfctl -f "$PF_CONF" >/dev/null 2>&1 || true
    echo "OK:pf 防直连锚点已移除(${ANCHOR_NAME})"
}

status_firewall() {
    if [ ! -f "$ANCHOR_FILE" ]; then
        echo "warn:未安装(建议运行一键修复开启内核防直连)"
        return 1
    fi
    if ! grep -Fq "$BEGIN_MARK" "$PF_CONF" 2>/dev/null; then
        echo "warn:锚点未挂接到 pf.conf(请运行一键修复)"
        return 1
    fi
    local pf_info
    pf_info=$(pfctl -s info 2>/dev/null || true)
    if [ -n "$pf_info" ]; then
        if ! printf '%s\n' "$pf_info" | grep -qi 'Status: Enabled'; then
            echo "fail:pf 防火墙未启用(规则未生效)"
            return 1
        fi
        local rules_cnt v4_cnt
        rules_cnt=$(pfctl -a "$ANCHOR_NAME" -sr 2>/dev/null | grep -c 'block drop out' || echo 0)
        v4_cnt=$(pfctl -a "$ANCHOR_NAME" -t anthropic_blocked_v4 -T show 2>/dev/null | grep -c . || echo 0)
        if [ "$rules_cnt" -ge 2 ] 2>/dev/null; then
            echo "ok:pf 锚点运行中(${rules_cnt}条阻断规则/${v4_cnt}条IPv4目标)"
            return 0
        fi
        echo "fail:pf 锚点已安装但未加载阻断规则"
        return 1
    fi
    # 非 root 用户调用 pfctl -s info 可能无权限，降级校验配置文件完整性并提示状态
    if grep -q 'block drop out quick' "$ANCHOR_FILE" 2>/dev/null; then
        echo "ok:pf 锚点已配置(${ANCHOR_NAME}, 非root只读核验)"
        return 0
    fi
    echo "warn:pf 锚点文件异常，请重新启用"
    return 1
}

cmd="${1:-status}"
shift || true
case "$cmd" in
    render)  render_rules "$@" ;;
    enable)  enable_firewall "$@" ;;
    refresh) enable_firewall --resolve "$@" ;;
    disable) disable_firewall ;;
    status)  status_firewall ;;
    *)
        echo "用法: pf-firewall.sh status|enable [--resolve] [--proxy URL]|refresh [--proxy URL]|disable|render"
        exit 2 ;;
esac
