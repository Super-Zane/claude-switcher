#!/bin/bash
# Claude 保镖 (参考模板) —— 安装程序会把 __HOME__ / __PROXY_MODE__ / __COUNTRY_TARGET__ 替换为实际值后安装
# 作用:
#   1. 代理(内核/TUN/默认路由/VPS隧道)异常时,立即关闭 Claude(桌面版与 Claude Code CLI),杜绝裸连重试
#   2. --daemon 常驻模式通过 route -n monitor 实时监听断网/重连/手机热点插拔,毫秒级触发急停与新接口 IPv6 关闭
#   3. 配合 /Library/Application Support/claude-switcher/pf-firewall.sh 实现内核级 0ms 防直连兜底
#   4. 默认(无参)执行单次检查并退出,100% 兼容原有脚本调用与单元测试
LOG="__HOME__/Library/Logs/claude-bodyguard.log"
MODE="__PROXY_MODE__"
HOME_DIR="__HOME__"
COUNTRY_TARGET="__COUNTRY_TARGET__"
PF_SCRIPT="/Library/Application Support/claude-switcher/pf-firewall.sh"
POLL_INTERVAL="${CLAUDE_BODYGUARD_INTERVAL:-2}"
VPS_PROBE_INTERVAL="${CLAUDE_BODYGUARD_VPS_PROBE_INTERVAL:-30}"
STRICT_ROUTE_CHECK="${CLAUDE_BODYGUARD_STRICT_ROUTE:-0}"
VPS_PROBE_ENABLED="${CLAUDE_BODYGUARD_VPS_PROBE:-1}"

# 安装用户 UID: root 守护从 __HOME__ 属主推导,只处理该用户的 CLI 进程。
# 推导失败宁可不杀,也不按进程名全系统扫描(避免误伤其他用户与 claude-switcher 自身)。
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_UID=$(stat -f %u "$HOME_DIR" 2>/dev/null || id -u "${HOME_DIR##*/}" 2>/dev/null)
else
    INSTALL_UID=$(id -u)
fi

log_guard() {
    mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >>"$LOG"
}

# ClashX / Pro / Meta 共用 .../Contents/MacOS/ClashX 主进程路径。
clashx_alive() {
    pgrep -f '/Contents/MacOS/ClashX' >/dev/null 2>&1 \
        || pgrep -x ClashX >/dev/null 2>&1 \
        || pgrep -x 'ClashX Pro' >/dev/null 2>&1 \
        || pgrep -x 'ClashX Meta' >/dev/null 2>&1
}

v2rayu_alive() {
    pgrep -f '/Contents/MacOS/V2RayU' >/dev/null 2>&1 \
        || pgrep -x V2RayU >/dev/null 2>&1 \
        || pgrep -f '\.V2RayU/(v2ray-core|xray-core)/(v2ray|xray)' >/dev/null 2>&1 \
        || pgrep -f 'V2RayU.*(v2ray|xray)' >/dev/null 2>&1
}

v2rayn_alive() {
    pgrep -f '/Contents/MacOS/v2rayN' >/dev/null 2>&1 \
        || pgrep -x v2rayN >/dev/null 2>&1 \
        || pgrep -f 'v2rayN.*(xray|v2ray|sing-box|mihomo)' >/dev/null 2>&1 \
        || pgrep -x xray >/dev/null 2>&1 \
        || pgrep -x v2ray >/dev/null 2>&1
}

pf_active() {
    [ -r "$PF_SCRIPT" ] || return 1
    case "$(/bin/bash "$PF_SCRIPT" status 2>/dev/null)" in
        ok:*) return 0 ;;
        *) return 1 ;;
    esac
}

v2ray_local_port_up() {
    python3 - "$HOME_DIR" "$MODE" <<'PY' 2>/dev/null
import json, os, socket, sys
home, mode = sys.argv[1], sys.argv[2]
ports = []
cfg = os.path.join(home, ".V2RayU", "config.json") if mode == "v2rayu" else os.path.join(home, "Library", "Application Support", "v2rayN", "guiConfigs", "config.json")
if os.path.isfile(cfg):
    try:
        for ib in json.load(open(cfg, encoding="utf-8")).get("inbounds") or []:
            p = ib.get("port")
            if isinstance(p, int) and 0 < p <= 65535:
                ports.append(p)
    except Exception:
        pass
ports.extend([1087, 1080, 10808, 10809])
for p in dict.fromkeys(ports):
    try:
        with socket.create_connection(("127.0.0.1", p), timeout=0.3):
            sys.exit(0)
    except Exception:
        pass
sys.exit(1)
PY
}

# TUN 在线判定: 兼容 Clash fake-ip (198.18.x) 与 v2rayN/sing-box TUN (172.18/172.19/198.19.x)
tun_interface_present() {
    ifconfig 2>/dev/null | grep -qE 'inet (198\.18\.|198\.19\.|172\.18\.|172\.19\.)'
}

# 默认路由判定: 防止手机热点(Wi-Fi/USB)上线或断网重连瞬间物理接口抢占默认路由
route_check_state() {
    local out iface
    out=$(route -n get 1.1.1.1 2>/dev/null) || { echo "down"; return 1; }
    iface=$(printf '%s\n' "$out" | awk '/interface:/{print $2; exit}')
    case "$iface" in
        utun[0-9]*) echo "tun:$iface"; return 0 ;;
        "") echo "down"; return 1 ;;
        *) echo "phys:$iface"; return 1 ;;
    esac
}

client_alive() {
    case "$MODE" in
        clash-verge)
            pgrep -f verge-mihomo >/dev/null 2>&1 ;;
        flclash)
            pgrep -f FlClashCore >/dev/null 2>&1 || pgrep -x FlClash >/dev/null 2>&1 ;;
        bettbox)
            pgrep -f BettboxCore >/dev/null 2>&1 || pgrep -x Bettbox >/dev/null 2>&1 ;;
        shadowrocket)
            nc=$(scutil --nc list 2>/dev/null)
            if echo "$nc" | grep -q 'com.liguangming.Shadowrocket'; then
                echo "$nc" | grep 'com.liguangming.Shadowrocket' | grep -q '(Connected)'
            else
                return 0
            fi ;;
        sing-box)
            pgrep -f sing-box >/dev/null 2>&1 ;;
        clashx)
            clashx_alive ;;
        surge)
            pgrep -f Surge >/dev/null 2>&1 ;;
        v2rayu)
            v2rayu_alive ;;
        v2rayn)
            v2rayn_alive ;;
        auto)
            return 0 ;;
        *)
            pgrep -f verge-mihomo >/dev/null 2>&1 ;;
    esac
}

# Claude Code CLI 进程: native claude/claude.exe 与 npm/bun 的 @anthropic-ai/claude-code。
# 过滤思路与 core/claude-switch.sh 的 cli_pids 一致: 先按安装用户 UID 圈定,再看进程名/CLI 入口参数。
cli_pids() {
    [ -n "$INSTALL_UID" ] || return 0
    ps -axo pid=,uid=,comm=,args= | awk -v uid="$INSTALL_UID" '
        $2 == uid && ($3 ~ /(^|\/)(claude|claude\.exe)$/ ||
        ($3 ~ /(^|\/)(node|bun)$/ && $5 ~ /(^|\/)@anthropic-ai\/claude-code\/(bin\/claude(\.exe)?|cli\.js)$/)) { print $1 }'
}

kill_claude_all() {
    local reason="${1:-代理离线(内核或TUN丢失)}"
    if pgrep -f '/Applications/Claude.app/Contents/MacOS/Claude' >/dev/null 2>&1; then
        pkill -f '/Applications/Claude.app/Contents/MacOS/Claude'
        log_guard "${reason},已自动关闭 Claude"
    fi
    local pids
    pids=$(cli_pids)
    if [ -n "$pids" ]; then
        kill -TERM $pids 2>/dev/null
        log_guard "${reason},已自动关闭 Claude Code CLI"
    fi
}

# 新上线物理接口(如手机 USB 热点)自动关闭 IPv6 (仅 root daemon 模式执行)
disable_new_ipv6_interfaces() {
    [ "$(id -u)" -eq 0 ] || return 0
    local svcs svc info
    svcs=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*') || return 0
    while IFS= read -r svc; do
        [ -n "$svc" ] || continue
        info=$(networksetup -getinfo "$svc" 2>/dev/null)
        if printf '%s\n' "$info" | grep -qi '^IPv6:' && ! printf '%s\n' "$info" | grep -qi '^IPv6:.*off'; then
            networksetup -setv6off "$svc" >/dev/null 2>&1 && log_guard "检测到新接口($svc)开启了 IPv6,已自动关闭"
        fi
    done <<< "$svcs"
}

# 隧道内轻量 VPS 探活 (防场景2: VPS 掉线或代理回落直连)
# 仅在代理路径被判定在线后调用,不直连发包; 返回 0=健康, 1=失联/出口国不符
probe_vps_health() {
    [ "$VPS_PROBE_ENABLED" = "1" ] || return 0
    case "$COUNTRY_TARGET" in
        [A-Z][A-Z]) ;;
        *) return 0 ;;
    esac
    local trace loc
    trace=$(curl -s --max-time 6 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
    loc=$(printf '%s\n' "$trace" | sed -n 's/^loc=\([A-Za-z][A-Za-z]\)$/\1/p' | head -n 1 | tr 'a-z' 'A-Z')
    [ -n "$loc" ] || return 1
    [ "$loc" = "$COUNTRY_TARGET" ] || return 1
    return 0
}

# 单次核心评估: 返回 0=安全, 1=需急停; 设置 FAIL_REASON
evaluate_health() {
    FAIL_REASON=""
    local has_tun=0 has_client=0 rt_state=""

    if tun_interface_present; then
        has_tun=1
    fi
    if client_alive; then
        has_client=1
    fi

    if [ "$has_client" -eq 0 ]; then
        FAIL_REASON="代理离线(客户端 $MODE 进程丢失)"
        return 1
    fi

    if [ "$has_tun" -eq 0 ]; then
        # 允许 V2RayU/v2rayN 在纯本地代理 + pf 防火墙兜底已启用时运行
        if { [ "$MODE" = "v2rayu" ] || [ "$MODE" = "v2rayn" ]; } && v2ray_local_port_up && pf_active; then
            return 0
        fi
        FAIL_REASON="代理离线(内核或TUN丢失)"
        return 1
    fi

    if [ "$STRICT_ROUTE_CHECK" = "1" ]; then
        rt_state=$(route_check_state)
        case "$rt_state" in
            tun:*) ;;
            down)
                FAIL_REASON="网络断开(默认路由丢失)"
                return 1 ;;
            phys:*)
                FAIL_REASON="路由异常(默认路由被物理接口 ${rt_state#phys:} 抢占,可能已切到手机热点)"
                return 1 ;;
        esac
    fi

    return 0
}

run_once() {
    if ! evaluate_health; then
        kill_claude_all "${FAIL_REASON:-代理离线(内核或TUN丢失)}"
    fi
}

run_daemon() {
    STRICT_ROUTE_CHECK=1
    log_guard "保镖常驻守护已启动(模式=$MODE, 严格路由校验=开, 事件驱动=route monitor)"

    # 启动时确保 pf 防直连锚点生效
    if [ -r "$PF_SCRIPT" ] && ! pf_active; then
        /bin/bash "$PF_SCRIPT" enable >/dev/null 2>&1 && log_guard "保镖启动时已激活 pf 防直连锚点"
    fi

    local trigger_fifo
    trigger_fifo=$(mktemp -u "${TMPDIR:-/tmp}/claude-bg-ev.XXXXXX")
    mkfifo "$trigger_fifo" 2>/dev/null || trigger_fifo=""
    local mon_pid=""

    cleanup_daemon() {
        [ -n "$mon_pid" ] && kill "$mon_pid" 2>/dev/null || true
        [ -n "$trigger_fifo" ] && rm -f "$trigger_fifo" 2>/dev/null || true
        exit 0
    }
    trap cleanup_daemon INT TERM EXIT

    if [ -n "$trigger_fifo" ] && command -v route >/dev/null 2>&1; then
        # 实时监听内核路由/网卡/地址变更事件(断网、重连、插拔手机热点毫秒级触发)
        (
            route -n monitor 2>/dev/null | while IFS= read -r line; do
                case "$line" in
                    *RTM_ADD*|*RTM_DELETE*|*RTM_CHANGE*|*RTM_IFINFO*|*RTM_NEWADDR*|*RTM_DELADDR*)
                        printf 'ev\n' > "$trigger_fifo" 2>/dev/null || break ;;
                esac
            done
        ) &
        mon_pid=$!
    fi

    local offline=0
    local stable_streak=2
    local vps_fail_streak=0
    local last_vps_probe=0
    local now ev_line

    while true; do
        if evaluate_health; then
            if [ "$offline" -eq 1 ]; then
                stable_streak=$((stable_streak + 1))
                if [ "$stable_streak" -lt 2 ]; then
                    # 重连冷却窗口: 刚刚恢复时尚未连续稳定，继续防抢跑
                    kill_claude_all "网络重连冷却期(等待 TUN 路由完全稳定)"
                else
                    offline=0
                    vps_fail_streak=0
                    log_guard "隧道与默认路由已恢复稳定,解除急停锁定"
                    disable_new_ipv6_interfaces
                    if [ -r "$PF_SCRIPT" ]; then
                        /bin/bash "$PF_SCRIPT" enable >/dev/null 2>&1 || true
                    fi
                fi
            else
                # 隧道健康期间按间隔执行低频 VPS 出口探活 (防 VPS 掉线或规则回落直连)
                now=$(date +%s)
                if [ "$((now - last_vps_probe))" -ge "$VPS_PROBE_INTERVAL" ]; then
                    last_vps_probe="$now"
                    if probe_vps_health; then
                        vps_fail_streak=0
                    else
                        vps_fail_streak=$((vps_fail_streak + 1))
                        if [ "$vps_fail_streak" -ge 2 ]; then
                            offline=1
                            stable_streak=0
                            kill_claude_all "VPS隧道探活连续失败或出口偏离(${COUNTRY_TARGET})"
                        fi
                    fi
                fi
            fi
        else
            offline=1
            stable_streak=0
            kill_claude_all "${FAIL_REASON:-代理离线(内核或TUN丢失)}"
            disable_new_ipv6_interfaces
        fi

        # 等待路由事件(毫秒唤醒)或快速兜底轮询超时(2s)
        if [ -n "$trigger_fifo" ]; then
            read -r -t "$POLL_INTERVAL" ev_line < "$trigger_fifo" 2>/dev/null || true
            if [ -n "${ev_line:-}" ]; then
                disable_new_ipv6_interfaces
            fi
        else
            sleep "$POLL_INTERVAL"
        fi
    done
}

case "${1:-}" in
    --daemon) run_daemon ;;
    *)        run_once ;;
esac
