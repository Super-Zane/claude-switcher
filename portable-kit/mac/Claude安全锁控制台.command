#!/bin/bash
# Claude 安全锁 · macOS 零依赖原生双锁控制台
# 锁 1 (直连切换锁): 在「全封闭模式(仅走海外TUN)」与「国内直连放行(放行国内，但死锁 Claude ASN/IP 与一切海外)」之间一键切换
# 锁 2 (持久化硬锁总开关): 代理退出/软件被杀/电脑死机重启后依然生效；仅在确定不用 Claude 时才手动解开并恢复电脑出厂网络
DIR="$(cd "$(dirname "$0")" && pwd)"
CORE="$DIR/claude-guard.sh"
chmod +x "$CORE" 2>/dev/null || true

show_alert() {
    local title="$1"
    local msg="$2"
    osascript - "$title" "$msg" <<'ASEOF' >/dev/null 2>&1
on run argv
    display dialog (item 2 of argv) with title (item 1 of argv) buttons {"好"} default button "好"
end run
ASEOF
}

confirm_danger() {
    local title="$1"
    local msg="$2"
    osascript - "$title" "$msg" <<'ASEOF' >/dev/null 2>&1
on run argv
    display dialog (item 2 of argv) with title (item 1 of argv) with icon caution buttons {"取消（继续保持硬锁）", "我确认不再使用 Claude，解开持久化硬锁"} default button "取消（继续保持硬锁）" cancel button "取消（继续保持硬锁）"
end run
ASEOF
}

ask_input() {
    local title="$1"
    local prompt="$2"
    local defval="$3"
    osascript - "$title" "$prompt" "$defval" <<'ASEOF' 2>/dev/null
on run argv
    set r to display dialog (item 2 of argv) with title (item 1 of argv) default answer (item 3 of argv) buttons {"取消", "确定"} default button "确定"
    return text returned of r
end run
ASEOF
}

while true; do
    STATUS_OUT=$("$CORE" status 2>/dev/null)
    LOCK_ST=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^LOCK=//p')
    LOCK_MODE=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^LOCK_MODE=//p')
    BOOT_ST=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^PERSISTENT_LOCK=//p')
    CUR_NODES=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^ENTRY_NODES=//p')
    CUR_CC=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^COUNTRY_TARGET=//p')
    [ "$CUR_NODES" = "未配置" ] && CUR_NODES=""

    if [ "$LOCK_ST" = "on" ] && [ "$LOCK_MODE" = "strict" ]; then
        BANNER="当前状态：🔒【锁1：全封闭安全模式】+【锁2：持久化硬锁已扣死 (开机自启=${BOOT_ST})】
说明：物理网卡仅放行代理入口，国内/海外/Claude/IPv6/WebRTC 全部 0ms 阻断。
代理入口：${CUR_NODES:-未配置} | 目标国家：${CUR_CC:-未配置}"
    elif [ "$LOCK_ST" = "on" ]; then
        BANNER="当前状态：🟡【锁1：国内直连放行】+【锁2：持久化硬锁已扣死 (开机自启=${BOOT_ST})】
说明：国内直连正常可用；Claude(ASN+域名IP) 与一切海外服务依然 0ms 死锁，误点 Claude 也不会泄露！
代理入口：${CUR_NODES:-国内中转可留空} | 目标国家：${CUR_CC:-未配置}"
    else
        BANNER="当前状态：🔓【锁2 已解开 — 电脑处于原生直连状态】
⚠️ 警告：持久化硬锁未开启！请勿在此状态下启动 Claude 桌面版、网页版或 Claude Code CLI！
代理入口：${CUR_NODES:-未配置} | 目标国家：${CUR_CC:-未配置}"
    fi

    CHOICE=$(osascript - "$BANNER" <<'ASEOF' 2>/dev/null
on run argv
    set p to item 1 of argv
    set itemsList to {¬
        "🟡【锁1切换】放行国内直连（但死锁 Claude 与一切海外 · 推荐日常态）", ¬
        "🔒【锁1切换】全封闭模式（仅走海外 TUN，连国内公网也全封 · 最严工作态）", ¬
        "⚙️ 一键初始化环境（首次交付：锁时区/地区/英文/关IPv6 + 扣死双锁）", ¬
        "🛡️ 验收操作系统防火墙与流量拦截日志（pfctl 丢包计数实证）", ¬
        "🔍 14维度深度体检（IP画像/DNS/WebRTC/TLS/WSS）", ¬
        "📄 导出交机体检报告到桌面", ¬
        "📝 修改海外代理入口白名单 IP / 域名", ¬
        "🔓【锁2高危操作】解开持久化硬锁（仅确定不用 Claude 时恢复出厂网络）", ¬
        "退出"¬
    }
    set picked to choose from list itemsList with title "Claude 双锁安全控制台 · macOS" with prompt p default items {item 1 of itemsList} OK button name "执行" cancel button name "退出"
    if picked is false then return "退出"
    return item 1 of picked
end run
ASEOF
)
    case "$CHOICE" in
        ""|"退出") exit 0 ;;
        "🟡"*)
            OUT=$("$CORE" lock-cn 2>&1)
            show_alert "锁 1：已切换为「国内直连放行 + 死锁 Claude 与海外」" "$OUT"
            ;;
        "🔒"*)
            if [ -z "$CUR_NODES" ]; then
                NODES=$(ask_input "全封闭模式需填写代理入口" "全封闭模式会连国内公网一并阻断，请先输入第一跳代理入口 IP 或域名（多个用逗号隔开）：" "") || continue
                [ -z "$NODES" ] && continue
                "$CORE" set-nodes "$NODES" >/dev/null 2>&1 || true
            fi
            OUT=$("$CORE" lock-strict 2>&1)
            show_alert "锁 1：已切换为「全封闭模式（仅海外 TUN）」" "$OUT"
            ;;
        "⚙️"*)
            NODES=$(ask_input "一键初始化环境" "请确认代理客户端（Stash/小火箭/Clash）已开启「全局 + TUN」。

请输入第一跳代理入口 IP 或域名（若链式代理第一跳在国内中转机可留空；直连海外 VPS 请填 IP，多个逗号隔开）：" "$CUR_NODES") || continue
            OUT=$("$CORE" init "$NODES" 2>&1)
            show_alert "一键初始化结果" "$OUT"
            ;;
        "🛡️"*)
            OUT=$("$CORE" verify-firewall 2>&1)
            show_alert "操作系统防火墙与流量拦截日志验收" "$OUT"
            ;;
        "🔍"*)
            OUT=$("$CORE" check 2>&1)
            show_alert "14 维度深度环境体检结果" "$OUT"
            ;;
        "📄"*)
            OUT=$("$CORE" export-report 2>&1)
            show_alert "交机体检报告已导出到桌面" "$OUT"
            ;;
        "📝"*)
            NODES=$(ask_input "修改代理入口白名单" "请输入第一跳代理入口 IP 或域名（多个用逗号隔开；若第一跳为国内中转可留空）：" "$CUR_NODES") || continue
            OUT=$("$CORE" set-nodes "$NODES" 2>&1)
            if [ "$LOCK_ST" = "on" ]; then
                if [ "$LOCK_MODE" = "strict" ]; then
                    LOCK_OUT=$("$CORE" lock-strict 2>&1)
                else
                    LOCK_OUT=$("$CORE" lock-cn 2>&1)
                fi
                OUT="${OUT}
${LOCK_OUT}"
            fi
            show_alert "入口白名单已更新" "$OUT"
            ;;
        "🔓"*)
            if confirm_danger "⚠️ 高危确认：解开锁 2（持久化硬锁）" "确定要解开【锁 2：持久化硬锁】并恢复电脑原生直连网络吗？

⚠️ 重要安全警告：
1. 软件将先自动关闭正在运行的 Claude 桌面版与 Claude Code CLI；
2. 解开此锁后，电脑将完全恢复到未使用本软件时的直连状态；
3. 解开后【千万不要】启动 Claude 桌面版、网页版或 Claude Code CLI 的任何服务，否则将立即暴露本地真实 IP！"; then
                OUT=$("$CORE" unlock-all 2>&1)
                show_alert "锁 2 已解开（电脑已恢复原生直连）" "$OUT"
            fi
            ;;
    esac
done
