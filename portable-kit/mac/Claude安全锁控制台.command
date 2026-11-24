#!/bin/bash
# Claude 安全锁 · macOS 极简单锁原生控制台
# 只有一把单锁开关:
#   - 🔒 开启安全锁: 内核持久化死锁 Claude(ASN+域名IP) 与一切海外直连，放行 Claude 仅通过海外 TUN 运行
#   - 🔓 关闭安全锁: 放行日常上网，但从系统底层锁死 Claude 进程（永远点不开，点开弹提示）+ 永久物理网卡阻断 Claude（除非卸载本软件）
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
    PROC_LOCKED=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^PROC_LOCKED=//p')
    BOOT_ST=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^PERSISTENT_LOCK=//p')
    STRICT_MODE=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^STRICT_MODE=//p')
    CUR_NODES=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^ENTRY_NODES=//p')
    CUR_CC=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^COUNTRY_TARGET=//p')
    [ "$CUR_NODES" = "未配置" ] && CUR_NODES=""

    if [ "$LOCK_ST" = "on" ]; then
        MODE_DESC="国内直连放行 · 海外与Claude死锁"
        [ "$LOCK_MODE" = "strict" ] && MODE_DESC="全封闭模式（连国内与裸DNS一并封锁）"
        BANNER="当前状态：🔒 安全锁已开启（Claude 可放心使用）
保护策略：${MODE_DESC} | 自愈开机守护=${BOOT_ST}
说明：Claude 只能通过海外 TUN 通信，代理退出/重启/软件被杀均 0ms 零泄露。
代理入口：${CUR_NODES:-国内中转可留空} | 目标国家：${CUR_CC:-未配置}"
        PRIMARY_ACTION="🔓 关闭安全锁（日常上网模式 · Claude 将被系统永久锁死，点开弹提示）"
    else
        BANNER="当前状态：🟡 日常上网模式（安全锁未开启 · Claude 已被系统锁死）
保护状态：Claude 进程已禁用(${PROC_LOCKED}) + 物理网卡永久阻断 Claude + hosts 黑洞
说明：可正常直连上网；此刻点开 Claude 会弹窗拦截，绝无直连泄露风险！
代理入口：${CUR_NODES:-国内中转可留空} | 目标国家：${CUR_CC:-未配置}"
        PRIMARY_ACTION="🔒 开启安全锁（启用防泄露硬锁并解锁 Claude 使用）"
    fi

    if [ "${STRICT_MODE:-0}" = "1" ]; then
        STRICT_LABEL="⚙️ 切换开锁策略（当前：全封闭模式 → 点击切回放行国内直连）"
    else
        STRICT_LABEL="⚙️ 切换开锁策略（当前：放行国内直连 → 点击切为全封闭模式）"
    fi

    CHOICE=$(osascript - "$BANNER" "$PRIMARY_ACTION" "$STRICT_LABEL" <<'ASEOF' 2>/dev/null
on run argv
    set p to item 1 of argv
    set mainBtn to item 2 of argv
    set strictBtn to item 3 of argv
    set itemsList to {¬
        mainBtn, ¬
        "🚀 一键初始化环境（首次交付：锁时区/地区/英文/关IPv6 + 开安全锁）", ¬
        "🛡️ 验收操作系统防火墙、进程锁与丢包日志", ¬
        "🔍 14维度深度体检（IP画像/DNS/WebRTC/TLS/WSS）", ¬
        "📄 导出交机体检报告到桌面", ¬
        "📝 修改代理入口白名单 IP / 域名", ¬
        strictBtn, ¬
        "退出"¬
    }
    set picked to choose from list itemsList with title "Claude 安全锁控制台 · macOS" with prompt p default items {item 1 of itemsList} OK button name "执行" cancel button name "退出"
    if picked is false then return "退出"
    return item 1 of picked
end run
ASEOF
)
    case "$CHOICE" in
        ""|"退出") exit 0 ;;
        "🔒"*)
            if [ "${STRICT_MODE:-0}" = "1" ] && [ -z "$CUR_NODES" ]; then
                NODES=$(ask_input "全封闭模式需填写代理入口" "当前启用了全封闭模式，请先输入第一跳代理入口 IP 或域名（多个逗号隔开）：" "") || continue
                [ -z "$NODES" ] && continue
                "$CORE" set-nodes "$NODES" >/dev/null 2>&1 || true
            fi
            OUT=$("$CORE" lock 2>&1)
            show_alert "🔒 安全锁已开启" "$OUT"
            ;;
        "🔓"*)
            OUT=$("$CORE" unlock 2>&1)
            show_alert "🟡 已切换为日常模式（Claude 已锁死）" "$OUT"
            ;;
        "🚀"*)
            NODES=$(ask_input "一键初始化环境" "请确认代理客户端（Stash/小火箭/Clash）已开启「全局 + TUN」。

请输入第一跳代理入口 IP 或域名（若链式代理第一跳在国内中转机可留空；直连海外 VPS 请填 IP，多个逗号隔开）：" "$CUR_NODES") || continue
            OUT=$("$CORE" init "$NODES" 2>&1)
            show_alert "一键初始化结果" "$OUT"
            ;;
        "🛡️"*)
            OUT=$("$CORE" verify-firewall 2>&1)
            show_alert "操作系统防火墙、进程锁与日志验收" "$OUT"
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
                LOCK_OUT=$("$CORE" lock 2>&1)
                OUT="${OUT}
${LOCK_OUT}"
            fi
            show_alert "入口白名单已更新" "$OUT"
            ;;
        "⚙️"*)
            OUT=$("$CORE" toggle-strict 2>&1)
            if [ "$LOCK_ST" = "on" ]; then
                LOCK_OUT=$("$CORE" lock 2>&1)
                OUT="${OUT}
${LOCK_OUT}"
            fi
            show_alert "开锁策略已更新" "$OUT"
            ;;
    esac
done
