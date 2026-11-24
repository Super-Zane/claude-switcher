#!/bin/bash
# Claude 安全锁 · macOS 零依赖原生图形控制台 (双击直接打开，无需 Xcode/编译)
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
    CUR_NODES=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^ENTRY_NODES=//p')
    CUR_CC=$(printf '%s\n' "$STATUS_OUT" | sed -n 's/^COUNTRY_TARGET=//p')
    [ "$CUR_NODES" = "未配置" ] && CUR_NODES=""

    if [ "$LOCK_ST" = "on" ]; then
        BANNER="当前状态：🟢 安全锁已开启（仅允许代理 TUN + 白名单入口节点，零直连泄露）
入口节点：${CUR_NODES:-未配置} | 目标地区：${CUR_CC:-未配置}"
    else
        BANNER="当前状态：🟡 直连模式（未加锁，使用 Claude 前请先开启安全锁）
入口节点：${CUR_NODES:-未配置} | 目标地区：${CUR_CC:-未配置}"
    fi

    CHOICE=$(osascript - "$BANNER" <<'ASEOF' 2>/dev/null
on run argv
    set p to item 1 of argv
    set itemsList to {¬
        "🟢 开启安全锁（使用 Claude 前点这里）", ¬
        "🟡 恢复直连模式（不用 Claude 时点这里）", ¬
        "⚙️ 一键初始化环境（首次交付/换节点时点这里）", ¬
        "🔍 14维度深度体检（IP画像/DNS/WebRTC/TLS/WSS）", ¬
        "📄 导出交机体检报告到桌面", ¬
        "📝 修改白名单代理入口 IP / 域名", ¬
        "退出"¬
    }
    set picked to choose from list itemsList with title "Claude 安全锁 · macOS 控制台" with prompt p default items {item 1 of itemsList} OK button name "执行" cancel button name "退出"
    if picked is false then return "退出"
    return item 1 of picked
end run
ASEOF
)
    case "$CHOICE" in
        ""|"退出") exit 0 ;;
        "🟢"*)
            if [ -z "$CUR_NODES" ]; then
                NODES=$(ask_input "设置代理入口节点" "请输入代理第一跳入口服务器 IP 或域名（链式代理请填第一跳入口；多个用逗号隔开）：" "") || continue
                [ -z "$NODES" ] && continue
                OUT=$("$CORE" set-nodes "$NODES" 2>&1)
                if ! printf '%s' "$OUT" | grep -q '^OK:'; then
                    show_alert "配置失败" "$OUT"
                    continue
                fi
            fi
            OUT=$("$CORE" lock 2>&1)
            show_alert "开启安全锁" "$OUT"
            ;;
        "🟡"*)
            OUT=$("$CORE" unlock 2>&1)
            show_alert "恢复直连模式" "$OUT"
            ;;
        "⚙️"*)
            NODES=$(ask_input "一键初始化环境" "请确认代理客户端（Stash/小火箭/Clash）已开启「全局 + TUN」。

请输入第一跳代理入口服务器 IP 或域名（多个用逗号隔开）：" "$CUR_NODES") || continue
            [ -z "$NODES" ] && continue
            OUT=$("$CORE" init "$NODES" 2>&1)
            show_alert "一键初始化结果" "$OUT"
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
            NODES=$(ask_input "修改白名单入口节点" "请输入代理第一跳入口服务器 IP 或域名（链式代理填第一跳；多个用逗号隔开）：" "$CUR_NODES") || continue
            [ -z "$NODES" ] && continue
            OUT=$("$CORE" set-nodes "$NODES" 2>&1)
            if [ "$LOCK_ST" = "on" ] && printf '%s' "$OUT" | grep -q '^OK:'; then
                LOCK_OUT=$("$CORE" lock 2>&1)
                OUT="${OUT}
${LOCK_OUT}"
            fi
            show_alert "入口节点已更新" "$OUT"
            ;;
    esac
done
