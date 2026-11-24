#!/bin/bash
# Claude 安全锁 · macOS 彻底卸载（先解开持久化硬锁并恢复原生网络，再清理安装文件）
clear
echo "=========================================="
echo "   Claude 持久化安全锁 · macOS 一键卸载"
echo "=========================================="
echo ""
GUARD="$HOME/.claude-guard/kit/mac/claude-guard.sh"
if [ -x "$GUARD" ]; then
    echo "正在解开持久化硬锁并恢复系统原生网络..."
    "$GUARD" unlock-all || true
fi
sudo rm -rf "/Applications/Claude安全锁.app" 2>/dev/null || rm -rf "/Applications/Claude安全锁.app" 2>/dev/null || true
rm -rf "$HOME/Desktop/Claude安全锁.app" "$HOME/.claude-guard" 2>/dev/null || true
echo ""
echo "✅ 已完全卸载，电脑防火墙与网络已恢复原生状态。"
read -n 1 -s -r -p "按任意键关闭窗口..."
