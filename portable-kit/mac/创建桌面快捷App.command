#!/bin/bash
# 可选: 在客户桌面生成一个可直接双击的「Claude安全锁.app」(调用本目录控制台，免去弹出终端黑框)
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/Desktop/Claude安全锁.app"
rm -rf "$APP"
osacompile -o "$APP" <<ASEOF
do shell script "/bin/bash '${DIR}/Claude安全锁控制台.command' >/dev/null 2>&1 &"
ASEOF
echo "✓ 已在桌面创建：${APP}"
echo "  客户以后直接双击桌面的「Claude安全锁」即可一键切换安全锁 / 直连模式！"
read -n 1 -s -r -p "按任意键关闭..."
