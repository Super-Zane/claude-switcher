#!/bin/bash
# Claude 安全锁 · macOS 一键安装器（零依赖、免 Xcode，安装后直接从桌面或应用程序打开）
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SRC/mac/claude-guard.sh" ]; then
    MAC_SRC="$SRC/mac"
    DATA_SRC="$SRC/data"
else
    MAC_SRC="$SRC"
    DATA_SRC="$(cd "$SRC/.." && pwd)/data"
fi
INSTALL_DIR="$HOME/.claude-guard/kit"
APP_PATH="/Applications/Claude安全锁.app"
DESKTOP_LINK="$HOME/Desktop/Claude安全锁.app"

clear
echo "=========================================="
echo "   Claude 持久化安全锁 · macOS 一键安装"
echo "=========================================="
echo ""

if [ ! -f "$MAC_SRC/claude-guard.sh" ] || [ ! -f "$DATA_SRC/cn-ipv4.txt" ]; then
    echo "❌ 安装包文件不完整，请先将整个压缩包完整解压后再双击安装。"
    read -n 1 -s -r -p "按任意键关闭安装窗口..."
    exit 1
fi

mkdir -p "$INSTALL_DIR/mac" "$INSTALL_DIR/data"
cp -f "$MAC_SRC/claude-guard.sh" "$MAC_SRC/Claude安全锁控制台.command" "$MAC_SRC/env-audit.py" "$INSTALL_DIR/mac/"
cp -f "$DATA_SRC/cn-ipv4.txt" "$INSTALL_DIR/data/"
chmod +x "$INSTALL_DIR/mac/claude-guard.sh" "$INSTALL_DIR/mac/Claude安全锁控制台.command" "$INSTALL_DIR/mac/env-audit.py"
/usr/bin/xattr -dr com.apple.quarantine "$INSTALL_DIR" 2>/dev/null || true

# 构建零依赖原生 macOS .app Bundle（不依赖 Xcode / swiftc / osacompile）
TMP_DIR="$(mktemp -d)"
TMP_APP="$TMP_DIR/Claude安全锁.app"
mkdir -p "$TMP_APP/Contents/MacOS"
cat > "$TMP_APP/Contents/Info.plist" <<'PLISTEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
    <key>CFBundleExecutable</key><string>claude-guard-launcher</string>
    <key>CFBundleIdentifier</key><string>com.claude-guard.console</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>Claude安全锁</string>
    <key>CFBundleDisplayName</key><string>Claude安全锁</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>2.0.0</string>
    <key>CFBundleVersion</key><string>200</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
PLISTEOF

cat > "$TMP_APP/Contents/MacOS/claude-guard-launcher" <<LAUNCEOF
#!/bin/bash
exec /bin/bash "${INSTALL_DIR}/mac/Claude安全锁控制台.command"
LAUNCEOF
chmod 755 "$TMP_APP/Contents/MacOS/claude-guard-launcher"
/usr/bin/xattr -dr com.apple.quarantine "$TMP_APP" 2>/dev/null || true

if rm -rf "$APP_PATH" 2>/dev/null && cp -R "$TMP_APP" "$APP_PATH" 2>/dev/null; then
    echo "✓ 已安装应用: $APP_PATH"
else
    echo "正在请求管理员权限安装到 /Applications..."
    sudo rm -rf "$APP_PATH"
    sudo cp -R "$TMP_APP" "$APP_PATH"
    echo "✓ 已安装应用: $APP_PATH"
fi

rm -rf "$DESKTOP_LINK" 2>/dev/null || true
cp -R "$TMP_APP" "$DESKTOP_LINK" 2>/dev/null || true
rm -rf "$TMP_DIR"
echo "✓ 已创建桌面快捷图标: $DESKTOP_LINK"
echo ""
echo "=========================================="
echo "  ✅ 安装完成！正在打开「Claude安全锁」..."
echo "  首次交付请点击「⚙️ 一键初始化环境」"
echo "=========================================="
open "$DESKTOP_LINK" 2>/dev/null || open "$APP_PATH" 2>/dev/null || true
read -n 1 -s -r -p "按任意键关闭安装窗口..."
