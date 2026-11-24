#!/bin/bash
# 构建标准 macOS 拖拽安装包: dist/Claude安全锁-macOS.dmg
# 内含:
#   - Claude安全锁.app (100% 自包含全部引擎与数据、带高清盾牌锁图标，拖进 Applications 即可双击使用)
#   - Applications 快捷方式 (标准拖拽安装体验)
#   - 卸载Claude安全锁.app (独立一键卸载还原器)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KIT_DIR="$ROOT_DIR/portable-kit"
DIST_DIR="$ROOT_DIR/dist"
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$DIST_DIR"

# 1. 生成高清应用图标 (.icns 与 .ico，纯 Python 零依赖)
ICON_DIR="$STAGE_DIR/icons"
python3 "$ROOT_DIR/scripts/generate-icons.py" "$ICON_DIR"
# 同步保存 Windows ICO 供 NSIS 打包复用
cp -f "$ICON_DIR/app.ico" "$KIT_DIR/windows/app.ico"

# 2. 构建 100% 自包含、Claude 暖米风格原生 SwiftUI 通用二进制 Claude安全锁.app (arm64 + x86_64)
DMG_SRC="$STAGE_DIR/dmg-root"
mkdir -p "$DMG_SRC"
APP="$DMG_SRC/Claude安全锁.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/kit/mac" "$APP/Contents/Resources/kit/data"

cp -f "$ICON_DIR/app.icns" "$APP/Contents/Resources/app.icns"
cp -f "$KIT_DIR/mac/claude-guard.sh" "$KIT_DIR/mac/env-audit.py" "$APP/Contents/Resources/kit/mac/"
cp -f "$KIT_DIR/data/cn-ipv4.txt" "$APP/Contents/Resources/kit/data/"
chmod 755 "$APP/Contents/Resources/kit/mac/claude-guard.sh" \
          "$APP/Contents/Resources/kit/mac/env-audit.py"

MOD_CACHE="$STAGE_DIR/swift-modcache"
mkdir -p "$MOD_CACHE"
swiftc -O -target arm64-apple-macos12.0 -module-cache-path "$MOD_CACHE" \
    -framework SwiftUI -framework AppKit \
    "$KIT_DIR/mac/ClaudeGuardApp.swift" -o "$STAGE_DIR/ClaudeGuard-arm64"
swiftc -O -target x86_64-apple-macos12.0 -module-cache-path "$MOD_CACHE" \
    -framework SwiftUI -framework AppKit \
    "$KIT_DIR/mac/ClaudeGuardApp.swift" -o "$STAGE_DIR/ClaudeGuard-x64"
lipo -create "$STAGE_DIR/ClaudeGuard-arm64" "$STAGE_DIR/ClaudeGuard-x64" \
    -output "$APP/Contents/MacOS/ClaudeGuard"
chmod 755 "$APP/Contents/MacOS/ClaudeGuard"

cat > "$APP/Contents/Info.plist" <<'PLISTEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
    <key>CFBundleExecutable</key><string>ClaudeGuard</string>
    <key>CFBundleIdentifier</key><string>com.claude-guard.app</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>Claude安全锁</string>
    <key>CFBundleDisplayName</key><string>Claude安全锁</string>
    <key>CFBundleIconFile</key><string>app.icns</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>2.1.0</string>
    <key>CFBundleVersion</key><string>210</string>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLISTEOF
plutil -lint "$APP/Contents/Info.plist" >/dev/null
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true

# 3. 构建独立 卸载Claude安全锁.app
UNINST="$DMG_SRC/卸载Claude安全锁.app"
mkdir -p "$UNINST/Contents/MacOS" "$UNINST/Contents/Resources/kit/mac" "$UNINST/Contents/Resources/kit/data"
cp -f "$ICON_DIR/uninstall.icns" "$UNINST/Contents/Resources/uninstall.icns"
cp -f "$KIT_DIR/mac/claude-guard.sh" "$UNINST/Contents/Resources/kit/mac/"
chmod 755 "$UNINST/Contents/Resources/kit/mac/claude-guard.sh"

cat > "$UNINST/Contents/Info.plist" <<'PLISTEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
    <key>CFBundleExecutable</key><string>ClaudeGuardUninstall</string>
    <key>CFBundleIdentifier</key><string>com.claude-guard.uninstaller</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>卸载Claude安全锁</string>
    <key>CFBundleDisplayName</key><string>卸载Claude安全锁</string>
    <key>CFBundleIconFile</key><string>uninstall.icns</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>2.1.0</string>
    <key>CFBundleVersion</key><string>210</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
PLISTEOF
plutil -lint "$UNINST/Contents/Info.plist" >/dev/null

cat > "$UNINST/Contents/MacOS/ClaudeGuardUninstall" <<'UNLAUNCHEOF'
#!/bin/bash
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
GUARD="$(cd "$SELF_DIR/../Resources/kit/mac" && pwd)/claude-guard.sh"

if ! /usr/bin/osascript <<'ASEOF' >/dev/null 2>&1
display dialog "确定要彻底卸载「Claude安全锁」吗？

卸载后将执行以下操作：
1. 还原被锁定的 Claude 桌面版与 CLI；
2. 彻底清除系统防火墙规则、自愈开机守护与 hosts 托管项；
3. 删除 /Applications/Claude安全锁.app 与本地配置。

⚠️ 卸载后电脑将恢复原生直连状态，请勿在无防护下启动 Claude。" with title "卸载 Claude安全锁" with icon caution buttons {"取消", "确认彻底卸载"} default button "取消" cancel button "取消"
ASEOF
then
    exit 0
fi

OUT=$("$GUARD" uninstall-all 2>&1 || true)
rm -rf "/Applications/Claude安全锁.app" "$HOME/Desktop/Claude安全锁.app" "$HOME/.claude-guard" 2>/dev/null || true

/usr/bin/osascript - "$OUT" <<'ASEOF' >/dev/null 2>&1
on run argv
    display dialog ("✅ 已完成彻底卸载，电脑已恢复原生状态。" & return & return & (item 1 of argv)) with title "卸载完成" buttons {"好"} default button "好"
end run
ASEOF
UNLAUNCHEOF
chmod 755 "$UNINST/Contents/MacOS/ClaudeGuardUninstall"

# 4. 添加 Applications 拖拽安装软链接、使用说明、防漏覆写模板与断网急救指南
ln -s /Applications "$DMG_SRC/Applications"
cp -f "$KIT_DIR/README-交付手册.md" "$DMG_SRC/使用说明.md"
cp -f "$KIT_DIR/templates/断网急救.txt" "$DMG_SRC/断网急救.txt"
cp -f "$KIT_DIR/templates/Clash-Verge-防漏覆写模板.yaml" "$DMG_SRC/Clash-Verge-防漏覆写模板.yaml"

# 5. 生成标准压缩 DMG 磁盘映像
OUT_DMG="$DIST_DIR/Claude安全锁-macOS.dmg"
rm -f "$OUT_DMG"
hdiutil create -volname "Claude安全锁" -srcfolder "$DMG_SRC" -ov -format UDZO "$OUT_DMG" >/dev/null

ls -lh "$OUT_DMG"
shasum -a 256 "$OUT_DMG"
