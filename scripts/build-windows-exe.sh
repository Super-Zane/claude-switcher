#!/bin/bash
# 使用 NSIS (makensis) 编译真正的单文件 Windows 原生安装程序: dist/Claude安全锁-Windows安装程序.exe
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
mkdir -p "$DIST_DIR"

if ! command -v makensis >/dev/null 2>&1; then
    echo "FAIL: 未找到 makensis，请先运行 brew install makensis" >&2
    exit 1
fi

if [ ! -f "$ROOT_DIR/portable-kit/windows/app.ico" ]; then
    TMP_ICONS="$(mktemp -d)"
    trap 'rm -rf "$TMP_ICONS"' EXIT
    python3 "$ROOT_DIR/scripts/generate-icons.py" "$TMP_ICONS"
    cp -f "$TMP_ICONS/app.ico" "$ROOT_DIR/portable-kit/windows/app.ico"
fi

makensis -V2 "$ROOT_DIR/scripts/nsis/claude-guard-windows.nsi"

OUT_EXE="$DIST_DIR/Claude安全锁-Windows安装程序.exe"
ls -lh "$OUT_EXE"
file "$OUT_EXE"
shasum -a 256 "$OUT_EXE"
