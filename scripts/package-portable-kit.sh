#!/bin/bash
# 打包生成可直接交付客户的 macOS 与 Windows 双端即装安装包
# 使用 Python zipfile 写入规范 UTF-8 标志位 (Bit 11)，确保 Windows 资源管理器与 macOS 归档工具解压中文文件名均零乱码，且保留 macOS 可执行权限
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KIT_DIR="$ROOT_DIR/portable-kit"
DIST_DIR="$ROOT_DIR/dist"
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$DIST_DIR"

# 1. 组装 macOS 安装包
MAC_PKG_NAME="Claude安全锁-macOS安装包"
MAC_STAGE="$STAGE_DIR/$MAC_PKG_NAME"
mkdir -p "$MAC_STAGE/mac" "$MAC_STAGE/data"

cp -f "$KIT_DIR/mac/一键安装.command" "$MAC_STAGE/一键安装.command"
cp -f "$KIT_DIR/mac/卸载.command" "$MAC_STAGE/卸载.command"
cp -f "$KIT_DIR/README-交付手册.md" "$MAC_STAGE/README-交付手册.md"
cp -f "$KIT_DIR/mac/claude-guard.sh" "$MAC_STAGE/mac/"
cp -f "$KIT_DIR/mac/Claude安全锁控制台.command" "$MAC_STAGE/mac/"
cp -f "$KIT_DIR/mac/env-audit.py" "$MAC_STAGE/mac/"
cp -f "$KIT_DIR/data/cn-ipv4.txt" "$MAC_STAGE/data/"
chmod 755 "$MAC_STAGE/一键安装.command" "$MAC_STAGE/卸载.command" \
    "$MAC_STAGE/mac/claude-guard.sh" "$MAC_STAGE/mac/Claude安全锁控制台.command" "$MAC_STAGE/mac/env-audit.py"

# 2. 组装 Windows 安装包
WIN_PKG_NAME="Claude安全锁-Windows安装包"
WIN_STAGE="$STAGE_DIR/$WIN_PKG_NAME"
mkdir -p "$WIN_STAGE/windows" "$WIN_STAGE/data"

cp -f "$KIT_DIR/windows/一键安装.bat" "$WIN_STAGE/一键安装.bat"
cp -f "$KIT_DIR/windows/卸载.bat" "$WIN_STAGE/卸载.bat"
cp -f "$KIT_DIR/README-交付手册.md" "$WIN_STAGE/README-交付手册.md"
cp -f "$KIT_DIR/windows/claude-guard.ps1" "$WIN_STAGE/windows/"
cp -f "$KIT_DIR/windows/ClaudeGuardUI.ps1" "$WIN_STAGE/windows/"
cp -f "$KIT_DIR/windows/env-audit.ps1" "$WIN_STAGE/windows/"
cp -f "$KIT_DIR/windows/claude-blocked-alert.vbs" "$WIN_STAGE/windows/"
cp -f "$KIT_DIR/windows/Claude安全锁控制台.bat" "$WIN_STAGE/windows/"
cp -f "$KIT_DIR/data/cn-ipv4.txt" "$WIN_STAGE/data/"
cp -f "$KIT_DIR/data/overseas-ipv4-ranges.txt" "$WIN_STAGE/data/"

MAC_ZIP="$DIST_DIR/${MAC_PKG_NAME}.zip"
WIN_ZIP="$DIST_DIR/${WIN_PKG_NAME}.zip"

python3 - "$STAGE_DIR" "$MAC_PKG_NAME" "$MAC_ZIP" "$WIN_PKG_NAME" "$WIN_ZIP" <<'PYEOF'
import os
import stat
import sys
import zipfile
from pathlib import Path

stage = Path(sys.argv[1])
jobs = [
    (sys.argv[2], Path(sys.argv[3])),
    (sys.argv[4], Path(sys.argv[5])),
]

for pkg_dir_name, out_zip in jobs:
    src_root = stage / pkg_dir_name
    if out_zip.exists():
        out_zip.unlink()
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in sorted(src_root.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(stage).as_posix()
            st = path.stat()
            zi = zipfile.ZipInfo(rel)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 3  # Unix，保留权限位供 macOS 解压恢复 +x
            zi.flag_bits |= 0x800  # 显式标记 UTF-8 文件名 (EFS)，Windows 资源管理器零乱码
            mode = stat.S_IMODE(st.st_mode)
            zi.external_attr = (stat.S_IFREG | mode) << 16
            zf.writestr(zi, path.read_bytes())
PYEOF

# 3. 输出 SHA256 校验和
shasum -a 256 "$MAC_ZIP" "$WIN_ZIP" | sed "s|$DIST_DIR/||" > "$DIST_DIR/SHA256SUMS.txt"

echo "已生成双端安装包:"
ls -lh "$MAC_ZIP" "$WIN_ZIP" "$DIST_DIR/SHA256SUMS.txt"
cat "$DIST_DIR/SHA256SUMS.txt"
