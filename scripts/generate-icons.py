#!/usr/bin/env python3
"""纯标准库生成高清 512x512 应用图标 (PNG + 多尺寸 Windows ICO)，零外部依赖。"""
import math
import struct
import sys
import zlib
from pathlib import Path


def make_png(width, height, rgba_bytes):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    raw = bytearray()
    stride = width * 4
    for y in range(height):
        raw.append(0)
        raw.extend(rgba_bytes[y * stride:(y + 1) * stride])
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(raw), 6)) + chunk(b"IEND", b"")


def render_shield_lock_rgba(size, theme="blue"):
    buf = bytearray(size * size * 4)
    cx = cy = (size - 1) / 2.0
    r_box = size * 0.44
    corner = size * 0.11

    if theme == "red":
        bg_top = (153, 27, 27)
        bg_bot = (69, 10, 10)
        ring_col = (248, 113, 113)
        lock_col = (254, 226, 226)
    else:
        bg_top = (30, 64, 175)
        bg_bot = (11, 17, 32)
        ring_col = (56, 189, 248)
        lock_col = (250, 204, 21)

    for y in range(size):
        ny = (y - cy) / (size * 0.5)
        t = y / max(1, size - 1)
        br = int(bg_top[0] * (1 - t) + bg_bot[0] * t)
        bg = int(bg_top[1] * (1 - t) + bg_bot[1] * t)
        bb = int(bg_top[2] * (1 - t) + bg_bot[2] * t)
        for x in range(size):
            nx = (x - cx) / (size * 0.5)
            # 圆角矩形 SDF (macOS Big Sur+ Squircle 风格)
            dx = abs(x - cx) - (r_box - corner)
            dy = abs(y - cy) - (r_box - corner)
            sdf = math.hypot(max(dx, 0.0), max(dy, 0.0)) + min(max(dx, dy), 0.0) - corner
            if sdf > 1.0:
                continue
            alpha = 255 if sdf <= 0.0 else int(max(0.0, min(1.0, 1.0 - sdf)) * 255)
            r, g, b = br, bg, bb

            # 盾牌外框与光晕
            in_shield = False
            if -0.58 <= ny <= 0.62:
                if ny < 0.05:
                    w = 0.52 - 0.04 * abs(ny + 0.25)
                else:
                    prog = (ny - 0.05) / 0.57
                    w = 0.52 * (1.0 - prog * prog)
                if abs(nx) <= w:
                    in_shield = True
                    # 盾牌描边
                    if abs(nx) >= w - 0.045 or ny <= -0.535:
                        r, g, b = ring_col
                    else:
                        r = min(255, int(r * 1.18 + 12))
                        g = min(255, int(g * 1.18 + 16))
                        b = min(255, int(b * 1.22 + 24))

            # 居中锁图标 (锁梁 + 锁体 + 锁孔)
            if in_shield:
                # 锁梁 (上半圆环)
                sh_cx, sh_cy = 0.0, -0.10
                d_sh = math.hypot(nx - sh_cx, ny - sh_cy)
                is_shackle = (ny <= sh_cy and 0.12 <= d_sh <= 0.19) or (sh_cy < ny <= 0.04 and 0.12 <= abs(nx) <= 0.19)
                # 锁体 (圆角矩形)
                is_body = (-0.24 <= nx <= 0.24) and (0.02 <= ny <= 0.36)
                # 锁孔
                d_hole = math.hypot(nx, ny - 0.16)
                is_keyhole = (d_hole <= 0.055) or (-0.025 <= nx <= 0.025 and 0.16 <= ny <= 0.27)
                if is_shackle or (is_body and not is_keyhole):
                    r, g, b = lock_col
                elif is_body and is_keyhole:
                    r, g, b = bg_bot

            idx = (y * size + x) * 4
            buf[idx] = r
            buf[idx + 1] = g
            buf[idx + 2] = b
            buf[idx + 3] = alpha
    return bytes(buf)


def write_ico(ico_path, png_list):
    """把多张 (size, png_bytes) 打包成标准 Windows PNG-in-ICO 图标文件。"""
    count = len(png_list)
    header = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries = bytearray()
    payload = bytearray()
    for sz, png_bytes in png_list:
        w = 0 if sz >= 256 else sz
        h = 0 if sz >= 256 else sz
        entries.extend(struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(png_bytes), offset))
        payload.extend(png_bytes)
        offset += len(png_bytes)
    Path(ico_path).write_bytes(header + bytes(entries) + bytes(payload))


def write_icns(icns_path, png_chunks):
    """把 (fourcc_bytes, png_bytes) 列表直接写入规范 Apple ICNS 文件，零外部依赖。"""
    body = bytearray()
    for tag, png_bytes in png_chunks:
        body.extend(tag)
        body.extend(struct.pack(">I", 8 + len(png_bytes)))
        body.extend(png_bytes)
    header = b"icns" + struct.pack(">I", 8 + len(body))
    Path(icns_path).write_bytes(header + bytes(body))


def main():
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)

    # 主程序蓝金盾牌锁图标 (ICNS + ICO)
    p512 = make_png(512, 512, render_shield_lock_rgba(512, "blue"))
    p256 = make_png(256, 256, render_shield_lock_rgba(256, "blue"))
    p128 = make_png(128, 128, render_shield_lock_rgba(128, "blue"))
    write_icns(out_dir / "app.icns", [(b"ic09", p512), (b"ic08", p256), (b"ic07", p128)])

    ico_frames = [(256, p256)]
    for sz in (64, 48, 32, 16):
        ico_frames.append((sz, make_png(sz, sz, render_shield_lock_rgba(sz, "blue"))))
    write_ico(out_dir / "app.ico", ico_frames)

    # 卸载器红盾牌图标 (ICNS)
    u512 = make_png(512, 512, render_shield_lock_rgba(512, "red"))
    u256 = make_png(256, 256, render_shield_lock_rgba(256, "red"))
    u128 = make_png(128, 128, render_shield_lock_rgba(128, "red"))
    write_icns(out_dir / "uninstall.icns", [(b"ic09", u512), (b"ic08", u256), (b"ic07", u128)])
    print(f"Icons generated in {out_dir}")


if __name__ == "__main__":
    main()
