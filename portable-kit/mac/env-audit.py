#!/usr/bin/env python3
"""Claude 安全锁 · macOS 14 维度深度本地环境体检引擎 (纯标准库，零外部依赖)

整合参考了以下开源项目的核心本地环境检测能力:
- TZZ520/claude-environment-check: 本地 DNS 大陆信号、代理环境变量/系统代理冲突脱敏、TLS 证书/MITM 校验、WebSocket、Claude Code 安装检测
- betaer/AiSignalGuard: 多源出口 IP 共识、路由/ASN 风险标签、严格语义(未知不冒充通过)与证据覆盖率
- Nooobhh/claude-analysis: 受限地区黑名单(含 CN/HK/MO 等)、IP 机房/代理/VPN/Tor 画像、多 STUN WebRTC 探测、端点延迟
"""

import argparse
import datetime
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

# Anthropic 明确不支持的受限地区代码 (含常见误区 HK/MO)
RESTRICTED_COUNTRIES = {"CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU"}

# 常见中国大陆公共 DNS (出现则提示 DNS 污染/泄露风险)
CN_DNS_SERVERS = {
    "114.114.114.114", "114.114.115.115",
    "223.5.5.5", "223.6.6.6",
    "119.29.29.29", "182.254.116.116",
    "180.76.76.76", "1.2.4.8", "210.2.4.8",
    "101.226.4.6", "218.30.118.6",
}

STUN_SERVERS = [
    ("stun.miwifi.com", 3478),
    ("stun.chat.bilibili.com", 3478),
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

COUNTRY_TZ_PREFIXES = {
    "US": ("America/", "Pacific/Honolulu", "US/"),
    "CA": ("America/", "Canada/"),
    "JP": ("Asia/Tokyo",),
    "SG": ("Asia/Singapore",),
    "TW": ("Asia/Taipei",),
    "GB": ("Europe/London",),
    "DE": ("Europe/Berlin",),
    "FR": ("Europe/Paris",),
    "KR": ("Asia/Seoul",),
    "AU": ("Australia/",),
    "MY": ("Asia/Kuala_Lumpur",),
}

SUSPICIOUS_MITM_ISSUERS = (
    "charles", "fiddler", "mitmproxy", "burp", "proxyman",
    "zscaler", "netskope", "kaspersky", "avast", "sangfor", "qianxin",
)


def run_cmd(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=timeout)
        return 0, out
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output or ""
    except Exception:
        return 1, ""


def sanitize_proxy_url(val):
    if not val:
        return ""
    return re.sub(r"://([^:@/\s]+):([^@/\s]+)@", r"://\1:***@", val)


def http_get_json(url, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": "claude-guard-audit/1.0", "Accept": "application/json"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            ms = int((time.monotonic() - t0) * 1000)
            return resp.status, json.loads(body), ms, ""
    except urllib.error.HTTPError as e:
        ms = int((time.monotonic() - t0) * 1000)
        return e.code, None, ms, f"HTTP {e.code}"
    except Exception as e:
        ms = int((time.monotonic() - t0) * 1000)
        return 0, None, ms, type(e).__name__


def http_get_text(url, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": "claude-guard-audit/1.0"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            ms = int((time.monotonic() - t0) * 1000)
            return resp.status, body, ms, ""
    except urllib.error.HTTPError as e:
        ms = int((time.monotonic() - t0) * 1000)
        return e.code, "", ms, f"HTTP {e.code}"
    except Exception as e:
        ms = int((time.monotonic() - t0) * 1000)
        return 0, "", ms, type(e).__name__


def probe_stun_one(host, port, timeout=2.0):
    try:
        addr = socket.gethostbyname(host)
    except Exception:
        return None
    txn = os.urandom(12)
    req = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + txn
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(req, (addr, port))
        data, _ = s.recvfrom(1024)
    except Exception:
        return None
    finally:
        s.close()
    if len(data) < 20 or data[0:2] != b"\x01\x01":
        return None
    pos = 20
    while pos + 4 <= len(data):
        atype, alen = struct.unpack("!HH", data[pos:pos + 4])
        aval = data[pos + 4:pos + 4 + alen]
        if atype == 0x0020 and len(aval) >= 8 and aval[1] == 0x01:
            ip_int = struct.unpack("!I", aval[4:8])[0] ^ 0x2112A442
            return socket.inet_ntoa(struct.pack("!I", ip_int))
        if atype == 0x0001 and len(aval) >= 8 and aval[1] == 0x01:
            return socket.inet_ntoa(aval[4:8])
        pos += 4 + alen + ((4 - alen % 4) % 4)
    return None


def probe_webrtc_all():
    found = []
    lock = threading.Lock()

    def worker(h, p):
        ip = probe_stun_one(h, p)
        if ip:
            with lock:
                if ip not in found:
                    found.append(ip)

    threads = [threading.Thread(target=worker, args=(h, p), daemon=True) for h, p in STUN_SERVERS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3.0)
    return found


def check_tls_endpoint(host, port=443, timeout=6):
    ctx = ssl.create_default_context()
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ms = int((time.monotonic() - t0) * 1000)
                ver = ssock.version() or "unknown"
                alpn = ssock.selected_alpn_protocol() or "none"
                cert = ssock.getpeercert() or {}
                issuer_parts = []
                for rdn in cert.get("issuer", ()):
                    for k, v in rdn:
                        if k in ("organizationName", "commonName"):
                            issuer_parts.append(v)
                issuer = " / ".join(issuer_parts) if issuer_parts else "unknown"
                mitm = any(tok in issuer.lower() for tok in SUSPICIOUS_MITM_ISSUERS)
                return {"ok": True, "version": ver, "alpn": alpn, "issuer": issuer, "mitm": mitm, "ms": ms}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def check_websocket_upgrade(host="claude.ai", port=443, timeout=6):
    """验证代理隧道是否允许 WSS WebSocket Upgrade 握手 (参考 TZZ520/claude-environment-check)。"""
    ctx = ssl.create_default_context()
    req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: claude-guard-audit/1.0\r\n\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(req)
                head = ssock.recv(512).decode("latin-1", errors="ignore")
                first_line = head.splitlines()[0] if head else ""
                m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", first_line)
                code = int(m.group(1)) if m else 0
                return {"ok": code > 0, "status": code, "line": first_line[:80]}
    except Exception as e:
        return {"ok": False, "status": 0, "error": type(e).__name__}


def load_guard_cfg(cfg_path):
    cfg = {}
    if cfg_path and os.path.isfile(cfg_path):
        for line in open(cfg_path, encoding="utf-8", errors="ignore"):
            m = re.match(r'^([A-Z0-9_]+)="(.*)"$', line.strip())
            if m:
                cfg[m.group(1)] = m.group(2)
    return cfg


def run_audit(args):
    items = []  # list of dict(id, name, state[ok|warn|fail|unknown], detail)

    def add(item_id, name, state, detail):
        items.append({"id": item_id, "name": name, "state": state, "detail": detail})

    cfg = load_guard_cfg(args.config)
    entry_nodes = cfg.get("ENTRY_NODES", "")
    target_cc = cfg.get("COUNTRY_TARGET", "")
    target_tz = cfg.get("TZ_TARGET", "")
    target_loc = cfg.get("LOCALE_TARGET", "")

    # 1. 内核级持久化防直连硬锁 (单锁模式: active=全防护可用Claude / standby=日常模式且Claude系统级死锁)
    lock_mode = "off"
    boot_persist = os.path.isfile(args.pf_boot_plist)
    if os.path.isfile(args.pf_anchor) and os.path.isfile(args.pf_conf):
        try:
            pf_txt = open(args.pf_conf, encoding="utf-8", errors="ignore").read()
            anc_txt = open(args.pf_anchor, encoding="utf-8", errors="ignore").read()
            if "# BEGIN claude-guard-pf" in pf_txt:
                if "mode=standby" in anc_txt:
                    lock_mode = "standby"
                elif "mode=strict" in anc_txt:
                    lock_mode = "strict"
                else:
                    lock_mode = "cn"
        except OSError:
            pass
    lock_on = lock_mode in ("cn", "strict")
    if lock_mode == "strict" and boot_persist:
        add("killswitch", "持久化安全锁 (pf)", "ok", f"一级锁已开启 · 100%流量只走TUN (KeepAlive自愈守护在线; 入口={entry_nodes or '自动探测'})")
    elif lock_mode == "cn":
        add("killswitch", "持久化安全锁 (pf)", "warn", "一级锁已关闭 · 国内白名单直连态 (海外与Claude遥测已死锁，用Claude前请先开一级锁)")
    elif lock_mode == "standby":
        add("killswitch", "持久化安全锁 (pf)", "warn", "二级放宽锁已打开 (严禁触碰任何Claude服务与邮件链接！底层进程与遥测黑洞仍在保护中)")
    elif lock_mode == "strict":
        add("killswitch", "持久化安全锁 (pf)", "warn", "一级锁已开启但缺少自愈守护，建议重新点击一次「开启安全锁」")
    else:
        add("killswitch", "持久化安全锁 (pf)", "fail", "尚未初始化 (请先开启代理「全局+TUN」，再点击「一键初始化」)")

    # 2. TUN 虚拟网卡与默认路由归属
    rc_rt, rt_out = run_cmd(["route", "-n", "get", "1.1.1.1"])
    rt_if = ""
    if rc_rt == 0:
        m = re.search(r"interface:\s*(\S+)", rt_out)
        if m:
            rt_if = m.group(1)
    _, if_out = run_cmd(["ifconfig"])
    tun_ips = re.findall(r"inet\s+((?:198\.18|198\.19|172\.18|172\.19)\.\d+\.\d+)", if_out)
    if rt_if.startswith("utun"):
        add("tun", "全局 TUN 与默认路由", "ok", f"在线 (默认路由={rt_if}{', TUN IP=' + tun_ips[0] if tun_ips else ''})")
    elif tun_ips:
        add("tun", "全局 TUN 与默认路由", "fail", f"虚拟网卡在({tun_ips[0]})，但默认路由被 {rt_if or '无'} 抢占(疑似手机热点/未开全局)")
    else:
        add("tun", "全局 TUN 与默认路由", "fail", f"未检测到 TUN (当前默认路由={rt_if or '断网'})")

    # 3. 本地系统 DNS 审计 + isp.ac 上游 DNS 出口实测 (防大陆 DNS 泄露)
    _, dns_out = run_cmd(["scutil", "--dns"])
    dns_servers = sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*([0-9a-fA-F.:]+)", dns_out)))
    cn_hits = [s for s in dns_servers if s in CN_DNS_SERVERS]
    _, dig_out = run_cmd(["dig", "+short", "+time=3", "+tries=1", "claude.ai"])
    claude_dns = dig_out.strip().splitlines()[0] if dig_out.strip() else ""
    upstream_dns_cn = []
    upstream_dns_note = ""
    if not args.offline:
        st_dl, dl_data, _, _ = http_get_json("https://isp.ac/dns-leak-test", timeout=5)
        if st_dl == 200 and dl_data:
            entries = dl_data if isinstance(dl_data, list) else (dl_data.get("servers") or dl_data.get("results") or [dl_data] if isinstance(dl_data, dict) else [])
            ccs = []
            for e in entries:
                if isinstance(e, dict):
                    cc_v = str(e.get("country_code") or e.get("country") or "").upper()
                    if cc_v:
                        ccs.append(cc_v)
                        if cc_v in ("CN", "CHINA"):
                            upstream_dns_cn.append(str(e.get("ip") or cc_v))
            if ccs:
                upstream_dns_note = f"; 上游DNS={','.join(sorted(set(ccs))[:3])}"
    if upstream_dns_cn:
        add("dns", "本地与上游 DNS 泄露", "fail", f"上游 DNS 出口检出中国大陆服务器({','.join(upstream_dns_cn[:2])})")
    elif cn_hits and not (claude_dns.startswith("198.18.") or claude_dns.startswith("198.19.")):
        add("dns", "本地与上游 DNS 泄露", "fail", f"发现大陆 DNS({','.join(cn_hits)}) 且 claude.ai 解析={claude_dns or '空'}{upstream_dns_note}")
    elif claude_dns.startswith("198.18.") or claude_dns.startswith("198.19."):
        add("dns", "本地与上游 DNS 泄露", "ok", f"Fake-IP 隧道接管 (claude.ai={claude_dns}{upstream_dns_note})")
    elif claude_dns:
        state = "warn" if cn_hits else "ok"
        extra = f"; 系统含大陆DNS({','.join(cn_hits)})" if cn_hits else ""
        add("dns", "本地与上游 DNS 泄露", state, f"Real-IP 解析 ({claude_dns}{extra}{upstream_dns_note})")
    else:
        add("dns", "本地与上游 DNS 泄露", "unknown", f"未能解析 claude.ai (系统DNS={','.join(dns_servers[:3]) or '无'})")

    # 4. 代理环境变量与系统代理冲突审计 (参考 TZZ520/claude-environment-check，自动脱敏)
    env_proxies = {}
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        v = os.environ.get(k)
        if v:
            env_proxies[k] = sanitize_proxy_url(v)
    _, sc_proxy = run_cmd(["scutil", "--proxy"])
    pac_on = "ProxyAutoConfigEnable : 1" in sc_proxy
    if env_proxies:
        summary = ", ".join(f"{k}={v}" for k, v in list(env_proxies.items())[:3])
        add("proxy_env", "代理环境变量与 PAC", "warn", f"检测到环境变量代理({summary})，全局 TUN 下请确认未指向错误端口")
    elif pac_on:
        add("proxy_env", "代理环境变量与 PAC", "warn", "系统开启了 PAC 自动代理，建议全局+TUN 模式下关闭 PAC 以免分流直连")
    else:
        add("proxy_env", "代理环境变量与 PAC", "ok", "无冲突代理环境变量或 PAC")

    # 5 & 6 & 7. 多源出口 IP 共识 + 受限地区校验 + ASN/风险画像 (参考 AiSignalGuard & claude-analysis)
    egress_sources = []
    risk_signals = {}
    if not args.offline:
        # 源 1: ipinfo
        st, d, ms, _ = http_get_json("https://ipinfo.io/json")
        if st == 200 and isinstance(d, dict) and d.get("ip"):
            cc = str(d.get("country", "")).upper()
            egress_sources.append(("ipinfo", d.get("ip"), cc, str(d.get("timezone", "")), str(d.get("org", ""))))
        # 源 2: ipwho.is (含免费 proxy/vpn/hosting/isp 信号)
        st, d, ms, _ = http_get_json("https://ipwho.is/")
        if st == 200 and isinstance(d, dict) and d.get("ip") and d.get("success", True):
            cc = str(d.get("country_code", "")).upper()
            conn = d.get("connection") or {}
            tz_obj = d.get("timezone") or {}
            org = f"AS{conn.get('asn')} {conn.get('isp') or conn.get('org') or ''}".strip() if conn.get("asn") else ""
            egress_sources.append(("ipwho.is", d.get("ip"), cc, str(tz_obj.get("id", "")), org))
        # 源 3: cloudflare trace
        st, body, ms, _ = http_get_text("https://www.cloudflare.com/cdn-cgi/trace")
        if st == 200 and body:
            cf_ip = cf_cc = ""
            for line in body.splitlines():
                if line.startswith("ip="):
                    cf_ip = line.split("=", 1)[1].strip()
                if line.startswith("loc="):
                    cf_cc = line.split("=", 1)[1].strip().upper()
            if cf_ip and cf_cc:
                egress_sources.append(("cloudflare", cf_ip, cf_cc, "", ""))
        # 源 4: ipapi.is (免费代理/机房/VPN/Tor 风险标签，参考 claude-analysis)
        st, d, ms, _ = http_get_json("https://api.ipapi.is/")
        if st == 200 and isinstance(d, dict) and d.get("ip"):
            loc = d.get("location") or {}
            asn = d.get("asn") or {}
            cc = str(loc.get("country_code", "")).upper()
            org = f"AS{asn.get('asn')} {asn.get('org', '')}".strip() if asn.get("asn") else ""
            egress_sources.append(("ipapi.is", d.get("ip"), cc, str(loc.get("timezone", "")), org))
            risk_signals = {
                "datacenter": d.get("is_datacenter"),
                "proxy": d.get("is_proxy"),
                "vpn": d.get("is_vpn"),
                "tor": d.get("is_tor"),
                "abuser": d.get("is_abuser"),
                "asn_type": asn.get("type"),
            }

    consensus_ip = ""
    consensus_cc = ""
    consensus_tz = ""
    consensus_org = ""
    if args.offline:
        add("egress", "多源出口 IP 共识", "unknown", "离线演练模式，未发起外部探测")
        add("region_policy", "Anthropic 地区合规性", "unknown", "离线演练模式")
        add("ip_risk", "IP 纯净度与 ASN 画像", "unknown", "离线演练模式")
    elif not egress_sources:
        add("egress", "多源出口 IP 共识", "fail", "全部 4 个出口探测源均失败 (请检查节点与入口白名单 IP)")
        add("region_policy", "Anthropic 地区合规性", "fail", "无法确认出口国家")
        add("ip_risk", "IP 纯净度与 ASN 画像", "unknown", "无可用情报源")
    else:
        ips = [x[1] for x in egress_sources if x[1]]
        ccs = [x[2] for x in egress_sources if x[2]]
        consensus_ip = max(set(ips), key=ips.count)
        consensus_cc = max(set(ccs), key=ccs.count) if ccs else ""
        consensus_tz = next((x[3] for x in egress_sources if x[3]), "")
        consensus_org = next((x[4] for x in egress_sources if x[4]), "")
        unique_ips = sorted(set(ips))
        unique_ccs = sorted(set(ccs))
        if len(unique_ccs) > 1:
            add("egress", "多源出口 IP 共识", "fail", f"多源国家分歧({','.join(unique_ccs)}), 存在分流不一致风险")
        elif len(unique_ips) > 1:
            add("egress", "多源出口 IP 共识", "warn", f"同国({consensus_cc})但多源 IP 不同({','.join(unique_ips)})，可能走负载均衡出口")
        else:
            add("egress", "多源出口 IP 共识", "ok", f"{consensus_ip} / {consensus_cc} ({len(egress_sources)} 源完全一致)")

        # 受限地区检查 (含 CN/HK/MO 等)
        if consensus_cc in RESTRICTED_COUNTRIES:
            add("region_policy", "Anthropic 地区合规性", "fail", f"出口 {consensus_cc} 属于 Anthropic 不支持地区，严禁登录使用！")
        elif target_cc and consensus_cc != target_cc:
            add("region_policy", "Anthropic 地区合规性", "warn", f"出口 {consensus_cc} 与初始化目标 {target_cc} 不一致，建议重新初始化时区")
        else:
            add("region_policy", "Anthropic 地区合规性", "ok", f"出口地区 {consensus_cc} 属于支持地区")

        # IP 纯净度 / 风险标签 (严格区分已知与未知)
        if risk_signals:
            flags = []
            for label, key in (("机房", "datacenter"), ("公开代理", "proxy"), ("VPN", "vpn"), ("Tor", "tor"), ("滥用记录", "abuser")):
                if risk_signals.get(key) is True:
                    flags.append(label)
            asn_type = risk_signals.get("asn_type") or "unknown"
            if flags:
                add("ip_risk", "IP 纯净度与 ASN 画像", "warn", f"命中风险标签[{','.join(flags)}] | 类型={asn_type} | {consensus_org}")
            else:
                add("ip_risk", "IP 纯净度与 ASN 画像", "ok", f"无代理/机房/滥用标记 | 类型={asn_type} | {consensus_org}")
        elif consensus_org:
            add("ip_risk", "IP 纯净度与 ASN 画像", "warn", f"仅获取到 ASN({consensus_org})，第三方风险标签源未响应")
        else:
            add("ip_risk", "IP 纯净度与 ASN 画像", "unknown", "未能获取 ASN 与风险画像")

    # 8. WebRTC / STUN 泄露探测
    if args.offline:
        add("webrtc", "WebRTC / STUN 泄露", "unknown", "离线演练模式")
    else:
        stun_ips = probe_webrtc_all()
        if not stun_ips:
            if lock_on:
                add("webrtc", "WebRTC / STUN 泄露", "ok", "无 STUN 响应 (物理网卡 STUN 已被 pf 安全锁内核阻断，零泄露)")
            else:
                add("webrtc", "WebRTC / STUN 泄露", "warn", "STUN 无响应 (节点未开 UDP 或被拦截；建议开启安全锁兜底)")
        else:
            leaked = [x for x in stun_ips if consensus_ip and x != consensus_ip]
            if leaked:
                add("webrtc", "WebRTC / STUN 泄露", "fail", f"严重泄露！STUN 暴露非出口 IP: {','.join(leaked)} (出口={consensus_ip})")
            else:
                add("webrtc", "WebRTC / STUN 泄露", "ok", f"仅返回代理出口 IP ({','.join(stun_ips)})")

    # 9. 时区 / UTC 偏移 / 地区 / 客户端语言一致性 (参考 AiSignalGuard & TZZ520)
    try:
        cur_tz = os.path.realpath("/etc/localtime").split("/zoneinfo/")[-1]
    except Exception:
        cur_tz = ""
    utc_offset = datetime.datetime.now().astimezone().strftime("%z")
    _, cur_loc = run_cmd(["defaults", "read", "-g", "AppleLocale"])
    cur_loc = cur_loc.strip()
    _, claude_lang = run_cmd(["defaults", "read", "com.anthropic.claudefordesktop", "AppleLanguages"])
    lang_en = "en-US" in claude_lang or "en" in cur_loc.lower()

    tz_issues = []
    if cur_tz in ("Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin", "Asia/Urumqi"):
        tz_issues.append(f"仍为中国大陆时区({cur_tz})")
    elif consensus_cc and consensus_cc in COUNTRY_TZ_PREFIXES:
        if not any(cur_tz.startswith(p) for p in COUNTRY_TZ_PREFIXES[consensus_cc]):
            tz_issues.append(f"时区({cur_tz})与出口国({consensus_cc})不匹配")
    if cur_loc.lower().startswith("zh_cn"):
        tz_issues.append(f"系统地区仍为 {cur_loc}")
    if not lang_en:
        tz_issues.append("Claude客户端语言未设 en-US")
    if tz_issues:
        add("locale_tz", "时区/地区/语言一致性", "fail", "; ".join(tz_issues))
    else:
        add("locale_tz", "时区/地区/语言一致性", "ok", f"时区={cur_tz}(UTC{utc_offset}), 地区={cur_loc}, 语言=en-US")

    # 10. 全接口 IPv6 检查
    _, svcs_out = run_cmd(["networksetup", "-listallnetworkservices"])
    v6_on = []
    for svc in svcs_out.splitlines()[1:]:
        svc = svc.strip()
        if not svc or svc.startswith("*"):
            continue
        _, info = run_cmd(["networksetup", "-getinfo", svc])
        for line in info.splitlines():
            if line.lower().startswith("ipv6:") and "off" not in line.lower():
                v6_on.append(svc)
                break
    if not v6_on:
        add("ipv6", "全接口 IPv6 封锁", "ok", "所有活跃网络服务均已关闭 IPv6" + (" + pf内核封锁" if lock_on else ""))
    elif lock_on:
        add("ipv6", "全接口 IPv6 封锁", "warn", f"接口({','.join(v6_on)})未关 IPv6，但 pf 安全锁已在内核阻断全部公网 IPv6")
    else:
        add("ipv6", "全接口 IPv6 封锁", "fail", f"以下接口未关 IPv6({','.join(v6_on)}) 且安全锁未开")

    # 11. Anthropic 多端点连通性与延迟 (参考 TZZ520 & claude-analysis)
    if args.offline:
        add("endpoints", "Anthropic 多端点连通", "unknown", "离线演练模式")
    else:
        ep_results = []
        ep_failed = []
        ep_blocked = []
        for label, url in (
            ("claude.ai", "https://claude.ai/"),
            ("api", "https://api.anthropic.com/v1/models"),
            ("platform", "https://platform.claude.com/"),
        ):
            code, _, ms, err = http_get_text(url, timeout=6)
            if code == 0:
                ep_failed.append(f"{label}:{err}")
            elif code == 451:
                ep_blocked.append(f"{label}:HTTP451(地区封锁)")
            else:
                ep_results.append(f"{label}:{code}({ms}ms)")
        if ep_blocked:
            add("endpoints", "Anthropic 多端点连通", "fail", "遭遇地区封锁: " + ", ".join(ep_blocked))
        elif ep_failed:
            add("endpoints", "Anthropic 多端点连通", "fail", "端点不可达: " + ", ".join(ep_failed))
        else:
            add("endpoints", "Anthropic 多端点连通", "ok", ", ".join(ep_results))

    # 12. TLS 证书完整性 / ALPN / MITM 劫持校验 (参考 TZZ520/claude-environment-check)
    if args.offline:
        add("tls", "TLS 证书与 MITM 校验", "unknown", "离线演练模式")
    else:
        tls_res = check_tls_endpoint("api.anthropic.com")
        if not tls_res["ok"]:
            add("tls", "TLS 证书与 MITM 校验", "fail", f"TLS 握手失败({tls_res.get('error')})")
        elif tls_res["mitm"]:
            add("tls", "TLS 证书与 MITM 校验", "fail", f"疑似中间人劫持证书! Issuer={tls_res['issuer']}")
        else:
            add("tls", "TLS 证书与 MITM 校验", "ok", f"{tls_res['version']} / ALPN={tls_res['alpn']} / {tls_res['issuer']} ({tls_res['ms']}ms)")

    # 13. WebSocket 隧道支持能力 (参考 TZZ520/claude-environment-check)
    if args.offline:
        add("ws", "WebSocket 隧道能力", "unknown", "离线演练模式")
    else:
        ws_res = check_websocket_upgrade("claude.ai")
        if ws_res["ok"]:
            add("ws", "WebSocket 隧道能力", "ok", f"WSS 升级请求已达源站 (HTTP {ws_res['status']})")
        else:
            add("ws", "WebSocket 隧道能力", "warn", f"WSS 握手异常 ({ws_res.get('error')})，流式响应可能受影响")

    # 14. Claude 客户端与 CLI 认证污染检查 (参考 TZZ520/claude-environment-check)
    has_desktop = os.path.isdir("/Applications/Claude.app")
    cli_bin = shutil.which("claude")
    cli_ver = ""
    if cli_bin:
        _, vout = run_cmd([cli_bin, "--version"], timeout=4)
        cli_ver = vout.strip().splitlines()[0] if vout.strip() else "已安装"
    override_vars = [k for k in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX") if os.environ.get(k)]
    cli_desc = f"Desktop={'已装' if has_desktop else '未装'}, CLI={cli_ver or '未装'}"
    if override_vars:
        add("client_env", "Claude 客户端与环境变量", "warn", f"{cli_desc}; 检测到覆盖变量({','.join(override_vars)})")
    else:
        add("client_env", "Claude 客户端与环境变量", "ok", f"{cli_desc}; 无第三方覆盖变量")

    # 汇总统计与覆盖率 (参考 AiSignalGuard 严格语义: 未知项不计入通过)
    counts = {"ok": 0, "warn": 0, "fail": 0, "unknown": 0}
    for it in items:
        counts[it["state"]] += 1
    total = len(items)
    verified = total - counts["unknown"]
    coverage = int(round((verified / total) * 100)) if total else 0

    report = {
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "platform": f"macOS {platform.mac_ver()[0]} ({platform.machine()})",
        "coverage_percent": coverage,
        "summary": counts,
        "items": items,
    }

    if args.json:
        text_out = json.dumps(report, ensure_ascii=False, indent=2)
    else:
        icons = {"ok": "[✓]", "warn": "[!]", "fail": "[✗]", "unknown": "[?]"}
        lines = [
            f"=== Claude 14 维度深度本地环境体检 ({report['platform']}) ===",
            f"时间: {report['timestamp']} | 证据覆盖率: {coverage}% ({verified}/{total} 已核实)",
            "-" * 58,
        ]
        for idx, it in enumerate(items, 1):
            lines.append(f"{idx:02d}. {icons[it['state']]} {it['name']}: {it['detail']}")
        lines.append("-" * 58)
        lines.append(
            f"统计: 通过={counts['ok']} | 警告={counts['warn']} | 失败={counts['fail']} | 未知={counts['unknown']}"
        )
        if counts["fail"] == 0 and counts["unknown"] == 0:
            lines.append("结论: 核心环境全部核实通过，可以放心交付/使用 Claude")
        elif counts["fail"] == 0:
            lines.append("结论: 已核实项无失败（存在未知或警告项，请结合明细确认）")
        else:
            lines.append(f"结论: 有 {counts['fail']} 项未通过，请先修复后再使用 Claude")
        text_out = "\n".join(lines)

    if args.export:
        with open(args.export, "w", encoding="utf-8") as f:
            f.write(text_out + "\n")

    print(text_out)
    return 0 if counts["fail"] == 0 else 1


def main():
    parser = argparse.ArgumentParser(description="Claude 安全锁 macOS 14 维度深度本地环境体检")
    parser.add_argument("--config", default=os.path.expanduser("~/.claude-guard/config.env"))
    parser.add_argument("--pf-conf", default="/etc/pf.conf")
    parser.add_argument("--pf-anchor", default="/etc/pf.anchors/com.claude-guard")
    parser.add_argument("--pf-boot-plist", default="/Library/LaunchDaemons/com.claude-guard.pfboot.plist")
    parser.add_argument("--json", action="store_true", help="输出 JSON 格式报告")
    parser.add_argument("--export", default="", help="将脱敏体检报告另存到指定文件")
    parser.add_argument("--offline", action="store_true", help="离线演练模式(不发外部网络请求，用于单元测试)")
    args = parser.parse_args()
    sys.exit(run_audit(args))


if __name__ == "__main__":
    main()
