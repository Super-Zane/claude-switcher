"""portable-kit (双锁持久化防泄露双端安装包) 全量自动化回归与安全边界测试。"""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "portable-kit"
DIST = ROOT / "dist"
MAC_GUARD = KIT / "mac" / "claude-guard.sh"
MAC_CONSOLE = KIT / "mac" / "Claude安全锁控制台.command"
MAC_SHORTCUT = KIT / "mac" / "创建桌面快捷App.command"
MAC_INSTALL = KIT / "mac" / "一键安装.command"
MAC_UNINSTALL = KIT / "mac" / "卸载.command"
MAC_AUDIT = KIT / "mac" / "env-audit.py"
WIN_GUARD = KIT / "windows" / "claude-guard.ps1"
WIN_AUDIT = KIT / "windows" / "env-audit.ps1"
WIN_UI = KIT / "windows" / "ClaudeGuardUI.ps1"
WIN_BAT = KIT / "windows" / "Claude安全锁控制台.bat"
WIN_INSTALL = KIT / "windows" / "一键安装.bat"
WIN_UNINSTALL = KIT / "windows" / "卸载.bat"
CN_IPV4_FILE = KIT / "data" / "cn-ipv4.txt"
OVERSEAS_IPV4_FILE = KIT / "data" / "overseas-ipv4-ranges.txt"
PKG_SCRIPT = ROOT / "scripts" / "package-portable-kit.sh"

# 复用仓库已有的 PowerShell 括号平衡校验器
sys.path.insert(0, str(ROOT / "tests"))
from test_windows_update_static import ps1_balance_error  # noqa: E402


class PortableKitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_mac_shell_scripts_syntax_and_executable(self):
        for path in (MAC_GUARD, MAC_CONSOLE, MAC_SHORTCUT, MAC_INSTALL, MAC_UNINSTALL, PKG_SCRIPT):
            with self.subTest(script=path.name):
                self.assertTrue(path.exists(), f"缺少脚本: {path}")
                self.assertTrue(os.access(path, os.X_OK), f"{path.name} 必须具备可执行权限")
                run = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True, timeout=5)
                self.assertEqual(run.returncode, 0, run.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "pfctl syntax validation requires macOS")
    def test_mac_dual_lock_pf_rules_pass_pfctl_with_real_cn_table(self):
        # 1. 全封闭模式(strict) 空白名单必须拒绝，防止锁死客户整机无法连代理
        empty_strict = subprocess.run(
            ["/bin/bash", str(MAC_GUARD), "render", "", "utun4", "198.18.0.1", "0", str(CN_IPV4_FILE), "160.79.104.0/21", "strict"],
            env=dict(os.environ, CLAUDE_GUARD_DIR=str(self.root)),
            capture_output=True, text=True, timeout=5,
        )
        self.assertNotEqual(empty_strict.returncode, 0)

        # 2. 锁1·国内直连放行模式(cn): 挂接真实 7,456 条 CN IPv4 文件，允许空白名单(链式代理第一跳在国内中转机)，必须通过真机 pfctl -nvf
        cn_run = subprocess.run(
            ["/bin/bash", str(MAC_GUARD), "render", "203.0.113.10", "utun5", "198.18.0.1", "0", str(CN_IPV4_FILE), "160.79.104.0/21, 104.18.1.1", "cn"],
            env=dict(os.environ, CLAUDE_GUARD_DIR=str(self.root)),
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(cn_run.returncode, 0, cn_run.stderr)
        cn_rules = cn_run.stdout
        self.assertIn(f'table <claude_guard_cn> persist file "{CN_IPV4_FILE}"', cn_rules)
        self.assertIn("table <claude_blocked_v4> persist { 160.79.104.0/21, 104.18.1.1 }", cn_rules)
        self.assertIn("block drop out log quick inet6 to <claude_blocked_v6>", cn_rules)
        self.assertIn("block drop out log quick inet6 all", cn_rules)
        self.assertIn("block drop out log quick inet to <claude_blocked_v4>", cn_rules)
        self.assertIn("block drop out log quick inet proto udp to any port { 3478, 5349, 19302 }", cn_rules)
        self.assertIn("pass out quick inet to <claude_guard_cn>", cn_rules)
        self.assertIn("block drop out log quick inet all", cn_rules)

        pf_cn = subprocess.run(["pfctl", "-nvf", "-"], input=cn_rules, capture_output=True, text=True, timeout=15)
        self.assertEqual(pf_cn.returncode, 0, pf_cn.stdout + pf_cn.stderr)

        # 3. 锁1·全封闭模式(strict): 必须连局域网裸 DNS 53 与全部公网一并阻断，且带 log，通过真机 pfctl -nvf
        strict_run = subprocess.run(
            ["/bin/bash", str(MAC_GUARD), "render", "203.0.113.10, 198.51.100.0/24", "utun5", "10.8.0.2", "0", str(CN_IPV4_FILE), "160.79.104.0/21", "strict"],
            env=dict(os.environ, CLAUDE_GUARD_DIR=str(self.root)),
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(strict_run.returncode, 0, strict_run.stderr)
        strict_rules = strict_run.stdout
        self.assertIn("203.0.113.10, 198.51.100.0/24", strict_rules)
        self.assertIn("10.8.0.2", strict_rules)
        self.assertIn("block drop out log quick inet proto { tcp, udp } to <claude_guard_lan> port 53", strict_rules)
        self.assertNotIn("pass out quick inet to <claude_guard_cn>", strict_rules)
        self.assertIn("block drop out log quick inet all", strict_rules)

        pf_strict = subprocess.run(["pfctl", "-nvf", "-"], input=strict_rules, capture_output=True, text=True, timeout=15)
        self.assertEqual(pf_strict.returncode, 0, pf_strict.stdout + pf_strict.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "macOS guard dry-run flow")
    def test_mac_set_nodes_dual_lock_dry_run_and_boot_persistence_markers(self):
        pf_conf = self.root / "pf.conf"
        pf_conf.write_text('# original pf.conf\nanchor "com.apple/*"\n', encoding="utf-8")
        hosts = self.root / "hosts"
        hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
        anchor = self.root / "com.claude-guard"

        env = dict(
            os.environ,
            CLAUDE_GUARD_DIR=str(self.root / "state"),
            CLAUDE_GUARD_PF_CONF=str(pf_conf),
            CLAUDE_GUARD_ANCHOR_FILE=str(anchor),
            CLAUDE_GUARD_HOSTS=str(hosts),
            CLAUDE_GUARD_DRY_RUN="1",
        )

        # 保存入口 IP (包含端口误粘贴自动清洗)
        r1 = subprocess.run(["/bin/bash", str(MAC_GUARD), "set-nodes", "203.0.113.10:443, 198.51.100.5"],
                            env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
        self.assertIn("OK:", r1.stdout)

        # 演练锁1国内直连放行模式
        r2 = subprocess.run(["/bin/bash", str(MAC_GUARD), "lock-cn"],
                            env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertIn("table <claude_guard_entries> persist { 203.0.113.10, 198.51.100.5 }", r2.stdout)
        self.assertIn("pass out quick inet to <claude_guard_cn>", r2.stdout)
        self.assertIn("OK:持久化硬锁演练通过 (mode=cn)", r2.stdout)

        # 演练锁1全封闭模式
        r3 = subprocess.run(["/bin/bash", str(MAC_GUARD), "lock-strict"],
                            env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(r3.returncode, 0, r3.stdout + r3.stderr)
        self.assertIn("OK:持久化硬锁演练通过 (mode=strict)", r3.stdout)

        # 验证开机持久化 LaunchDaemon 与 verify-firewall 验收逻辑存在于脚本中
        guard_text = MAC_GUARD.read_text(encoding="utf-8")
        self.assertIn('PF_BOOT_LABEL="com.claude-guard.pfboot"', guard_text)
        self.assertIn("/Library/LaunchDaemons/${PF_BOOT_LABEL}.plist", guard_text)
        self.assertIn("RunAtLoad", guard_text)
        self.assertIn("_verify_firewall_root()", guard_text)
        self.assertIn("pflog0", guard_text)

        # 验证托管块写入与无痕清理不破坏原始 hosts 内容
        block_test = f"""
source "{MAC_GUARD}"
write_managed_block "{hosts}" "# BEGIN claude-guard-hosts" "# END claude-guard-hosts" "203.0.113.10 entry.example.com"
grep -q "entry.example.com" "{hosts}" || exit 1
remove_managed_block "{hosts}" "# BEGIN claude-guard-hosts" "# END claude-guard-hosts"
grep -q "entry.example.com" "{hosts}" && exit 2
grep -q "127.0.0.1 localhost" "{hosts}" || exit 3
"""
        r4 = subprocess.run(["/bin/bash", "-c", block_test], env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(r4.returncode, 0, r4.stdout + r4.stderr)

    def test_windows_scripts_bom_lf_braces_dual_lock_and_zero_gap_swap(self):
        for p in (WIN_GUARD, WIN_AUDIT, WIN_UI):
            with self.subTest(file=p.name):
                raw = p.read_bytes()
                self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), f"{p.name} 必须带 UTF-8 BOM")
                self.assertEqual(raw.count(b"\r\n"), 0, f"{p.name} 必须使用 LF 换行")
                text = raw.decode("utf-8-sig")
                self.assertIsNone(ps1_balance_error(text))
                self.assertNotIn("Invoke-Expression", text)

        # 所有 .bat 必须使用无 BOM + CRLF（避免 chcp 65001 第一行 @echo off 遇 BOM 报错）
        for bat in (WIN_BAT, WIN_INSTALL, WIN_UNINSTALL):
            with self.subTest(bat=bat.name):
                raw = bat.read_bytes()
                self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), f"{bat.name} 不能带 UTF-8 BOM")
                self.assertGreater(raw.count(b"\r\n"), 0, f"{bat.name} 必须使用 CRLF 换行")
                self.assertIn("RunAs", raw.decode("utf-8"))

        audit_text = WIN_AUDIT.read_text(encoding="utf-8-sig")
        for token in ("RESTRICTED_COUNTRIES", "CN_DNS_SERVERS", "Test-StunServer", "Test-TlsEndpoint", "Test-WssUpgrade", "Hide-ProxyCreds", "coverage_percent", "LogBlocked"):
            self.assertIn(token, audit_text)

        guard_text = WIN_GUARD.read_text(encoding="utf-8-sig")
        self.assertIn("1.0.0.0", guard_text)
        self.assertIn("223.255.255.255", guard_text)
        self.assertNotIn("0.0.0.0-126.255.255.255", guard_text)
        self.assertNotIn("255.255.255.255'", guard_text)
        for token in (
            "ClaudeGuard-KillSwitch",
            "ClaudeGuard-Block-Claude-ASN-V4-",
            "ClaudeGuard-Block-All-Public-V6-",
            "ClaudeGuard-Block-TargetApp-V4-",
            "ClaudeGuard-Block-Overseas-V4-Part",
            "ClaudeGuard-Block-Strict-All-V4-",
            "Subtract-CidrsFromRanges",
            "LogBlocked True",
            "pfirewall.log",
            "$oldRules | Remove-NetFirewallRule",
            "Invoke-VerifyFirewall",
            "Invoke-UnlockAll",
        ):
            self.assertIn(token, guard_text, f"claude-guard.ps1 缺少关键能力: {token}")

    def test_windows_ui_xaml_well_formed_dual_lock_and_warning_dialog(self):
        ui_text = WIN_UI.read_text(encoding="utf-8-sig")
        match = re.search(r'\$xaml = @"\n(.*?)\n"@', ui_text, re.S)
        self.assertIsNotNone(match)
        root = ET.fromstring(match.group(1))
        x_name = "{http://schemas.microsoft.com/winfx/2006/xaml}Name"
        names = [node.get(x_name) for node in root.iter() if node.get(x_name)]
        self.assertEqual(len(names), len(set(names)), "XAML x:Name 不得重复")
        for ctrl in (
            "StatusPill", "StatusText", "StatusSub", "NodesInput", "BtnSaveNodes",
            "BtnLockCn", "BtnLockStrict", "BtnUnlockAll", "BtnInit", "BtnVerifyFw",
            "BtnCheck", "BtnExport", "OutputBox",
        ):
            self.assertIn(ctrl, names)
            self.assertIn(f"FindName('{ctrl}')", ui_text)
        # 锁 2 解锁必须带强二次确认警示弹窗，且默认选 No
        self.assertIn("MessageBox", ui_text)
        self.assertIn("MessageBoxResult]::No", ui_text)
        self.assertIn("千万不要", ui_text)

    def test_mac_14_dim_env_audit_offline_json_export_and_persistence_check(self):
        """验证 14 维度深度体检引擎: JSON 结构、开机持久化校验、脱敏代理密码与导出文件。"""
        pf_conf = self.root / "pf.conf"
        pf_conf.write_text('# BEGIN claude-guard-pf\nanchor "com.claude-guard"\n# END claude-guard-pf\n', encoding="utf-8")
        anchor = self.root / "com.claude-guard"
        anchor.write_text("block drop out log quick inet all\n", encoding="utf-8")
        boot_plist = self.root / "com.claude-guard.pfboot.plist"
        boot_plist.write_text("<plist/>", encoding="utf-8")
        cfg = self.root / "config.env"
        cfg.write_text('ENTRY_NODES="203.0.113.10"\nCOUNTRY_TARGET="US"\nLOCK_MODE="cn"\n', encoding="utf-8")
        export_file = self.root / "report.json"

        env = dict(os.environ, HTTPS_PROXY="http://alice:supersecret@127.0.0.1:7890")
        run = subprocess.run(
            [
                "python3", str(MAC_AUDIT),
                "--config", str(cfg),
                "--pf-conf", str(pf_conf),
                "--pf-anchor", str(anchor),
                "--pf-boot-plist", str(boot_plist),
                "--offline", "--json",
                "--export", str(export_file),
            ],
            env=env, capture_output=True, text=True, timeout=15,
        )
        data = json.loads(run.stdout)
        self.assertEqual(len(data["items"]), 14, f"应恰好输出 14 维度体检，实际: {len(data['items'])}")
        ids = [it["id"] for it in data["items"]]
        for expected_id in ("killswitch", "tun", "dns", "proxy_env", "egress", "region_policy", "ip_risk", "webrtc", "locale_tz", "ipv6", "endpoints", "tls", "ws", "client_env"):
            self.assertIn(expected_id, ids)
        ks = next(it for it in data["items"] if it["id"] == "killswitch")
        self.assertEqual(ks["state"], "ok")
        self.assertIn("开机守护", ks["detail"])
        pe = next(it for it in data["items"] if it["id"] == "proxy_env")
        self.assertEqual(pe["state"], "warn")
        self.assertIn("alice:***@", pe["detail"])
        self.assertNotIn("supersecret", run.stdout)
        self.assertTrue(export_file.is_file())
        self.assertNotIn("supersecret", export_file.read_text(encoding="utf-8"))
        self.assertGreater(data["summary"]["unknown"], 0)
        self.assertLess(data["coverage_percent"], 100)

    def test_real_cn_and_overseas_ip_tables_and_subtract_whitelist_math(self):
        """验证真实 7,456 条 CN 表与 4,751 条海外补集表的一致性、合法单播边界、以及精准挖空白名单入口 IP。"""
        self.assertTrue(CN_IPV4_FILE.is_file())
        self.assertTrue(OVERSEAS_IPV4_FILE.is_file())

        cn_nets = [ipaddress.IPv4Network(line.strip(), strict=False)
                   for line in CN_IPV4_FILE.read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.strip().startswith("#")]
        self.assertGreater(len(cn_nets), 5000, "CN IPv4 列表条目异常过少")

        # 防御性断言: Anthropic 官方 ASN 160.79.104.0/21 绝对不能出现在 CN 放行表中
        anth_net = ipaddress.IPv4Network("160.79.104.0/21")
        for n in cn_nets:
            self.assertFalse(n.overlaps(anth_net), f"CN 表意外与 Anthropic ASN 重叠: {n}")

        # 解析预计算海外补集表并校验全部落在 1.0.0.0 - 223.255.255.255 合法单播边界内
        lo = int(ipaddress.IPv4Address("1.0.0.0"))
        hi = int(ipaddress.IPv4Address("223.255.255.255"))
        ov_intervals = []
        for line in OVERSEAS_IPV4_FILE.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split("-")
            a = int(ipaddress.IPv4Address(parts[0]))
            b = int(ipaddress.IPv4Address(parts[1])) if len(parts) > 1 else a
            self.assertGreaterEqual(a, lo)
            self.assertLessEqual(b, hi)
            self.assertLessEqual(a, b)
            ov_intervals.append((a, b))
        self.assertGreater(len(ov_intervals), 2000)

        # 模拟 Windows Subtract-CidrsFromRanges 精准挖空海外白名单入口 IP 203.0.113.10/32
        ex_net = ipaddress.IPv4Network("203.0.113.10/32")
        ex_s, ex_e = int(ex_net.network_address), int(ex_net.broadcast_address)
        subtracted = []
        for s, e in ov_intervals:
            if ex_e < s or ex_s > e:
                subtracted.append((s, e))
            else:
                if s < ex_s:
                    subtracted.append((s, ex_s - 1))
                if e > ex_e:
                    subtracted.append((ex_e + 1, e))

        def is_blocked_overseas(ip_str):
            v = int(ipaddress.IPv4Address(ip_str))
            return any(s <= v <= e for s, e in subtracted)

        # 1. 国内直连服务、局域网、TUN、白名单海外入口均不被封锁
        for allowed_ip in ("114.114.114.114", "223.5.5.5", "110.242.68.66", "192.168.1.1", "10.0.0.1", "198.18.0.1", "203.0.113.10"):
            self.assertFalse(is_blocked_overseas(allowed_ip), f"不应被海外规则封锁: {allowed_ip}")

        # 2. Anthropic 官方 ASN 与海外常见服务、白名单相邻 IP 全部 100% 落入封锁区间
        for blocked_ip in ("160.79.104.10", "160.79.111.200", "1.1.1.1", "8.8.8.8", "104.18.1.1", "142.250.190.78", "203.0.113.9", "203.0.113.11"):
            self.assertTrue(is_blocked_overseas(blocked_ip), f"必须被海外规则封锁: {blocked_ip}")

    def test_dist_installers_zip_integrity_utf8_flags_and_permissions(self):
        """验证双端即装安装包 zip 结构完整、带 UTF-8 Bit 11 标志位 (Windows 中文零乱码) 且 macOS 脚本带 +x 权限。"""
        mac_zip = DIST / "Claude安全锁-macOS安装包.zip"
        win_zip = DIST / "Claude安全锁-Windows安装包.zip"
        self.assertTrue(mac_zip.is_file(), f"缺少 macOS 安装包: {mac_zip}")
        self.assertTrue(win_zip.is_file(), f"缺少 Windows 安装包: {win_zip}")

        with zipfile.ZipFile(mac_zip) as zf:
            names = set(zf.namelist())
            for req in (
                "Claude安全锁-macOS安装包/一键安装.command",
                "Claude安全锁-macOS安装包/卸载.command",
                "Claude安全锁-macOS安装包/README-交付手册.md",
                "Claude安全锁-macOS安装包/mac/claude-guard.sh",
                "Claude安全锁-macOS安装包/mac/Claude安全锁控制台.command",
                "Claude安全锁-macOS安装包/mac/env-audit.py",
                "Claude安全锁-macOS安装包/data/cn-ipv4.txt",
            ):
                self.assertIn(req, names)
            for info in zf.infolist():
                self.assertTrue(info.flag_bits & 0x800, f"{info.filename} 必须带 UTF-8 Bit 11 标志")
                if info.filename.endswith((".command", ".sh", ".py")):
                    unix_mode = (info.external_attr >> 16) & 0o777
                    self.assertTrue(unix_mode & 0o111, f"{info.filename} 解压后必须保留可执行权限")

        with zipfile.ZipFile(win_zip) as zf:
            names = set(zf.namelist())
            for req in (
                "Claude安全锁-Windows安装包/一键安装.bat",
                "Claude安全锁-Windows安装包/卸载.bat",
                "Claude安全锁-Windows安装包/README-交付手册.md",
                "Claude安全锁-Windows安装包/windows/claude-guard.ps1",
                "Claude安全锁-Windows安装包/windows/ClaudeGuardUI.ps1",
                "Claude安全锁-Windows安装包/windows/env-audit.ps1",
                "Claude安全锁-Windows安装包/windows/Claude安全锁控制台.bat",
                "Claude安全锁-Windows安装包/data/cn-ipv4.txt",
                "Claude安全锁-Windows安装包/data/overseas-ipv4-ranges.txt",
            ):
                self.assertIn(req, names)
            for info in zf.infolist():
                self.assertTrue(info.flag_bits & 0x800, f"{info.filename} 必须带 UTF-8 Bit 11 标志")


if __name__ == "__main__":
    unittest.main()
