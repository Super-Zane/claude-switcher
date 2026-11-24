"""portable-kit (极简单锁 + 永久系统级进程锁与遥测防线) 全量自动化回归与安全边界测试。"""
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
MAC_INSTALL = KIT / "mac" / "一键安装.command"
MAC_UNINSTALL = KIT / "mac" / "卸载.command"
MAC_AUDIT = KIT / "mac" / "env-audit.py"
WIN_GUARD = KIT / "windows" / "claude-guard.ps1"
WIN_AUDIT = KIT / "windows" / "env-audit.ps1"
WIN_UI = KIT / "windows" / "ClaudeGuardUI.ps1"
WIN_VBS = KIT / "windows" / "claude-blocked-alert.vbs"
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
        for path in (MAC_GUARD, MAC_CONSOLE, MAC_INSTALL, MAC_UNINSTALL, PKG_SCRIPT):
            with self.subTest(script=path.name):
                self.assertTrue(path.exists(), f"缺少脚本: {path}")
                self.assertTrue(os.access(path, os.X_OK), f"{path.name} 必须具备可执行权限")
                run = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True, timeout=5)
                self.assertEqual(run.returncode, 0, run.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "pfctl syntax validation requires macOS")
    def test_mac_three_pf_modes_pass_pfctl_with_real_cn_table(self):
        # 1. 全封闭模式(strict) 空白名单必须拒绝
        empty_strict = subprocess.run(
            ["/bin/bash", str(MAC_GUARD), "render", "", "utun4", "198.18.0.1", "0", str(CN_IPV4_FILE), "160.79.104.0/21", "strict"],
            env=dict(os.environ, CLAUDE_GUARD_DIR=str(self.root)),
            capture_output=True, text=True, timeout=5,
        )
        self.assertNotEqual(empty_strict.returncode, 0)

        # 2. 安全锁开启·国内直连放行(cn): 挂接真实 7,456 条 CN 表，通过 pfctl -nvf
        cn_run = subprocess.run(
            ["/bin/bash", str(MAC_GUARD), "render", "203.0.113.10", "utun5", "198.18.0.1", "0", str(CN_IPV4_FILE), "160.79.104.0/21, 104.18.1.1", "cn"],
            env=dict(os.environ, CLAUDE_GUARD_DIR=str(self.root)),
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(cn_run.returncode, 0, cn_run.stderr)
        cn_rules = cn_run.stdout
        self.assertIn(f'table <claude_guard_cn> persist file "{CN_IPV4_FILE}"', cn_rules)
        self.assertIn("block drop out log quick inet to <claude_blocked_v4>", cn_rules)
        self.assertIn("pass out quick inet to <claude_guard_cn>", cn_rules)
        self.assertIn("block drop out log quick inet all", cn_rules)
        pf_cn = subprocess.run(["pfctl", "-nvf", "-"], input=cn_rules, capture_output=True, text=True, timeout=15)
        self.assertEqual(pf_cn.returncode, 0, pf_cn.stdout + pf_cn.stderr)

        # 3. 安全锁开启·全封闭(strict): 封裸 DNS 53 + 全公网，通过 pfctl -nvf
        strict_run = subprocess.run(
            ["/bin/bash", str(MAC_GUARD), "render", "203.0.113.10", "utun5", "10.8.0.2", "0", str(CN_IPV4_FILE), "160.79.104.0/21", "strict"],
            env=dict(os.environ, CLAUDE_GUARD_DIR=str(self.root)),
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(strict_run.returncode, 0, strict_run.stderr)
        self.assertIn("block drop out log quick inet proto { tcp, udp } to <claude_guard_lan> port 53", strict_run.stdout)
        pf_strict = subprocess.run(["pfctl", "-nvf", "-"], input=strict_run.stdout, capture_output=True, text=True, timeout=15)
        self.assertEqual(pf_strict.returncode, 0, pf_strict.stdout + pf_strict.stderr)

        # 4. 安全锁关闭·日常常驻底线(standby): 放行日常上网但永久阻断 Claude ASN/遥测 IP (IPv4 + IPv6)，通过 pfctl -nvf
        standby_run = subprocess.run(
            ["/bin/bash", str(MAC_GUARD), "render", "", "utun5", "198.18.0.1", "0", "", "160.79.104.0/21, 104.18.1.1", "standby"],
            env=dict(os.environ, CLAUDE_GUARD_DIR=str(self.root)),
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(standby_run.returncode, 0, standby_run.stderr)
        st_rules = standby_run.stdout
        self.assertIn("mode=standby", st_rules)
        self.assertIn("block drop out log quick inet to <claude_blocked_v4>", st_rules)
        self.assertIn("block drop out log quick inet6 to <claude_blocked_v6>", st_rules)
        self.assertNotIn("block drop out log quick inet all", st_rules)
        pf_st = subprocess.run(["pfctl", "-nvf", "-"], input=st_rules, capture_output=True, text=True, timeout=15)
        self.assertEqual(pf_st.returncode, 0, pf_st.stdout + pf_st.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "macOS lossless app & CLI process lock flow")
    def test_mac_lossless_process_lock_idempotent_hosts_blackhole_and_restore(self):
        """实测 macOS 关闭安全锁时: 无损藏匿真 Claude.app + chmod a-x + 部署占位弹窗 + 拦截 CLI + 写入 24 个遥测域名黑洞；重复 unlock 幂等不损坏原应用；开锁/卸载后 100% 原样还原！"""
        fake_apps = self.root / "Applications"
        fake_claude = fake_apps / "Claude.app"
        fake_bin = fake_claude / "Contents" / "MacOS" / "Claude"
        fake_bin.parent.mkdir(parents=True)
        orig_app_bytes = b"#!/bin/sh\necho REAL_CLAUDE_APP_BINARY_SIGNATURE_OK\n"
        fake_bin.write_bytes(orig_app_bytes)
        os.chmod(fake_bin, 0o755)

        fake_cli_dir = self.root / "bin"
        fake_cli_dir.mkdir(parents=True)
        fake_cli = fake_cli_dir / "claude"
        orig_cli_bytes = b"#!/bin/sh\necho REAL_CLAUDE_CLI_OK\n"
        fake_cli.write_bytes(orig_cli_bytes)
        os.chmod(fake_cli, 0o755)

        hosts = self.root / "hosts"
        hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
        pf_conf = self.root / "pf.conf"
        pf_conf.write_text('# orig\nanchor "com.apple/*"\n', encoding="utf-8")

        env = dict(
            os.environ,
            CLAUDE_GUARD_DIR=str(self.root / "state"),
            CLAUDE_GUARD_PF_CONF=str(pf_conf),
            CLAUDE_GUARD_ANCHOR_FILE=str(self.root / "com.claude-guard"),
            CLAUDE_GUARD_HOSTS=str(hosts),
            CLAUDE_GUARD_CLAUDE_APP=str(fake_claude),
            CLAUDE_GUARD_HIDDEN_APP=str(fake_apps / ".Claude-Locked.app"),
            CLAUDE_GUARD_EXTRA_CLI=str(fake_cli),
            CLAUDE_GUARD_DRY_RUN="1",
        )

        # 1. 执行 unlock (日常模式): 必须锁死 Claude.app 和 CLI 并写入遥测 hosts 黑洞
        r1 = subprocess.run(["/bin/bash", str(MAC_GUARD), "unlock"], env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
        self.assertTrue((fake_claude / ".claude-guard-blocker").is_file(), "原位应部署占位拦截器")
        hidden_bin = fake_apps / ".Claude-Locked.app" / "Contents" / "MacOS" / "Claude"
        self.assertTrue(hidden_bin.is_file(), "真实 Claude.app 必须无损藏匿")
        self.assertEqual(hidden_bin.read_bytes(), orig_app_bytes, "真实应用字节必须零篡改")
        self.assertFalse(os.access(hidden_bin, os.X_OK), "藏匿的真实二进制必须被 chmod a-x 剥夺执行位")

        # 占位器 Info.plist 必须通过 plutil -lint
        r_pl = subprocess.run(["plutil", "-lint", str(fake_claude / "Contents" / "Info.plist")], capture_output=True, text=True)
        self.assertEqual(r_pl.returncode, 0, r_pl.stdout + r_pl.stderr)

        # CLI 必须已被占位拦截，且原 CLI 无损藏匿并失去执行位
        self.assertIn("CLAUDE_GUARD_CLI_BLOCKER", fake_cli.read_text(encoding="utf-8"))
        hidden_cli = fake_cli_dir / ".claude-guard-real-claude"
        self.assertEqual(hidden_cli.read_bytes(), orig_cli_bytes)
        self.assertFalse(os.access(hidden_cli, os.X_OK))

        # hosts 必须包含全部核心与遥测域名黑洞
        hosts_txt = hosts.read_text(encoding="utf-8")
        for dom in ("claude.ai", "api.anthropic.com", "statsig.anthropic.com", "o1158394.ingest.us.sentry.io", "statsigapi.net", "featuregates.org"):
            self.assertIn(f"0.0.0.0 {dom}", hosts_txt)

        # 2. 幂等校验: 连续第二次执行 unlock，绝对不能覆写损坏藏匿的真实 Claude.app!
        r2 = subprocess.run(["/bin/bash", str(MAC_GUARD), "unlock"], env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertEqual(hidden_bin.read_bytes(), orig_app_bytes)
        self.assertEqual(hidden_cli.read_bytes(), orig_cli_bytes)

        # 3. 开启安全锁 (lock): 必须 100% 无损还原真实 Claude.app 与 CLI 并恢复执行权限
        r3 = subprocess.run(["/bin/bash", str(MAC_GUARD), "lock"], env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(r3.returncode, 0, r3.stdout + r3.stderr)
        self.assertFalse((fake_claude / ".claude-guard-blocker").exists())
        self.assertFalse((fake_apps / ".Claude-Locked.app").exists())
        self.assertEqual(fake_bin.read_bytes(), orig_app_bytes)
        self.assertTrue(os.access(fake_bin, os.X_OK), "开锁后真实 Claude.app 必须恢复可执行权限")
        self.assertEqual(fake_cli.read_bytes(), orig_cli_bytes)
        self.assertTrue(os.access(fake_cli, os.X_OK), "开锁后真实 claude CLI 必须恢复可执行权限")

        # 验证自愈开机守护逻辑存在于脚本中
        guard_text = MAC_GUARD.read_text(encoding="utf-8")
        self.assertIn("install_pf_boot_daemon_root()", guard_text)
        self.assertIn("Claude Helper", guard_text)

    def test_windows_scripts_bom_lf_ifeo_telemetry_and_single_lock_ui(self):
        for p in (WIN_GUARD, WIN_AUDIT, WIN_UI):
            with self.subTest(file=p.name):
                raw = p.read_bytes()
                self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), f"{p.name} 必须带 UTF-8 BOM")
                self.assertEqual(raw.count(b"\r\n"), 0, f"{p.name} 必须使用 LF 换行")
                text = raw.decode("utf-8-sig")
                self.assertIsNone(ps1_balance_error(text))
                self.assertNotIn("Invoke-Expression", text)

        # claude-blocked-alert.vbs 必须为 UTF-16 LE BOM，确保中文 Windows wscript 0ms 零乱码弹窗
        vbs_raw = WIN_VBS.read_bytes()
        self.assertTrue(vbs_raw.startswith(b"\xff\xfe"), "claude-blocked-alert.vbs 必须为 UTF-16 LE BOM")
        vbs_txt = vbs_raw.decode("utf-16")
        self.assertIn("Claude安全锁控制台.bat", vbs_txt)
        self.assertIn("安全锁当前未开启", vbs_txt)

        for bat in (WIN_BAT, WIN_INSTALL, WIN_UNINSTALL):
            with self.subTest(bat=bat.name):
                raw = bat.read_bytes()
                self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), f"{bat.name} 不能带 UTF-8 BOM")
                self.assertGreater(raw.count(b"\r\n"), 0, f"{bat.name} 必须使用 CRLF 换行")
                self.assertIn("RunAs", raw.decode("utf-8"))

        guard_text = WIN_GUARD.read_text(encoding="utf-8-sig")
        self.assertIn("1.0.0.0", guard_text)
        self.assertIn("223.255.255.255", guard_text)
        self.assertNotIn("0.0.0.0-126.255.255.255", guard_text)
        for token in (
            "Image File Execution Options\\Claude.exe",
            "claude-blocked-alert.vbs",
            "Enable-ClaudeProcessLock",
            "Disable-ClaudeProcessLock",
            "Ensure-FirewallProfilesEnabled",
            "statsig.anthropic.com",
            "o1158394.ingest.us.sentry.io",
            "statsigapi.net",
            "featuregates.org",
            "ClaudeGuard-Standby-Claude-V4-",
            "ClaudeGuard-Block-Overseas-V4-Part",
            "$oldRules | Remove-NetFirewallRule",
            "Invoke-UninstallAll",
            "pfirewall.log",
        ):
            self.assertIn(token, guard_text, f"claude-guard.ps1 缺少关键能力: {token}")

        # 校验极简单锁 WPF XAML 合法性及控件绑定（不含易误触的解除永久锁按钮）
        ui_text = WIN_UI.read_text(encoding="utf-8-sig")
        match = re.search(r'\$xaml = @"\n(.*?)\n"@', ui_text, re.S)
        self.assertIsNotNone(match)
        root = ET.fromstring(match.group(1))
        x_name = "{http://schemas.microsoft.com/winfx/2006/xaml}Name"
        names = [node.get(x_name) for node in root.iter() if node.get(x_name)]
        self.assertEqual(len(names), len(set(names)), "XAML x:Name 不得重复")
        for ctrl in ("StatusPill", "StatusText", "StatusSub", "BtnToggleLock", "ChkStrictMode", "NodesInput", "BtnSaveNodes", "BtnInit", "BtnVerifyFw", "BtnCheck", "BtnExport", "OutputBox"):
            self.assertIn(ctrl, names)
            self.assertIn(f"FindName('{ctrl}')", ui_text)
        self.assertNotIn("BtnUnlockAll", names, "极简单锁主界面不得暴露解除永久锁的误触按钮")

    def test_mac_14_dim_env_audit_active_and_standby_modes(self):
        pf_conf = self.root / "pf.conf"
        pf_conf.write_text('# BEGIN claude-guard-pf\nanchor "com.claude-guard"\n# END claude-guard-pf\n', encoding="utf-8")
        anchor = self.root / "com.claude-guard"
        anchor.write_text("# mode=cn\nblock drop out log quick inet all\n", encoding="utf-8")
        boot_plist = self.root / "com.claude-guard.pfboot.plist"
        boot_plist.write_text("<plist/>", encoding="utf-8")
        cfg = self.root / "config.env"
        cfg.write_text('ENTRY_NODES="203.0.113.10"\nCOUNTRY_TARGET="US"\n', encoding="utf-8")
        export_file = self.root / "report.json"

        env = dict(os.environ, HTTPS_PROXY="http://alice:supersecret@127.0.0.1:7890")
        run = subprocess.run(
            ["python3", str(MAC_AUDIT), "--config", str(cfg), "--pf-conf", str(pf_conf), "--pf-anchor", str(anchor), "--pf-boot-plist", str(boot_plist), "--offline", "--json", "--export", str(export_file)],
            env=env, capture_output=True, text=True, timeout=15,
        )
        data = json.loads(run.stdout)
        self.assertEqual(len(data["items"]), 14)
        ks = next(it for it in data["items"] if it["id"] == "killswitch")
        self.assertEqual(ks["state"], "ok")
        self.assertNotIn("supersecret", run.stdout)
        self.assertNotIn("supersecret", export_file.read_text(encoding="utf-8"))

        # 切到 standby 模式时，体检第 1 项应清晰回报「日常上网模式 + Claude 进程与遥测网络已系统级死锁」
        anchor.write_text("# mode=standby\nblock drop out log quick inet to <claude_blocked_v4>\n", encoding="utf-8")
        run2 = subprocess.run(
            ["python3", str(MAC_AUDIT), "--config", str(cfg), "--pf-conf", str(pf_conf), "--pf-anchor", str(anchor), "--pf-boot-plist", str(boot_plist), "--offline", "--json"],
            capture_output=True, text=True, timeout=15,
        )
        data2 = json.loads(run2.stdout)
        ks2 = next(it for it in data2["items"] if it["id"] == "killswitch")
        self.assertEqual(ks2["state"], "warn")
        self.assertIn("遥测", ks2["detail"])

    def test_real_cn_and_overseas_ip_tables_and_subtract_whitelist_math(self):
        cn_nets = [ipaddress.IPv4Network(line.strip(), strict=False)
                   for line in CN_IPV4_FILE.read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.strip().startswith("#")]
        self.assertGreater(len(cn_nets), 5000)
        anth_net = ipaddress.IPv4Network("160.79.104.0/21")
        for n in cn_nets:
            self.assertFalse(n.overlaps(anth_net))

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
            ov_intervals.append((a, b))

        ex_s = int(ipaddress.IPv4Address("203.0.113.10"))
        subtracted = []
        for s, e in ov_intervals:
            if ex_s < s or ex_s > e:
                subtracted.append((s, e))
            else:
                if s < ex_s:
                    subtracted.append((s, ex_s - 1))
                if e > ex_s:
                    subtracted.append((ex_s + 1, e))

        def is_blocked(ip_str):
            v = int(ipaddress.IPv4Address(ip_str))
            return any(s <= v <= e for s, e in subtracted)

        for allowed_ip in ("114.114.114.114", "223.5.5.5", "110.242.68.66", "192.168.1.1", "198.18.0.1", "203.0.113.10"):
            self.assertFalse(is_blocked(allowed_ip))
        for blocked_ip in ("160.79.104.10", "1.1.1.1", "8.8.8.8", "104.18.1.1", "203.0.113.9", "203.0.113.11"):
            self.assertTrue(is_blocked(blocked_ip))

    def test_dist_installers_zip_integrity_utf8_flags_and_permissions(self):
        mac_zip = DIST / "Claude安全锁-macOS安装包.zip"
        win_zip = DIST / "Claude安全锁-Windows安装包.zip"
        self.assertTrue(mac_zip.is_file())
        self.assertTrue(win_zip.is_file())

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
                self.assertTrue(info.flag_bits & 0x800)
                if info.filename.endswith((".command", ".sh", ".py")):
                    self.assertTrue(((info.external_attr >> 16) & 0o777) & 0o111)

        with zipfile.ZipFile(win_zip) as zf:
            names = set(zf.namelist())
            for req in (
                "Claude安全锁-Windows安装包/一键安装.bat",
                "Claude安全锁-Windows安装包/卸载.bat",
                "Claude安全锁-Windows安装包/README-交付手册.md",
                "Claude安全锁-Windows安装包/windows/claude-guard.ps1",
                "Claude安全锁-Windows安装包/windows/ClaudeGuardUI.ps1",
                "Claude安全锁-Windows安装包/windows/env-audit.ps1",
                "Claude安全锁-Windows安装包/windows/claude-blocked-alert.vbs",
                "Claude安全锁-Windows安装包/windows/Claude安全锁控制台.bat",
                "Claude安全锁-Windows安装包/data/cn-ipv4.txt",
                "Claude安全锁-Windows安装包/data/overseas-ipv4-ranges.txt",
            ):
                self.assertIn(req, names)
            for info in zf.infolist():
                self.assertTrue(info.flag_bits & 0x800)

    def test_native_dmg_and_windows_exe_installers_valid(self):
        """验证标准 macOS .dmg 与原生 PE32 Windows .exe 安装程序均已构建且文件头合法。"""
        dmg = DIST / "Claude安全锁-macOS.dmg"
        exe = DIST / "Claude安全锁-Windows安装程序.exe"
        self.assertTrue(dmg.is_file(), f"缺少 macOS DMG: {dmg}")
        self.assertTrue(exe.is_file(), f"缺少 Windows EXE: {exe}")
        self.assertGreater(dmg.stat().st_size, 50_000)
        self.assertGreater(exe.stat().st_size, 80_000)
        # Windows PE32 可执行文件必须以 MZ 头开头
        self.assertTrue(exe.read_bytes().startswith(b"MZ"), "Windows 安装包必须为合法 PE 可执行文件")
        # macOS UDZO DMG 尾部 koly trailer 校验
        dmg_bytes = dmg.read_bytes()
        self.assertIn(b"koly", dmg_bytes[-1024:], "macOS DMG 必须为合法 UDZO 磁盘映像")


if __name__ == "__main__":
    unittest.main()
