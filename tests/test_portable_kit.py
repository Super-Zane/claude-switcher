"""portable-kit (方案 A 极简双端交付包) 自动化回归与安全边界测试。"""
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "portable-kit"
MAC_GUARD = KIT / "mac" / "claude-guard.sh"
MAC_CONSOLE = KIT / "mac" / "Claude安全锁控制台.command"
MAC_SHORTCUT = KIT / "mac" / "创建桌面快捷App.command"
MAC_AUDIT = KIT / "mac" / "env-audit.py"
WIN_GUARD = KIT / "windows" / "claude-guard.ps1"
WIN_AUDIT = KIT / "windows" / "env-audit.ps1"
WIN_UI = KIT / "windows" / "ClaudeGuardUI.ps1"
WIN_BAT = KIT / "windows" / "Claude安全锁控制台.bat"

# 复用仓库已有的 PowerShell 括号平衡校验器
sys.path.insert(0, str(ROOT / "tests"))
from test_windows_update_static import ps1_balance_error  # noqa: E402


class PortableKitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_mac_shell_scripts_syntax_and_executable(self):
        for path in (MAC_GUARD, MAC_CONSOLE, MAC_SHORTCUT):
            with self.subTest(script=path.name):
                self.assertTrue(path.exists())
                self.assertTrue(os.access(path, os.X_OK), f"{path.name} 必须具备可执行权限")
                run = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True, timeout=5)
                self.assertEqual(run.returncode, 0, run.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "pfctl syntax validation requires macOS")
    def test_mac_pf_rules_pass_pfctl_and_reject_empty_whitelist(self):
        # 空白名单必须拒绝，防止锁死客户整机断网
        empty_run = subprocess.run(
            ["/bin/bash", str(MAC_GUARD), "render", "", "utun4", "198.18.0.1", "0"],
            env=dict(os.environ, CLAUDE_GUARD_DIR=str(self.root)),
            capture_output=True, text=True, timeout=5,
        )
        self.assertNotEqual(empty_run.returncode, 0)

        # 多入口 IP + 自定义 TUN IP + 默认封锁物理裸 DNS 53，必须通过真机 pfctl -nvf
        ok_run = subprocess.run(
            ["/bin/bash", str(MAC_GUARD), "render", "203.0.113.10, 198.51.100.0/24", "utun5", "10.8.0.2", "0"],
            env=dict(os.environ, CLAUDE_GUARD_DIR=str(self.root)),
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(ok_run.returncode, 0, ok_run.stderr)
        rules = ok_run.stdout
        self.assertIn("203.0.113.10, 198.51.100.0/24", rules)
        self.assertIn("10.8.0.2", rules)
        self.assertIn("block drop out quick inet6 all", rules)
        self.assertIn("block drop out quick inet proto { tcp, udp } to <claude_guard_lan> port 53", rules)
        self.assertIn("block drop out quick inet all", rules)

        pf_check = subprocess.run(["pfctl", "-nvf", "-"], input=rules, capture_output=True, text=True, timeout=10)
        self.assertEqual(pf_check.returncode, 0, pf_check.stdout + pf_check.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "macOS guard dry-run flow")
    def test_mac_set_nodes_lock_unlock_and_managed_blocks(self):
        pf_conf = self.root / "pf.conf"
        pf_conf.write_text("# original pf.conf\nanchor \"com.apple/*\"\n", encoding="utf-8")
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

        # 演练开启安全锁
        r2 = subprocess.run(["/bin/bash", str(MAC_GUARD), "lock"],
                            env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertIn("table <claude_guard_entries> persist { 203.0.113.10, 198.51.100.5 }", r2.stdout)
        self.assertIn("OK:安全锁演练通过", r2.stdout)

        # 验证托管块写入与无痕清理不破坏原始 hosts 内容
        block_test = f"""
source "{MAC_GUARD}"
write_managed_block "{hosts}" "# BEGIN claude-guard-hosts" "# END claude-guard-hosts" "203.0.113.10 entry.example.com"
grep -q "entry.example.com" "{hosts}" || exit 1
remove_managed_block "{hosts}" "# BEGIN claude-guard-hosts" "# END claude-guard-hosts"
grep -q "entry.example.com" "{hosts}" && exit 2
grep -q "127.0.0.1 localhost" "{hosts}" || exit 3
"""
        r3 = subprocess.run(["/bin/bash", "-c", block_test], env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(r3.returncode, 0, r3.stdout + r3.stderr)

    def test_windows_scripts_bom_lf_braces_and_safe_unicast_bounds(self):
        for p in (WIN_GUARD, WIN_AUDIT, WIN_UI):
            with self.subTest(file=p.name):
                raw = p.read_bytes()
                self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), f"{p.name} 必须带 UTF-8 BOM")
                self.assertEqual(raw.count(b"\r\n"), 0, f"{p.name} 必须使用 LF 换行")
                text = raw.decode("utf-8-sig")
                self.assertIsNone(ps1_balance_error(text))
                self.assertNotIn("Invoke-Expression", text)

        audit_text = WIN_AUDIT.read_text(encoding="utf-8-sig")
        for token in ("RESTRICTED_COUNTRIES", "CN_DNS_SERVERS", "Test-StunServer", "Test-TlsEndpoint", "Test-WssUpgrade", "Hide-ProxyCreds", "coverage_percent"):
            self.assertIn(token, audit_text)

        guard_text = WIN_GUARD.read_text(encoding="utf-8-sig")
        self.assertIn("1.0.0.0", guard_text)
        self.assertIn("223.255.255.255", guard_text)
        self.assertNotIn("0.0.0.0-126.255.255.255", guard_text)
        self.assertNotIn("255.255.255.255'", guard_text)
        self.assertIn("ClaudeGuard-KillSwitch", guard_text)
        self.assertIn("ClaudeGuard-Block-NonWhitelist-V4", guard_text)
        self.assertIn("ClaudeGuard-Block-All-Public-V6", guard_text)

        # .bat 必须存在且调用 ClaudeGuardUI.ps1 并带 RunAs 提权
        bat_text = WIN_BAT.read_text(encoding="utf-8")
        self.assertIn("RunAs", bat_text)
        self.assertIn("ClaudeGuardUI.ps1", bat_text)

    def test_windows_ui_xaml_well_formed_and_all_controls_bound(self):
        ui_text = WIN_UI.read_text(encoding="utf-8-sig")
        match = re.search(r'\$xaml = @"\n(.*?)\n"@', ui_text, re.S)
        self.assertIsNotNone(match)
        root = ET.fromstring(match.group(1))
        x_name = "{http://schemas.microsoft.com/winfx/2006/xaml}Name"
        names = [node.get(x_name) for node in root.iter() if node.get(x_name)]
        self.assertEqual(len(names), len(set(names)), "XAML x:Name 不得重复")
        for ctrl in ("StatusPill", "StatusText", "StatusSub", "NodesInput", "BtnSaveNodes", "BtnLock", "BtnUnlock", "BtnInit", "BtnCheck", "BtnExport", "BtnRefresh", "OutputBox"):
            self.assertIn(ctrl, names)
            self.assertIn(f"FindName('{ctrl}')", ui_text)

    def test_mac_14_dim_env_audit_offline_json_export_and_sanitization(self):
        """验证 14 维度深度体检引擎: JSON 结构、证据覆盖率、脱敏代理密码与导出文件。"""
        import json
        pf_conf = self.root / "pf.conf"
        pf_conf.write_text("# BEGIN claude-guard-pf\nanchor \"com.claude-guard\"\n# END claude-guard-pf\n", encoding="utf-8")
        anchor = self.root / "com.claude-guard"
        anchor.write_text("block drop out quick inet all\n", encoding="utf-8")
        cfg = self.root / "config.env"
        cfg.write_text('ENTRY_NODES="203.0.113.10"\nCOUNTRY_TARGET="US"\n', encoding="utf-8")
        export_file = self.root / "report.json"

        env = dict(os.environ, HTTPS_PROXY="http://alice:supersecret@127.0.0.1:7890")
        run = subprocess.run(
            [
                "python3", str(MAC_AUDIT),
                "--config", str(cfg),
                "--pf-conf", str(pf_conf),
                "--pf-anchor", str(anchor),
                "--offline", "--json",
                "--export", str(export_file),
            ],
            env=env, capture_output=True, text=True, timeout=15,
        )
        # 校验输出是合法 JSON 且恰好 14 个维度
        data = json.loads(run.stdout)
        self.assertEqual(len(data["items"]), 14, f"应恰好输出 14 维度体检，实际: {len(data['items'])}")
        ids = [it["id"] for it in data["items"]]
        for expected_id in ("killswitch", "tun", "dns", "proxy_env", "egress", "region_policy", "ip_risk", "webrtc", "locale_tz", "ipv6", "endpoints", "tls", "ws", "client_env"):
            self.assertIn(expected_id, ids)
        # 安全锁应识别为 ok
        ks = next(it for it in data["items"] if it["id"] == "killswitch")
        self.assertEqual(ks["state"], "ok")
        # 代理密码必须被脱敏，绝不出现在输出或导出报告里
        pe = next(it for it in data["items"] if it["id"] == "proxy_env")
        self.assertEqual(pe["state"], "warn")
        self.assertIn("alice:***@", pe["detail"])
        self.assertNotIn("supersecret", run.stdout)
        self.assertTrue(export_file.is_file())
        self.assertNotIn("supersecret", export_file.read_text(encoding="utf-8"))
        # 离线模式下外部探测项必须诚实标为 unknown，覆盖率应小于 100%
        self.assertGreater(data["summary"]["unknown"], 0)
        self.assertLess(data["coverage_percent"], 100)

    def test_ipv4_complement_algorithm_exact_math(self):
        """验证与 claude-guard.ps1 完全等价的 IPv4 补集算法在单 IP / CIDR / 边界上的数学正确性。"""
        def complement(exclude_cidrs):
            lo = int(ipaddress.IPv4Address("1.0.0.0"))
            hi = int(ipaddress.IPv4Address("223.255.255.255"))
            ivs = []
            for c in exclude_cidrs:
                net = ipaddress.IPv4Network(c, strict=False)
                s = max(lo, int(net.network_address))
                e = min(hi, int(net.broadcast_address))
                if s <= e:
                    ivs.append((s, e))
            ivs.sort()
            merged = []
            for s, e in ivs:
                if not merged or s > merged[-1][1] + 1:
                    merged.append([s, e])
                else:
                    merged[-1][1] = max(merged[-1][1], e)
            out = []
            cur = lo
            for s, e in merged:
                if cur < s:
                    out.append((cur, s - 1))
                cur = e + 1
            if cur <= hi:
                out.append((cur, hi))
            return out

        excludes = ["10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "203.0.113.10/32"]
        blocked = complement(excludes)
        # 校验: 203.0.113.10 (白名单入口) 不在任何封锁区间内; 而其相邻 IP 203.0.113.9 / 203.0.113.11 与 Anthropic 160.79.104.10 全部被封锁
        def is_blocked(ip_str):
            v = int(ipaddress.IPv4Address(ip_str))
            return any(s <= v <= e for s, e in blocked)

        self.assertFalse(is_blocked("203.0.113.10"))
        self.assertFalse(is_blocked("192.168.1.1"))
        self.assertFalse(is_blocked("172.20.10.1"))
        self.assertFalse(is_blocked("127.0.0.1"))
        self.assertTrue(is_blocked("203.0.113.9"))
        self.assertTrue(is_blocked("203.0.113.11"))
        self.assertTrue(is_blocked("160.79.104.10"))
        self.assertTrue(is_blocked("1.1.1.1"))
        self.assertTrue(is_blocked("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
