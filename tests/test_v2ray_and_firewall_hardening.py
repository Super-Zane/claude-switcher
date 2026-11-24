"""V2RayU / v2rayN、内核级防直连防火墙 (macOS pf & Windows Firewall)、
事件驱动保镖 4 大泄露场景与 Issue #54 修复的综合回归测试。"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAC_CORE = ROOT / "core" / "claude-switch.sh"
MAC_PF = ROOT / "core" / "pf-firewall.sh"
MAC_GUARD = ROOT / "daemons" / "claude-bodyguard.sh"
MAC_PLIST = ROOT / "daemons" / "local.claude-bodyguard.plist"
MAC_INSTALL = ROOT / "installer" / "安装.command"
MAC_UNINSTALL = ROOT / "installer" / "卸载.command"
WIN_CORE = ROOT / "windows" / "claude-switch.ps1"
WIN_FW = ROOT / "windows" / "claude-firewall.ps1"
WIN_GUARD = ROOT / "windows" / "claude-bodyguard.ps1"
WIN_INSTALL = ROOT / "windows" / "install.ps1"
WIN_UI = ROOT / "windows" / "SwitcherUI.ps1"


class V2RayAndFirewallHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fakebin = self.root / "bin"
        self.fakebin.mkdir()

    def stub(self, name, content):
        p = self.fakebin / name
        p.write_text(content, encoding="utf-8")
        p.chmod(0o755)
        return p

    # ---- 1. macOS pf 防火墙规则生成、白名单防误伤与 pfctl 真机语法校验 ----
    @unittest.skipUnless(sys.platform == "darwin", "pfctl syntax check requires macOS")
    def test_pf_firewall_renders_valid_syntax_and_excludes_vps_whitelist(self):
        extra_v4 = self.root / "extra_v4.txt"
        extra_v6 = self.root / "extra_v6.txt"
        wl_v4 = self.root / "wl_v4.txt"
        # 模拟 104.18.1.2 是用户走 Cloudflare CDN 的 VPS 节点 IP，同时恰好在解析结果中出现
        extra_v4.write_text("104.18.1.2\n160.79.104.10\n", encoding="utf-8")
        extra_v6.write_text("2607:6bc0::10\n", encoding="utf-8")
        wl_v4.write_text("104.18.1.2\n", encoding="utf-8")

        run = subprocess.run(
            ["/bin/bash", str(MAC_PF), "render", str(extra_v4), str(extra_v6), str(wl_v4), "utun4"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        rules = run.stdout
        # 确认放行回环与 TUN 网段、放行白名单、阻断物理接口 Anthropic 与 STUN UDP
        self.assertIn("pass out quick on lo0 all", rules)
        self.assertIn("198.18.0.0/15, 172.18.0.0/15", rules)
        self.assertIn("pass out quick on utun4 all", rules)
        self.assertIn("block drop out quick inet proto { tcp, udp } to <anthropic_blocked_v4>", rules)
        self.assertIn("block drop out quick inet6 proto { tcp, udp } to <anthropic_blocked_v6>", rules)
        self.assertIn("port { 3478, 5349, 19302 }", rules)
        # 确认白名单 IP 已从 blocked_v4 排除，避免封死用户自己的代理节点
        v4_line = next(l for l in rules.splitlines() if "table <anthropic_blocked_v4>" in l)
        self.assertIn("160.79.104.0/21", v4_line)
        self.assertNotIn("104.18.1.2", v4_line)
        self.assertIn("table <claude_proxy_whitelist> persist { 104.18.1.2 }", rules)

        # 使用真实 macOS pfctl -nvf 校验语法合法性（只解析不加载）
        pf_check = subprocess.run(["pfctl", "-nvf", "-"], input=rules, capture_output=True, text=True, timeout=10)
        self.assertEqual(pf_check.returncode, 0, pf_check.stdout + pf_check.stderr)

    # ---- 2. macOS V2RayU / v2rayN 客户端切换与路由规则审计/导出 ----
    @unittest.skipUnless(sys.platform == "darwin", "sed -i '' is macOS syntax")
    def test_macos_supports_v2rayu_and_v2rayn_set_client_and_rules_audit(self):
        core_copy = self.root / "claude-switch.sh"
        core_copy.write_text(MAC_CORE.read_text(encoding="utf-8"), encoding="utf-8")
        core_copy.chmod(0o755)
        self.stub("launchctl", "#!/bin/sh\nexit 1\n")
        env = dict(os.environ, HOME=str(self.root), CLAUDE_SWITCHER_CORE=str(core_copy),
                   PATH=f"{self.fakebin}:/usr/bin:/bin")

        for mode in ("v2rayu", "v2rayn"):
            r = subprocess.run(["/bin/bash", str(core_copy), "set-client", mode],
                               env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn(f"PROXY_MODE=\"{mode}\"", core_copy.read_text(encoding="utf-8"))

        # 导出防直连路由规则并验证合法 JSON
        exported = self.root / "v2ray-routing.json"
        exp = subprocess.run(["/bin/bash", str(core_copy), "v2ray-rules", "export", str(exported)],
                             env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(exp.returncode, 0, exp.stdout + exp.stderr)
        tpl = json.loads(exported.read_text(encoding="utf-8"))
        self.assertEqual(tpl["rules"][0]["outboundTag"], "proxy")
        self.assertIn("domain:claude.ai", tpl["rules"][0]["domain"])

        # 审计包含 direct 回落的错误 V2Ray 配置必须 FAIL
        bad_cfg = self.root / "bad-v2ray.json"
        bad_cfg.write_text(json.dumps({
            "routing": {"rules": [{"type": "field", "domain": ["domain:anthropic.com"], "outboundTag": "direct"}]}
        }), encoding="utf-8")
        bad = subprocess.run(["/bin/bash", str(core_copy), "v2ray-rules", "check", str(bad_cfg)],
                             env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(bad.returncode, 1, bad.stdout)
        self.assertIn("FAIL:检测到 Anthropic 域名被配置为直连", bad.stdout)

        # 审计合规配置必须 OK
        good_cfg = self.root / "good-v2ray.json"
        good_cfg.write_text(json.dumps({"routing": tpl}), encoding="utf-8")
        good = subprocess.run(["/bin/bash", str(core_copy), "v2ray-rules", "check", str(good_cfg)],
                              env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(good.returncode, 0, good.stdout)
        self.assertIn("OK:", good.stdout)

    # ---- 3. 模拟四大泄露场景下的 macOS 保镖行为 ----
    def _make_guard(self, mode, country="US"):
        text = MAC_GUARD.read_text(encoding="utf-8")
        text = text.replace("__HOME__", str(self.root))
        text = text.replace("__PROXY_MODE__", mode)
        text = text.replace("__COUNTRY_TARGET__", country)
        script = self.root / f"guard-{mode}.sh"
        script.write_text(text, encoding="utf-8")
        (self.root / "Library" / "Logs").mkdir(parents=True, exist_ok=True)
        return script

    def _run_guard_once(self, script, extra_env=None):
        env = dict(os.environ, HOME=str(self.root), CLAUDE_SWITCHER_TEST_ROOT=str(self.root),
                   PATH=f"{self.fakebin}:/usr/bin:/bin")
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["/bin/bash", "-c", 'enable -n kill\n. "$1"', "guard", str(script)],
            env=env, capture_output=True, text=True, timeout=8,
        )

    @unittest.skipUnless(sys.platform == "darwin", "macOS bodyguard test")
    def test_scenario_v2rayn_tun_172_19_keeps_guard_online(self):
        """v2rayN 在 macOS 使用 sing-box TUN 172.19.0.1 时保镖应识别为在线不误杀。"""
        script = self._make_guard("v2rayn")
        self.stub("ifconfig", "#!/bin/sh\necho 'inet 172.19.0.1 --> 172.19.0.2'\n")
        self.stub("route", "#!/bin/sh\necho '   interface: utun4'\n")
        self.stub("pgrep", "#!/bin/sh\ncase \"$*\" in *v2rayN*|*Claude.app*) exit 0 ;; *) exit 1 ;; esac\n")
        self.stub("pkill", "#!/bin/sh\ntouch \"$CLAUDE_SWITCHER_TEST_ROOT/pkill-called\"\n")
        self.stub("id", "#!/bin/sh\necho 502\n")
        self.stub("ps", "#!/bin/sh\necho '  101 502 node /tmp/server.js'\n")

        run = self._run_guard_once(script, {"CLAUDE_BODYGUARD_STRICT_ROUTE": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse((self.root / "pkill-called").exists())

    @unittest.skipUnless(sys.platform == "darwin", "macOS bodyguard test")
    def test_scenario_3_mobile_hotspot_hijacks_default_route_triggers_kill(self):
        """场景 3: 手机热点插上后 TUN 虽仍在，但默认路由被 en7(热点) 抢占，保镖必须立刻急停。"""
        script = self._make_guard("v2rayn")
        self.stub("ifconfig", "#!/bin/sh\necho 'inet 172.19.0.1'\n")
        self.stub("route", "#!/bin/sh\necho '   interface: en7'\n")
        self.stub("pgrep", "#!/bin/sh\ncase \"$*\" in *v2rayN*|*Claude.app*) exit 0 ;; *) exit 1 ;; esac\n")
        self.stub("pkill", "#!/bin/sh\ntouch \"$CLAUDE_SWITCHER_TEST_ROOT/pkill-called\"\n")
        self.stub("id", "#!/bin/sh\necho 502\n")
        self.stub("ps", "#!/bin/sh\necho '  101 502 node /tmp/server.js'\n")

        run = self._run_guard_once(script, {"CLAUDE_BODYGUARD_STRICT_ROUTE": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue((self.root / "pkill-called").exists(), "手机热点抢占默认路由时必须立刻关闭 Claude")
        log = (self.root / "Library" / "Logs" / "claude-bodyguard.log").read_text(encoding="utf-8")
        self.assertIn("en7", log)

    @unittest.skipUnless(sys.platform == "darwin", "macOS bodyguard test")
    def test_scenario_4_network_drop_no_default_route_triggers_kill(self):
        """场景 4: 完全断网瞬间无默认路由，保镖必须立刻急停 Claude。"""
        script = self._make_guard("clash-verge")
        self.stub("ifconfig", "#!/bin/sh\necho 'inet 198.18.0.1'\n")
        self.stub("route", "#!/bin/sh\nexit 1\n")
        self.stub("pgrep", "#!/bin/sh\ncase \"$*\" in *verge-mihomo*|*Claude.app*) exit 0 ;; *) exit 1 ;; esac\n")
        self.stub("pkill", "#!/bin/sh\ntouch \"$CLAUDE_SWITCHER_TEST_ROOT/pkill-called\"\n")
        self.stub("id", "#!/bin/sh\necho 502\n")
        self.stub("ps", "#!/bin/sh\necho '  101 502 node /tmp/server.js'\n")

        run = self._run_guard_once(script, {"CLAUDE_BODYGUARD_STRICT_ROUTE": "1"})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue((self.root / "pkill-called").exists(), "完全断网瞬间必须立刻关闭 Claude")
        log = (self.root / "Library" / "Logs" / "claude-bodyguard.log").read_text(encoding="utf-8")
        self.assertIn("默认路由丢失", log)

    def test_macos_plist_uses_keepalive_event_daemon_and_uninstaller_cleans_pf(self):
        plist = MAC_PLIST.read_text(encoding="utf-8")
        self.assertIn("<string>--daemon</string>", plist)
        self.assertIn("<key>KeepAlive</key><true/>", plist)
        uninstall = MAC_UNINSTALL.read_text(encoding="utf-8")
        self.assertIn("pf-firewall.sh", uninstall)
        self.assertIn("disable", uninstall)
        install = MAC_INSTALL.read_text(encoding="utf-8")
        self.assertIn("v2rayu", install)
        self.assertIn("v2rayn", install)
        self.assertIn("pf-firewall.sh", install)

    # ---- 4. Windows 防火墙、v2rayN、事件驱动保镖与 Issue #54 修复静态验证 ----
    def test_windows_firewall_script_bom_lf_and_core_rules(self):
        raw = WIN_FW.read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), "claude-firewall.ps1 必须使用 UTF-8 BOM")
        self.assertEqual(raw.count(b"\r\n"), 0, "claude-firewall.ps1 必须使用 LF")
        text = raw.decode("utf-8-sig")
        for token in (
            "ClaudeSwitcher-KillSwitch",
            "160.79.104.0/21",
            "2607:6bc0::/48",
            "172.20.0.0-198.17.255.255",
            "ClaudeSwitcher-Block-Anthropic-V4",
            "ClaudeSwitcher-Block-STUN-UDP-V4",
            "ClaudeSwitcher-Block-App-Direct-V4-",
            "Get-ProxyServerWhitelist",
            "Get-ProtectedClaudeExecutables",
        ):
            self.assertIn(token, text)
        self.assertNotIn("Invoke-Expression", text)

    def test_windows_issue_54_72h_and_battery_and_process_liveness_fixed(self):
        win_install = WIN_INSTALL.read_text(encoding="utf-8-sig")
        win_core = WIN_CORE.read_text(encoding="utf-8-sig")
        for label, text in (("install.ps1", win_install), ("claude-switch.ps1", win_core)):
            with self.subTest(file=label):
                self.assertIn("New-ScheduledTaskSettingsSet", text)
                self.assertIn("-ExecutionTimeLimit ([TimeSpan]::Zero)", text)
                self.assertIn("-AllowStartIfOnBatteries", text)
                self.assertIn("-DontStopIfGoingOnBatteries", text)
                self.assertIn("-RestartCount 3", text)
        # checkdetail 必须核验保镖真实运行进程与 ExecutionTimeLimit
        self.assertIn("function Get-BodyguardStatusLine", win_core)
        self.assertIn("Win32_Process", win_core)
        self.assertIn("claude-bodyguard.ps1", win_core)
        self.assertIn("PT0S", win_core)

    def test_windows_v2rayn_and_event_driven_bodyguard_and_cli_kill(self):
        win_core = WIN_CORE.read_text(encoding="utf-8-sig")
        win_guard = WIN_GUARD.read_text(encoding="utf-8-sig")
        win_install = WIN_INSTALL.read_text(encoding="utf-8-sig")
        win_ui = WIN_UI.read_text(encoding="utf-8-sig")

        for text in (win_core, win_guard, win_install, win_ui):
            self.assertIn("v2rayn", text)
            self.assertIn("v2rayN", text)

        # 事件驱动 NetworkChange + 默认路由抢占检测 + CLI 进程急停
        self.assertIn("NetworkAddressChanged", win_guard)
        self.assertIn("NetworkAvailabilityChanged", win_guard)
        self.assertIn("Get-NetRoute -DestinationPrefix '0.0.0.0/0'", win_guard)
        self.assertIn("172.19.*", win_guard)
        self.assertIn("@anthropic-ai", win_guard)
        self.assertIn("Stop-ProtectedClaudeProcesses", win_guard)


if __name__ == "__main__":
    unittest.main()
