# V2RayU / v2rayN 与双端内核级防直连兜底指南（macOS + Windows）

本分叉（`Super-Zane/claude-switcher`）基于上游 `YOURSJEYO/claude-switcher`（`v1.10.0`）构建，面向 **macOS 与 Windows 双端**补齐了社区 Issue `#4` 与 `#54` 中长期未解的核心防泄露能力。

---

## 一、新增核心能力总览

| 能力 | macOS | Windows |
| --- | --- | --- |
| **V2RayU 支持** | 完整支持（识别 `V2RayU.app` / `v2ray-core` / `xray`；支持 TUN 模式及“纯本地代理 + `pf` 防直连”双模式） | — |
| **v2rayN 支持** | 完整支持（v7+ Avalonia 版，兼容 `172.19.0.1` / `172.18.0.1` sing-box TUN） | 完整支持（识别 `v2rayN` / `xray` / `v2ray` / `sing-box` / `mihomo` 与 Wintun/sing-box TUN） |
| **内核级防直连防火墙** | `core/pf-firewall.sh`（独立 `pf` 锚点 `com.claude-switcher`） | `windows/claude-firewall.ps1`（Windows Defender Firewall 分组 `ClaudeSwitcher-KillSwitch`） |
| **事件驱动新一代保镖** | `KeepAlive` + `route -n monitor` 毫秒级响应 + 2 秒兜底 + 新热点接口自动关 IPv6 + VPS 出口探活 | `.NET NetworkChange` 事件毫秒级响应 + 2 秒兜底 + 默认路由优先级校验 + CLI 进程急停 |
| **Windows `#54` 修复** | — | 计划任务解除 72 小时自动终止与电池模式限制；体检真正校验 `claude-bodyguard.ps1` 进程存活 |

---

## 二、四大高危泄露场景覆盖矩阵

### 场景 1：TUN 忘开了
- **内核层（0 毫秒）**：
  - **macOS**：`pf` 锚点仅放行 `lo0` 与代理 TUN 网段（`198.18.0.0/15`, `172.18.0.0/15`），物理网卡发往 Anthropic 官方专属段（`160.79.104.0/21`、`2607:6bc0::/48`）及动态解析精准 IP 的 TCP/UDP 流量直接 `block drop out quick`，连首个 SYN 包都发不出去。
  - **Windows**：Windows 防火墙按非 TUN 源地址区间阻断全系统物理网卡直连 Anthropic，并额外锁定 `Claude.exe`（含 MSIX）与 `claude.exe` 的物理网卡公网出站（IPv4 + IPv6）。
- **进程层**：即使绕过切换器直接点开 Claude 桌面版或 CLI，事件驱动保镖也会在 2 秒内强制终止。

### 场景 2：VPS 突然掉了，代理内核回落到直连（DIRECT）
- **内核层（0 毫秒）**：哪怕代理进程和 TUN 网卡都还活着，一旦代理内核把发往 Anthropic 的请求回落为 `DIRECT` 走物理网卡发出，源地址为物理网卡 IP，直接撞上内核防直连规则被 DROP（同时本工具自动提取用户代理配置中的 VPS 服务器 IP 加入白名单，不误伤走 Cloudflare CDN 中转的代理节点）。
- **配置审计**：运行 `v2ray-rules check` 检查配置中是否将 Anthropic 域名误设为 `direct`；运行 `v2ray-rules export` 一键导出标准强制代理路由规则。
- **进程层**：macOS 常驻保镖支持隧道内低频 VPS 出口探活（严格仅走隧道，连续两次失败或出口偏离目标国即急停）。

### 场景 3：手机热点（Wi-Fi 或 USB 共享）给电脑开网络
- **接口无关防火墙**：macOS `pf` 与 Windows 非 TUN 本地地址区间（`172.20.10.x` iPhone 热点、`192.168.42/43.x` Android 热点均在拦截区间内）**不依赖静态接口名**，新插上的 USB/Wi-Fi 热点网卡立即生效。
- **默认路由抢占检测**：双端体检与保镖均实时校验最高优先级默认路由（macOS `route -n get 1.1.1.1` / Windows `Get-NetRoute -DestinationPrefix 0.0.0.0/0`），一旦手机热点抢占默认路由，毫秒级急停 Claude。
- **全接口 IPv6 封堵**：不再写死只查 `Wi-Fi`；macOS 遍历全部启用物理服务关闭 IPv6，且常驻保镖捕获新接口上线事件时自动关闭其 IPv6；双端防火墙同步拦截物理接口 IPv6 直连 Anthropic 及 STUN UDP（`3478/5349/19302`）。

### 场景 4：网络突然断开与重连那一刻的泄露
- **断网瞬间**：macOS `route -n monitor` 与 Windows `NetworkChange` 毫秒级捕获默认路由丢失/链路断开事件，立即急停 Claude 并锁定进入**重连冷却期**。
- **重连瞬间**：在物理网卡 DHCP 刚恢复、TUN 隧道尚未重建完成的 0.5–5 秒黄金窗口内，内核防火墙保持 0 毫秒 DROP 拦截；保镖要求连续 2 轮确认 TUN + 默认路由 + 代理进程均稳定后才解除冷却锁定，防止后台 Electron/CLI 抢跑重连。

---

## 三、常用命令速查

### macOS
```bash
# 切换客户端为 V2RayU 或 v2rayN
~/.local/bin/claude-switch.sh set-client v2rayu
~/.local/bin/claude-switch.sh set-client v2rayn

# 查看 / 启用 / 刷新动态IP / 停用 pf 内核防直连锚点
~/.local/bin/claude-switch.sh firewall status
~/.local/bin/claude-switch.sh firewall enable
~/.local/bin/claude-switch.sh firewall refresh
~/.local/bin/claude-switch.sh firewall disable

# 审计或导出 V2RayU / v2rayN 防直连路由规则
~/.local/bin/claude-switch.sh v2ray-rules check
~/.local/bin/claude-switch.sh v2ray-rules export ~/Desktop/v2ray-anthropic-rules.json
```

### Windows（PowerShell）
```powershell
# 切换客户端为 v2rayN
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude-switcher\claude-switch.ps1" set-client v2rayn

# 查看 / 启用 / 刷新 / 停用 Windows 防火墙防直连规则（ClaudeSwitcher-KillSwitch）
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude-switcher\claude-switch.ps1" firewall status
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude-switcher\claude-switch.ps1" firewall enable
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude-switcher\claude-switch.ps1" firewall refresh
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude-switcher\claude-switch.ps1" firewall disable

# 审计或导出 v2rayN 防直连路由规则
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude-switcher\claude-switch.ps1" v2ray-rules check
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude-switcher\claude-switch.ps1" v2ray-rules export "$env:USERPROFILE\Desktop\v2rayn-anthropic-rules.json"
```

---

## 四、诚实的安全边界说明

1. **V2RayU 纯代理（无 TUN）模式**：通过 `pf` 拦截物理网卡直连 Anthropic/STUN，并在经由切换器启动 Claude/CLI 时自动注入 `--proxy-server` / `HTTPS_PROXY`。但如果某些非 Anthropic 第三方遥测域名位于未预解析的共享 CDN IP 上且进程无视代理，仍可能绕过；**最高安全级别始终建议开启 TUN 模式（如 v2rayN / Clash Verge / FlClash / sing-box）并同时开启内核防火墙兜底**。
2. **共享 CDN IP 动态性**：Anthropic 官方专属段（`160.79.104.0/21`、`2607:6bc0::/48`）为永久封锁；`claude.ai` 等前端 CDN IP 建议在切换网络或节点后运行一次 `firewall refresh` 刷新。Windows 端因额外叠加了 `Claude.exe`/`claude.exe` 进程级物理公网阻断，即便前端更换 CDN IP 也可零直连拦截。
3. **验证边界**：macOS 端已在本机完成 `pfctl -nvf` 真机语法校验、SwiftUI 编译与全量单测；Windows 端已完成 156+ 项静态、XAML、BOM/LF、括号平衡与逻辑契约校验，首次在真机 Windows 上运行请以管理员权限执行 `windows\install.ps1` 并检查「防火墙兜底」与「保镖」项是否为绿。
