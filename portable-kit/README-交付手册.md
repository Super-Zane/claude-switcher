# Claude 持久化安全锁 · 极简单锁双端交付手册

本安装包专为 **零依赖、3 分钟快速交机、绝对防直连与防遥测泄露** 设计：无需 Xcode、无需编译、无需配置复杂代理规则，**macOS（Stash / 小火箭 Shadowrocket / Clash Verge / v2rayN）与 Windows（Clash Verge / v2rayN）通用**。

---

## 核心设计：极简单锁 + 永久防呆（除非彻底卸载，否则 Claude 永远跑不出 TUN！）

只有**一把清晰的大开关**，零学习成本、杜绝按错锁导致封号：

### 🔒 状态一：安全锁开启（Claude 使用模式）
- **操作系统内核持久化防火墙**（macOS `pf` + 自愈开机守护 / Windows Defender Firewall WFP 持久化策略）：
  - 物理网卡 0ms 死锁 **Claude/Anthropic 官方 ASN（`160.79.104.0/21` / `2607:6bc0::/48`）+ 24 个主站/API/全部遥测与崩溃上报域名 IP（含 `statsig.anthropic.com`、`o1158394.ingest.sentry.io`、`statsigapi.net`、`featuregates.org` 等）+ 一切海外公网 IPv4 + 全部公网 IPv6 + WebRTC/STUN UDP**（默认放行中国大陆直连 7,456 段；如需连国内公网与物理裸 DNS 也封，可在控制台勾选「全封闭模式」）；
  - 放行 Claude 桌面版与 CLI 正常运行——**此时 Claude 只能通过海外代理 TUN 通信，哪怕代理闪退、软件被杀、电脑死机重启或切到手机热点，TUN 以外 0 字节能发出去**！

### 🟡 状态二：安全锁关闭（日常上网模式 — Claude 永久锁死！）
- 放行电脑正常日常上网；
- **但同时自动触发 4 重系统级永久死锁（重启、退出本软件、未开代理均持续生效，除非彻底运行「卸载」程序！）**：
  1. **系统级进程死锁（永远点不开，点开立刻弹中文提示！）**：
     - **macOS**：将 `/Applications/Claude.app` 真实应用原子藏匿并剥夺执行位（零破坏原应用代码签名），原位放置同图标拦截器；`claude` CLI 同样拦截。无论从 Dock / 启动台 / Spotlight / 终端点开 Claude，0ms 弹出清晰中文提醒引导先开安全锁，真实进程 0 指令启动！
     - **Windows**：写入操作系统内核级 **IFEO 注册表拦截（`Image File Execution Options\Claude.exe`）**——无论传统版还是微软商店 MSIX 版、无论它自动更新多少次版本号，点开永远启动不了真进程，0ms 弹出中文警示框并可一键打开安全锁控制台！
  2. **彻底清零后台残留进程**：切换瞬间强清所有 `Claude Helper` / `Update.exe` / `claude` CLI 进程，杜绝后台更新器发遥测包；
  3. **`hosts` 本地域名黑洞**：将全部 24 个 Claude 主服务与遥测域名（`claude.ai`、`statsig.anthropic.com`、`o1158394.ingest.us.sentry.io` 等）写入 `0.0.0.0` + `::` 黑洞，**就算浏览器里还留着 Claude 标签页，连本地 DNS 查询都发不出去**；
  4. **内核防火墙常驻底线（`standby`）**：macOS `pf`（带系统升级自愈开机守护）与 Windows WFP **永久保留物理网卡对 Anthropic ASN 与全部遥测 IP 的 0ms DROP 规则**！

> **彻底恢复出厂**：主界面不提供解除永久防线的误触按钮；只有运行安装包根目录的 **`卸载.command`**（macOS）或 **`卸载.bat`**（Windows），才会完整还原 Claude 应用并清除所有系统级进程锁与防火墙规则。

---

## 一、macOS 一键安装与交机（约 2 分钟）

1. 解压 `Claude安全锁-macOS安装包.zip`，右键根目录 **`一键安装.command` → 打开**（首次放行未公证提示）。
   - 自动安装到 `~/.claude-guard/kit`，在 `/Applications/` 与 **桌面** 生成零编译原生 **`Claude安全锁.app`** 并自动打开。
2. 在 Stash / 小火箭 / Clash Verge / v2rayN 中开启 **全局模式（Global） + TUN / 增强模式 / Fake-IP（`198.18.0.1`）**，关闭代理内 IPv6。
3. 在控制台点 **「🚀 一键初始化环境」**（链式代理若第一跳在国内中转机，入口 IP 可直接留空；直连海外 VPS 请填第一跳入口 IP）。
4. 点 **「🛡️ 验收操作系统防火墙、进程锁与丢包日志」** 和 **「🔍 14维度深度体检」** 确认全绿即可交机！

---

## 二、Windows 一键安装与交机（约 2 分钟）

1. 先将 `Claude安全锁-Windows安装包.zip` **右键 → 全部解压缩**，双击根目录 **`一键安装.bat`**（自动 UAC 提权，若 SmartScreen 提示点「更多信息 → 仍要运行」）。
   - 自动安装到 `C:\ProgramData\ClaudeGuard`，在 **桌面** 生成 **`Claude安全锁`** 快捷方式并自动打开深色控制台。
2. 配置代理客户端：
   - **Clash Verge**：安装并启用 **服务模式（Service Mode）** → 打开 **TUN** → 选择 **全局（Global）**；
   - **v2rayN**：**右键以管理员身份运行** → 勾选 **「启用 Tun」** → 路由选 **全局（Global）**。
3. 点击 **「🚀 一键初始化环境」**，完成后点击 **「🛡️ 验收防火墙与日志」**（自动核验三档防火墙未被杀软关闭、IFEO 锁状态与 `pfirewall.log` 最近 `DROP` 记录）及 **「🔍 14维度深度体检」** 即可交机！

---

## 三、客户日常怎么用？（一句话交代）

- **要用 Claude 时**：先开代理（全局 + TUN）→ 点桌面 **「Claude安全锁」** → 点 **「🔒 开启安全锁」** → 放心用 Claude！
- **不用 Claude 要日常上网时**：点桌面 **「Claude安全锁」** → 点 **「🔓 关闭安全锁」** → 正常上网（此时 Claude 已被系统锁死，误点会弹窗提醒，绝对不会泄露直连 IP 或遥测流量！）。
