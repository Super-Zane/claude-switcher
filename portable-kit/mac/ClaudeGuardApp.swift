import SwiftUI
import AppKit
import Foundation

// MARK: - Claude 品牌暖米陶土橙主题色板
extension Color {
    static let claudeBg       = Color(red: 0.980, green: 0.976, blue: 0.961) // #FAF9F5 暖米纸色
    static let claudeSurface  = Color(red: 1.000, green: 1.000, blue: 1.000) // #FFFFFF 卡片白
    static let claudeSubtle   = Color(red: 0.953, green: 0.937, blue: 0.902) // #F3EFE6 暖杏次级底
    static let claudeBorder   = Color(red: 0.906, green: 0.886, blue: 0.847) // #E7E2D8 柔和沙色边
    static let claudeAccent   = Color(red: 0.851, green: 0.467, blue: 0.341) // #D97757 Claude 陶土橙
    static let claudeAccentDk = Color(red: 0.761, green: 0.380, blue: 0.259) // #C26142
    static let claudeInk      = Color(red: 0.122, green: 0.118, blue: 0.114) // #1F1E1D 深暖炭
    static let claudeMuted    = Color(red: 0.420, green: 0.400, blue: 0.369) // #6B665E 温灰文案

    static let lampGreen      = Color(red: 0.086, green: 0.639, blue: 0.290) // #16A34A 翡翠绿
    static let lampGreenBg    = Color(red: 0.863, green: 0.988, blue: 0.906) // #DCFCE7
    static let lampAmber      = Color(red: 0.851, green: 0.467, blue: 0.024) // #D97706 琥珀金
    static let lampAmberBg    = Color(red: 0.996, green: 0.953, blue: 0.780) // #FEF3C7
    static let lampRed        = Color(red: 0.863, green: 0.149, blue: 0.149) // #DC2626 警示红
    static let lampRedBg      = Color(red: 0.996, green: 0.886, blue: 0.886) // #FEE2E2
    static let lampGray       = Color(red: 0.612, green: 0.639, blue: 0.686) // #9CA3AF 未知灰
    static let lampGrayBg     = Color(red: 0.945, green: 0.949, blue: 0.957) // #F1F2F4
}

// MARK: - 数据模型
struct AuditItem: Identifiable, Decodable {
    let id: String
    let name: String
    let state: String // ok | warn | fail | unknown | pending
    let detail: String
}

struct AuditSummary: Decodable {
    let ok: Int
    let warn: Int
    let fail: Int
    let unknown: Int
}

struct AuditReport: Decodable {
    let timestamp: String?
    let coverage_percent: Int
    let summary: AuditSummary
    let items: [AuditItem]
}

enum ActiveTab: String, CaseIterable {
    case dashboard = "亮灯仪表盘"
    case logs = "防火墙与执行日志"
}

// MARK: - 业务逻辑视图模型
final class GuardViewModel: ObservableObject {
    @Published var lockState: String = "off"        // on | standby | off
    @Published var lockMode: String = "off"         // cn | strict | standby | off
    @Published var procLocked: Bool = false
    @Published var bootPersist: Bool = false
    @Published var strictMode: Bool = false
    @Published var entryNodes: String = ""
    @Published var targetCountry: String = "未配置"
    @Published var targetTz: String = "未配置"

    @Published var auditItems: [AuditItem] = GuardViewModel.defaultPlaceholderItems()
    @Published var auditSummary = AuditSummary(ok: 0, warn: 0, fail: 0, unknown: 0)
    @Published var coveragePercent: Int = 0
    @Published var lastAuditTime: String = "尚未检测"
    @Published var hasAuditRun: Bool = false

    @Published var isBusy: Bool = false
    @Published var busyLabel: String = ""
    @Published var activeTab: ActiveTab = .dashboard
    @Published var logText: String = "欢迎使用 Claude 持久化安全锁！\n\n• 首次交付：在 Stash / 小火箭 / Clash Verge 开启「全局 + TUN」，点击「一键初始化环境」。\n• 亮灯验收：点击「一键全面体检」，14 项环境指标实时逐一亮灯。\n• 永久防呆：关闭安全锁切回日常上网时，Claude 将从系统底层锁死（点开弹提示）并黑洞全部 25 个遥测域名。"
    @Published var toastMessage: String = ""
    @Published var toastIsError: Bool = false

    let guardScript: String
    let auditScript: String
    let cfgFile: String
    let pfConf = "/etc/pf.conf"
    let pfAnchor = "/etc/pf.anchors/com.claude-guard"
    let pfBootPlist = "/Library/LaunchDaemons/com.claude-guard.pfboot.plist"

    init() {
        let fm = FileManager.default
        let resKit = (Bundle.main.resourcePath ?? "") + "/kit/mac"
        let exeParent = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().path
        let candidates = [
            resKit,
            exeParent,
            NSHomeDirectory() + "/.claude-guard/kit/mac"
        ]
        var foundDir = resKit
        for c in candidates {
            if fm.fileExists(atPath: c + "/claude-guard.sh") {
                foundDir = c
                break
            }
        }
        self.guardScript = foundDir + "/claude-guard.sh"
        self.auditScript = foundDir + "/env-audit.py"
        self.cfgFile = NSHomeDirectory() + "/.claude-guard/config.env"
        refreshStatus()
    }

    static func defaultPlaceholderItems() -> [AuditItem] {
        let specs: [(String, String)] = [
            ("killswitch", "持久化安全锁 (pf)"),
            ("tun", "全局 TUN 与默认路由"),
            ("dns", "本地与上游 DNS 泄露"),
            ("proxy_env", "代理环境变量与 PAC"),
            ("egress", "多源出口 IP 共识"),
            ("region_policy", "Anthropic 地区合规"),
            ("ip_risk", "IP 纯净度与 ASN 画像"),
            ("webrtc", "WebRTC / STUN 泄露"),
            ("locale_tz", "时区 / 地区 / 语言"),
            ("ipv6", "全接口 IPv6 封锁"),
            ("endpoints", "Anthropic 多端点延迟"),
            ("tls", "TLS 证书与 MITM 校验"),
            ("ws", "WebSocket 隧道握手"),
            ("client_env", "Claude 客户端与变量")
        ]
        return specs.map { AuditItem(id: $0.0, name: $0.1, state: "pending", detail: "点击「一键全面体检」开始实时检测") }
    }

    private func runProcess(executable: String, arguments: [String]) -> (Int32, String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executable)
        proc.arguments = arguments
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        env["LC_ALL"] = "en_US.UTF-8"
        proc.environment = env
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        do {
            try proc.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            proc.waitUntilExit()
            let out = String(data: data, encoding: .utf8) ?? ""
            return (proc.terminationStatus, out.trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            return (1, "执行失败: \(error.localizedDescription)")
        }
    }

    func refreshStatus(completion: (() -> Void)? = nil) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let (_, out) = self.runProcess(executable: "/bin/bash", arguments: [self.guardScript, "status"])
            var map: [String: String] = [:]
            for line in out.split(separator: "\n") {
                if let idx = line.firstIndex(of: "=") {
                    let k = String(line[..<idx])
                    let v = String(line[line.index(after: idx)...])
                    map[k] = v
                }
            }
            DispatchQueue.main.async {
                self.lockState = map["LOCK"] ?? "off"
                self.lockMode = map["LOCK_MODE"] ?? "off"
                self.procLocked = (map["PROC_LOCKED"] == "on")
                self.bootPersist = (map["PERSISTENT_LOCK"] == "on")
                self.strictMode = (map["STRICT_MODE"] == "1")
                let n = map["ENTRY_NODES"] ?? ""
                if self.entryNodes.isEmpty && n != "未配置" { self.entryNodes = n }
                self.targetCountry = map["COUNTRY_TARGET"] ?? "未配置"
                self.targetTz = map["TZ_TARGET"] ?? "未配置"
                completion?()
            }
        }
    }

    private func setToast(_ msg: String, isError: Bool = false) {
        self.toastMessage = msg
        self.toastIsError = isError
    }

    func togglePrimaryLock() {
        let targetAction = (lockState == "on") ? "unlock" : "lock"
        if targetAction == "lock" && strictMode && entryNodes.trimmingCharacters(in: .whitespaces).isEmpty {
            setToast("全封闭模式需先填写第一跳代理入口 IP 或域名！", isError: true)
            return
        }
        runGuardTask(
            label: targetAction == "lock" ? "正在启用持久化安全锁并放行 Claude..." : "正在切回日常模式并从系统底层锁死 Claude...",
            preSaveNodes: (targetAction == "lock"),
            args: [targetAction]
        ) { [weak self] code, out in
            guard let self else { return }
            if code == 0 {
                self.setToast(targetAction == "lock" ? "安全锁已开启，Claude 现已安全解锁" : "已切回日常模式，Claude 已被系统底层锁死")
            } else {
                self.setToast(out.split(separator: "\n").last.map(String.init) ?? "操作失败", isError: true)
            }
        }
    }

    func runInitEnvironment() {
        runGuardTask(
            label: "正在一键初始化环境（检测海外地区、锁时区/地区/英文、关 IPv6、开安全锁）...",
            preSaveNodes: false,
            args: ["init", entryNodes.trimmingCharacters(in: .whitespaces)]
        ) { [weak self] code, out in
            guard let self else { return }
            if code == 0 {
                self.setToast("一键初始化完成！正在自动执行 14 维度亮灯体检...")
                self.runFullAudit()
            } else {
                self.setToast(out.split(separator: "\n").last.map(String.init) ?? "初始化失败", isError: true)
                self.activeTab = .logs
            }
        }
    }

    func saveNodes() {
        let trimmed = entryNodes.trimmingCharacters(in: .whitespacesAndNewlines)
        runGuardTask(label: "正在保存并验证代理入口白名单...", preSaveNodes: false, args: ["set-nodes", trimmed]) { [weak self] code, out in
            guard let self else { return }
            if code == 0 {
                if self.lockState == "on" {
                    self.runGuardTask(label: "正在将新白名单同步写入内核防火墙...", preSaveNodes: false, args: ["lock"]) { c2, _ in
                        self.setToast(c2 == 0 ? "入口白名单已保存并实时生效" : "白名单已保存，但防火墙同步失败", isError: c2 != 0)
                    }
                } else {
                    self.setToast("入口白名单已保存")
                }
            } else {
                self.setToast(out, isError: true)
            }
        }
    }

    func setStrictMode(_ enabled: Bool) {
        if enabled && entryNodes.trimmingCharacters(in: .whitespaces).isEmpty {
            self.strictMode = false
            setToast("开启全封闭模式前，请先填入第一跳代理入口 IP 或域名！", isError: true)
            return
        }
        guard enabled != strictMode || true else { return }
        runGuardTask(label: "正在切换开锁策略...", preSaveNodes: !entryNodes.trimmingCharacters(in: .whitespaces).isEmpty, args: ["toggle-strict"]) { [weak self] code, _ in
            guard let self else { return }
            if code == 0 && self.lockState == "on" {
                self.runGuardTask(label: "正在刷新内核防火墙规则...", preSaveNodes: false, args: ["lock"]) { c2, _ in
                    self.setToast(c2 == 0 ? "已切换并实时生效新策略" : "策略切换失败", isError: c2 != 0)
                }
            } else {
                self.setToast(code == 0 ? "策略已更新（下次开锁生效）" : "策略切换失败", isError: code != 0)
            }
        }
    }

    func verifyFirewall() {
        runGuardTask(label: "正在核验操作系统 pf 内核规则、自愈守护与真实丢包计数...", preSaveNodes: false, args: ["verify-firewall"]) { [weak self] code, _ in
            guard let self else { return }
            self.activeTab = .logs
            self.setToast(code == 0 ? "操作系统防火墙验收通过" : "防火墙未处于完全锁定状态，请查看详情", isError: code != 0)
        }
    }

    func runFullAudit() {
        guard !isBusy else { return }
        isBusy = true
        busyLabel = "正在并发执行 14 维度深度体检（IP 画像 / DNS 泄露 / WebRTC / TLS / 延迟）..."
        activeTab = .dashboard
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let (_, out) = self.runProcess(
                executable: "/usr/bin/python3",
                arguments: [
                    self.auditScript,
                    "--config", self.cfgFile,
                    "--pf-conf", self.pfConf,
                    "--pf-anchor", self.pfAnchor,
                    "--pf-boot-plist", self.pfBootPlist,
                    "--json"
                ]
            )
            var parsed: AuditReport? = nil
            if let data = out.data(using: .utf8) {
                parsed = try? JSONDecoder().decode(AuditReport.self, from: data)
            }
            DispatchQueue.main.async {
                self.isBusy = false
                self.busyLabel = ""
                if let report = parsed {
                    self.auditItems = report.items
                    self.auditSummary = report.summary
                    self.coveragePercent = report.coverage_percent
                    self.lastAuditTime = report.timestamp ?? "刚刚"
                    self.hasAuditRun = true
                    if report.summary.fail == 0 {
                        self.setToast("体检完成：\(report.summary.ok) 项绿灯通过，0 项高危失败（覆盖率 \(report.coverage_percent)%）")
                    } else {
                        self.setToast("体检检出 \(report.summary.fail) 项红灯异常，请优先排查红灯项！", isError: true)
                    }
                } else {
                    self.logText = "体检输出解析异常：\n\(out)"
                    self.activeTab = .logs
                    self.setToast("体检执行异常，请切换到日志页查看", isError: true)
                }
                self.refreshStatus()
            }
        }
    }

    func exportReportToDesktop() {
        runGuardTask(label: "正在生成脱敏交机体检报告到桌面...", preSaveNodes: false, args: ["export-report"]) { [weak self] code, out in
            guard let self else { return }
            let fileLine = out.split(separator: "\n").first(where: { $0.hasPrefix("REPORT_FILE=") })
            let path = fileLine.map { String($0.dropFirst("REPORT_FILE=".count)) } ?? "桌面"
            self.setToast(code == 0 ? "交机报告已导出：\(URL(fileURLWithPath: path).lastPathComponent)" : "导出失败，请查看日志", isError: code != 0)
        }
    }

    private func runGuardTask(label: String, preSaveNodes: Bool, args: [String], done: @escaping (Int32, String) -> Void) {
        guard !isBusy else { return }
        isBusy = true
        busyLabel = label
        let nodesCopy = entryNodes.trimmingCharacters(in: .whitespacesAndNewlines)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            if preSaveNodes && !nodesCopy.isEmpty {
                _ = self.runProcess(executable: "/bin/bash", arguments: [self.guardScript, "set-nodes", nodesCopy])
            }
            let (code, out) = self.runProcess(executable: "/bin/bash", arguments: [self.guardScript] + args)
            DispatchQueue.main.async {
                self.isBusy = false
                self.busyLabel = ""
                if !out.isEmpty { self.logText = out }
                self.refreshStatus {
                    done(code, out)
                }
            }
        }
    }
}

// MARK: - 亮灯指示灯组件
struct StatusLamp: View {
    let state: String

    var color: Color {
        switch state {
        case "ok": return .lampGreen
        case "warn": return .lampAmber
        case "fail": return .lampRed
        default: return .lampGray
        }
    }

    var body: some View {
        ZStack {
            Circle()
                .fill(color.opacity(state == "pending" ? 0.12 : 0.22))
                .frame(width: 20, height: 20)
            Circle()
                .fill(color)
                .frame(width: 10, height: 10)
                .shadow(color: state == "pending" ? .clear : color.opacity(0.65), radius: 4, x: 0, y: 0)
        }
    }
}

// MARK: - 单项体检亮灯卡片
struct AuditCardView: View {
    let item: AuditItem

    var badgeText: String {
        switch item.state {
        case "ok": return "通过"
        case "warn": return "警告"
        case "fail": return "异常"
        case "unknown": return "未知"
        default: return "待测"
        }
    }

    var badgeFg: Color {
        switch item.state {
        case "ok": return .lampGreen
        case "warn": return .lampAmber
        case "fail": return .lampRed
        default: return .claudeMuted
        }
    }

    var badgeBg: Color {
        switch item.state {
        case "ok": return .lampGreenBg
        case "warn": return .lampAmberBg
        case "fail": return .lampRedBg
        default: return .lampGrayBg
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            StatusLamp(state: item.state)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(item.name)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundColor(.claudeInk)
                        .lineLimit(1)
                    Spacer()
                    Text(badgeText)
                        .font(.system(size: 10.5, weight: .semibold))
                        .foregroundColor(badgeFg)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(badgeBg))
                }
                Text(item.detail)
                    .font(.system(size: 11))
                    .foregroundColor(.claudeMuted)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.claudeSurface)
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .stroke(item.state == "fail" ? Color.lampRed.opacity(0.45) : Color.claudeBorder, lineWidth: 1)
                )
        )
    }
}

// MARK: - 主界面
struct ContentView: View {
    @StateObject private var vm = GuardViewModel()

    var statusPillInfo: (String, Color, Color, String) {
        if vm.lockState == "on" {
            let modeStr = vm.lockMode == "strict" ? "全封闭模式" : "放行国内 · 海外/Claude死锁"
            return ("安全锁已开启", .lampGreen, .lampGreenBg, "Claude 已放行且仅走海外 TUN（\(modeStr)）· 60s自愈守护=\(vm.bootPersist ? "在线" : "未装")")
        } else if vm.lockState == "standby" {
            return ("日常模式 · Claude已锁死", .lampAmber, .lampAmberBg, "日常上网可用 · Claude 进程已锁死(\(vm.procLocked ? "生效" : "未检测到App")) + 25个遥测域名黑洞 + 永久ASN拦截")
        } else {
            return ("尚未初始化", .claudeMuted, .lampGrayBg, "请先打开代理客户端「全局 + TUN」，再点击下方「一键初始化环境」")
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // 顶部 Claude 品牌 Header
            headerView
                .padding(.horizontal, 22)
                .padding(.top, 18)
                .padding(.bottom, 14)

            // 单锁主控制区 + 入口白名单
            controlCard
                .padding(.horizontal, 22)

            // 14 维度亮灯体检仪表盘 / 日志切换区
            auditSection
                .padding(.horizontal, 22)
                .padding(.top, 14)
                .padding(.bottom, 16)
        }
        .frame(minWidth: 820, idealWidth: 860, minHeight: 680, idealHeight: 720)
        .background(Color.claudeBg)
    }

    private var headerView: some View {
        let pill = statusPillInfo
        return HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(LinearGradient(colors: [Color.claudeAccent, Color.claudeAccentDk], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 44, height: 44)
                    .shadow(color: Color.claudeAccent.opacity(0.25), radius: 6, x: 0, y: 3)
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 21, weight: .semibold))
                    .foregroundColor(.white)
            }
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text("Claude 安全锁")
                        .font(.system(size: 19, weight: .bold, design: .serif))
                        .foregroundColor(.claudeInk)
                    Text("v2.1")
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundColor(.claudeAccent)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.claudeAccent.opacity(0.12)))
                }
                Text(pill.3)
                    .font(.system(size: 11.5))
                    .foregroundColor(.claudeMuted)
                    .lineLimit(1)
            }
            Spacer()
            HStack(spacing: 7) {
                StatusLamp(state: vm.lockState == "on" ? "ok" : (vm.lockState == "standby" ? "warn" : "pending"))
                Text(pill.0)
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundColor(pill.1)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(Capsule().fill(pill.2))
        }
    }

    private var controlCard: some View {
        VStack(spacing: 12) {
            HStack(spacing: 12) {
                // 单锁主大开关
                Button(action: { vm.togglePrimaryLock() }) {
                    HStack(spacing: 10) {
                        Image(systemName: vm.lockState == "on" ? "lock.open.fill" : "lock.fill")
                            .font(.system(size: 15, weight: .semibold))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(vm.lockState == "on" ? "关闭安全锁（切回日常上网 · 自动锁死 Claude）" : "开启安全锁（启用内核防泄露硬锁并解锁 Claude）")
                                .font(.system(size: 13.5, weight: .semibold))
                            Text(vm.lockState == "on" ? "切回日常模式后，Claude 进程与 25 个遥测域名将永久锁死，点开弹提示" : "开启后 Claude 只能走海外 TUN，代理退出/重启/死机 0ms 零泄露")
                                .font(.system(size: 10.5))
                                .opacity(0.88)
                        }
                        Spacer()
                    }
                    .foregroundColor(.white)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 11)
                    .background(
                        RoundedRectangle(cornerRadius: 11)
                            .fill(vm.lockState == "on" ? Color.lampAmber : Color.claudeAccent)
                    )
                }
                .buttonStyle(.plain)
                .disabled(vm.isBusy)

                // 一键初始化按钮
                Button(action: { vm.runInitEnvironment() }) {
                    VStack(spacing: 3) {
                        Image(systemName: "wand.and.stars")
                            .font(.system(size: 15, weight: .semibold))
                        Text("一键初始化")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundColor(.claudeInk)
                    .frame(width: 104, height: 54)
                    .background(
                        RoundedRectangle(cornerRadius: 11)
                            .fill(Color.claudeSubtle)
                            .overlay(RoundedRectangle(cornerRadius: 11).stroke(Color.claudeBorder, lineWidth: 1))
                    )
                }
                .buttonStyle(.plain)
                .disabled(vm.isBusy)
                .help("首次交付一键锁定时区、地区、英文界面、关闭全网卡 IPv6 并开启安全锁")
            }

            Divider().background(Color.claudeBorder)

            // 代理入口配置 + 全封闭开关
            HStack(spacing: 10) {
                Image(systemName: "network")
                    .foregroundColor(.claudeMuted)
                    .font(.system(size: 12.5))
                Text("代理入口白名单")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.claudeInk)
                TextField("国内中转链式代理可留空；直连海外 VPS 或全封闭模式填第一跳 IP（逗号分隔）", text: $vm.entryNodes)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12))
                Button("保存") { vm.saveNodes() }
                    .font(.system(size: 12, weight: .medium))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 5)
                    .background(RoundedRectangle(cornerRadius: 7).fill(Color.claudeSubtle))
                    .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.claudeBorder, lineWidth: 1))
                    .buttonStyle(.plain)
                    .disabled(vm.isBusy)

                Divider().frame(height: 18)

                Toggle(isOn: Binding(
                    get: { vm.strictMode },
                    set: { vm.setStrictMode($0) }
                )) {
                    Text("全封闭模式")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.claudeInk)
                }
                .toggleStyle(.switch)
                .controlSize(.small)
                .disabled(vm.isBusy)
                .help("勾选后开启安全锁时连国内公网与物理裸 DNS 53 也一并封锁")
            }

            if vm.isBusy || !vm.toastMessage.isEmpty {
                HStack(spacing: 8) {
                    if vm.isBusy {
                        ProgressView().scaleEffect(0.65).frame(width: 14, height: 14)
                        Text(vm.busyLabel)
                            .font(.system(size: 11.5, weight: .medium))
                            .foregroundColor(.claudeAccent)
                    } else {
                        Image(systemName: vm.toastIsError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .foregroundColor(vm.toastIsError ? .lampRed : .lampGreen)
                            .font(.system(size: 12))
                        Text(vm.toastMessage)
                            .font(.system(size: 11.5, weight: .medium))
                            .foregroundColor(vm.toastIsError ? .lampRed : .claudeInk)
                    }
                    Spacer()
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(vm.toastIsError && !vm.isBusy ? Color.lampRedBg.opacity(0.6) : Color.claudeSubtle)
                )
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color.claudeSurface)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.claudeBorder, lineWidth: 1))
                .shadow(color: Color.black.opacity(0.03), radius: 8, x: 0, y: 2)
        )
    }

    private var auditSection: some View {
        VStack(spacing: 10) {
            // 工具栏: 汇总亮灯数 + 视图切换 + 一键体检/验收/导出按钮
            HStack(spacing: 10) {
                Picker("", selection: $vm.activeTab) {
                    ForEach(ActiveTab.allCases, id: \.self) { t in
                        Text(t.rawValue).tag(t)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 220)

                if vm.hasAuditRun {
                    HStack(spacing: 8) {
                        Label("\(vm.auditSummary.ok)", systemImage: "circle.fill")
                            .foregroundColor(.lampGreen)
                        Label("\(vm.auditSummary.warn)", systemImage: "circle.fill")
                            .foregroundColor(.lampAmber)
                        Label("\(vm.auditSummary.fail)", systemImage: "circle.fill")
                            .foregroundColor(.lampRed)
                        Text("覆盖率 \(vm.coveragePercent)%")
                            .foregroundColor(.claudeMuted)
                    }
                    .font(.system(size: 11.5, weight: .semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(Capsule().fill(Color.claudeSubtle))
                }

                Spacer()

                Button(action: { vm.verifyFirewall() }) {
                    Label("验收防火墙日志", systemImage: "shield.lefthalf.filled")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.claudeInk)
                        .padding(.horizontal, 11)
                        .padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.claudeSurface))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.claudeBorder, lineWidth: 1))
                }
                .buttonStyle(.plain)
                .disabled(vm.isBusy)

                Button(action: { vm.exportReportToDesktop() }) {
                    Label("导出报告", systemImage: "doc.text")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.claudeInk)
                        .padding(.horizontal, 11)
                        .padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.claudeSurface))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.claudeBorder, lineWidth: 1))
                }
                .buttonStyle(.plain)
                .disabled(vm.isBusy)

                Button(action: { vm.runFullAudit() }) {
                    Label("一键全面体检", systemImage: "bolt.shield.fill")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 13)
                        .padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.claudeAccent))
                }
                .buttonStyle(.plain)
                .disabled(vm.isBusy)
            }

            // 内容区: 14 项 2 列亮灯网格 OR 终端日志
            if vm.activeTab == .dashboard {
                ScrollView {
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 9) {
                        ForEach(vm.auditItems) { item in
                            AuditCardView(item: item)
                        }
                    }
                    .padding(.vertical, 2)
                }
            } else {
                ScrollView {
                    Text(vm.logText)
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundColor(.claudeInk)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(12)
                }
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Color.claudeSurface)
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.claudeBorder, lineWidth: 1))
                )
            }
        }
    }
}

// MARK: - 原生 AppKit 窗口入口 (免 Xcode 项目文件，直接 swiftc 单文件编译)
final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!

    func applicationDidFinishLaunching(_ notification: Notification) {
        let hosting = NSHostingController(rootView: ContentView())
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 860, height: 720),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Claude 安全锁"
        window.titlebarAppearsTransparent = true
        window.backgroundColor = NSColor(red: 0.980, green: 0.976, blue: 0.961, alpha: 1.0)
        window.contentViewController = hosting
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
