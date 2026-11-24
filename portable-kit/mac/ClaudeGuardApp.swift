import SwiftUI
import AppKit
import Foundation

// MARK: - Claude 品牌暖米陶土橙主题色板
extension Color {
    static let claudeBg       = Color(red: 0.980, green: 0.976, blue: 0.961) // #FAF9F5
    static let claudeSurface  = Color(red: 1.000, green: 1.000, blue: 1.000) // #FFFFFF
    static let claudeSubtle   = Color(red: 0.953, green: 0.937, blue: 0.902) // #F3EFE6
    static let claudeBorder   = Color(red: 0.906, green: 0.886, blue: 0.847) // #E7E2D8
    static let claudeAccent   = Color(red: 0.851, green: 0.467, blue: 0.341) // #D97757
    static let claudeAccentDk = Color(red: 0.761, green: 0.380, blue: 0.259) // #C26142
    static let claudeInk      = Color(red: 0.122, green: 0.118, blue: 0.114) // #1F1E1D
    static let claudeMuted    = Color(red: 0.420, green: 0.400, blue: 0.369) // #6B665E

    static let lampGreen      = Color(red: 0.086, green: 0.639, blue: 0.290) // #16A34A
    static let lampGreenBg    = Color(red: 0.863, green: 0.988, blue: 0.906) // #DCFCE7
    static let lampAmber      = Color(red: 0.851, green: 0.467, blue: 0.024) // #D97706
    static let lampAmberBg    = Color(red: 0.996, green: 0.953, blue: 0.780) // #FEF3C7
    static let lampRed        = Color(red: 0.863, green: 0.149, blue: 0.149) // #DC2626
    static let lampRedBg      = Color(red: 0.996, green: 0.886, blue: 0.886) // #FEE2E2
    static let lampGray       = Color(red: 0.612, green: 0.639, blue: 0.686) // #9CA3AF
    static let lampGrayBg     = Color(red: 0.945, green: 0.949, blue: 0.957) // #F1F2F4
}

// MARK: - 数据模型
struct AuditItem: Identifiable, Decodable {
    let id: String
    let name: String
    let state: String
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

// MARK: - 视图模型
final class GuardViewModel: ObservableObject {
    @Published var lockState: String = "off"        // on(一级锁开·全走TUN) | cn(一级锁关·国内白名单) | relax(二级放宽锁开) | off
    @Published var lockMode: String = "off"
    @Published var procLocked: Bool = false
    @Published var bootPersist: Bool = false
    @Published var entryNodes: String = ""
    @Published var targetCountry: String = "未配置"

    @Published var auditItems: [AuditItem] = GuardViewModel.defaultPlaceholderItems()
    @Published var auditSummary = AuditSummary(ok: 0, warn: 0, fail: 0, unknown: 0)
    @Published var coveragePercent: Int = 0
    @Published var hasAuditRun: Bool = false

    @Published var isBusy: Bool = false
    @Published var busyLabel: String = ""
    @Published var activeTab: ActiveTab = .dashboard
    @Published var logText: String = "欢迎使用 Claude 持久化安全锁 v2.2！\n\n• 首次交付：在代理客户端开启「全局 + TUN」，点击「一键初始化」自动锁死环境并在桌面生成《断网急救.txt》。\n• 一级安全锁开启：100% 公网流量强制只走代理 TUN，安心使用 Claude。\n• 一级安全锁关闭：自动退出并锁死 Claude 全版本进程，放行国内白名单网络，持续阻断一切海外与遥测服务器。\n• 二级放宽锁：仅当国内偏门流量被误拦时开启（底层 Claude 进程与 34 个遥测/邮件链接黑洞依然焊死）。"
    @Published var toastMessage: String = ""
    @Published var toastIsError: Bool = false

    @Published var showConfirmClosePrimary: Bool = false
    @Published var showConfirmOpenRelax: Bool = false

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
        var foundDir = resKit
        for c in [resKit, exeParent, NSHomeDirectory() + "/.claude-guard/kit/mac"] {
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
                    map[String(line[..<idx])] = String(line[line.index(after: idx)...])
                }
            }
            DispatchQueue.main.async {
                self.lockState = map["LOCK"] ?? "off"
                self.lockMode = map["LOCK_MODE"] ?? "off"
                self.procLocked = (map["PROC_LOCKED"] == "on")
                self.bootPersist = (map["PERSISTENT_LOCK"] == "on")
                let n = map["ENTRY_NODES"] ?? ""
                if self.entryNodes.isEmpty && n != "未配置" { self.entryNodes = n }
                self.targetCountry = map["COUNTRY_TARGET"] ?? "未配置"
                completion?()
            }
        }
    }

    private func setToast(_ msg: String, isError: Bool = false) {
        self.toastMessage = msg
        self.toastIsError = isError
    }

    func handlePrimaryLockTap() {
        if lockState == "on" {
            showConfirmClosePrimary = true
        } else {
            enablePrimaryLock()
        }
    }

    func enablePrimaryLock() {
        runGuardTask(
            label: "正在启用一级安全锁（100% 流量强制只走 TUN）并放行 Claude...",
            preSaveNodes: true,
            args: ["lock"]
        ) { [weak self] code, out in
            guard let self else { return }
            if code == 0 {
                self.setToast("一级安全锁已开启！一切流量 100% 只走代理 TUN，Claude 已安全解锁")
            } else {
                self.setToast(out.split(separator: "\n").last.map(String.init) ?? "开启失败", isError: true)
            }
        }
    }

    func confirmDisablePrimaryLock() {
        runGuardTask(
            label: "正在退出所有 Claude 进程，并切换为国内白名单直连网络...",
            preSaveNodes: false,
            args: ["unlock"]
        ) { [weak self] code, out in
            guard let self else { return }
            if code == 0 {
                self.setToast("已退出 Claude 并切回国内网络！海外与 Claude 遥测持续阻断，Claude 进程已锁死")
            } else {
                self.setToast(out.split(separator: "\n").last.map(String.init) ?? "切换失败", isError: true)
            }
        }
    }

    func handleRelaxToggleTap() {
        if lockState == "relax" {
            // 关闭二级放宽锁 -> 回到一级锁关闭的国内白名单保护态
            confirmDisablePrimaryLock()
        } else {
            showConfirmOpenRelax = true
        }
    }

    func confirmEnableRelaxMode() {
        runGuardTask(
            label: "正在打开二级放宽锁（放宽普通公网规则，保持 Claude 进程与遥测黑洞死锁）...",
            preSaveNodes: false,
            args: ["relax"]
        ) { [weak self] code, out in
            guard let self else { return }
            if code == 0 {
                self.setToast("⚠️ 二级放宽锁已打开！切勿打开任何 Claude 服务或点击任何 Claude 邮件链接", isError: true)
            } else {
                self.setToast(out.split(separator: "\n").last.map(String.init) ?? "操作失败", isError: true)
            }
        }
    }

    func runInitEnvironment() {
        runGuardTask(
            label: "正在一键初始化环境（锁时区/地区/英文、关 IPv6、生成急救指南、开启全走 TUN 锁）...",
            preSaveNodes: false,
            args: ["init", entryNodes.trimmingCharacters(in: .whitespaces)]
        ) { [weak self] code, out in
            guard let self else { return }
            if code == 0 {
                self.setToast("一键初始化完成（桌面已生成《断网急救.txt》），正在执行亮灯体检...")
                self.runFullAudit()
            } else {
                self.setToast(out.split(separator: "\n").last.map(String.init) ?? "初始化失败", isError: true)
                self.activeTab = .logs
            }
        }
    }

    func saveNodes() {
        let trimmed = entryNodes.trimmingCharacters(in: .whitespacesAndNewlines)
        runGuardTask(label: "正在保存第一跳代理入口白名单...", preSaveNodes: false, args: ["set-nodes", trimmed]) { [weak self] code, out in
            guard let self else { return }
            if code == 0 && self.lockState == "on" {
                self.runGuardTask(label: "正在将新白名单同步写入内核防火墙...", preSaveNodes: false, args: ["lock"]) { c2, _ in
                    self.setToast(c2 == 0 ? "入口白名单已保存并实时生效" : "防火墙同步失败", isError: c2 != 0)
                }
            } else {
                self.setToast(code == 0 ? "入口配置已更新" : out, isError: code != 0)
            }
        }
    }

    func writeEmergencyGuide() {
        runGuardTask(label: "正在向桌面生成本机专属《断网急救.txt》...", preSaveNodes: false, args: ["write-emergency"]) { [weak self] code, _ in
            self?.setToast(code == 0 ? "已在桌面生成本机专属《断网急救.txt》，建议用手机拍照留存" : "生成急救指南失败", isError: code != 0)
        }
    }

    func verifyFirewall() {
        runGuardTask(label: "正在核验操作系统 pf 规则、全版本自愈守护与真实丢包计数...", preSaveNodes: false, args: ["verify-firewall"]) { [weak self] code, _ in
            guard let self else { return }
            self.activeTab = .logs
            self.setToast(code == 0 ? "操作系统防火墙与自愈守护验收通过" : "防火墙未处于锁定状态，请查看详情", isError: code != 0)
        }
    }

    func runFullAudit() {
        guard !isBusy else { return }
        isBusy = true
        busyLabel = "正在并发执行 14 维度深度体检（IP 画像 / isp.ac DNS 泄露 / WebRTC / TLS / 延迟）..."
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
                    self.hasAuditRun = true
                    if report.summary.fail == 0 {
                        self.setToast("体检完成：\(report.summary.ok) 项绿灯通过，0 项高危异常（覆盖率 \(report.coverage_percent)%）")
                    } else {
                        self.setToast("体检检出 \(report.summary.fail) 项红灯异常，请优先排查红灯卡片！", isError: true)
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
            let fileLine = out.split(separator: "\n").first(where: { $0.hasPrefix("REPORT_FILE=") })
            let path = fileLine.map { String($0.dropFirst("REPORT_FILE=".count)) } ?? "桌面"
            self?.setToast(code == 0 ? "交机报告已导出：\(URL(fileURLWithPath: path).lastPathComponent)" : "导出失败", isError: code != 0)
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

// MARK: - 亮灯组件
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
            Circle().fill(color.opacity(state == "pending" ? 0.12 : 0.22)).frame(width: 20, height: 20)
            Circle().fill(color).frame(width: 10, height: 10)
                .shadow(color: state == "pending" ? .clear : color.opacity(0.65), radius: 4)
        }
    }
}

struct AuditCardView: View {
    let item: AuditItem
    var badge: (String, Color, Color) {
        switch item.state {
        case "ok": return ("通过", .lampGreen, .lampGreenBg)
        case "warn": return ("警告", .lampAmber, .lampAmberBg)
        case "fail": return ("异常", .lampRed, .lampRedBg)
        case "unknown": return ("未知", .claudeMuted, .lampGrayBg)
        default: return ("待测", .claudeMuted, .lampGrayBg)
        }
    }
    var body: some View {
        let b = badge
        return HStack(alignment: .top, spacing: 10) {
            StatusLamp(state: item.state).padding(.top, 1)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(item.name).font(.system(size: 12.5, weight: .semibold)).foregroundColor(.claudeInk).lineLimit(1)
                    Spacer()
                    Text(b.0).font(.system(size: 10.5, weight: .semibold)).foregroundColor(b.1)
                        .padding(.horizontal, 7).padding(.vertical, 2).background(Capsule().fill(b.2))
                }
                Text(item.detail).font(.system(size: 11)).foregroundColor(.claudeMuted).lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8.5)
        .background(
            RoundedRectangle(cornerRadius: 10).fill(Color.claudeSurface)
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(item.state == "fail" ? Color.lampRed.opacity(0.45) : Color.claudeBorder, lineWidth: 1))
        )
    }
}

// MARK: - 主界面
struct ContentView: View {
    @StateObject private var vm = GuardViewModel()

    var statusPillInfo: (String, Color, Color, String, String) {
        switch vm.lockState {
        case "on":
            return ("一级安全锁已开启", .lampGreen, .lampGreenBg, "ok", "100% 公网流量强制只走代理 TUN · Claude 已解锁 · 自愈守护=\(vm.bootPersist ? "在线" : "未装")")
        case "cn":
            return ("国内白名单直连态", .lampAmber, .lampAmberBg, "warn", "Claude 全版本进程已锁死 + 海外与 34 个遥测域名持续 0ms 阻断")
        case "relax":
            return ("二级放宽锁已打开", .lampRed, .lampRedBg, "fail", "⚠️ 无全网防护！严禁打开任何 Claude 服务或点击任何 Claude 邮件链接")
        default:
            return ("尚未初始化", .claudeMuted, .lampGrayBg, "pending", "请先打开代理客户端「全局 + TUN」，再点击下方「一键初始化」")
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            headerView
                .padding(.horizontal, 22)
                .padding(.top, 16)
                .padding(.bottom, 12)

            if vm.lockState == "relax" {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.octagon.fill").foregroundColor(.lampRed)
                    Text("高危提醒：当前电脑没有全网防护！请不要打开任何与 Claude 相关的服务，包括电子邮件里不要点击 Claude 发来的任何邮件和链接！（底层 Claude 进程与遥测黑洞仍在保护中）")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundColor(.lampRed)
                    Spacer()
                }
                .padding(.horizontal, 14).padding(.vertical, 8)
                .background(RoundedRectangle(cornerRadius: 10).fill(Color.lampRedBg))
                .padding(.horizontal, 22)
                .padding(.bottom, 10)
            }

            controlCard
                .padding(.horizontal, 22)

            auditSection
                .padding(.horizontal, 22)
                .padding(.top, 12)
                .padding(.bottom, 14)
        }
        .frame(minWidth: 840, idealWidth: 880, minHeight: 720, idealHeight: 760)
        .background(Color.claudeBg)
        // 弹窗 1: 关闭一级安全锁警告
        .alert("确认关闭一级安全锁并切换回国内网络？", isPresented: $vm.showConfirmClosePrimary) {
            Button("取消", role: .cancel) {}
            Button("退出 Claude 并切回国内网络", role: .destructive) {
                vm.confirmDisablePrimaryLock()
            }
        } message: {
            Text("关闭一级安全锁时：\n1. 将立即退出正在运行的 Claude 桌面版、所有 Helper 与 Claude Code CLI；\n2. 切换为国内白名单直连网络，但一切海外与 Claude 遥测服务器仍持续阻挡；\n3. Claude 进程将被系统锁死，再次使用前请先开启一级安全锁。")
        }
        // 弹窗 2: 打开二级放宽锁高危警告（含电子邮件与链接提示）
        .alert("⚠️ 警告：此时电脑没有全网防护！", isPresented: $vm.showConfirmOpenRelax) {
            Button("取消（保持拦截保护）", role: .cancel) {}
            Button("我已知晓风险，打开二级放宽锁", role: .destructive) {
                vm.confirmEnableRelaxMode()
            }
        } message: {
            Text("打开二级放宽锁将放宽防火墙规则（防止误伤国内规则未收录的流量）。\n\n⚠️ 请务必遵守：此时电脑没有防护，请不要打开任何与 Claude 相关的服务，包括在电子邮件里不要点击 Claude 发来的电子邮件和 Claude 发来的任何链接！\n\n（注：底层 Claude 全版本进程锁与遥测黑洞仍将保持锁定，除非彻底卸载本软件。）")
        }
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
                    Text("v2.2")
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundColor(.claudeAccent)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Capsule().fill(Color.claudeAccent.opacity(0.12)))
                }
                Text(pill.4)
                    .font(.system(size: 11.5))
                    .foregroundColor(.claudeMuted)
                    .lineLimit(1)
            }
            Spacer()
            HStack(spacing: 7) {
                StatusLamp(state: pill.3)
                Text(pill.0)
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundColor(pill.1)
            }
            .padding(.horizontal, 12).padding(.vertical, 7)
            .background(Capsule().fill(pill.2))
        }
    }

    private var controlCard: some View {
        VStack(spacing: 10) {
            HStack(spacing: 12) {
                // 一级主安全锁大开关
                Button(action: { vm.handlePrimaryLockTap() }) {
                    HStack(spacing: 10) {
                        Image(systemName: vm.lockState == "on" ? "lock.open.fill" : "lock.fill")
                            .font(.system(size: 15, weight: .semibold))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(vm.lockState == "on" ? "关闭一级安全锁（弹窗确认并退出 Claude → 恢复国内网络）" : "开启一级安全锁（100% 流量强制只走 TUN · 解锁 Claude 使用）")
                                .font(.system(size: 13.5, weight: .semibold))
                            Text(vm.lockState == "on" ? "关闭后放行国内白名单网络，海外与 Claude 遥测持续阻断，Claude 进程自动锁死" : "配合全局 + TUN 使用，物理网卡一切国内外公网/裸DNS/IPv6/STUN 全部 0ms 拦截")
                                .font(.system(size: 10.5))
                                .opacity(0.9)
                        }
                        Spacer()
                    }
                    .foregroundColor(.white)
                    .padding(.horizontal, 16).padding(.vertical, 10)
                    .background(RoundedRectangle(cornerRadius: 11).fill(vm.lockState == "on" ? Color.lampAmber : Color.claudeAccent))
                }
                .buttonStyle(.plain)
                .disabled(vm.isBusy)

                Button(action: { vm.runInitEnvironment() }) {
                    VStack(spacing: 3) {
                        Image(systemName: "wand.and.stars").font(.system(size: 15, weight: .semibold))
                        Text("一键初始化").font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundColor(.claudeInk)
                    .frame(width: 106, height: 52)
                    .background(
                        RoundedRectangle(cornerRadius: 11).fill(Color.claudeSubtle)
                            .overlay(RoundedRectangle(cornerRadius: 11).stroke(Color.claudeBorder, lineWidth: 1))
                    )
                }
                .buttonStyle(.plain)
                .disabled(vm.isBusy)
            }

            Divider().background(Color.claudeBorder)

            // 入口节点 + 二级持久化放宽锁
            HStack(spacing: 10) {
                Image(systemName: "network").foregroundColor(.claudeMuted).font(.system(size: 12))
                Text("第一跳入口 IP")
                    .font(.system(size: 12, weight: .medium)).foregroundColor(.claudeInk)
                TextField("留空自动识别当前代理连接 IP；或手动填第一跳节点 IP（逗号分隔）", text: $vm.entryNodes)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12))
                Button("保存") { vm.saveNodes() }
                    .font(.system(size: 12, weight: .medium))
                    .padding(.horizontal, 11).padding(.vertical, 5)
                    .background(RoundedRectangle(cornerRadius: 7).fill(Color.claudeSubtle))
                    .overlay(RoundedRectangle(cornerRadius: 7).stroke(Color.claudeBorder, lineWidth: 1))
                    .buttonStyle(.plain)
                    .disabled(vm.isBusy)

                Divider().frame(height: 18)

                // 二级持久化放宽锁按钮
                Button(action: { vm.handleRelaxToggleTap() }) {
                    HStack(spacing: 5) {
                        Image(systemName: vm.lockState == "relax" ? "shield.slash.fill" : "exclamationmark.shield")
                            .font(.system(size: 11.5))
                        Text(vm.lockState == "relax" ? "关闭二级放宽锁（恢复拦截）" : "二级放宽锁（防国内误伤）")
                            .font(.system(size: 11.5, weight: .semibold))
                    }
                    .foregroundColor(vm.lockState == "relax" ? .white : .lampRed)
                    .padding(.horizontal, 11).padding(.vertical, 5)
                    .background(
                        RoundedRectangle(cornerRadius: 7)
                            .fill(vm.lockState == "relax" ? Color.lampRed : Color.lampRedBg.opacity(0.75))
                    )
                }
                .buttonStyle(.plain)
                .disabled(vm.isBusy)
            }

            if vm.isBusy || !vm.toastMessage.isEmpty {
                HStack(spacing: 8) {
                    if vm.isBusy {
                        ProgressView().scaleEffect(0.65).frame(width: 14, height: 14)
                        Text(vm.busyLabel).font(.system(size: 11.5, weight: .medium)).foregroundColor(.claudeAccent)
                    } else {
                        Image(systemName: vm.toastIsError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .foregroundColor(vm.toastIsError ? .lampRed : .lampGreen).font(.system(size: 12))
                        Text(vm.toastMessage).font(.system(size: 11.5, weight: .medium))
                            .foregroundColor(vm.toastIsError ? .lampRed : .claudeInk)
                    }
                    Spacer()
                }
                .padding(.horizontal, 10).padding(.vertical, 5.5)
                .background(RoundedRectangle(cornerRadius: 8).fill(vm.toastIsError && !vm.isBusy ? Color.lampRedBg.opacity(0.6) : Color.claudeSubtle))
            }
        }
        .padding(13)
        .background(
            RoundedRectangle(cornerRadius: 14).fill(Color.claudeSurface)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.claudeBorder, lineWidth: 1))
                .shadow(color: Color.black.opacity(0.03), radius: 8, x: 0, y: 2)
        )
    }

    private var auditSection: some View {
        VStack(spacing: 10) {
            HStack(spacing: 8) {
                Picker("", selection: $vm.activeTab) {
                    ForEach(ActiveTab.allCases, id: \.self) { t in Text(t.rawValue).tag(t) }
                }
                .pickerStyle(.segmented)
                .frame(width: 210)

                if vm.hasAuditRun {
                    HStack(spacing: 7) {
                        Label("\(vm.auditSummary.ok)", systemImage: "circle.fill").foregroundColor(.lampGreen)
                        Label("\(vm.auditSummary.warn)", systemImage: "circle.fill").foregroundColor(.lampAmber)
                        Label("\(vm.auditSummary.fail)", systemImage: "circle.fill").foregroundColor(.lampRed)
                        Text("覆盖 \(vm.coveragePercent)%").foregroundColor(.claudeMuted)
                    }
                    .font(.system(size: 11, weight: .semibold))
                    .padding(.horizontal, 9).padding(.vertical, 4)
                    .background(Capsule().fill(Color.claudeSubtle))
                }

                Spacer()

                Button(action: { vm.writeEmergencyGuide() }) {
                    Label("急救指南", systemImage: "cross.case")
                        .font(.system(size: 11.5, weight: .medium)).foregroundColor(.claudeInk)
                        .padding(.horizontal, 9).padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.claudeSurface))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.claudeBorder, lineWidth: 1))
                }
                .buttonStyle(.plain).disabled(vm.isBusy)

                Button(action: { vm.verifyFirewall() }) {
                    Label("验收防火墙日志", systemImage: "shield.lefthalf.filled")
                        .font(.system(size: 11.5, weight: .medium)).foregroundColor(.claudeInk)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.claudeSurface))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.claudeBorder, lineWidth: 1))
                }
                .buttonStyle(.plain).disabled(vm.isBusy)

                Button(action: { vm.exportReportToDesktop() }) {
                    Label("导出报告", systemImage: "doc.text")
                        .font(.system(size: 11.5, weight: .medium)).foregroundColor(.claudeInk)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.claudeSurface))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.claudeBorder, lineWidth: 1))
                }
                .buttonStyle(.plain).disabled(vm.isBusy)

                Button(action: { vm.runFullAudit() }) {
                    Label("一键全面体检", systemImage: "bolt.shield.fill")
                        .font(.system(size: 12, weight: .semibold)).foregroundColor(.white)
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color.claudeAccent))
                }
                .buttonStyle(.plain).disabled(vm.isBusy)
            }

            if vm.activeTab == .dashboard {
                ScrollView {
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 8) {
                        ForEach(vm.auditItems) { item in AuditCardView(item: item) }
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
                    RoundedRectangle(cornerRadius: 12).fill(Color.claudeSurface)
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.claudeBorder, lineWidth: 1))
                )
            }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    func applicationDidFinishLaunching(_ notification: Notification) {
        let hosting = NSHostingController(rootView: ContentView())
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 880, height: 750),
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
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
