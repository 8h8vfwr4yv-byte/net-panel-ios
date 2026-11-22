import SwiftUI

@main
struct NetPanelApp: App {
    @StateObject private var panel = PanelState()
    @StateObject private var log = LogStore()

    var body: some Scene {
        WindowGroup {
            TabView {
                StatusView()
                    .tabItem { Label("状态", systemImage: "waveform.path.ecg") }
                LatencyView()
                    .tabItem { Label("延迟", systemImage: "gauge.with.dots.needle.33percent") }
                PresetView()
                    .tabItem { Label("预设", systemImage: "arrow.triangle.branch") }
                LogView()
                    .tabItem { Label("日志", systemImage: "doc.text") }
            }
            .environmentObject(panel)
            .environmentObject(log)
        }
    }
}

// MARK: - 状态

struct StatusView: View {
    @EnvironmentObject var log: LogStore
    @State private var ifaces: [NetInterface] = []
    @State private var outIP: String = "—"
    @State private var outIface: String? = nil
    @State private var proxy = NetDiag.ProxyInfo()

    private var tunnels: [NetInterface] { ifaces.filter { $0.isTunnel } }
    private var connectionType: String {
        if ifaces.contains(where: { $0.name.hasPrefix("en") && !$0.isIPv6 }) { return "Wi-Fi / 有线" }
        if ifaces.contains(where: { $0.name.hasPrefix("pdp_ip") }) { return "蜂窝网络" }
        return ifaces.isEmpty ? "无网络" : "其他"
    }

    var body: some View {
        NavigationStack {
            List {
                Section("连接") {
                    row("网络类型", connectionType)
                    row("出口 IP", outIP)
                    row("默认路径", outIface.map { name in
                        tunnels.contains { $0.name == name } ? "\(name)（隧道）" : "\(name)（直连）"
                    } ?? "未知")
                }
                Section {
                    if tunnels.isEmpty {
                        row("隧道接口", "未检测到")
                    } else {
                        ForEach(tunnels) { t in
                            row(t.name, t.address)
                        }
                    }
                } header: {
                    Text("隧道状态")
                } footer: {
                    Text("通过枚举 utun 接口判断：存在 utun 地址通常意味着有 VPN/隧道在工作。默认路径若经由 utun，说明流量正走隧道。")
                }
                Section("系统代理（只读）") {
                    row("HTTP 代理", proxy.http ?? "未设置")
                    row("HTTPS 代理", proxy.https ?? "未设置")
                    row("SOCKS 代理", proxy.socks ?? "未设置")
                    row("PAC 地址", proxy.pacURL ?? "未设置")
                }
                Section("全部接口") {
                    if ifaces.isEmpty {
                        Text("未获取到接口").foregroundStyle(.secondary)
                    }
                    ForEach(ifaces) { iface in
                        HStack {
                            Text(iface.name)
                                .font(.body.monospaced())
                            Spacer()
                            Text(iface.address)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                }
            }
            .navigationTitle("隧道状态")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { refresh() } label: { Image(systemName: "arrow.clockwise") }
                }
            }
            .onAppear { refresh() }
        }
    }

    private func row(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value).foregroundStyle(.secondary).lineLimit(1)
        }
    }

    private func refresh() {
        DispatchQueue.global(qos: .userInitiated).async {
            let list = NetDiag.interfaces()
            let out = NetDiag.outbound()
            let px = NetDiag.systemProxy()
            DispatchQueue.main.async {
                ifaces = list
                outIP = out?.ip ?? "获取失败"
                outIface = out?.interface
                proxy = px
                log.log("刷新状态：出口 \(outIP)，路径 \(outIface ?? "未知")，隧道接口 \(tunnels.count) 个")
            }
        }
    }
}

// MARK: - 延迟测试

struct LatencyView: View {
    @EnvironmentObject var panel: PanelState
    @EnvironmentObject var log: LogStore
    @State private var results: [String: String] = [:]
    @State private var testing = false
    @State private var dnsResult: String = "未测试"
    @State private var customHost = ""
    @State private var customResult: String? = nil

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack {
                        Text("当前预设")
                        Spacer()
                        Text(panel.preset.name).foregroundStyle(.secondary)
                    }
                    HStack {
                        Text("DNS 解析服务器")
                        Spacer()
                        Text(panel.preset.resolver).foregroundStyle(.secondary)
                    }
                }
                Section {
                    ForEach(panel.preset.targets) { target in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(target.label)
                                Text("\(target.host):\(target.port)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(results[target.host] ?? "—")
                                .font(.body.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                    }
                    Button {
                        runTests()
                    } label: {
                        Label(testing ? "测试中…" : "开始延迟测试", systemImage: "play.fill")
                    }
                    .disabled(testing)
                } header: {
                    Text("目标延迟（TCP 握手）")
                } footer: {
                    Text("沙盒限制下 App 无法发送 ICMP ping，这里用 TCP 连接握手计时模拟延迟，每个目标测 3 次取平均。")
                }
                Section("DNS 解析") {
                    HStack {
                        Text(panel.preset.dnsDomain)
                        Spacer()
                        Text(dnsResult).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Button("测试解析") { runDNS() }
                        .disabled(testing)
                }
                Section("自定义目标") {
                    TextField("主机名或 IP，如 www.apple.com", text: $customHost)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Button("测试（443 端口）") { runCustom() }
                        .disabled(customHost.isEmpty || testing)
                    if let customResult {
                        Text(customResult).font(.callout).foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("延迟测试")
        }
    }

    private func runTests() {
        testing = true
        let targets = panel.preset.targets
        for t in targets { results[t.host] = "测试中…" }
        DispatchQueue.global(qos: .userInitiated).async {
            for t in targets {
                var samples: [Double] = []
                for _ in 0..<3 {
                    if let ms = NetDiag.tcpLatency(host: t.host, port: t.port) { samples.append(ms) }
                }
                let text = samples.isEmpty ? "超时" : String(format: "%.0f ms", samples.reduce(0, +) / Double(samples.count))
                DispatchQueue.main.async {
                    results[t.host] = text
                    log.log("延迟 \(t.label) \(t.host): \(text)")
                }
            }
            DispatchQueue.main.async { testing = false }
        }
    }

    private func runDNS() {
        testing = true
        dnsResult = "查询中…"
        let domain = panel.preset.dnsDomain
        let resolver = panel.preset.resolver
        DispatchQueue.global(qos: .userInitiated).async {
            let r = NetDiag.dnsQuery(domain: domain, resolver: resolver)
            DispatchQueue.main.async {
                testing = false
                if let r {
                    dnsResult = String(format: "%.0f ms → %@", r.ms, r.ips.first ?? "无结果")
                    log.log("DNS \(domain) @\(resolver)：\(dnsResult)")
                } else {
                    dnsResult = "查询超时"
                    log.log("DNS \(domain) @\(resolver)：超时")
                }
            }
        }
    }

    private func runCustom() {
        testing = true
        customResult = "测试中…"
        let host = customHost
        DispatchQueue.global(qos: .userInitiated).async {
            let ms = NetDiag.tcpLatency(host: host, port: 443)
            DispatchQueue.main.async {
                testing = false
                customResult = ms.map { String(format: "%.0f ms", $0) } ?? "超时/不可达"
                log.log("自定义目标 \(host):443 → \(customResult ?? "")")
            }
        }
    }
}

// MARK: - 分流预设

struct PresetView: View {
    @EnvironmentObject var panel: PanelState
    @EnvironmentObject var log: LogStore

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(DiagPreset.all) { preset in
                        Button {
                            if panel.preset.id != preset.id {
                                panel.preset = preset
                                log.log("切换分流预设 → \(preset.name)（解析服务器 \(preset.resolver)）")
                            }
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(preset.name)
                                        .foregroundStyle(.primary)
                                    Text(preset.desc)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if panel.preset.id == preset.id {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundStyle(.blue)
                                }
                            }
                        }
                    }
                } footer: {
                    Text("预设只切换本面板的检测目标、DNS 解析服务器与关注重点，不会修改系统网络、代理或路由设置。本 App 不包含任何代理/隧道功能。")
                }
                Section("当前预设目标") {
                    ForEach(panel.preset.targets) { t in
                        HStack {
                            Text(t.label)
                            Spacer()
                            Text("\(t.host):\(t.port)")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("分流预设")
        }
    }
}

// MARK: - 日志

struct LogView: View {
    @EnvironmentObject var log: LogStore
    @State private var showClearConfirm = false

    var body: some View {
        NavigationStack {
            List {
                if log.entries.isEmpty {
                    Text("暂无日志").foregroundStyle(.secondary)
                }
                ForEach(Array(log.entries.enumerated().reversed()), id: \.offset) { _, entry in
                    Text(entry)
                        .font(.caption.monospaced())
                }
            }
            .navigationTitle("诊断日志")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: log.exportText) {
                        Image(systemName: "square.and.arrow.up")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button(role: .destructive) { showClearConfirm = true } label: {
                        Image(systemName: "trash")
                    }
                }
            }
            .alert("清空日志？", isPresented: $showClearConfirm) {
                Button("取消", role: .cancel) {}
                Button("清空", role: .destructive) { log.clear() }
            }
        }
    }
}
