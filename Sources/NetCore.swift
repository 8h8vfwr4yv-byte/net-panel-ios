import Foundation
import CFNetwork

// MARK: - 纯诊断工具箱
// 只做网络检测：接口枚举、系统代理设置读取、TCP 握手计时、DNS 查询计时、出口 IP 探测。
// 不包含任何代理/隧道实现，不修改任何系统网络设置。

struct NetInterface: Identifiable {
    var id: String { name + "-" + address }
    let name: String
    let address: String
    let isIPv6: Bool
    var isTunnel: Bool { name.hasPrefix("utun") }
}

enum NetDiag {
    // MARK: 接口列表
    static func interfaces() -> [NetInterface] {
        var result: [NetInterface] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return result }
        defer { freeifaddrs(head) }
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cur {
            defer { cur = ifa.pointee.ifa_next }
            guard let addr = ifa.pointee.ifa_addr else { continue }
            let family = addr.pointee.sa_family
            guard family == sa_family_t(AF_INET) || family == sa_family_t(AF_INET6) else { continue }
            let name = String(cString: ifa.pointee.ifa_name)
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let rc = getnameinfo(addr, socklen_t(addr.pointee.sa_len),
                                 &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            guard rc == 0 else { continue }
            let ip = String(cString: host)
            if ip == "127.0.0.1" || ip == "::1" { continue }
            result.append(NetInterface(name: name, address: ip, isIPv6: family == sa_family_t(AF_INET6)))
        }
        return result
    }

    // MARK: 出口 IP 与默认路径接口（UDP connect 后读本地端点，再匹配接口）
    static func outbound() -> (ip: String, interface: String?)? {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var dest = sockaddr_in()
        dest.sin_family = sa_family_t(AF_INET)
        dest.sin_port = in_port_t(53).bigEndian
        dest.sin_addr.s_addr = inet_addr("8.8.8.8")
        let conn = withUnsafePointer(to: &dest) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard conn == 0 else { return nil }
        var local = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let got = withUnsafeMutablePointer(to: &local) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        guard got == 0 else { return nil }
        let ip = String(cString: inet_ntoa(local.sin_addr))
        let iface = interfaces().first { $0.address == ip }?.name
        return (ip, iface)
    }

    // MARK: 系统代理设置（只读）
    struct ProxyInfo {
        var http: String? = nil
        var https: String? = nil
        var socks: String? = nil
        var pacURL: String? = nil
        var anyEnabled: Bool { http != nil || https != nil || socks != nil || pacURL != nil }
    }

    static func systemProxy() -> ProxyInfo {
        var info = ProxyInfo()
        guard let raw = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else { return info }
        func endpoint(_ enableKey: String, _ proxyKey: String, _ portKey: String) -> String? {
            guard let on = raw[enableKey] as? NSNumber, on.boolValue,
                  let host = raw[proxyKey] as? String else { return nil }
            if let port = raw[portKey] as? NSNumber { return "\(host):\(port.intValue)" }
            return host
        }
        // iOS 上 CFNetwork 的部分常量不可用，直接用字典的原始键名
        info.http = endpoint("HTTPEnable", "HTTPProxy", "HTTPPort")
        info.https = endpoint("HTTPSEnable", "HTTPSProxy", "HTTPSPort")
        info.socks = endpoint("SOCKSEnable", "SOCKSProxy", "SOCKSPort")
        if let pac = raw["ProxyAutoConfigURLString"] as? String, !pac.isEmpty {
            info.pacURL = pac
        }
        return info
    }

    // MARK: TCP 握手延迟（沙盒内无法发 ICMP，用 TCP connect 计时模拟 ping）
    static func tcpLatency(host: String, port: UInt16, timeoutSec: Double = 3.0) -> Double? {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        // 非阻塞 connect + select 等待可写
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let start = Date()
        let rc = connect(fd, first.pointee.ai_addr, first.pointee.ai_addrlen)
        if rc != 0 {
            guard errno == EINPROGRESS else { return nil }
            var writeSet = fd_set()
            fdZero(&writeSet)
            fdSet(fd, &writeSet)
            var tv = timeval(tv_sec: Int(timeoutSec), tv_usec: Int32((timeoutSec - Double(Int(timeoutSec))) * 1_000_000))
            let ready = select(fd + 1, nil, &writeSet, nil, &tv)
            guard ready > 0 else { return nil }
            var err: Int32 = 0
            var errLen = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errLen) == 0, err == 0 else { return nil }
        }
        return Date().timeIntervalSince(start) * 1000.0
    }

    // MARK: DNS 查询（向指定解析服务器发 A 记录查询并计时）
    static func dnsQuery(domain: String, resolver: String, timeoutSec: Int = 3) -> (ips: [String], ms: Double)? {
        // 组装查询报文
        var packet = Data()
        let id = UInt16.random(in: 0...UInt16.max)
        packet.append(UInt8(id >> 8)); packet.append(UInt8(id & 0xff))
        packet.append(contentsOf: [0x01, 0x00])             // RD
        packet.append(contentsOf: [0x00, 0x01])             // QDCOUNT 1
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in domain.split(separator: ".") {
            packet.append(UInt8(label.count))
            packet.append(contentsOf: [UInt8](label.utf8))
        }
        packet.append(0)
        packet.append(contentsOf: [0x00, 0x01, 0x00, 0x01]) // A / IN

        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var tv = timeval(tv_sec: timeoutSec, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var dest = sockaddr_in()
        dest.sin_family = sa_family_t(AF_INET)
        dest.sin_port = in_port_t(53).bigEndian
        dest.sin_addr.s_addr = inet_addr(resolver)
        let start = Date()
        let sent = packet.withUnsafeBytes { buf in
            withUnsafePointer(to: &dest) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, buf.baseAddress, packet.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == packet.count else { return nil }
        var buffer = [UInt8](repeating: 0, count: 2048)
        let n = recv(fd, &buffer, buffer.count, 0)
        let ms = Date().timeIntervalSince(start) * 1000.0
        guard n > 12 else { return nil }

        // 解析回答
        let anCount = Int(buffer[6]) << 8 | Int(buffer[7])
        var offset = 12
        // 跳过问题部分
        while offset < n, buffer[offset] != 0 { offset += Int(buffer[offset]) + 1 }
        offset += 5 // 0 结尾 + QTYPE + QCLASS
        var ips: [String] = []
        for _ in 0..<anCount {
            guard offset + 12 <= n else { break }
            if buffer[offset] & 0xC0 == 0xC0 { offset += 2 } else {
                while offset < n, buffer[offset] != 0 { offset += Int(buffer[offset]) + 1 }
                offset += 1
            }
            guard offset + 10 <= n else { break }
            let type = Int(buffer[offset]) << 8 | Int(buffer[offset + 1])
            let rdLen = Int(buffer[offset + 8]) << 8 | Int(buffer[offset + 9])
            offset += 10
            if type == 1, rdLen == 4, offset + 4 <= n {
                ips.append("\(buffer[offset]).\(buffer[offset + 1]).\(buffer[offset + 2]).\(buffer[offset + 3])")
            }
            offset += rdLen
        }
        return (ips, ms)
    }
}

// fd_set 辅助（Swift 里没有现成的宏）
private func fdZero(_ set: inout fd_set) {
    set = fd_set()
}
private func fdSet(_ fd: Int32, _ set: inout fd_set) {
    let intOffset = Int(fd / 32)
    let bitOffset = Int(fd % 32)
    withUnsafeMutablePointer(to: &set) { ptr in
        let intPtr = UnsafeMutablePointer<Int32>(OpaquePointer(ptr))
        intPtr[intOffset] |= Int32(1) << Int32(bitOffset)
    }
}

// MARK: - 诊断日志

final class LogStore: ObservableObject {
    @Published var entries: [String] = []
    private let key = "netpanel.log.entries"

    init() {
        entries = UserDefaults.standard.stringArray(forKey: key) ?? []
        if entries.isEmpty { log("面板启动") }
    }

    func log(_ message: String) {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        entries.append("[\(f.string(from: Date()))] \(message)")
        if entries.count > 500 { entries.removeFirst(entries.count - 500) }
        UserDefaults.standard.set(entries, forKey: key)
    }

    func clear() {
        entries.removeAll()
        UserDefaults.standard.removeObject(forKey: key)
    }

    var exportText: String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return "网络诊断日志（\(f.string(from: Date()))）\n\n" + entries.joined(separator: "\n")
    }
}

// MARK: - 分流预设（仅切换本面板的检测目标，不动系统设置）

struct DiagTarget: Identifiable {
    var id: String { host }
    let label: String
    let host: String
    let port: UInt16
}

struct DiagPreset: Identifiable {
    let id: String
    let name: String
    let desc: String
    let resolver: String
    let dnsDomain: String
    let targets: [DiagTarget]

    static let all: [DiagPreset] = [
        DiagPreset(id: "direct", name: "直连诊断", desc: "国内目标 + 阿里 DNS，判断本地网络质量",
                   resolver: "223.5.5.5", dnsDomain: "www.baidu.com",
                   targets: [
                       DiagTarget(label: "百度", host: "www.baidu.com", port: 443),
                       DiagTarget(label: "腾讯", host: "www.qq.com", port: 443),
                       DiagTarget(label: "阿里 DNS", host: "223.5.5.5", port: 443)
                   ]),
        DiagPreset(id: "tunnel", name: "隧道诊断", desc: "海外目标 + Cloudflare DNS，重点看隧道接口与路径",
                   resolver: "1.1.1.1", dnsDomain: "www.apple.com",
                   targets: [
                       DiagTarget(label: "Apple", host: "www.apple.com", port: 443),
                       DiagTarget(label: "Google", host: "www.google.com", port: 443),
                       DiagTarget(label: "Cloudflare", host: "1.1.1.1", port: 443)
                   ]),
        DiagPreset(id: "full", name: "全面体检", desc: "国内外目标全测 + 谷歌 DNS",
                   resolver: "8.8.8.8", dnsDomain: "www.apple.com",
                   targets: [
                       DiagTarget(label: "百度", host: "www.baidu.com", port: 443),
                       DiagTarget(label: "腾讯", host: "www.qq.com", port: 443),
                       DiagTarget(label: "Apple", host: "www.apple.com", port: 443),
                       DiagTarget(label: "Google", host: "www.google.com", port: 443),
                       DiagTarget(label: "Cloudflare", host: "1.1.1.1", port: 443)
                   ])
    ]
}

final class PanelState: ObservableObject {
    @Published var preset: DiagPreset = DiagPreset.all[0] {
        didSet { UserDefaults.standard.set(preset.id, forKey: "netpanel.preset") }
    }
    init() {
        if let saved = UserDefaults.standard.string(forKey: "netpanel.preset"),
           let found = DiagPreset.all.first(where: { $0.id == saved }) {
            preset = found
        }
    }
}
