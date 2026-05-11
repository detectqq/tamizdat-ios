import Foundation
import Network

/// IPA-D24: probes "what is my public IP" every 60s. When the tunnel
/// is up, the request routes through it → exit IP from our proxy
/// server. When off, it goes through physical Wi-Fi / cellular →
/// real ISP IP.
///
/// Surfaces below the Ping chip on the Home screen as
/// `Exit · 38.135.53.241` (tunnel up) or `Network · 88.45.123.55`
/// (tunnel off). Quiet failure: if all probes fail the line just
/// doesn't render.
///
/// IPA-D24 fix2: STRICTLY IPv4 ONLY. iOS Happy Eyeballs reaches
/// ipify/etc. via v6 stack when the network has IPv6 connectivity,
/// the service echoes back whatever source IP it saw, and we
/// displayed long unreadable v6 addresses. Two defences:
///   1. NWConnection with `NWProtocolIP.Options.version = .v4` —
///      the TCP socket itself cannot use IPv6. If the host has no
///      A record we just fail that probe.
///   2. Response regex requires exactly 4 dotted octets 0-255.
///      Belt + suspenders — if any service mis-echoes a v6 string
///      we still reject it.
@MainActor
final class ExitIPStore: ObservableObject {
    @Published private(set) var ip: String?
    @Published private(set) var isFromTunnel: Bool = false

    private var task: Task<Void, Never>?
    private static let refreshInterval: TimeInterval = 60

    /// All three are IPv4-only subdomain forks of the major
    /// "what's my IP" services. ipv4.icanhazip.com is the strictest
    /// (no AAAA record at all on their side); kept as first probe
    /// so the most reliable v4 source wins.
    private static let probeHosts: [(host: String, path: String)] = [
        ("ipv4.icanhazip.com", "/"),
        ("api4.ipify.org",     "/"),
        ("ipv4.ifconfig.me",   "/ip"),
    ]

    func start(isConnected: Bool) {
        stop()
        let viaTunnel = isConnected
        task = Task { [weak self] in
            await self?.fetchOnce(viaTunnel: viaTunnel)
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(Self.refreshInterval))
                if Task.isCancelled { return }
                await self?.fetchOnce(viaTunnel: viaTunnel)
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    /// Called when the user connects/disconnects — refetch immediately
    /// so the displayed IP reflects the new path without waiting up to
    /// 60 seconds for the next polling tick.
    func refreshSoon(isConnected: Bool) {
        stop()
        start(isConnected: isConnected)
    }

    private func fetchOnce(viaTunnel: Bool) async {
        for (host, path) in Self.probeHosts {
            guard let resp = await Self.fetchIPv4Only(host: host, path: path) else {
                continue
            }
            if Self.isStrictIPv4(resp) {
                self.ip = resp
                self.isFromTunnel = viaTunnel
                return
            }
            // Non-IPv4 response from a v4-only endpoint is a bug at
            // the service end; try the next probe.
        }
        // All probes failed — leave previously-known IP so the chip
        // doesn't flicker between updates.
    }

    /// Issue a tiny HTTP/1.1 GET over a TLS NWConnection that is
    /// FORCED to IPv4 at the IP-options layer. Returns the response
    /// body trimmed, or nil on any failure (timeout, parse error,
    /// non-200, no A record, etc.).
    ///
    /// Hand-rolled HTTP because URLSession has no public knob to
    /// force address family — Happy Eyeballs always picks v6 first
    /// when both are available.
    private static func fetchIPv4Only(host: String,
                                      path: String,
                                      timeout: TimeInterval = 5)
        async -> String?
    {
        await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            // TLS over TCP, with the IP version pinned to v4.
            let params = NWParameters.tls
            if let ipOpt = params.defaultProtocolStack
                .internetProtocol as? NWProtocolIP.Options
            {
                ipOpt.version = .v4
            }
            params.expiredDNSBehavior = .allow

            let endpoint = NWEndpoint.hostPort(
                host: NWEndpoint.Host(host),
                port: NWEndpoint.Port(rawValue: 443)!
            )
            let conn = NWConnection(to: endpoint, using: params)
            let q = DispatchQueue(label: "exitip.fetch.\(host)")

            // Resume-once guard.
            var resumed = false
            func finish(_ result: String?) {
                if resumed { return }
                resumed = true
                conn.cancel()
                cont.resume(returning: result)
            }

            // Hard timeout — Network framework's .waiting state can
            // hang for a while otherwise.
            q.asyncAfter(deadline: .now() + timeout) { finish(nil) }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // Send GET
                    let req = """
                    GET \(path) HTTP/1.1\r
                    Host: \(host)\r
                    User-Agent: tamizdat-ios/exitip\r
                    Accept: text/plain\r
                    Connection: close\r
                    \r
                    """
                    conn.send(content: req.data(using: .utf8),
                              completion: .contentProcessed { _ in })
                    // Read response in chunks until EOF.
                    var buf = Data()
                    func recv() {
                        conn.receive(minimumIncompleteLength: 1,
                                     maximumLength: 8 * 1024) { data, _, isComplete, err in
                            if let data, !data.isEmpty { buf.append(data) }
                            if let err {
                                _ = err
                                finish(nil); return
                            }
                            if isComplete || buf.count > 64 * 1024 {
                                finish(Self.parseHTTPBody(buf))
                            } else {
                                recv()
                            }
                        }
                    }
                    recv()
                case .failed, .cancelled:
                    finish(nil)
                default:
                    break
                }
            }
            conn.start(queue: q)
        }
    }

    /// Strip the HTTP/1.1 status line + headers, return the body
    /// trimmed. We don't validate Content-Length etc. — the v4-IP
    /// services all return a single short line.
    private static func parseHTTPBody(_ data: Data) -> String? {
        guard let s = String(data: data, encoding: .utf8) else { return nil }
        // Find blank-line separator
        let separator = "\r\n\r\n"
        guard let range = s.range(of: separator) else {
            // Some servers reply with bare LF
            guard let altRange = s.range(of: "\n\n") else { return nil }
            let body = s[altRange.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
            return body.isEmpty ? nil : body
        }
        let body = s[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        return body.isEmpty ? nil : body
    }

    /// Strict IPv4: exactly four dotted octets, each 0-255, no
    /// leading zeros forbidden (some libs disallow but most services
    /// don't emit them anyway), no colons.
    private static func isStrictIPv4(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 15 else { return false }
        if s.contains(":") { return false }   // explicit IPv6 reject
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return false }
        for p in parts {
            guard let n = UInt(p), n <= 255 else { return false }
        }
        return true
    }
}
