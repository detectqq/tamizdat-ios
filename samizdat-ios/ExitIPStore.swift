import Foundation

/// IPA-D24/D25: probes "what is my public IP" every 60s via plain
/// URLSession.shared so iOS routes through the system default route.
/// When the tunnel is up, URLSession sees the tunnel → exit IP from
/// our proxy server. When off, it goes through physical Wi-Fi /
/// cellular → real ISP IP.
///
/// Surfaces below the Ping chip on the Home screen as
/// `Exit · 38.135.53.241` (tunnel up) or `Network · 88.45.123.55`
/// (tunnel off). Quiet failure: if all probes fail the line just
/// doesn't render.
///
/// IPA-D25 fix2: NWConnection-based hand-rolled HTTPS was over-
/// engineering and silently failed on some networks (operator saw
/// nothing rendered at all). Reverted to plain URLSession.shared.
/// IPv6-prevention is now done at the RESPONSE-validation layer:
/// strict IPv4 regex rejects anything containing ':'. Combined with
/// v4-only probe hostnames (`ipv4.icanhazip.com` has no AAAA record;
/// URLSession is forced to v4) the chip never shows IPv6.
@MainActor
final class ExitIPStore: ObservableObject {
    @Published private(set) var ip: String?
    @Published private(set) var isFromTunnel: Bool = false

    private var task: Task<Void, Never>?
    private static let refreshInterval: TimeInterval = 60

    /// Order matters — `ipv4.icanhazip.com` first because it's the
    /// strictest v4-only (no AAAA record at all, so URLSession is
    /// forced into the v4 stack at DNS time). Others are belt+suspender.
    private static let probeURLs = [
        "https://ipv4.icanhazip.com",
        "https://api4.ipify.org",
        "https://ipv4.ifconfig.me/ip",
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
        // IPA-D25 fix4: per-fetch ephemeral URLSession.
        //
        // URLSession.shared keeps a long-lived TCP connection pool. When
        // the user toggles VPN, iOS does NOT invalidate already-open
        // sockets — they keep using the physical interface they were
        // opened on. Result: bridge.state flips to .connected, ping
        // prober (extension/Go side, dials via samizdat.Client) reports
        // success through tunnel, but URLSession.shared reuses an old
        // socket from BEFORE connect → ExitIP probe goes through
        // physical Wi-Fi → returns LTE/router IP for many minutes.
        //
        // Operator: "пару минут висел с роутерным/lte айпи, показывал
        // пинг, показывал коннектед". Ephemeral config + invalidate
        // after each fetch forces a fresh socket every probe, so the
        // socket honors whatever the system default route is RIGHT NOW.
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 5
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpShouldUsePipelining = false
        config.httpMaximumConnectionsPerHost = 1
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }

        for urlStr in Self.probeURLs {
            guard let url = URL(string: urlStr) else { continue }
            var req = URLRequest(url: url, timeoutInterval: 5)
            req.httpMethod = "GET"
            req.cachePolicy = .reloadIgnoringLocalCacheData
            req.setValue("tamizdat-ios/exitip", forHTTPHeaderField: "User-Agent")
            req.setValue("close", forHTTPHeaderField: "Connection")
            do {
                let (data, resp) = try await session.data(for: req)
                guard let http = resp as? HTTPURLResponse,
                      http.statusCode == 200 else { continue }
                let text = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if let text, Self.isStrictIPv4(text) {
                    self.ip = text
                    self.isFromTunnel = viaTunnel
                    return
                }
                // Got a response but it wasn't IPv4 — could be IPv6 (if
                // iOS somehow reached a probe via v6 stack) OR HTML
                // error page. Try the next probe.
            } catch {
                continue
            }
        }
        // All probes failed — leave the previously-known IP so the
        // surface doesn't flicker between updates.
    }

    /// Strict IPv4: exactly four dotted decimal octets each 0-255.
    /// Reject anything with ':' (IPv6) unconditionally.
    private static func isStrictIPv4(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 15 else { return false }
        if s.contains(":") { return false }
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return false }
        for p in parts {
            guard let n = UInt(p), n <= 255 else { return false }
        }
        return true
    }
}
