import Foundation

/// IPA-D24: probes "what is my public IP" every 60s via plain
/// URLSession.shared so iOS routes through the system default route.
/// When the tunnel is up, URLSession sees the tunnel → exit IP from
/// our proxy server. When off, it goes through physical Wi-Fi /
/// cellular → real ISP IP.
///
/// Surfaces below the Ping chip on the Home screen as
/// `Exit · 38.135.53.241` (tunnel up) or `Network · 88.45.123.55`
/// (tunnel off). Quiet failure: if all 3 probes fail the line just
/// doesn't render.
@MainActor
final class ExitIPStore: ObservableObject {
    @Published private(set) var ip: String?
    @Published private(set) var isFromTunnel: Bool = false

    private var task: Task<Void, Never>?
    private static let refreshInterval: TimeInterval = 60
    // IPA-D24 fix: IPv4-only subdomains so the chip never overflows
    // with a long IPv6 address. iOS prefers IPv6 by default when the
    // network has it (most modern Wi-Fi), which made the displayed IP
    // unreadable. ipify/icanhazip/ifconfig.me all provide v4-only
    // forks at these hostnames.
    private static let probeURLs = [
        "https://api4.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://ipv4.ifconfig.me/ip"
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
        for urlStr in Self.probeURLs {
            guard let url = URL(string: urlStr) else { continue }
            var req = URLRequest(url: url, timeoutInterval: 5)
            req.httpMethod = "GET"
            req.cachePolicy = .reloadIgnoringLocalCacheData
            do {
                let (data, resp) = try await URLSession.shared.data(for: req)
                guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else { continue }
                let text = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if let text, isValidIP(text) {
                    self.ip = text
                    self.isFromTunnel = viaTunnel
                    return
                }
            } catch {
                continue  // try next URL
            }
        }
        // All probes failed — leave previously-known IP if any so the
        // surface doesn't flicker.
    }

    private func isValidIP(_ s: String) -> Bool {
        // Quick sanity check — IPv4 or IPv6 shape, length cap.
        guard !s.isEmpty, s.count <= 45 else { return false }
        // Reject if there's a space, newline or HTML tag
        if s.contains(" ") || s.contains("<") || s.contains("\n") { return false }
        return s.contains(".") || s.contains(":")
    }
}
