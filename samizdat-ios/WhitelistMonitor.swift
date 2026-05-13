import Foundation

/// IPA-D28: WhitelistMonitor — runs in the MAIN APP while the VPN is
/// disconnected so the App Group `WhitelistStatusStore.activeEndpoint`
/// is already populated by the time the user taps Connect. Picks up
/// where the extension's `WhitelistDetector` left off; goes silent
/// once the extension is running (the extension owns the verdict).
///
/// Operator: "мониторинг белых списков должен быть даже тогда когда
/// впн не подключен. выбран соответствующий режим чтобы сразу
/// подключиться к нужному впн конфигу".
///
/// Probes are TCP-connect to port 443 against the same two hosts the
/// extension's ICMP detector uses (`WhitelistProbePreferences.testHost`
/// and `.whitelistHost`). TCP-connect is the universal fallback the
/// extension uses too (D25), and ICMP from a sandboxed iOS app is
/// fiddlier — TCP is enough to answer "is the network whitelist-mode
/// or free?".
///
/// Lifecycle: ContentView starts the monitor when:
///   - bridge.state == .disconnected
///   - EndpointModeStore.current == .auto
///   - the view is visible (foreground)
/// and stops it on .onDisappear, on bridge.connecting/connected (the
/// extension takes over), or when the user flips auto-mode off.
@MainActor
final class WhitelistMonitor: ObservableObject {

    // IPA-D30: 5s → 3s cycle for near-instant whitelist detection.
    // 2s ICMP timeout (was 3s TCP). Monitor only runs when VPN is off
    // AND main app is foregrounded, so battery cost of bumped cadence
    // is bounded (user can only stare at the app for so long before
    // backgrounding).
    private static let probeTimeout: TimeInterval = 2
    private static let cycleInterval: TimeInterval = 3
    private static let firstCycleDelay: TimeInterval = 0

    private var task: Task<Void, Never>?
    private var pingers: [ICMPPinger] = []

    /// Begin monitoring. Idempotent; no-op if already running.
    func start() {
        guard task == nil else { return }
        task = Task { [weak self] in
            // First cycle after a short delay so we don't pile work
            // onto the same tick the view appears on.
            try? await Task.sleep(for: .seconds(Self.firstCycleDelay))
            while !Task.isCancelled {
                await self?.runCycle()
                try? await Task.sleep(for: .seconds(Self.cycleInterval))
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
        for p in pingers { p.cancel() }
        pingers.removeAll()
    }

    private func runCycle() async {
        // Only do anything if auto mode is still on. If the user
        // flipped manual while the loop was sleeping, exit quietly.
        guard EndpointModeStore.current == .auto else {
            WhitelistStatusStore.current = .unknown
            return
        }
        let testHost = WhitelistProbePreferences.testHost
        let whitelistHost = WhitelistProbePreferences.whitelistHost

        async let testOK = probeHost(testHost)
        async let whitelistOK = probeHost(whitelistHost)
        let (t, w) = await (testOK, whitelistOK)

        // Same decision matrix as extension's WhitelistDetector. We
        // write `current` and `activeEndpoint` so the extension's
        // startTunnel picks the right blob immediately on next connect.
        switch (t, w) {
        case (true, true):
            WhitelistStatusStore.current = .off
            WhitelistStatusStore.activeEndpoint = .primary
        case (false, true):
            WhitelistStatusStore.current = .detected
            WhitelistStatusStore.activeEndpoint = .backup
        case (true, false):
            // Likely misconfigured whitelist host (or transient blip
            // on Yandex). Keep current activeEndpoint; mark status.
            WhitelistStatusStore.current = .unknown
        case (false, false):
            // Both unreachable — phone has no internet at all (lift,
            // metro, plane). Mark as such; don't switch endpoint.
            WhitelistStatusStore.current = .noNetwork
        }
    }

    /// TCP-connect probe to `host:443`. Returns true on `.ready` within
    /// `probeTimeout`. The connection is canceled as soon as it
    /// resolves either way.
    /// IPA-D30: real ICMP echo via the shared ICMPPinger (was TCP-connect
    /// to port 443). TCP probes were too permissive — on operator's LTE,
    /// the carrier dropped ICMP to 8.8.8.8 but TCP-to-443 worked anyway,
    /// so the detector falsely reported "Free internet" while native ping
    /// tool was showing 100% packet loss to 8.8.8.8.
    ///
    /// We're in main app process (VPN off, no utun present), so we don't
    /// need IP_BOUND_IF — kernel routes via the system default route
    /// (wifi/cellular).
    private func probeHost(_ host: String) async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            let target: ICMPPinger.Target
            // Detect IP-literal vs hostname. Same simple shape check
            // we use elsewhere — strictly enough for IPv4 dotted-quad
            // or anything with ':' (IPv6).
            if Self.looksLikeIPLiteral(host) {
                target = .ip(host)
            } else {
                target = .hostname(host)
            }
            let pinger = ICMPPinger(target: target, interfaceIndex: nil)
            pingers.append(pinger)
            pinger.ping(timeout: Self.probeTimeout) { ok, _ in
                cont.resume(returning: ok)
            }
        }
    }

    private static func looksLikeIPLiteral(_ s: String) -> Bool {
        if s.contains(":") { return true }   // IPv6
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { UInt($0).map { $0 <= 255 } ?? false }
    }
}
