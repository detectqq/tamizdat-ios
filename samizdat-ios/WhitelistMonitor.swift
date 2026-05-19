import Foundation
import Network

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
    // D45: cadence now user-configurable via WhitelistProbePreferences.
    private static let probeTimeout: TimeInterval = 2
    private static let httpTimeout: TimeInterval = 3
    private static var cycleInterval: TimeInterval {
        TimeInterval(WhitelistProbePreferences.probeInterval)
    }
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
        var (t, w) = await (testOK, whitelistOK)

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
            // D65: Both ICMP unreachable — ICMPPinger may not work from
            // the app sandbox on some devices (observed on iPhone 16 Pro
            // Max). Fall back to HTTP: URLSession HEAD requests go through
            // carrier DPI. Under TSPU whitelist, DPI inspects HTTP data
            // and blocks non-whitelisted destinations — unlike raw TCP
            // handshake which passes through (D63). HTTP results feed into
            // the FULL decision matrix, not just "network alive?" check.
            async let httpTestOK = httpProbe(host: testHost)
            async let httpWhitelistOK = httpProbe(host: whitelistHost)
            let (httpT, httpW) = await (httpTestOK, httpWhitelistOK)
            switch (httpT, httpW) {
            case (true, true):
                WhitelistStatusStore.current = .off
                WhitelistStatusStore.activeEndpoint = .primary
            case (false, true):
                WhitelistStatusStore.current = .detected
                WhitelistStatusStore.activeEndpoint = .backup
            case (true, false):
                WhitelistStatusStore.current = .unknown
            case (false, false):
                // Both HTTP also failed. TCP fallback ONLY to distinguish
                // "no network" from "hosts don't serve HTTP on port 80".
                async let tcpTestOK = tcpProbe(host: testHost)
                async let tcpWhitelistOK = tcpProbe(host: whitelistHost)
                let (tcpT, tcpW) = await (tcpTestOK, tcpWhitelistOK)
                if !tcpT && !tcpW {
                    WhitelistStatusStore.current = .noNetwork
                }
                // else: network alive but both ICMP + HTTP failed.
                // Keep current status + endpoint unchanged.
            }
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

    /// D59: TCP-connect fallback probe to `host:443`. Returns true if
    /// the TCP handshake completes within `probeTimeout`. Used when ICMP
    /// fails — many networks block ICMP but allow TCP 443.
    private func tcpProbe(host: String) async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            let params: NWParameters = .tcp
            // Pin to IPv4 — matches the extension's fallback behaviour.
            if let ipOpts = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
                ipOpts.version = .v4
            }
            // Serial queue so stateUpdateHandler + timeout never race
            // on the `settled` flag (avoids double-resume crash).
            let probeQ = DispatchQueue(label: "com.anarki.samizdat.monitor.tcp-probe")
            let conn = NWConnection(host: NWEndpoint.Host(host), port: 443, using: params)
            var settled = false
            let settle: (Bool) -> Void = { ok in
                guard !settled else { return }
                settled = true
                conn.cancel()
                cont.resume(returning: ok)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:      settle(true)
                case .failed:     settle(false)
                case .cancelled:  settle(false)
                default:          break
                }
            }
            conn.start(queue: probeQ)
            // Timeout — same budget as ICMP probe.
            probeQ.asyncAfter(deadline: .now() + Self.probeTimeout) {
                settle(false)
            }
        }
    }

    /// D65: HTTP HEAD fallback probe to `http://<host>/`. URLSession
    /// requests go through carrier DPI — under TSPU whitelist mode, DPI
    /// inspects HTTP data and blocks non-whitelisted destinations. Unlike
    /// a raw TCP handshake (which passes through DPI because it doesn't
    /// carry inspectable payload), HTTP sends an actual request that DPI
    /// can filter.
    ///
    /// Returns true if any HTTP response is received within `httpTimeout`.
    /// Redirect-following is disabled — the first response (even 3xx)
    /// confirms the host is reachable through DPI.
    private func httpProbe(host: String) async -> Bool {
        // IPv6 addresses need brackets in URLs.
        let urlHost = host.contains(":") ? "[\(host)]" : host
        guard let url = URL(string: "http://\(urlHost)/") else { return false }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = Self.httpTimeout
        config.timeoutIntervalForResource = Self.httpTimeout + 1
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        // Don't follow redirects — the first response is enough to
        // confirm the host is reachable through DPI. Redirect targets
        // might live on different (blocked) domains.
        let delegate = WhitelistHTTPProbeDelegate()
        let session = URLSession(configuration: config,
                                 delegate: delegate,
                                 delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        request.timeoutInterval = Self.httpTimeout

        do {
            let (_, _) = try await session.data(for: request)
            return true
        } catch {
            return false
        }
    }

    private static func looksLikeIPLiteral(_ s: String) -> Bool {
        if s.contains(":") { return true }   // IPv6
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { UInt($0).map { $0 <= 255 } ?? false }
    }
}

/// Stops URLSession from following HTTP redirects. Used by
/// `WhitelistMonitor.httpProbe` so we detect reachability from the
/// FIRST HTTP response — the redirect target might be on a different
/// (blocked) domain.
private final class WhitelistHTTPProbeDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession,
                    task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
