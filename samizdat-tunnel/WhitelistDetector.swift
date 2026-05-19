import Foundation
import Network
import UserNotifications

/// IPA-D23: ICMP-based whitelist detector (rewrite of the IPA-Q TCP
/// cascade). Mirrors the operator's prod-proven 2-target design.
///
/// Each cycle:
///   - Ping `testHost`      (default 8.8.8.8) — should answer under free
///                                              internet
///   - Ping `whitelistHost` (default 77.88.8.8) — should answer even
///                                                under TSPU whitelist mode
///   Both pings fire in parallel, each with a 3 s timeout.
///
/// Outcome decision matrix:
///   testOK  + whitelistOK   → .clearAll              ENDPOINT = primary
///   testFail + whitelistOK  → .whitelistOn           ENDPOINT = backup
///   testOK  + whitelistFail → .whitelistMisconfigured (log warn, keep current)
///   testFail + whitelistFail → .noNetwork            pause, no switch
///
/// Preserved from the old IPA-Q implementation:
///   - hold-down between actual endpoint switches (anti-flap)
///   - WhitelistStatus writes to App Group for the main-app status badge
///   - notePathChange(satisfied:) pauses on NWPath unsatisfied
///   - Low-Power-Mode stretches cadence ×3
///   - applyConfig() rebuilds targets after the user edits prefs
///
/// Dropped from IPA-Q:
///   - 4-canary TCP cascade — replaced with 2 ICMP targets
///   - "frozen" captive-portal heuristic — operator's simpler design
///     surfaces the weird case as `.whitelistMisconfigured` instead
final class WhitelistDetector {

    // Tunables (kept compatible with IPA-Q timings so battery profile
    // is unchanged for users running auto-mode).
    // IPA-D28 fix: 30s → 5s for near-instant detection. Detector runs
    // inside the extension only when VPN is up, so battery is bounded
    // by tunnel-active time. Hold-down (60s) still prevents endpoint
    // thrashing on flapping networks.
    private static let probeTimeout: TimeInterval = 3
    private static let holdDownSeconds: TimeInterval = 60

    /// Read user-configured cadence; double it when on backup.
    private static var normalCadence: TimeInterval {
        TimeInterval(WhitelistProbePreferences.probeInterval)
    }
    private static var onBackupCadence: TimeInterval {
        TimeInterval(WhitelistProbePreferences.probeInterval) * 2
    }
    private static var failbackSuccessesNeeded: Int {
        WhitelistProbePreferences.successesNeeded
    }

    // Hooks injected by PacketTunnelProvider.
    private let log: (String) -> Void
    private let switchEndpoint: (EndpointMode) -> Void
    private let pathProvider: () -> Network.NWPath?

    private let queue = DispatchQueue(label: "com.anarki.samizdat-test.detector", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var activePingers: [ICMPPinger] = []
    // IPA-D25: TCP-fallback connections held during in-flight probe
    // so we can cancel them on stop().
    private var activeTCPConns: [NWConnection] = []
    private static let tcpFallbackTimeout: TimeInterval = 3

    // Targets (re-read on applyConfig). Stored on the detector's queue.
    private var testHost: String = WhitelistProbePreferences.defaultTestHost
    private var whitelistHost: String = WhitelistProbePreferences.defaultWhitelistHost

    // State.
    private var lastSwitchedAt = Date.distantPast
    private var failbackSuccesses = 0
    private var isPathSatisfied = true
    private var stopped = false

    init(log: @escaping (String) -> Void,
         switchEndpoint: @escaping (EndpointMode) -> Void,
         pathProvider: @escaping () -> Network.NWPath?) {
        self.log = log
        self.switchEndpoint = switchEndpoint
        self.pathProvider = pathProvider
    }

    func start() {
        queue.async { [weak self] in
            guard let self else { return }
            self.stopped = false
            self.applyConfigLocked()
            self.scheduleNextProbe(after: 2)
            self.log("info: WhitelistDetector(ICMP) started — testHost=\(self.testHost) whitelistHost=\(self.whitelistHost)")
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.stopped = true
            self.timer?.cancel(); self.timer = nil
            for p in self.activePingers { p.cancel() }
            self.activePingers.removeAll()
            for c in self.activeTCPConns { c.cancel() }
            self.activeTCPConns.removeAll()
            // D59 FIX: do NOT reset WhitelistStatusStore.current here.
            // The last-known detection result should persist so the UI
            // keeps showing "Whitelist active" / "Free internet" across
            // VPN connect/disconnect cycles. The main-app WhitelistMonitor
            // picks up when the extension stops; the 200s stale-check in
            // ContentView.refreshWhitelistStatus() handles truly stale data.
            self.log("info: WhitelistDetector stopped (status preserved)")
        }
    }

    /// Re-reads the user-configured target hosts from App Group
    /// UserDefaults and adopts them for the next cycle. Called by
    /// PacketTunnelProvider on the "refreshWhitelistProbes" provider
    /// message.
    func applyConfig() {
        queue.async { [weak self] in
            self?.applyConfigLocked()
        }
    }

    private func applyConfigLocked() {
        let t = WhitelistProbePreferences.testHost
        let w = WhitelistProbePreferences.whitelistHost
        if t != testHost || w != whitelistHost {
            log("info: detector targets updated: testHost=\(t) whitelistHost=\(w)")
            testHost = t
            whitelistHost = w
        }
    }

    /// Notify the detector that NWPath status flipped. Resets per-cycle
    /// state so we don't carry stale failure counts across a reconnect.
    func notePathChange(satisfied: Bool) {
        queue.async { [weak self] in
            guard let self else { return }
            let was = self.isPathSatisfied
            self.isPathSatisfied = satisfied
            if was != satisfied {
                self.failbackSuccesses = 0
                if !satisfied {
                    WhitelistStatusStore.current = .noNetwork
                    self.log("info: detector paused (path unsatisfied)")
                } else {
                    // IPA-D25 BUG FIX: when path recovers, transition
                    // status to `.unknown` ("Monitoring…") so the UI
                    // doesn't stay stuck on stale "Paused — no network"
                    // for the 30 s until the next probe cycle completes.
                    //
                    // Root cause we hit on D24: NEPacketTunnelProvider
                    // sees a brief NWPath.unsatisfied window while the
                    // tunnel routes are being plumbed at startTunnel
                    // (this writes .noNetwork), then immediately a
                    // .satisfied event when settings install completes.
                    // The recovery branch used to ONLY log and not reset
                    // the store → UI stayed on noNetwork for ~30 s while
                    // tunnel was already fully functional.
                    WhitelistStatusStore.current = .unknown
                    self.log("info: detector resumed (path satisfied)")
                }
            }
        }
    }

    // MARK: – cycle

    private func scheduleNextProbe(after delay: TimeInterval) {
        timer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + delay)
        t.setEventHandler { [weak self] in
            self?.runCycle()
        }
        t.resume()
        timer = t
    }

    private func runCycle() {
        guard !stopped else { return }

        guard EndpointModeStore.current == .auto else {
            log("info: detector cycle skip (mode=\(EndpointModeStore.current.rawValue))")
            scheduleNextProbe(after: Self.normalCadence)
            return
        }
        if !isPathSatisfied {
            log("info: detector cycle skip (path unsatisfied)")
            scheduleNextProbe(after: Self.normalCadence)
            return
        }
        log("info: detector cycle start (testHost=\(testHost) whitelistHost=\(whitelistHost))")

        let onBackup = (WhitelistStatusStore.activeEndpoint == .backup)
        let baseCadence = onBackup ? Self.onBackupCadence : Self.normalCadence
        let cadence = ProcessInfo.processInfo.isLowPowerModeEnabled ? baseCadence * 3 : baseCadence

        parallelProbe { [weak self] testOK, whitelistOK in
            guard let self else { return }
            // D63 FIX: when BOTH ICMP probes fail, TCP fallback only
            // determines "network alive vs truly offline". TCP 443
            // passes through TSPU even under whitelist (carrier blocks
            // ICMP but allows TCP), so feeding TCP into the full
            // decision matrix caused false .clearAll on devices where
            // ICMP was flaky to both hosts. Now: if TCP confirms
            // network is alive, keep the current status/endpoint
            // unchanged; only declare .noNetwork if TCP also fails.
            if !testOK && !whitelistOK {
                // D65: HTTP fallback first — goes through DPI, can
                // differentiate whitelist from free (unlike TCP which
                // just checks handshake). Falls to TCP only if HTTP
                // also fails for both hosts.
                self.httpFallbackProbe { [weak self] httpTestOK, httpWhitelistOK in
                    guard let self else { return }
                    switch (httpTestOK, httpWhitelistOK) {
                    case (true, true):
                        self.handleOutcome(.clearAll)
                        self.scheduleNextProbe(after: cadence)
                    case (false, true):
                        self.handleOutcome(.whitelistOn)
                        self.scheduleNextProbe(after: cadence)
                    case (true, false):
                        self.handleOutcome(.whitelistMisconfigured)
                        self.scheduleNextProbe(after: cadence)
                    case (false, false):
                        // Both HTTP also failed. TCP only for
                        // "no network" vs "hosts don't serve HTTP".
                        self.tcpFallbackProbe { [weak self] tcpTestOK, tcpWhitelistOK in
                            guard let self else { return }
                            if !tcpTestOK && !tcpWhitelistOK {
                                self.handleOutcome(.noNetwork)
                            } else {
                                self.log("info: detector: ICMP+HTTP failed but TCP alive — keeping current verdict")
                            }
                            self.scheduleNextProbe(after: cadence)
                        }
                    }
                }
                return
            }
            let outcome: Outcome
            switch (testOK, whitelistOK) {
            case (true,  true):  outcome = .clearAll
            case (false, true):  outcome = .whitelistOn
            case (true,  false): outcome = .whitelistMisconfigured
            case (false, false): outcome = .noNetwork // unreachable; guarded above
            }
            self.handleOutcome(outcome)
            self.scheduleNextProbe(after: cadence)
        }
    }

    private enum Outcome: String {
        case clearAll
        case whitelistOn
        case whitelistMisconfigured
        case noNetwork
    }

    /// Pings both targets in parallel, calls completion with their
    /// outcomes once both have settled. Completion delivered on `queue`.
    private func parallelProbe(completion: @escaping (_ testOK: Bool, _ whitelistOK: Bool) -> Void) {
        // Snapshot interface index for both probes.
        let ifindex = pickPhysicalInterfaceIndex()
        if ifindex == nil {
            log("warn: detector probe — no physical interface available, pings will likely fail")
        }
        let pingerTest = ICMPPinger(target: parseTarget(testHost),
                                    interfaceIndex: ifindex)
        let pingerWhitelist = ICMPPinger(target: parseTarget(whitelistHost),
                                         interfaceIndex: ifindex)
        activePingers = [pingerTest, pingerWhitelist]

        var testRes: Bool?
        var whitelistRes: Bool?
        let group = DispatchGroup()
        group.enter()
        group.enter()

        pingerTest.ping(timeout: Self.probeTimeout) { [weak self] ok, rtt in
            self?.queue.async {
                self?.log("info: detector ping testHost=\(self?.testHost ?? "?") → \(ok ? "ok" : "fail") in \(Int(rtt*1000))ms")
                testRes = ok
                group.leave()
            }
        }
        pingerWhitelist.ping(timeout: Self.probeTimeout) { [weak self] ok, rtt in
            self?.queue.async {
                self?.log("info: detector ping whitelistHost=\(self?.whitelistHost ?? "?") → \(ok ? "ok" : "fail") in \(Int(rtt*1000))ms")
                whitelistRes = ok
                group.leave()
            }
        }

        group.notify(queue: queue) { [weak self] in
            guard let self else { return }
            self.activePingers.removeAll()
            completion(testRes ?? false, whitelistRes ?? false)
        }
    }

    /// IPA-D25: TCP-connect probe at port 443 against testHost and
    /// whitelistHost in parallel, with the same physical-interface
    /// pinning as ICMP. Used as a fallback only when both ICMP
    /// probes have already failed. A successful TCP handshake is
    /// treated as "ok via TCP fallback" — overwrites the failed
    /// ICMP result before the outcome matrix is evaluated.
    ///
    /// The probes ride excludedRoutes that the PacketTunnelProvider
    /// already adds for the same hosts (D23 wiring), and
    /// `requiredInterfaceType` pins the socket to wifi/cellular so
    /// the connection bypasses our own utun. Completion delivered
    /// on `queue`.
    private func tcpFallbackProbe(completion: @escaping (_ testOK: Bool, _ whitelistOK: Bool) -> Void) {
        // Pick physical interface preference from current path.
        var pinned: NWInterface.InterfaceType? = nil
        var pinnedName: String = "<default>"
        if let path = pathProvider() {
            if path.usesInterfaceType(.wifi) {
                pinned = .wifi; pinnedName = "wifi"
            } else if path.usesInterfaceType(.cellular) {
                pinned = .cellular; pinnedName = "cellular"
            } else if path.usesInterfaceType(.wiredEthernet) {
                pinned = .wiredEthernet; pinnedName = "wired"
            }
        }

        var testRes: Bool?
        var whitelistRes: Bool?
        let group = DispatchGroup()
        group.enter()
        group.enter()

        let tHost = self.testHost
        let wHost = self.whitelistHost

        self.runTCPProbe(host: tHost, pinned: pinned, pinnedName: pinnedName) { [weak self] ok in
            self?.queue.async {
                self?.log("info: detector probe testHost=\(tHost) → ICMP fail, TCP fallback \(ok ? "ok" : "fail")")
                testRes = ok
                group.leave()
            }
        }
        self.runTCPProbe(host: wHost, pinned: pinned, pinnedName: pinnedName) { [weak self] ok in
            self?.queue.async {
                self?.log("info: detector probe whitelistHost=\(wHost) → ICMP fail, TCP fallback \(ok ? "ok" : "fail")")
                whitelistRes = ok
                group.leave()
            }
        }

        group.notify(queue: queue) {
            completion(testRes ?? false, whitelistRes ?? false)
        }
    }

    /// Single TCP-connect probe to `host:443`. Settles exactly once.
    /// Cancels the connection as soon as it reaches .ready — we only
    /// need SYN/SYN-ACK to confirm reachability. On timeout, cancel
    /// and report fail.
    private func runTCPProbe(host: String,
                             pinned: NWInterface.InterfaceType?,
                             pinnedName: String,
                             completion: @escaping (_ ok: Bool) -> Void) {
        let params: NWParameters = .tcp
        if let p = pinned {
            params.requiredInterfaceType = p
        }
        // Disable IPv6 (Happy Eyeballs) — our excludedRoutes are v4
        // only and we want a deterministic v4 path.
        if let ipOptions = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ipOptions.version = .v4
        }

        let endpointHost = NWEndpoint.Host(host)
        let conn = NWConnection(host: endpointHost, port: 443, using: params)
        activeTCPConns.append(conn)
        log("info: detector TCP fallback \(host):443 starting (pinned=\(pinnedName))")

        var didSettle = false
        let settle: (Bool, String) -> Void = { [weak self] ok, reason in
            guard let self else { return }
            if didSettle { return }
            didSettle = true
            // Remove from active list + cancel underlying.
            if let idx = self.activeTCPConns.firstIndex(where: { $0 === conn }) {
                self.activeTCPConns.remove(at: idx)
            }
            conn.cancel()
            self.log("info: detector TCP fallback \(host):443 settled \(ok ? "ok" : "fail") (\(reason))")
            completion(ok)
        }

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                settle(true, "ready")
            case .failed(let err):
                settle(false, "failed: \(err)")
            case .cancelled:
                settle(false, "cancelled")
            case .waiting(let err):
                // Let timeout decide; log the reason.
                self.log("info: detector TCP fallback \(host):443 waiting: \(err)")
            default:
                break
            }
        }
        conn.start(queue: queue)

        // Timeout — same 3 s budget as ICMP.
        queue.asyncAfter(deadline: .now() + Self.tcpFallbackTimeout) {
            settle(false, "timeout")
        }
    }

    /// D65: HTTP HEAD fallback probe to both targets in parallel.
    /// URLSession requests go through carrier DPI — under TSPU whitelist,
    /// DPI inspects HTTP data and blocks non-whitelisted destinations.
    /// Unlike raw TCP handshake (which passes through DPI), HTTP sends
    /// actual data that DPI can filter.
    ///
    /// Note: from the extension, URLSession traffic exits via the system
    /// default route (not our own utun) because NEPacketTunnelProvider's
    /// excludedRoutes already exclude probe target IPs.
    private func httpFallbackProbe(completion: @escaping (_ testOK: Bool, _ whitelistOK: Bool) -> Void) {
        let tHost = self.testHost
        let wHost = self.whitelistHost
        var testRes: Bool?
        var whitelistRes: Bool?
        let group = DispatchGroup()
        group.enter()
        group.enter()

        runHTTPProbe(host: tHost) { [weak self] ok in
            self?.queue.async {
                self?.log("info: detector HTTP fallback testHost=\(tHost) → \(ok ? "ok" : "fail")")
                testRes = ok
                group.leave()
            }
        }
        runHTTPProbe(host: wHost) { [weak self] ok in
            self?.queue.async {
                self?.log("info: detector HTTP fallback whitelistHost=\(wHost) → \(ok ? "ok" : "fail")")
                whitelistRes = ok
                group.leave()
            }
        }

        group.notify(queue: queue) {
            completion(testRes ?? false, whitelistRes ?? false)
        }
    }

    /// Single HTTP HEAD probe to `http://<host>/`. Settles with true if
    /// any HTTP response is received, false on timeout/error. Redirects
    /// are NOT followed — the first response confirms DPI reachability.
    private func runHTTPProbe(host: String,
                              completion: @escaping (_ ok: Bool) -> Void) {
        let urlHost = host.contains(":") ? "[\(host)]" : host
        guard let url = URL(string: "http://\(urlHost)/") else {
            completion(false)
            return
        }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = Self.tcpFallbackTimeout
        config.timeoutIntervalForResource = Self.tcpFallbackTimeout + 1
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let delegate = DetectorHTTPProbeDelegate()
        let session = URLSession(configuration: config,
                                 delegate: delegate,
                                 delegateQueue: nil)
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        request.timeoutInterval = Self.tcpFallbackTimeout

        log("info: detector HTTP fallback \(host) starting")
        let task = session.dataTask(with: request) { [weak self] _, response, error in
            let ok = error == nil && response != nil
            self?.queue.async {
                self?.log("info: detector HTTP fallback \(host) settled \(ok ? "ok" : "fail")")
                session.invalidateAndCancel()
                completion(ok)
            }
        }
        task.resume()
    }

    /// Parses `"8.8.8.8"` or `"google.com"` into the corresponding
    /// ICMPPinger.Target. The pinger itself does the IP-literal
    /// detection — but we forward a typed enum so the intent is clear.
    private func parseTarget(_ s: String) -> ICMPPinger.Target {
        // Hostnames vs IPs: cheap check — does it have a letter? If
        // it parses as an IP via inet_pton inside ICMPPinger then
        // .ip() is functionally equivalent to .hostname(); we keep
        // it as .hostname only when the string clearly is a name.
        let isHostname = s.contains(where: { $0.isLetter || $0 == "-" })
        return isHostname ? .hostname(s) : .ip(s)
    }

    /// Returns the index of the first non-loopback, non-utun physical
    /// interface on the current path. Used to scope the ping socket so
    /// the packet actually leaves the device via Wi-Fi/cellular instead
    /// of going back through our own utun.
    private func pickPhysicalInterfaceIndex() -> UInt32? {
        guard let path = pathProvider() else { return nil }
        // Prefer wifi → cellular → wired.
        let order: [NWInterface.InterfaceType] = [.wifi, .cellular, .wiredEthernet]
        for kind in order {
            if let iface = path.availableInterfaces.first(where: { $0.type == kind }) {
                return UInt32(iface.index)
            }
        }
        return nil
    }

    // MARK: – decisions

    private func handleOutcome(_ outcome: Outcome) {
        let now = Date()
        let inHoldDown = now.timeIntervalSince(lastSwitchedAt) < Self.holdDownSeconds
        log("info: detector cycle outcome=\(outcome.rawValue) holdDown=\(inHoldDown)")

        switch outcome {
        case .clearAll:
            // Internet reachable + whitelist reachable. If on backup,
            // count failback successes until threshold.
            failbackSuccesses += 1
            if WhitelistStatusStore.activeEndpoint == .backup
                && failbackSuccesses >= Self.failbackSuccessesNeeded
                && !inHoldDown {
                log("info: detector: failback → primary (whitelist gone)")
                applySwitch(to: .primary)
                failbackSuccesses = 0
            }
            WhitelistStatusStore.current = .off

        case .whitelistOn:
            failbackSuccesses = 0
            if WhitelistStatusStore.activeEndpoint != .backup && !inHoldDown {
                log("warn: detector: WHITELIST ACTIVE — switching to backup")
                applySwitch(to: .backup)
            }
            WhitelistStatusStore.current = .detected

        case .whitelistMisconfigured:
            // testHost reachable but whitelistHost dead — likely a
            // misconfigured whitelist target (typo, dead IP). Don't
            // switch; just keep the current effective endpoint and
            // warn loudly so the user can see it in the log.
            failbackSuccesses = 0
            log("warn: detector: whitelist target unreachable but test target OK — check whitelistHost setting")
            // Paint the badge as "off" since internet is up; the warn
            // line above is the operator signal.
            WhitelistStatusStore.current = .off

        case .noNetwork:
            failbackSuccesses = 0
            WhitelistStatusStore.current = .noNetwork
        }
    }

    private func applySwitch(to endpoint: EndpointMode) {
        lastSwitchedAt = Date()
        WhitelistStatusStore.activeEndpoint = endpoint
        switchEndpoint(endpoint)
        postSwitchNotification(to: endpoint)
    }

    private func postSwitchNotification(to endpoint: EndpointMode) {
        guard NotificationPreferences.enabled else { return }
        let content = UNMutableNotificationContent()
        switch endpoint {
        case .backup:
            content.title = "Whitelist mode detected"
            content.body  = "Switched to whitelist server to keep traffic flowing."
        case .primary, .auto:
            content.title = "Whitelist lifted"
            content.body  = "Switched back to main server."
        }
        content.sound = .default
        content.categoryIdentifier = NotificationIDs.categoryIdentifier
        let id = (endpoint == .backup) ? NotificationIDs.detectedID : NotificationIDs.recoveredID
        let req = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { [weak self] err in
            if let err = err {
                self?.log("warn: notification post failed: \(err)")
            } else {
                self?.log("info: notification posted (\(endpoint.rawValue))")
            }
        }
    }
}

/// Stops URLSession from following HTTP redirects. Used by
/// `WhitelistDetector.runHTTPProbe` so we detect reachability from the
/// FIRST HTTP response — the redirect target might be on a different
/// (blocked) domain.
private final class DetectorHTTPProbeDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession,
                    task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
