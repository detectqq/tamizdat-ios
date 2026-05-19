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

    // Targets (re-read on applyConfig). Stored on the detector's queue.
    private var testHost: String = WhitelistProbePreferences.defaultTestHost
    private var whitelistHost: String = WhitelistProbePreferences.defaultWhitelistHost

    // State.
    private var lastSwitchedAt = Date.distantPast
    private var failbackSuccesses = 0
    private var whitelistSuccesses = 0
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
                self.whitelistSuccesses = 0
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
            let outcome: Outcome
            switch (testOK, whitelistOK) {
            case (true,  true):  outcome = .clearAll
            case (false, true):  outcome = .whitelistOn
            case (true,  false): outcome = .whitelistMisconfigured
            case (false, false): outcome = .noNetwork
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
            whitelistSuccesses = 0
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
            whitelistSuccesses += 1
            if WhitelistStatusStore.activeEndpoint != .backup
                && whitelistSuccesses >= Self.failbackSuccessesNeeded
                && !inHoldDown {
                log("warn: detector: WHITELIST ACTIVE — switching to backup")
                applySwitch(to: .backup)
                whitelistSuccesses = 0
            }
            WhitelistStatusStore.current = .detected

        case .whitelistMisconfigured:
            failbackSuccesses = 0
            whitelistSuccesses = 0
            log("warn: detector: whitelist target unreachable but test target OK — check whitelistHost setting")
            // Paint the badge as "off" since internet is up; the warn
            // line above is the operator signal.
            WhitelistStatusStore.current = .off

        case .noNetwork:
            failbackSuccesses = 0
            whitelistSuccesses = 0
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
