import Foundation
import Network

/// WhitelistDetector — periodic out-of-tunnel TCP probe cascade that
/// decides whether the current network is in TSPU whitelist mode and
/// flips the active samizdat endpoint accordingly.
///
/// Probe cascade per cycle (sequential, 3 s per step):
///   1. TCP 1.1.1.1:443  (Cloudflare canary)
///   2. TCP 8.8.8.8:443  (Google canary, only if step 1 failed)
///   3. TCP 77.88.8.8:443 (Yandex DNS primary, only if 1 + 2 failed)
///   4. TCP 77.88.8.1:443 (Yandex DNS secondary, only if 1+2+3 failed)
///
/// Decisions:
///   - any of 1..2 ✅                          → internet OK, status=.off
///   - all of 1..2 ❌, any of 3..4 ✅         → WHITELIST, status=.detected
///   - all 4 ❌                                → no network, status=.noNetwork
///                                                (counters paused)
///
/// State machine guarantees:
///   - hold-down 60 s between actual endpoint switches (anti-flap)
///   - failback to primary requires 2 consecutive ✅ on canary 1+2
///   - probes are SKIPPED entirely when NWPathMonitor reports
///     unsatisfied path (counters reset on path-status flip)
///   - low power mode → cadence ×3 (90 s normal, 180 s on-backup)
///   - detector is started only when EndpointModeStore.current == .auto
///
/// All probe traffic is added to NEPacketTunnelNetworkSettings.excludedRoutes
/// (1.1.1.1/32, 8.8.8.8/32, 77.88.8.0/24) so the probes really go via the
/// underlying interface, not through our own samizdat tunnel.
final class WhitelistDetector {

    // Tunables.
    private static let probeTimeout: TimeInterval = 3
    private static let normalCadence: TimeInterval = 30
    private static let onBackupCadence: TimeInterval = 60
    private static let holdDownSeconds: TimeInterval = 60
    private static let captiveFreezeSeconds: TimeInterval = 300
    private static let failbackSuccessesNeeded: Int = 2

    // Probe targets — kept in sync with excludedRoutes added by the
    // PacketTunnelProvider so the underlying interface is actually used.
    private struct Canary { let host: String; let port: NWEndpoint.Port }
    private static let internetCanaries: [Canary] = [
        Canary(host: "1.1.1.1", port: 443),
        Canary(host: "8.8.8.8", port: 443),
    ]
    private static let ruCanaries: [Canary] = [
        Canary(host: "77.88.8.8", port: 443), // Yandex DNS primary
        Canary(host: "77.88.8.1", port: 443), // Yandex DNS secondary
    ]

    // Hooks injected by PacketTunnelProvider.
    private let log: (String) -> Void
    private let switchEndpoint: (EndpointMode) -> Void
    private let pathProvider: () -> Network.NWPath?

    private let queue = DispatchQueue(label: "com.anarki.samizdat-test.detector", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var pendingConn: NWConnection?
    private var pendingTimeoutWork: DispatchWorkItem?

    // State.
    private var lastSwitchedAt = Date.distantPast
    private var failbackSuccesses = 0
    private var captiveFreezeUntil = Date.distantPast
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
            self.scheduleNextProbe(after: 2) // first probe ~2 s after start
            self.log("info: WhitelistDetector started")
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.stopped = true
            self.timer?.cancel(); self.timer = nil
            self.pendingTimeoutWork?.cancel(); self.pendingTimeoutWork = nil
            self.pendingConn?.cancel(); self.pendingConn = nil
            WhitelistStatusStore.current = .unknown
            self.log("info: WhitelistDetector stopped")
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

        // Auto mode required.
        guard EndpointModeStore.current == .auto else {
            scheduleNextProbe(after: Self.normalCadence)
            return
        }

        // Path gate — skip cycle if no network.
        if !isPathSatisfied {
            scheduleNextProbe(after: Self.normalCadence)
            return
        }

        // Captive freeze gate.
        if Date() < captiveFreezeUntil {
            scheduleNextProbe(after: 30)
            return
        }

        // Cadence depends on current effective endpoint.
        let onBackup = (WhitelistStatusStore.activeEndpoint == .backup)
        let baseCadence = onBackup ? Self.onBackupCadence : Self.normalCadence
        let cadence = ProcessInfo.processInfo.isLowPowerModeEnabled ? baseCadence * 3 : baseCadence

        cascadeProbe { [weak self] outcome in
            guard let self else { return }
            self.handleOutcome(outcome)
            self.scheduleNextProbe(after: cadence)
        }
    }

    private enum CascadeOutcome {
        case internetOK
        case whitelistActive
        case noNetwork
        case captiveSuspected
    }

    /// Walks the cascade in order, stopping on the first ✅ in steps 1..2
    /// or the first ✅ in steps 3..4 after all of 1..2 failed. Calls
    /// completion exactly once on the detector queue.
    private func cascadeProbe(completion: @escaping (CascadeOutcome) -> Void) {
        runOne(canaries: Self.internetCanaries, idx: 0) { [weak self] internetOK, allSucceededFast in
            guard let self else { return }
            if internetOK {
                // Captive portal suspicion: 1.1.1.1 OR 8.8.8.8 connecting
                // ridiculously fast (sub-50 ms) on first cycle is rare on
                // cellular and may indicate a portal MITM. We only treat
                // this as suspicious if BOTH internet canaries connect
                // ridiculously fast (so a single fast Wi-Fi probe doesn't
                // trip the freeze).
                if allSucceededFast {
                    completion(.captiveSuspected)
                } else {
                    completion(.internetOK)
                }
                return
            }
            // Internet canaries all failed — try RU.
            self.runOne(canaries: Self.ruCanaries, idx: 0) { ruOK, _ in
                if ruOK {
                    completion(.whitelistActive)
                } else {
                    completion(.noNetwork)
                }
            }
        }
    }

    /// Probes a list of canaries sequentially; returns true on first
    /// success. allSucceededFast = true if every probe returned in
    /// <50 ms (captive-portal hint).
    private func runOne(canaries: [Canary],
                        idx: Int,
                        fastSoFar: Bool = true,
                        completion: @escaping (Bool, Bool) -> Void) {
        if idx >= canaries.count {
            completion(false, false)
            return
        }
        let c = canaries[idx]
        probeOnce(canary: c) { [weak self] ok, elapsed in
            guard let self else { return }
            if ok {
                let stillFast = fastSoFar && elapsed < 0.050
                completion(true, stillFast)
                return
            }
            self.runOne(canaries: canaries, idx: idx + 1, fastSoFar: false, completion: completion)
        }
    }

    /// Single TCP-connect probe with timeout. Closes the connection as
    /// soon as it transitions to .ready (we only need SYN/SYN-ACK to
    /// confirm reachability, not data). Result delivered exactly once.
    private func probeOnce(canary: Canary,
                           completion: @escaping (_ ok: Bool, _ elapsed: TimeInterval) -> Void) {
        let started = Date()
        var didSettle = false
        let settle: (Bool) -> Void = { [weak self] ok in
            guard let self else { return }
            if didSettle { return }
            didSettle = true
            self.pendingTimeoutWork?.cancel(); self.pendingTimeoutWork = nil
            let conn = self.pendingConn
            self.pendingConn = nil
            conn?.cancel()
            completion(ok, Date().timeIntervalSince(started))
        }

        let host = NWEndpoint.Host(canary.host)
        let conn = NWConnection(host: host, port: canary.port, using: .tcp)
        pendingConn = conn

        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                settle(true)
            case .failed(_), .cancelled:
                settle(false)
            case .waiting:
                // Waiting on a connectivity issue — let timeout decide.
                break
            default:
                break
            }
        }
        conn.start(queue: queue)

        let timeoutWork = DispatchWorkItem { settle(false) }
        pendingTimeoutWork = timeoutWork
        queue.asyncAfter(deadline: .now() + Self.probeTimeout, execute: timeoutWork)
    }

    // MARK: – decisions

    private func handleOutcome(_ outcome: CascadeOutcome) {
        let now = Date()
        let inHoldDown = now.timeIntervalSince(lastSwitchedAt) < Self.holdDownSeconds

        switch outcome {
        case .internetOK:
            // Internet reachable. If we're on backup, count failback
            // successes; on N consecutive ✅, switch back to primary.
            failbackSuccesses += 1
            if WhitelistStatusStore.activeEndpoint == .backup
                && failbackSuccesses >= Self.failbackSuccessesNeeded
                && !inHoldDown {
                log("info: detector: failback → primary (whitelist gone)")
                applySwitch(to: .primary)
                failbackSuccesses = 0
            }
            WhitelistStatusStore.current = .off

        case .whitelistActive:
            failbackSuccesses = 0
            if WhitelistStatusStore.activeEndpoint != .backup && !inHoldDown {
                log("warn: detector: WHITELIST ACTIVE — switching to backup")
                applySwitch(to: .backup)
            }
            WhitelistStatusStore.current = .detected

        case .noNetwork:
            failbackSuccesses = 0
            // Don't switch on transient network loss; just paint the
            // badge gray so the user knows monitoring is live but
            // currently has no signal.
            WhitelistStatusStore.current = .noNetwork

        case .captiveSuspected:
            // Both global canaries returned in <50 ms — treat as portal.
            // Freeze switching for 5 minutes; show yellow.
            captiveFreezeUntil = now.addingTimeInterval(Self.captiveFreezeSeconds)
            log("warn: detector: captive portal suspected — freezing 300 s")
            WhitelistStatusStore.current = .frozen
        }
    }

    private func applySwitch(to endpoint: EndpointMode) {
        lastSwitchedAt = Date()
        WhitelistStatusStore.activeEndpoint = endpoint
        switchEndpoint(endpoint)
    }
}
