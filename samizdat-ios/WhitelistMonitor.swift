import Foundation
import Network

/// D65: WhitelistMonitor — runs in the MAIN APP while the VPN is
/// disconnected. Pure ICMP probes to testHost and whitelistHost.
///
/// Two user-configurable settings:
///   - `probeInterval`   — seconds between probe attempts
///   - `successesNeeded` — consecutive matching results before switching
///
/// Decision matrix (same as extension's WhitelistDetector):
///   testOK + whitelistOK   → free internet   → activeEndpoint = primary
///   testFail + whitelistOK → whitelist active → activeEndpoint = backup
///   testOK + whitelistFail → misconfigured    → keep current
///   testFail + whitelistFail → no network     → keep current
///
/// Switching requires `successesNeeded` consecutive identical verdicts
/// to avoid flapping on transient probe failures.
@MainActor
final class WhitelistMonitor: ObservableObject {

    private static let probeTimeout: TimeInterval = 2
    private static var cycleInterval: TimeInterval {
        TimeInterval(WhitelistProbePreferences.probeInterval)
    }

    private var task: Task<Void, Never>?
    private var pingers: [ICMPPinger] = []

    // Consecutive-result counters — switching happens only after
    // `successesNeeded` consecutive identical verdicts.
    private var whitelistCount = 0
    private var freeCount = 0

    /// Begin monitoring. Idempotent; no-op if already running.
    func start() {
        guard task == nil else { return }
        // Restore persisted counters so progress survives start/stop cycles.
        whitelistCount = WhitelistStatusStore.whitelistConsecutiveCount
        freeCount = WhitelistStatusStore.freeConsecutiveCount
        task = Task { [weak self] in
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

    // MARK: – cycle

    private func runCycle() async {
        guard EndpointModeStore.current == .auto else {
            WhitelistStatusStore.current = .unknown
            return
        }
        let testHost = WhitelistProbePreferences.testHost
        let whitelistHost = WhitelistProbePreferences.whitelistHost
        let threshold = WhitelistProbePreferences.successesNeeded

        // Clean up any leftover pingers from previous cycle.
        for p in pingers { p.cancel() }
        pingers.removeAll()

        // D65 fix: probes run SEQUENTIALLY — two simultaneous SOCK_DGRAM
        // ICMP sockets confuse the kernel's reply demux on some devices
        // (iPhone 16 Pro Max observed: replies delivered to wrong socket,
        // sequence mismatch → both probes timeout). Serializing avoids
        // this. Worst case: 2 × probeTimeout per cycle.
        let t = await probeHost(testHost)
        let w = await probeHost(whitelistHost)

        switch (t, w) {
        case (true, true):
            // Free internet — both hosts reachable.
            whitelistCount = 0
            freeCount += 1
            WhitelistStatusStore.current = .off
            if WhitelistStatusStore.activeEndpoint == .backup
                && freeCount >= threshold {
                WhitelistStatusStore.activeEndpoint = .primary
                freeCount = 0
            }

        case (false, true):
            // Whitelist active — testHost blocked, whitelistHost ok.
            freeCount = 0
            whitelistCount += 1
            WhitelistStatusStore.current = .detected
            if WhitelistStatusStore.activeEndpoint != .backup
                && whitelistCount >= threshold {
                WhitelistStatusStore.activeEndpoint = .backup
                whitelistCount = 0
            }

        case (true, false):
            // Misconfigured — testHost ok but whitelistHost down.
            whitelistCount = 0
            freeCount = 0
            WhitelistStatusStore.current = .unknown

        case (false, false):
            // Both unreachable — no network (or ICMP broken).
            whitelistCount = 0
            freeCount = 0
            WhitelistStatusStore.current = .noNetwork
        }

        // Persist counters across app lifecycle (background/foreground,
        // VPN state changes) so they survive start/stop resets.
        WhitelistStatusStore.whitelistConsecutiveCount = whitelistCount
        WhitelistStatusStore.freeConsecutiveCount = freeCount
    }

    // MARK: – ICMP probe

    private func probeHost(_ host: String) async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            let target: ICMPPinger.Target
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
