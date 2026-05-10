import Foundation
import SwiftUI

/// IPA-Z: live tunnel-shape + RTT view-model for the main-screen lamp.
///
/// On iOS the main app and the PacketTunnel extension are separate
/// processes, each with its own gomobile-bound socksstub Go runtime.
/// State (rt.samizdatClient and friends) lives only in the extension.
/// To surface it on the main screen we use the standard enterprise
/// pattern that sing-box-for-apple / Outline / Tailscale follow on
/// iOS:
///
///   NETunnelProviderSession.sendProviderMessage("status")  →  JSON
///
/// The extension's handleAppMessage("status") responds synchronously
/// with a JSON-encoded TamizdatStatusSnapshot built from in-process
/// Socksstub*() getters. Round-trip ~10-30 ms (mach-message), well
/// below our 500 ms polling cadence.
///
/// Lamp logic — variant-agnostic, single OR (matches Win-GUI exactly):
///
///   isLite          = realShape == "ShapeLite" (or legacy "lite")
///   hasLockedOnLite = liteAlive > 0 && lockedFlows > 0
///   isLit           = isLite || hasLockedOnLite
///
/// RTT bucket: lit → p50 of samples taken in ShapeLite. Not lit → p50
/// of samples taken in ShapeFull. "—" if no samples in that bucket.

/// Wire shape of the status RPC. Encoded as JSON on the extension
/// side, decoded on the main-app side. Field names must stay in sync
/// with the encoder in PacketTunnelProvider.swift.
///
/// IPA-D21: ping* fields added. Legacy realShape/lockedFlows/liteAlive/
/// rttLiteMs/rttBulkMs are kept in the wire format (no harm; extension
/// still emits them) but no longer drive UI rendering — the lamp now
/// reads pingMs / pingFailed instead. Future cleanup commit will drop
/// the dead fields once v0.2.D21 has rolled out and no skewed clients
/// remain.
struct TamizdatStatusSnapshot: Codable, Equatable {
    /// Ground-truth wire-shape: "ShapeFull" / "ShapeLite" / "" (offline).
    /// IPA-D21: still used as the offline-detect flag (empty string =
    /// extension disconnected / no client).
    let realShape: String
    /// RTP-stickylocked realtime flow count (proven realtime). LEGACY.
    let lockedFlows: Int
    /// V2/V3 only — dedicated lite-class transport up (1) or not (0).
    /// Always 0 on V1. LEGACY.
    let liteAlive: Int
    /// p50 RTT in ms during ShapeLite samples; -1 if none. LEGACY.
    let rttLiteMs: Int
    /// p50 RTT in ms during ShapeFull samples; -1 if none. LEGACY.
    let rttBulkMs: Int

    /// IPA-D21: last successful real-internet ping latency, in ms.
    /// -1 if no successful probe yet.
    let pingMs: Int
    /// IPA-D21: most recent probe succeeded.
    let pingOK: Bool
    /// IPA-D21: 2+ consecutive probe failures — triggers the yellow
    /// "Proxy unreachable" shield on the main screen.
    let pingFailed: Bool
    /// IPA-D21: echo-back of the currently-configured probe URL
    /// (debugging aid; not rendered on the main screen).
    let pingURL: String

    static let offline = TamizdatStatusSnapshot(
        realShape: "", lockedFlows: 0, liteAlive: 0,
        rttLiteMs: -1, rttBulkMs: -1,
        pingMs: -1, pingOK: false, pingFailed: false, pingURL: ""
    )

    // IPA-D21: tolerate older extension JSON (pre-D21 lacks ping*
    // fields). Once everyone's on D21+ this can be removed in the same
    // cleanup commit that drops the legacy RTT fields.
    private enum CodingKeys: String, CodingKey {
        case realShape, lockedFlows, liteAlive, rttLiteMs, rttBulkMs
        case pingMs, pingOK, pingFailed, pingURL
    }

    init(realShape: String, lockedFlows: Int, liteAlive: Int,
         rttLiteMs: Int, rttBulkMs: Int,
         pingMs: Int, pingOK: Bool, pingFailed: Bool, pingURL: String) {
        self.realShape = realShape
        self.lockedFlows = lockedFlows
        self.liteAlive = liteAlive
        self.rttLiteMs = rttLiteMs
        self.rttBulkMs = rttBulkMs
        self.pingMs = pingMs
        self.pingOK = pingOK
        self.pingFailed = pingFailed
        self.pingURL = pingURL
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.realShape   = (try? c.decode(String.self, forKey: .realShape))   ?? ""
        self.lockedFlows = (try? c.decode(Int.self,    forKey: .lockedFlows)) ?? 0
        self.liteAlive   = (try? c.decode(Int.self,    forKey: .liteAlive))   ?? 0
        self.rttLiteMs   = (try? c.decode(Int.self,    forKey: .rttLiteMs))   ?? -1
        self.rttBulkMs   = (try? c.decode(Int.self,    forKey: .rttBulkMs))   ?? -1
        self.pingMs      = (try? c.decode(Int.self,    forKey: .pingMs))      ?? -1
        self.pingOK      = (try? c.decode(Bool.self,   forKey: .pingOK))      ?? false
        self.pingFailed  = (try? c.decode(Bool.self,   forKey: .pingFailed))  ?? false
        self.pingURL     = (try? c.decode(String.self, forKey: .pingURL))     ?? ""
    }
}

@MainActor
final class TamizdatStatusStore: ObservableObject {
    @Published private(set) var snapshot: TamizdatStatusSnapshot = .offline

    private var timer: Timer?

    /// Pollling cadence. 500 ms is the same value sing-box-for-apple
    /// uses for its connection-stat polling. Drop to 250 ms or lower
    /// if lamp feel is sluggish; round-trip RPC is ~10-30 ms so we
    /// have headroom.
    static let pollInterval: TimeInterval = 0.5

    /// Convenience pass-through so callers can write
    /// `lampStore.realShape.isEmpty` without reaching into snapshot.
    var realShape: String { snapshot.realShape }

    /// IPA-D21: true when the most-recent two ping probes failed. Drives
    /// the yellow "Proxy unreachable" shield on the main screen.
    var pingHealthy: Bool { !snapshot.pingFailed }

    /// IPA-D21: single-line status under the shield.
    ///
    ///   "Ping 42ms"     — healthy, last probe ok
    ///   "Ping failed"   — 2+ consecutive misses (shield flips yellow)
    ///   "Ping —"        — connected, prober ran but no successful sample yet
    ///   "— offline —"   — extension not connected / no client
    ///
    /// (Replaces the bulk/lite shape lamp from IPA-Z, which was dead
    /// after D18 disabled cover traffic + the realtime detector.)
    var lampLabel: String {
        if snapshot.realShape.isEmpty {
            return "— offline —"
        }
        if snapshot.pingFailed {
            return "Ping failed"
        }
        if snapshot.pingMs >= 0 {
            return "Ping \(snapshot.pingMs)ms"
        }
        return "Ping —"
    }

    /// Begin polling. Idempotent. Safe from .onAppear.
    func start() {
        guard timer == nil else { return }
        Task { await self.poll() } // immediate first sample
        let t = Timer(timeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.poll()
            }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    /// Stop polling. Safe from .onDisappear.
    func stop() {
        timer?.invalidate()
        timer = nil
    }

    private func poll() async {
        let result = await VPNProfileStore.shared.fetchTamizdatStatus()
        // Avoid re-publishing identical snapshots — saves SwiftUI
        // re-render work when nothing changed.
        if result != snapshot {
            snapshot = result
        }
    }
}
