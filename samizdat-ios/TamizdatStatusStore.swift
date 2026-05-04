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
struct TamizdatStatusSnapshot: Codable, Equatable {
    /// Ground-truth wire-shape: "ShapeFull" / "ShapeLite" / "" (offline).
    let realShape: String
    /// RTP-stickylocked realtime flow count (proven realtime).
    let lockedFlows: Int
    /// V2/V3 only — dedicated lite-class transport up (1) or not (0).
    /// Always 0 on V1.
    let liteAlive: Int
    /// p50 RTT in ms during ShapeLite samples; -1 if none.
    let rttLiteMs: Int
    /// p50 RTT in ms during ShapeFull samples; -1 if none.
    let rttBulkMs: Int

    static let offline = TamizdatStatusSnapshot(
        realShape: "", lockedFlows: 0, liteAlive: 0,
        rttLiteMs: -1, rttBulkMs: -1
    )
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

    /// True when realtime-shape is active on the wire. Variant-
    /// agnostic; matches the Win-GUI single-OR rule.
    var isLit: Bool {
        let s = snapshot
        let isLite = (s.realShape == "ShapeLite" || s.realShape == "lite")
        let hasLockedOnLite = s.liteAlive > 0 && s.lockedFlows > 0
        return isLite || hasLockedOnLite
    }

    /// Compose the same single-line label the Windows GUI shows:
    ///
    ///   "● lite • RTT 17ms"
    ///   "○ bulk • RTT 23ms"
    ///   "○ bulk • RTT —"
    ///   "— offline —"           (extension not connected / no client)
    var lampLabel: String {
        if snapshot.realShape.isEmpty {
            return "— offline —"
        }
        let dot = isLit ? "●" : "○"
        let modeText = isLit ? "lite" : "bulk"
        let rttMs: Int = isLit ? snapshot.rttLiteMs : snapshot.rttBulkMs
        let rttPart = rttMs >= 0 ? " • RTT \(rttMs)ms" : " • RTT —"
        return "\(dot) \(modeText)\(rttPart)"
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
