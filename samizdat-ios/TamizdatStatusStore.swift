import Foundation
import SwiftUI
import SamizdatClient   // IPA-D25 fix7: for SocksstubNoteForegroundPoll()

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

    /// IPA-D22: cumulative hev rx_bytes since extension start.
    /// Sourced from `hev_socks5_tunnel_stats()` in PacketTunnelProvider.
    /// 0 when offline. The wire field is named `rxBytes`.
    let rxBytes: Int64
    /// IPA-D22: cumulative hev tx_bytes since extension start.
    /// 0 when offline. The wire field is named `txBytes`.
    let txBytes: Int64
    /// IPA-D22: monotonic seconds since the extension's startTunnel call
    /// completed. 0 when offline. Surfaced as the Uptime stat tile.
    let uptimeSec: Int64
    /// IPA-D22: 1 while `rewireUpstream` is mid-flight (samizdat client
    /// being torn down + rebuilt after a path change). The shield flips
    /// to amber "Reconnecting…" during this window. 0 otherwise.
    let isRewiring: Int

    /// VK TURN relay credentials available from the server.
    let hasTURNCreds: Bool

    static let offline = TamizdatStatusSnapshot(
        realShape: "", lockedFlows: 0, liteAlive: 0,
        rttLiteMs: -1, rttBulkMs: -1,
        pingMs: -1, pingOK: false, pingFailed: false, pingURL: "",
        rxBytes: 0, txBytes: 0, uptimeSec: 0, isRewiring: 0,
        hasTURNCreds: false
    )

    // IPA-D21: tolerate older extension JSON (pre-D21 lacks ping*
    // fields). Once everyone's on D21+ this can be removed in the same
    // cleanup commit that drops the legacy RTT fields.
    // IPA-D22: rxBytes / txBytes / uptimeSec / isRewiring added; same
    // default-tolerant decode pattern.
    private enum CodingKeys: String, CodingKey {
        case realShape, lockedFlows, liteAlive, rttLiteMs, rttBulkMs
        case pingMs, pingOK, pingFailed, pingURL
        case rxBytes, txBytes, uptimeSec, isRewiring
        case hasTURNCreds
    }

    init(realShape: String, lockedFlows: Int, liteAlive: Int,
         rttLiteMs: Int, rttBulkMs: Int,
         pingMs: Int, pingOK: Bool, pingFailed: Bool, pingURL: String,
         rxBytes: Int64, txBytes: Int64, uptimeSec: Int64, isRewiring: Int,
         hasTURNCreds: Bool = false) {
        self.realShape = realShape
        self.lockedFlows = lockedFlows
        self.liteAlive = liteAlive
        self.rttLiteMs = rttLiteMs
        self.rttBulkMs = rttBulkMs
        self.pingMs = pingMs
        self.pingOK = pingOK
        self.pingFailed = pingFailed
        self.pingURL = pingURL
        self.rxBytes = rxBytes
        self.txBytes = txBytes
        self.uptimeSec = uptimeSec
        self.isRewiring = isRewiring
        self.hasTURNCreds = hasTURNCreds
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
        self.rxBytes     = (try? c.decode(Int64.self,  forKey: .rxBytes))     ?? 0
        self.txBytes     = (try? c.decode(Int64.self,  forKey: .txBytes))     ?? 0
        self.uptimeSec   = (try? c.decode(Int64.self,  forKey: .uptimeSec))   ?? 0
        self.isRewiring  = (try? c.decode(Int.self,    forKey: .isRewiring))  ?? 0
        self.hasTURNCreds = (try? c.decode(Bool.self,  forKey: .hasTURNCreds)) ?? false
    }
}

@MainActor
final class TamizdatStatusStore: ObservableObject {
    @Published private(set) var snapshot: TamizdatStatusSnapshot = .offline

    /// IPA-D22: total tunnel rx/tx bytes (from hev counters via the
    /// "status" RPC, published whenever we get a non-offline reply).
    /// Used by the Data stat tile + ping chip data-rate readout.
    @Published private(set) var rxBytes: Int64 = 0
    @Published private(set) var txBytes: Int64 = 0

    /// IPA-D22: monotonic timestamp when the snapshot first transitioned
    /// from offline → online. Cleared on the next offline tick. Drives
    /// the "Uptime" stat tile. We do NOT reset on rewireUpstream — that
    /// only swaps the upstream endpoint, the tunnel itself stays up.
    @Published private(set) var tunnelStartedAt: Date?

    // IPA-D25: removed `smoothedRateKBps` + `dataRateText` (and the
    // per-sample EMA bookkeeping that fed them). The ping chip no
    // longer renders a bandwidth indicator — operator wanted it gone
    // from the code, not just the UI. Total bytes since connect
    // remain on the Data stat tile via `rxBytes` / `txBytes` /
    // `dataText`.

    private var timer: Timer?

    /// IPA-D65b: True while the main-app refresher is solving a VK
    /// captcha (auto WKWebView or manual sheet). Drives a small
    /// "Решаем капчу..." indicator under the shield. Backed by a
    /// `Combine`-style mirror of `TURNCredsRefresher.isRefreshing`.
    @Published private(set) var captchaIsActive: Bool = false

    /// IPA-D65b: published mirror — true iff the cached VK TURN creds
    /// in App Group UserDefaults are fresh enough to use without
    /// triggering a refresh. The extension surfaces the same bit via
    /// the status RPC (`snapshot.hasTURNCreds`); this main-app-side
    /// mirror lets `ContentView` repaint when the cache changes while
    /// the VPN is offline.
    @Published private(set) var turnCredsValid: Bool = TURNCredsStore.shared.isFresh

    /// Phase 2D-PART-C: true when the in-process VK TURN runner
    /// (mobile/socksstub/vkturn.go) reports itself alive. The runner
    /// lives in the EXTENSION process, not the main app, so this
    /// always returns false in the main app — wire it up here so a
    /// future RPC field can light up the home-screen TURN tile.
    var turnUpstreamRunning: Bool { SocksstubTURNUpstreamRunning() }

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
        // IPA-D25 fix7: foreground heartbeat to the Go-side ping
        // prober. Every status poll tells the extension "user is
        // watching" so the prober speeds up to 3s cadence. After
        // the heartbeat goes stale (>5s), prober slows to 30s.
        // This poll only runs while the view is visible (.onAppear /
        // .onDisappear lifecycle), so backgrounding the app stops
        // the heartbeat naturally.
        SocksstubNoteForegroundPoll()

        let result = await VPNProfileStore.shared.fetchTamizdatStatus()
        // Avoid re-publishing identical snapshots — saves SwiftUI
        // re-render work when nothing changed.
        if result != snapshot {
            snapshot = result
        }
        applyDerivedState(snap: result)

        // IPA-D65b: mirror the refresher's in-flight flag so any
        // observer of this store can render a "Решаем капчу..." chip
        // without separately subscribing to `TURNCredsRefresher`.
        let active = TURNCredsRefresher.shared.isRefreshing
        if captchaIsActive != active {
            captchaIsActive = active
        }
    }

    // MARK: – Derived state (IPA-D22)

    /// Re-derive uptime / data / rate from the latest snapshot. Called
    /// on every poll. Updates the @Published mirror properties only when
    /// they actually change, to keep SwiftUI re-renders minimal.
    private func applyDerivedState(snap: TamizdatStatusSnapshot) {
        let online = !snap.realShape.isEmpty
        let now = Date()

        // Uptime: derived directly from snap.uptimeSec (extension-side
        // anchor). We don't rely on a Swift-side timestamp because the
        // app may have been launched after the tunnel was already up
        // (background restore), and we'd start counting at 0 then.
        if online && snap.uptimeSec > 0 {
            let inferredStart = now.addingTimeInterval(-TimeInterval(snap.uptimeSec))
            // Only re-assign if the new value drifts meaningfully (>2 s)
            // to avoid republishing every poll.
            if let cur = tunnelStartedAt {
                if abs(cur.timeIntervalSince(inferredStart)) > 2 {
                    tunnelStartedAt = inferredStart
                }
            } else {
                tunnelStartedAt = inferredStart
            }
        } else {
            if tunnelStartedAt != nil { tunnelStartedAt = nil }
        }

        // Cumulative bytes — straight pass-through. Feeds the Data
        // stat tile via `dataText`.
        if rxBytes != snap.rxBytes { rxBytes = snap.rxBytes }
        if txBytes != snap.txBytes { txBytes = snap.txBytes }

        // VK TURN creds are written by the main app even when the VPN
        // is offline, so mirror the local cache separately from the NE
        // status RPC and publish changes for the TURN stat tile.
        let freshTurnCreds = TURNCredsStore.shared.isFresh
        if turnCredsValid != freshTurnCreds { turnCredsValid = freshTurnCreds }
        // IPA-D25: per-sample rate computation removed with the
        // bandwidth chip; `now` is no longer used here, but kept on
        // the signature for the uptime block above.
        _ = now
    }

    // MARK: – Formatted strings (IPA-D22)

    /// "Main" / "Whitelist" — synced from `EndpointModeStore.current`.
    /// The store doesn't know which mode is selected — caller passes
    /// the resolved label in. Kept as a free helper for symmetry.
    static func modeLabel(active: EndpointMode) -> String {
        switch active {
        case .primary: return "Main"
        case .backup:  return "Whitelist"
        case .auto:    return "Auto"
        }
    }

    /// "14:32" for under 1 hour, "1:14" for hours+min. "—" if offline.
    var uptimeText: String {
        guard let started = tunnelStartedAt else { return "—" }
        let elapsed = Int(Date().timeIntervalSince(started))
        if elapsed < 0 { return "—" }
        if elapsed < 3600 {
            let m = elapsed / 60
            let s = elapsed % 60
            return String(format: "%d:%02d", m, s)
        }
        let h = elapsed / 3600
        let m = (elapsed % 3600) / 60
        return String(format: "%d:%02d", h, m)
    }

    /// Unit for the Uptime stat tile: "min" if <1h else "h".
    var uptimeUnit: String {
        guard let started = tunnelStartedAt else { return "" }
        return Date().timeIntervalSince(started) < 3600 ? "min" : "h"
    }

    /// Auto-scaled total data text + unit, e.g. ("284", "MB").
    var dataText: (value: String, unit: String) {
        let total = rxBytes + txBytes
        if total <= 0 { return ("0", "B") }
        let kb = Double(total) / 1024.0
        let mb = kb / 1024.0
        let gb = mb / 1024.0
        if gb >= 1.0 {
            return (String(format: gb >= 10 ? "%.0f" : "%.1f", gb), "GB")
        }
        if mb >= 1.0 {
            return (String(format: mb >= 10 ? "%.0f" : "%.1f", mb), "MB")
        }
        if kb >= 1.0 {
            return (String(format: "%.0f", kb), "KB")
        }
        return (String(total), "B")
    }

    /// IPA-D22: true when the extension is currently in a rewireUpstream
    /// rebuild. Drives the "Reconnecting…" shield state.
    var isReconnecting: Bool { snapshot.isRewiring != 0 && !snapshot.realShape.isEmpty }
}
