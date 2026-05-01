import Foundation

/// User-facing toggle for "Game-optimized mode": when on, the samizdat
/// client is constructed with DisableDefaultSecurity=true, which turns
/// off the anti-DPI defaults that make real-time games (Roblox, voice,
/// QUIC-heavy apps) jitter:
///
///   - BytesPerTransportSoftCap = 0     (no transport rotation;
///                                       default 13 312 B rotates the
///                                       TLS+H2 transport every few
///                                       seconds during heavy traffic
///                                       — game freezes during each
///                                       rotation handshake)
///   - TCPFragmentation = false         (no Geneva fragmentation —
///                                       lower jitter on UDP-in-TCP)
///   - RecordFragmentation = false      (no TLS-record splitting)
///   - CoverTrafficEnabled = false      (no background dials competing
///                                       for bandwidth)
///   - MinTransports = 1                (single transport instead of 2)
///
/// Trade-off: weaker DPI camouflage. User opts in for gaming, opts out
/// for daily browsing.
///
/// Persisted in App Group UserDefaults so the extension reads it at
/// startTunnel and on live RPC reconfigure.
enum PerformancePreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let gameOptimizedKey = "gameOptimizedMode"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Default OFF. Anti-DPI is the project's main reason to exist —
    /// only turn it off when the user explicitly asks for game perf.
    static var gameOptimized: Bool {
        get { defaults?.bool(forKey: gameOptimizedKey) ?? false }
        set { defaults?.set(newValue, forKey: gameOptimizedKey) }
    }
}
