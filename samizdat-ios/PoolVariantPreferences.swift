import Foundation

/// User-facing picker for the tamizdat connection-pool strategy. Mirrors
/// the V1/V2/V3 radio in the Windows-GUI client. Each variant carries a
/// distinct trade-off between stealth (single-transport posture) and
/// throughput (multi-transport parallelism). Plan B+ adaptive shape flip
/// (lite/bulk auto-toggle on realtime traffic) runs identically across
/// all three variants — the variant only chooses the *number* of TCP/443
/// connections the client is willing to keep open, not whether they are
/// realtime-shaped or bulk-shaped.
///
///   - v1 — single transport, no rotation, max stealth. Pairs with
///     StrictSingleH2 (one TCP/443 forever). Best for whitelist /
///     #546-sensitive networks. Throughput limited to one H2 conn.
///
///   - v2 — up to 2 transports under load, 1 prewarm. Balanced —
///     stays under the #546 12-conn threshold per ISP, gets
///     parallelism on heavy pages.
///
///   - v3 — adaptive 2..4 transports. Best throughput, but increases
///     TLS-conn fingerprint per ISP. Use when bandwidth matters more
///     than wire-stealth.
///
/// Empty value (default `.v1`) reproduces what the project shipped at
/// HEAD 0000701 (V1-full hardcoded in socksstub.go). Plan B+ now arrives
/// automatically with the bumped vendor; the variant picker is the
/// next-level operator-tunable knob layered on top.
///
/// Persisted in App Group UserDefaults so the extension reads it at
/// startTunnel and on live RPC reconfigure (refreshSamizdatClient).
enum PoolVariant: String, CaseIterable, Identifiable {
    case v1 = "v1"
    case v2 = "v2"
    case v3 = "v3"

    var id: String { rawValue }

    /// UI label shown in the Picker.
    var displayName: String {
        switch self {
        case .v1: return "V1 — single transport (stealth)"
        case .v2: return "V2 — up to 2 (balanced)"
        case .v3: return "V3 — adaptive 2..4 (throughput)"
        }
    }

    /// Short caption shown under the picker.
    var caption: String {
        switch self {
        case .v1: return "One TCP/443. Max stealth, slowest. Pairs with StrictSingleH2."
        case .v2: return "Up to two TCP/443. Stays below #546 (12) per ISP."
        case .v3: return "2..4 TCP/443. Best throughput; taller TLS fingerprint."
        }
    }
}

enum PoolVariantPreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let key = "poolVariantMode"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Default `.v1`. Matches what socksstub shipped hardcoded before
    /// the picker was added — existing user devices upgrading to this
    /// build keep the same behaviour until the user actively flips
    /// the picker.
    static var current: PoolVariant {
        get {
            let raw = defaults?.string(forKey: key) ?? ""
            return PoolVariant(rawValue: raw) ?? .v1
        }
        set { defaults?.set(newValue.rawValue, forKey: key) }
    }
}
