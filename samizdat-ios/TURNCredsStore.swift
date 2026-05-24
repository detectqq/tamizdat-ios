import Foundation

/// App Group-backed cache for VK TURN credentials acquired by the
/// main-app WKWebView solver.
///
/// WHY App Group UserDefaults: the Network Extension cannot run a
/// WKWebView (Apple disallows; only the main app process can host
/// WebKit), so the creds-acquire flow lives in the main app. The
/// extension reads the cached creds at startTunnel and on each
/// status RPC. The cache is the canonical source of truth — the
/// main app writes on every refresh, the extension only reads.
///
/// Lifetime model:
///   - `acquiredAt` is set when VK API returns creds.
///   - `lifetime` is the TTL VK announces (seconds; typically ~30 min).
///   - `expiresAt = acquiredAt + lifetime`.
///   - `isFresh` ⇒ creds exist AND will still be alive 5 min from now.
///   - `needsRefresh` ⇒ creds missing OR will expire within 5 min.
///
/// We refresh ~5 min ahead of expiry so the first failed creds-bound
/// connection attempt has full creds for retry. A burst of refreshes
/// during a quick succession of scene-active events is naturally
/// debounced by the actor in `VKCredsClient.fetchCredentials` (single
/// flight).
struct VKTURNCredentials: Codable, Equatable {
    /// TURN realm username — passed verbatim to libstun / libice.
    let username: String
    /// TURN realm password — opaque bearer; treat as a secret.
    let password: String
    /// Ordered TURN URLs (host:port) returned by VK / OK back-end. The
    /// scheme prefix (`turn:` / `turns:`) is stripped by the client.
    let turnURLs: [String]
    /// VK-advertised credential lifetime in seconds. Negative or zero
    /// means VK didn't return a `lifetime` / `ttl`; we treat such creds
    /// as already needing refresh.
    let lifetime: TimeInterval
    /// Wall-clock time the creds were acquired. Used to compute
    /// `expiresAt` for client-side cache decisions.
    let acquiredAt: Date

    var expiresAt: Date {
        acquiredAt.addingTimeInterval(max(lifetime, 0))
    }
}

func vkCredsAsJSON(creds: VKTURNCredentials) -> String {
    struct LogShape: Encodable {
        let username: String
        let password: String
        let turn_servers: [String]
        let lifetime_sec: Int
    }

    let shape = LogShape(
        username: creds.username,
        password: creds.password,
        turn_servers: creds.turnURLs,
        lifetime_sec: Int(creds.lifetime)
    )

    do {
        let data = try JSONEncoder().encode(shape)
        guard let json = String(data: data, encoding: .utf8) else {
            return "<encode-failed: non-utf8 JSON>"
        }
        return json
    } catch {
        return "<encode-failed: \(error)>"
    }
}

/// Singleton helper around the App Group UserDefaults.
///
/// Concurrency: UserDefaults is itself thread-safe and we only do
/// small synchronous Codable round-trips here, so no locking is
/// required. The Network Extension reads from a separate process; iOS
/// flushes the suite store via shared memory.
final class TURNCredsStore {
    static let shared = TURNCredsStore()

    /// App Group identifier shared with the extension. MUST stay in
    /// sync with `samizdat-ios.entitlements` /
    /// `samizdat-tunnel.entitlements` and the same constant referenced
    /// in `EndpointModeStore`, `PacketTunnelProvider`, etc.
    private static let appGroupID = "group.com.anarki.samizdat-test"
    /// UserDefaults key. Versioned in case the schema changes later
    /// — bump to `v2` on breaking changes so an old extension that
    /// can't decode the new shape simply sees "no creds" and falls
    /// back to its no-TURN path instead of crashing on decode.
    private static let storageKey = "tamizdat.vkTURNCreds.v1"

    /// Cushion before expiry that triggers a refresh. 15 min gives the
    /// foreground 5-minute heartbeat (TURNCredsRefresher) four chances
    /// at refresh before the creds actually expire — and gives the BG
    /// task scheduler equally generous slack when iOS gates the
    /// background runner.
    ///
    /// Bumped from 5 → 15 min on the autonomous-refresh pass: the old
    /// 5-min cushion was barely longer than the foreground heartbeat
    /// (5 min) and the BG runner (45 min target), which meant every
    /// missed iOS BG slot collapsed the refresh window onto the actual
    /// expiry and we ate 15 s VK Allocate timeouts on Connect.
    static let refreshCushion: TimeInterval = 15 * 60

    private var defaults: UserDefaults? {
        UserDefaults(suiteName: Self.appGroupID)
    }

    private init() {}

    /// Persisted creds (if any). Returns nil if the entry is missing
    /// or the stored payload can't be decoded (e.g. schema drift).
    func load() -> VKTURNCredentials? {
        guard let data = defaults?.data(forKey: Self.storageKey) else { return nil }
        do {
            return try JSONDecoder.iso8601.decode(VKTURNCredentials.self, from: data)
        } catch {
            // Decode failures are silent on purpose — a corrupt entry
            // is the same as no entry from the caller's perspective.
            return nil
        }
    }

    /// Replace the current entry with `creds`. Atomic; the extension
    /// reads the new value on its next status RPC tick (≤ 500 ms).
    func save(_ creds: VKTURNCredentials) {
        guard let defaults else { return }
        do {
            let data = try JSONEncoder.iso8601.encode(creds)
            defaults.set(data, forKey: Self.storageKey)
        } catch {
            // Encoding can't realistically fail for this Codable shape;
            // if it does we drop the write rather than crash so the app
            // remains usable.
        }
        // Also mirror as a plain-string JSON under a fixed key the
        // Network Extension reads inline (extension can't import
        // VKTURNCredentials so it can't decode the binary blob above).
        // Wire shape matches what mobile/socksstub::parseVKTurnCredsJSON
        // expects: {username, password, turn_servers, lifetime_sec}.
        defaults.set(vkCredsAsJSON(creds: creds), forKey: "tamizdat.vkTURNCredsJSON")

        // Mirror the acquisition timestamp as a standalone key so the
        // extension can pre-flight-check creds age WITHOUT decoding
        // the Codable blob (extension can't see VKTURNCredentials).
        // Used by PacketTunnelProvider.attachVKTurnUpstream to refuse
        // a 15-s VK Allocate timeout when creds are already past the
        // safety margin.
        defaults.set(creds.acquiredAt, forKey: "tamizdat.vkTURNCredsAcquiredAt")
    }

    /// Drop the cached entry. Used when the user signs out, when VK
    /// rejects a known-stale entry, or in tests. Wipes all three keys
    /// the save() path writes (binary blob, plain-string JSON for the
    /// extension, and the standalone acquiredAt stamp) so a stale
    /// timestamp can never linger past a clear().
    func clear() {
        defaults?.removeObject(forKey: Self.storageKey)
        defaults?.removeObject(forKey: "tamizdat.vkTURNCredsJSON")
        defaults?.removeObject(forKey: "tamizdat.vkTURNCredsAcquiredAt")
    }

    /// `true` iff creds exist and have at least `refreshCushion`
    /// seconds of remaining lifetime. Drives the green/grey TURN tile
    /// in the main UI and the `hasTURNCreds` field in the status RPC.
    var isFresh: Bool {
        guard let c = load() else { return false }
        return c.expiresAt.timeIntervalSinceNow > Self.refreshCushion
    }

    /// `true` iff the cache is empty or close to expiring. Drives the
    /// refresh-on-scene-active path in `App.swift`.
    var needsRefresh: Bool {
        guard let c = load() else { return true }
        return c.expiresAt.timeIntervalSinceNow <= Self.refreshCushion
    }
}

// MARK: – Codable date helpers

extension JSONEncoder {
    /// ISO-8601 dates so the persisted JSON is human-readable in the
    /// App Group plist and easier to debug than a raw Double.
    static var iso8601: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }
}

extension JSONDecoder {
    static var iso8601: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}

// MARK: – VK creds runtime configuration (App Group preferences)

/// Static helper that surfaces the VK creds knobs from App Group
/// UserDefaults. Kept separate from `TURNCredsStore` so the refresh
/// coordinator can read these without entangling read/write paths.
///
/// At this stage of the rollout we expect the call hash to come from
/// server-pushed config or a one-off Settings field — the refresh
/// coordinator simply skips refresh when no hash is set, so the iOS
/// client degrades gracefully to "no VK TURN" until the operator
/// provides one.
enum VKCredsPreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let primaryHashKey = "tamizdat.vkCallHash"
    private static let secondaryHashKey = "tamizdat.vkCallHashSecondary"
    private static let deviceIDKey = "tamizdat.vkDeviceID"
    private static let peerAddrKey = "tamizdat.vkPeerAddr"
    private static let connectPasswordKey = "tamizdat.vkConnectPassword"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    static var primaryCallHash: String {
        get { defaults?.string(forKey: primaryHashKey) ?? "" }
        set { defaults?.set(newValue, forKey: primaryHashKey) }
    }

    static var secondaryCallHash: String? {
        get {
            let s = defaults?.string(forKey: secondaryHashKey) ?? ""
            return s.isEmpty ? nil : s
        }
        set { defaults?.set(newValue ?? "", forKey: secondaryHashKey) }
    }

    static var peerAddr: String {
        get { defaults?.string(forKey: peerAddrKey) ?? "" }
        set { defaults?.set(newValue, forKey: peerAddrKey) }
    }

    static var connectPassword: String {
        get { defaults?.string(forKey: connectPasswordKey) ?? "" }
        set { defaults?.set(newValue, forKey: connectPasswordKey) }
    }

    /// Stable per-install UUID — lazy-initialised on first read so the
    /// extension and the main app see the same value through the App
    /// Group store.
    static var deviceID: String {
        if let s = defaults?.string(forKey: deviceIDKey), !s.isEmpty {
            return s
        }
        let fresh = UUID().uuidString
        defaults?.set(fresh, forKey: deviceIDKey)
        return fresh
    }

    /// True iff a primary hash is configured — refresh is a no-op
    /// otherwise.
    static var isConfigured: Bool {
        !primaryCallHash.isEmpty
    }
}

enum EndpointTurnMode: String, CaseIterable, Identifiable {
    case off
    case vk

    var id: String { rawValue }

    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let key = "tamizdat.endpointTurnMode"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    static var current: EndpointTurnMode {
        get {
            guard let raw = defaults?.string(forKey: key),
                  let mode = EndpointTurnMode(rawValue: raw)
            else { return .off }
            return mode
        }
        set {
            defaults?.set(newValue.rawValue, forKey: key)
        }
    }
}

// The main-app-only refresh coordinator (`TURNCredsRefresher`) lives
// in a separate file so that this one can be compiled by both the
// main app target AND the Network Extension target — the extension
// only needs the read-side primitives (`VKTURNCredentials`,
// `TURNCredsStore`, `VKCredsPreferences`) and must NOT pull in
// WKWebView / SwiftUI dependencies. See `TURNCredsRefresher.swift`.
