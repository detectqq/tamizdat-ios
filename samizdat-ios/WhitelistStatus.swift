import Foundation

/// Live whitelist-detection state surfaced by WhitelistDetector. Persisted
/// in App Group UserDefaults so the main-app UI can poll it (Darwin
/// cross-process notifications would be cleaner but UserDefaults polling
/// at 2 Hz is plenty responsive for a status badge).
enum WhitelistStatus: String {
    case unknown    // grey  — not monitoring (auto off) OR no decisive cascade yet
    case off        // green — internet reachable, primary endpoint OK
    case detected   // red   — whitelist active, switched to backup
    case frozen     // yellow — captive portal detected, decisions frozen
    case noNetwork  // grey  — path unsatisfied (lift/forest), probes paused

    var isMonitoring: Bool {
        self != .unknown
    }
}

enum WhitelistStatusStore {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let statusKey = "whitelistStatus"
    private static let updatedAtKey = "whitelistStatusUpdatedAt"
    private static let activeEndpointKey = "whitelistActiveEndpoint"

    // Main-app WhitelistMonitor consecutive-result counters
    private static let whitelistCountKey = "whitelistConsecutiveCount"
    private static let freeCountKey = "freeConsecutiveCount"

    // Extension WhitelistDetector consecutive-result counters
    private static let failbackSuccessesKey = "whitelistFailbackSuccesses"
    private static let whitelistSuccessesKey = "whitelistWhitelistSuccesses"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// The current detector verdict.
    static var current: WhitelistStatus {
        get {
            guard let raw = defaults?.string(forKey: statusKey),
                  let s = WhitelistStatus(rawValue: raw)
            else { return .unknown }
            return s
        }
        set {
            defaults?.set(newValue.rawValue, forKey: statusKey)
            defaults?.set(Date().timeIntervalSince1970, forKey: updatedAtKey)
        }
    }

    /// Wall-clock seconds since the last status write. UI uses this to
    /// stale-out the badge if the extension stops reporting.
    static var ageSeconds: TimeInterval {
        let then = defaults?.double(forKey: updatedAtKey) ?? 0
        guard then > 0 else { return .infinity }
        return Date().timeIntervalSince1970 - then
    }

    /// Which endpoint the detector is currently routing through. Mirrors
    /// EndpointMode but tracks the *effective* choice (auto-mode picks
    /// primary or backup at runtime).
    static var activeEndpoint: EndpointMode {
        get {
            guard let raw = defaults?.string(forKey: activeEndpointKey),
                  let m = EndpointMode(rawValue: raw)
            else { return .primary }
            return m
        }
        set {
            defaults?.set(newValue.rawValue, forKey: activeEndpointKey)
        }
    }

    // -- Main-app monitor counters (WhitelistMonitor) --

    static var whitelistConsecutiveCount: Int {
        get { defaults?.integer(forKey: whitelistCountKey) ?? 0 }
        set { defaults?.set(newValue, forKey: whitelistCountKey) }
    }

    static var freeConsecutiveCount: Int {
        get { defaults?.integer(forKey: freeCountKey) ?? 0 }
        set { defaults?.set(newValue, forKey: freeCountKey) }
    }

    // -- Extension detector counters (WhitelistDetector) --

    static var failbackSuccesses: Int {
        get { defaults?.integer(forKey: failbackSuccessesKey) ?? 0 }
        set { defaults?.set(newValue, forKey: failbackSuccessesKey) }
    }

    static var whitelistSuccessesExtension: Int {
        get { defaults?.integer(forKey: whitelistSuccessesKey) ?? 0 }
        set { defaults?.set(newValue, forKey: whitelistSuccessesKey) }
    }

    static func reset() {
        defaults?.removeObject(forKey: statusKey)
        defaults?.removeObject(forKey: updatedAtKey)
        defaults?.removeObject(forKey: activeEndpointKey)
        defaults?.removeObject(forKey: whitelistCountKey)
        defaults?.removeObject(forKey: freeCountKey)
        defaults?.removeObject(forKey: failbackSuccessesKey)
        defaults?.removeObject(forKey: whitelistSuccessesKey)
    }
}
