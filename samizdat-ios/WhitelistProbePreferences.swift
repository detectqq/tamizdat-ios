import Foundation

/// IPA-D23: user-facing settings for the new ICMP-based WhitelistDetector.
/// Two targets, both IP-or-hostname:
///
///   - `testHost`      — "should ping when free internet works"
///                       (default 8.8.8.8 / Google DNS)
///   - `whitelistHost` — "should ping even under TSPU whitelist mode"
///                       (default 77.88.8.8 / Yandex DNS — Russian
///                       infrastructure, kept reachable by RU ISPs
///                       during whitelist throttling)
///
/// Persisted in App Group UserDefaults under
/// `tamizdat.whitelistTestHost` and `tamizdat.whitelistWhitelistHost`
/// so the extension can read on startTunnel + on live
/// `refreshWhitelistProbes` provider messages.
///
/// Mirrors the storage pattern used by `PingURLPreferences`.
enum WhitelistProbePreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let testHostKey = "tamizdat.whitelistTestHost"
    private static let whitelistHostKey = "tamizdat.whitelistWhitelistHost"
    private static let successesKey = "tamizdat.whitelistSuccessesNeeded"
    private static let intervalKey = "tamizdat.whitelistProbeInterval"

    static let defaultTestHost = "8.8.8.8"
    static let defaultWhitelistHost = "77.88.8.8"
    static let defaultSuccessesNeeded = 6
    static let defaultProbeInterval = 1

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// "Test" target — should be reachable when there is normal internet.
    /// Empty / whitespace-only stored value returns the default.
    static var testHost: String {
        get {
            let stored = defaults?.string(forKey: testHostKey) ?? ""
            return stored.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? defaultTestHost : stored
        }
        set {
            let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                defaults?.removeObject(forKey: testHostKey)
            } else {
                defaults?.set(trimmed, forKey: testHostKey)
            }
        }
    }

    /// "Whitelist" target — should remain reachable under TSPU whitelist
    /// throttling (Yandex / Sberbank / ru-gov anycast).
    static var whitelistHost: String {
        get {
            let stored = defaults?.string(forKey: whitelistHostKey) ?? ""
            return stored.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? defaultWhitelistHost : stored
        }
        set {
            let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                defaults?.removeObject(forKey: whitelistHostKey)
            } else {
                defaults?.set(trimmed, forKey: whitelistHostKey)
            }
        }
    }

    /// How many consecutive "clear" cycles before switching back from
    /// backup to primary. Default 2. Range 1…10.
    static var successesNeeded: Int {
        get {
            let v = defaults?.integer(forKey: successesKey) ?? 0
            return v >= 1 && v <= 10 ? v : defaultSuccessesNeeded
        }
        set {
            let clamped = max(1, min(10, newValue))
            defaults?.set(clamped, forKey: successesKey)
        }
    }

    /// Seconds between probe cycles. Default 3. Range 1…30.
    static var probeInterval: Int {
        get {
            let v = defaults?.integer(forKey: intervalKey) ?? 0
            return v >= 1 && v <= 30 ? v : defaultProbeInterval
        }
        set {
            let clamped = max(1, min(30, newValue))
            defaults?.set(clamped, forKey: intervalKey)
        }
    }

    /// Restore all settings to their compiled-in defaults.
    static func reset() {
        defaults?.removeObject(forKey: testHostKey)
        defaults?.removeObject(forKey: whitelistHostKey)
        defaults?.removeObject(forKey: successesKey)
        defaults?.removeObject(forKey: intervalKey)
    }
}
