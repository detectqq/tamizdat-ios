import Foundation

/// IPA-D21: user-facing setting for the real-internet ping prober's
/// target URL. Persisted in App Group UserDefaults so the extension can
/// read it at startTunnel time and on live "refreshPingURL" provider
/// messages.
///
/// Mirrors the NotificationPreferences / EndpointMode storage pattern
/// — single source of truth in App Group UserDefaults under
/// `tamizdat.pingProbeURL`. Default points at Google's connectivity
/// probe (returns 204 No Content, ~tiny payload, well-known stable).
enum PingURLPreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let key = "tamizdat.pingProbeURL"
    static let defaultURL = "https://ya.ru"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Current URL the prober pings, or the default if the user has not
    /// set one (or set it to empty). Both reader (extension + app side)
    /// and writer (app side, via SettingsView) hit this.
    static var url: String {
        get {
            let stored = defaults?.string(forKey: key) ?? ""
            return stored.isEmpty ? defaultURL : stored
        }
        set {
            let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                defaults?.removeObject(forKey: key)
            } else {
                defaults?.set(trimmed, forKey: key)
            }
        }
    }

    /// Clears the stored value so reads return the default.
    static func resetToDefault() {
        defaults?.removeObject(forKey: key)
    }
}
