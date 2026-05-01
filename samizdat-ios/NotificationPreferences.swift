import Foundation
import UserNotifications

/// User-facing toggle for whitelist-event notifications. Persisted in
/// App Group UserDefaults so the extension can read it directly when
/// firing local notifications on status change.
enum NotificationPreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let enabledKey = "notificationsEnabled"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Master switch. Default OFF — user must opt in (and grant iOS
    /// permission) explicitly the first time they flip it.
    static var enabled: Bool {
        get { defaults?.bool(forKey: enabledKey) ?? false }
        set { defaults?.set(newValue, forKey: enabledKey) }
    }

    /// Async helper for the main app to request iOS permission. Returns
    /// the granted status; the caller should bounce the toggle back to
    /// false if granted == false.
    static func requestPermission() async -> Bool {
        let center = UNUserNotificationCenter.current()
        do {
            return try await center.requestAuthorization(options: [.alert, .sound])
        } catch {
            return false
        }
    }

    /// Whether iOS currently has notifications enabled for this app.
    /// (User may have toggled them off in iOS Settings after granting
    /// permission earlier.) The extension uses this to short-circuit
    /// notification posting.
    static func currentSystemAuthorization() async -> UNAuthorizationStatus {
        await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
    }
}

/// Identifiers for whitelist-detection notifications. Kept as constants
/// so extension and main app post / handle them consistently.
enum NotificationIDs {
    static let categoryIdentifier = "WHITELIST_DETECTION"
    static let detectedID = "whitelist.detected"
    static let recoveredID = "whitelist.recovered"
}
