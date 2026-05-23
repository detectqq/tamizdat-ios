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

    // Phase 2G: VK Smart Captcha required a human. Posted whenever
    // `TURNCredsRefresher.manualChallenge` flips from nil to non-nil
    // (i.e. the auto-solver bailed because VK served a slider).
    // Deliberately NOT gated by NotificationPreferences.enabled — this
    // is on the critical path; without it the VPN silently dies when
    // VK rotates to a slider variant.
    static let captchaRequiredID = "captcha.required"
}

/// Convenience helpers for the captcha-required notification.
/// Separated from `NotificationPreferences` because that enum stores
/// the master toggle (which captcha notifications deliberately bypass).
enum CaptchaNotification {
    /// Schedule the local notification immediately. iOS permission
    /// authorization is checked synchronously — if denied, this is a
    /// no-op (we can't surface anything; the manual sheet still shows
    /// inside the app on next launch).
    @MainActor
    static func post() {
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized
                    || settings.authorizationStatus == .provisional
            else { return }
            let content = UNMutableNotificationContent()
            content.title = "Tamizdat"
            content.body = "Решите капчу, чтобы прокси продолжал работать"
            content.sound = .default
            let req = UNNotificationRequest(
                identifier: NotificationIDs.captchaRequiredID,
                content: content,
                trigger: nil
            )
            center.add(req, withCompletionHandler: nil)
        }
    }

    /// Cancel an outstanding captcha-required prompt. Called when the
    /// user resolves the challenge or cancels it.
    @MainActor
    static func cancel() {
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers:
            [NotificationIDs.captchaRequiredID])
        center.removeDeliveredNotifications(withIdentifiers:
            [NotificationIDs.captchaRequiredID])
    }
}
