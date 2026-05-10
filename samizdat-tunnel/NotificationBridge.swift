import Foundation
import SamizdatClient
import UserNotifications

/// Bridges Go-side `OnNotification` callbacks (server-pushed
/// `CoverConfigBundle.Notification`, Phase C, 2026-05-10) into:
///   1. App Group UserDefaults under `tamizdat.lastNotification` — so the
///      foreground app can render an alert on resume / observer fire.
///   2. `UNUserNotificationCenter` local notification — so the user still
///      sees the message when the app is backgrounded.
///   3. Darwin CFNotification — wakes the foreground app to re-read App
///      Group UserDefaults reactively.
///
/// Gated on `NotificationPreferences.enabled` (reusing the existing
/// whitelist-alerts toggle per cookbook §7 Q4 default). The OS-level UN
/// notification post is skipped when the toggle is off, but the App Group
/// persist + Darwin wake still fire so an in-app banner can render if the
/// app happens to be foregrounded.
///
/// `NSObject` so the gomobile-emitted ObjC binding (Go interface →
/// `SocksstubNotificationCallbackProtocol`) can call us. The single Go
/// callback method `OnNotification(code, title, body, locale string)` is
/// surfaced in Swift as `onNotification(_:title:body:locale:)`.
final class NotificationBridge: NSObject, SocksstubNotificationCallbackProtocol {
    static let shared = NotificationBridge()

    /// Called from a Go goroutine. Bounce to a Swift dispatch queue before
    /// touching UserDefaults / UNUserNotificationCenter.
    func onNotification(_ code: String?, title: String?, body: String?, locale: String?) {
        let payload = NotificationPayload(
            code: code ?? "",
            title: title ?? "",
            body: body ?? "",
            locale: locale ?? "",
            postedAt: Date().timeIntervalSince1970
        )
        DispatchQueue.global(qos: .userInitiated).async {
            Self.persist(payload)
            Self.postLocal(payload)
            Self.postDarwin()
        }
    }

    // MARK: - Internals

    private static func persist(_ p: NotificationPayload) {
        guard let defaults = UserDefaults(suiteName: ServerNotificationConstants.appGroupID) else {
            return
        }
        if let data = try? JSONEncoder().encode(p) {
            defaults.set(data, forKey: ServerNotificationConstants.userDefaultsKey)
        }
    }

    private static func postLocal(_ p: NotificationPayload) {
        // Gate OS-level banner on the user-facing toggle (cookbook §5(c)
        // Step 2). App Group persist + Darwin wake already happened, so a
        // foregrounded app still gets an in-app alert via the observer.
        guard NotificationPreferences.enabled else { return }

        let content = UNMutableNotificationContent()
        content.title = p.title.isEmpty ? "Tamizdat" : p.title
        if !p.body.isEmpty { content.body = p.body }
        content.sound = .default
        content.categoryIdentifier = ServerNotificationConstants.unCategoryIdentifier
        // `code` as identifier → a re-delivered same-code notification
        // replaces the existing one in Notification Center (no double-buzz).
        let id = ServerNotificationConstants.unIdentifierPrefix + p.code
        let req = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { _ in /* best-effort */ }
    }

    private static func postDarwin() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(ServerNotificationConstants.darwinNotificationName),
            nil, nil, true
        )
    }
}
