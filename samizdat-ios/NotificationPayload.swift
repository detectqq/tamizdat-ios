import Foundation

/// Server-pushed user-facing notification (Phase C, 2026-05-10).
///
/// Delivered to the client as a `CoverConfigBundle.Notification` field on a
/// magic-CONNECT bundle fetch. The extension persists the most recent payload
/// into App Group UserDefaults under `tamizdat.lastNotification`; the main app
/// observes a Darwin notification and re-reads the value to render an alert.
///
/// Shared between the `samizdat-ios` app target and the `samizdat-tunnel`
/// extension target via `project.yml` — both targets use the same wire shape.
struct NotificationPayload: Codable, Equatable {
    /// Machine-readable cause: `"quota_exhausted"`, `"expired"`,
    /// `"admin_message"`, `"admin_broadcast"`, `"notification_pending"`.
    let code: String
    /// Short human-readable title (server-supplied, may be Russian).
    let title: String
    /// Longer free-form text, may be empty.
    let body: String
    /// BCP-47 hint, e.g. `"ru"`.
    let locale: String
    /// Unix epoch seconds when the bridge received the callback.
    let postedAt: TimeInterval
}

/// Constants shared between app and extension for Phase C iOS-notify.
enum ServerNotificationConstants {
    static let appGroupID = "group.com.anarki.samizdat-test"
    static let userDefaultsKey = "tamizdat.lastNotification"
    static let darwinNotificationName: CFString =
        "com.anarki.samizdat-test.notification.posted" as CFString
    static let unCategoryIdentifier = "TAMIZDAT_SERVER_MSG"
    static let unIdentifierPrefix = "tamizdat.server."
}

struct TurnProfileUpdatePayload: Codable, Equatable {
    let provider: String
    let roomHashPrefix: String
    let peer: String
    let version: Int
    let postedAt: TimeInterval
}

enum TurnProfileUpdateConstants {
    static let appGroupID = ServerNotificationConstants.appGroupID
    static let userDefaultsKey = "tamizdat.lastTurnProfileUpdate"
    static let darwinNotificationName: CFString =
        "com.anarki.samizdat-test.turn-profile.updated" as CFString
}
