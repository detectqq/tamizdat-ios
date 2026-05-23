import Foundation

/// When the whitelist detector flips the tunnel onto the "whitelist"
/// endpoint, this enum decides WHAT that endpoint actually is.
///
///   - `.h2Backup` — the long-standing behaviour: dial the secondary
///                   `tamizdat://...` URI the user pasted in Settings.
///   - `.vkTurn`   — new (Phase 2G): route the same traffic through
///                   VK TURN instead. The backup URI is unused (but
///                   NOT deleted — the operator may flip back).
///
/// Stored in App Group UserDefaults so the Network Extension and the
/// main app see the same value through a shared suite.
enum WhitelistMode: String, CaseIterable, Identifiable {
    case h2Backup
    case vkTurn

    var id: String { rawValue }

    /// Russian label for SwiftUI pickers (operator-facing). Keep the
    /// strings short — they live inside a segmented control.
    var label: String {
        switch self {
        case .h2Backup: return "H2"
        case .vkTurn:   return "TURN"
        }
    }

    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let storeKey = "tamizdat.whitelistMode"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Current selection. Default is `.h2Backup` so existing installs
    /// keep their old behaviour after upgrade until the user opts in.
    static var current: WhitelistMode {
        get {
            guard let raw = defaults?.string(forKey: storeKey),
                  let mode = WhitelistMode(rawValue: raw) else {
                return .h2Backup
            }
            return mode
        }
        set {
            defaults?.set(newValue.rawValue, forKey: storeKey)
        }
    }
}
