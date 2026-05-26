import Foundation

/// When whitelist handling is OFF (endpoint mode Main), traffic always uses
/// the main H2 `tamizdat://` URI, regardless of this picker.
///
/// When whitelist handling is active (manual Whitelist endpoint, or Auto after
/// the detector switched to Whitelist), this enum decides what that whitelist
/// endpoint means.
///
///   - `.h2Backup` — dial the secondary/whitelist `tamizdat://` URI the user
///                   pasted in Config/Endpoints.
///   - `.vkTurn`   — route traffic through the configured TURN relay instead.
///                   The H2 whitelist URI is preserved but not required for
///                   TURN mode.
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
