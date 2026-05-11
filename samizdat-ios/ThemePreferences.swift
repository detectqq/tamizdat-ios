import Foundation
import SwiftUI

/// IPA-D22: persistence for the cream/dark theme picker in Settings →
/// Appearance. Default is `.cream` (operator decision; see CLAUDE.md).
///
/// We store the choice in standard UserDefaults rather than the App
/// Group container because the theme is a main-app-only concern — the
/// extension doesn't render any UI.
enum AppTheme: String, CaseIterable, Identifiable {
    case cream
    case dark

    var id: String { rawValue }

    /// Title shown in the segmented control.
    var label: String {
        switch self {
        case .cream: return "Cream"
        case .dark:  return "Dark"
        }
    }

    /// Maps the user pick to a SwiftUI `ColorScheme`. We always force a
    /// scheme — the design relies on theme tokens, not system colours,
    /// so the iOS system Dark/Light switch must NOT auto-flip the UI.
    var colorScheme: ColorScheme {
        switch self {
        case .cream: return .light
        case .dark:  return .dark
        }
    }

    /// Matching ThemeTokens.
    var tokens: ThemeTokens {
        switch self {
        case .cream: return .cream
        case .dark:  return .dark
        }
    }
}

enum ThemePreferences {
    private static let key = "tamizdat.theme"

    static var current: AppTheme {
        get {
            let raw = UserDefaults.standard.string(forKey: key) ?? AppTheme.cream.rawValue
            return AppTheme(rawValue: raw) ?? .cream
        }
        set {
            UserDefaults.standard.set(newValue.rawValue, forKey: key)
        }
    }
}
