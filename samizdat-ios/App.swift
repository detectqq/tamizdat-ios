import SwiftUI

@main
struct SamizdatTestApp: App {
    /// IPA-D22: theme is held at the App level so any sheet/child gets
    /// the right tokens via `@Environment(\.themeTokens)`. SettingsView's
    /// Appearance segmented control posts `Notification.Name
    /// .tamizdatThemeChanged` when the user picks a new theme; the root
    /// listens and re-reads `ThemePreferences.current` to update.
    @State private var theme: AppTheme = ThemePreferences.current

    init() {
        // Register Geist fonts as a safety net (Info.plist's UIAppFonts
        // should already have done this but xcodegen has historically
        // dropped the entry, and the fallback to SF Pro is loud — best
        // to also register at launch).
        GeistFont.register()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(\.themeTokens, theme.tokens)
                .preferredColorScheme(theme.colorScheme)
                .onReceive(NotificationCenter.default.publisher(for: .tamizdatThemeChanged)) { _ in
                    theme = ThemePreferences.current
                }
        }
    }
}
