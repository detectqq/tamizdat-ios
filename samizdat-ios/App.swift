import SwiftUI

@main
struct SamizdatTestApp: App {
    /// IPA-D22: theme is held at the App level so any sheet/child gets
    /// the right tokens via `@Environment(\.themeTokens)`. SettingsView's
    /// Appearance segmented control posts `Notification.Name
    /// .tamizdatThemeChanged` when the user picks a new theme; the root
    /// listens and re-reads `ThemePreferences.current` to update.
    @State private var theme: AppTheme = ThemePreferences.current

    /// IPA-D65b: scenePhase listener. The VK TURN refresher kicks off
    /// in the background when the app becomes active and the cached
    /// creds are within `TURNCredsStore.refreshCushion` (5 min) of
    /// expiry. We deliberately do NOT block startup — the refresh is
    /// a `Task { ... }` fire-and-forget. If creds are still fresh, the
    /// refresher returns immediately.
    @Environment(\.scenePhase) private var scenePhase

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
        .onChange(of: scenePhase) { _, newPhase in
            if newPhase == .active {
                // Fire-and-forget; the refresher is single-flight and
                // cheap when not needed (one App Group UserDefaults
                // read).
                Task { @MainActor in
                    TURNCredsRefresher.shared.refreshIfNeeded()
                }
            }
        }
    }
}
