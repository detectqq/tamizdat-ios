import SwiftUI
import BackgroundTasks

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
    /// creds are within `TURNCredsStore.refreshCushion` (15 min) of
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

        // VK TURN credentials live ~1 hour; we lean on three refresh
        // channels:
        //   1. Foreground 5-min Timer inside TURNCredsRefresher.shared
        //      (armed in its init, fires whenever app is in memory).
        //   2. scenePhase.active hook below (covers app-foreground races
        //      where the Timer hasn't ticked yet).
        //   3. BGAppRefreshTaskRequest — registered here at launch, fires
        //      whenever iOS gives us a slot (~45 min nominal cadence).
        // The BG identifier MUST match
        //   - `Info.plist::BGTaskSchedulerPermittedIdentifiers`
        //   - `TURNCredsRefresher.backgroundTaskIdentifier`
        // …or the register call throws at runtime.
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: TURNCredsRefresher.backgroundTaskIdentifier,
            using: nil // any queue iOS hands us
        ) { task in
            guard let refreshTask = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            TURNCredsRefresher.runBackgroundRefresh(task: refreshTask)
        }
        // Queue the first request straight away so iOS has something
        // on the books even if the user never touches the app again
        // during this lifecycle.
        TURNCredsRefresher.scheduleBackgroundRefresh()
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
                    // If creds are about to expire (less than 10 min
                    // remaining), force a refresh regardless of the
                    // cushion threshold. This is the operator's
                    // "I opened the app right before I needed it"
                    // scenario — burn one VK API hit rather than risk
                    // a 15-s connect timeout.
                    if let creds = TURNCredsStore.shared.load(),
                       creds.expiresAt.timeIntervalSinceNow < 600 {
                        TURNCredsRefresher.shared.forceRefresh()
                    } else {
                        TURNCredsRefresher.shared.refreshIfNeeded()
                    }
                }
            }
        }
    }
}
