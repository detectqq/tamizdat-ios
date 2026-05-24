import Foundation
import SwiftUI
import BackgroundTasks
import UserNotifications

/// Drives VK TURN credential acquisition + caching on the main-app side.
///
/// WHY this file is main-app-only: it owns `CaptchaWebViewManager`
/// (WKWebView) and the SwiftUI plumbing for the manual fallback
/// (`ManualCaptchaSheet`). The Network Extension cannot import WebKit
/// — Apple disallows WKWebView in app extensions, and the build
/// would fail. The pure-read side (`TURNCredsStore`,
/// `VKTURNCredentials`, `VKCredsPreferences`) lives in
/// `TURNCredsStore.swift` and IS shared with the extension target.
///
/// Lifetimes:
///   - Single shared instance per process; survives scene transitions.
///   - Owns a per-process `VKCredsClient` actor — its URLSession +
///     cookie jar live as long as the app process.
///   - The slider-fallback flow is surfaced via `manualChallenge`,
///     which `ContentView` binds to a `ManualCaptchaSheet`. When the
///     sheet finishes, the coordinator resumes its waiting
///     continuation with the user-supplied success_token.
@MainActor
final class TURNCredsRefresher: ObservableObject {
    static let shared = TURNCredsRefresher()

    /// True while a refresh is in flight. Drives the "Resolving
    /// captcha..." status indicator + dedupes concurrent triggers.
    @Published private(set) var isRefreshing: Bool = false

    /// Last refresh outcome — nil until the first attempt lands.
    /// Surfaced for UI / log display.
    @Published private(set) var lastError: String?

    /// When non-nil, a `ManualCaptchaSheet` should be presented so
    /// the user can solve the slider. The sheet calls `resolveManual`
    /// / `cancelManual` to drive the refresh forward.
    @Published var manualChallenge: ManualChallenge?

    /// Active single-flight task; we cancel + replace rather than
    /// stacking refreshes when multiple scene-active events fire in
    /// quick succession.
    private var inFlight: Task<Void, Never>?

    /// Last successful App Group credentials write in this process.
    /// Used to debounce accidental immediate `forceRefresh` replays.
    private var lastSaveAt: Date?

    /// Manual-fallback handoff: when the auto solver throws
    /// `.sliderRequired`, we open the sheet and `await` this
    /// continuation. The sheet calls `resolveManual(token:)` to
    /// resume with the token or `cancelManual()` to throw.
    private var manualContinuation: CheckedContinuation<String, Error>?

    /// 5-minute foreground heartbeat — while the app is alive in the
    /// foreground (or kept alive by the VPN extension's main-app
    /// host), this timer calls `refreshIfNeeded()` every 300 s. Paired
    /// with the 15-min `refreshCushion`, that gives four refresh
    /// chances per credential lifetime — enough to ride through any
    /// single network hiccup without ever letting creds expire.
    private var heartbeatTimer: Timer?

    /// Number of refresh attempts that have failed in a row. Reset on
    /// success. When it hits `failureNotificationThreshold` we
    /// schedule a local notification so the user knows to open the
    /// app and solve a captcha manually.
    private var consecutiveFailures: Int = 0

    /// BG task identifier — MUST match the one registered in
    /// `BGTaskScheduler.shared.register(...)` (called from App.swift)
    /// and the `BGTaskSchedulerPermittedIdentifiers` array in
    /// `Info.plist`. Keep all three in sync.
    ///
    /// `nonisolated` so the BG-task register closure in App.swift can
    /// read it from off-MainActor without an `await`.
    nonisolated static let backgroundTaskIdentifier = "com.anarki.samizdat-test.creds-refresh"

    private init() {
        startHeartbeat()
    }

    /// Identifies a pending manual challenge for the SwiftUI sheet.
    struct ManualChallenge: Identifiable, Equatable {
        let id = UUID()
        let redirectURI: URL
        let sessionToken: String
    }

    /// Fire-and-forget refresh entry point. Called from `App.swift`
    /// on scenePhase.active. Idempotent — if a refresh is in progress
    /// or creds are still fresh, this returns immediately.
    func refreshIfNeeded() {
        TURNLog.info("turncreds", "refreshIfNeeded called")
        guard !isRefreshing else {
            TURNLog.warn("turncreds", "refreshIfNeeded: skipped — isRefreshing is true")
            return
        }
        guard VKCredsPreferences.isConfigured else {
            TURNLog.warn("turncreds", "refreshIfNeeded: skipped — isConfigured is false")
            return
        }
        guard TURNCredsStore.shared.needsRefresh else {
            TURNLog.warn("turncreds", "refreshIfNeeded: skipped — needsRefresh is false")
            return
        }
        startRefresh()
    }

    /// Manually trigger a refresh regardless of staleness. Intended
    /// for "Refresh now" UI affordances; currently unused but kept
    /// public so a future Settings row can call it.
    func forceRefresh() {
        if let elapsedMs = millisecondsSinceLastSave,
           elapsedMs < Int(Self.forceRefreshDebounceAfterSave * 1000) {
            TURNLog.warn("turncreds", "forceRefresh debounced (\(elapsedMs) ms since last save)")
            return
        }
        TURNLog.info("turncreds", "forceRefresh called")
        guard !isRefreshing else {
            TURNLog.warn("turncreds", "forceRefresh: skipped — isRefreshing is true")
            return
        }
        guard VKCredsPreferences.isConfigured else {
            TURNLog.warn("turncreds", "forceRefresh: skipped — isConfigured is false")
            return
        }
        startRefresh()
    }

    /// Called by `ManualCaptchaSheet.onSuccess` — hands the user-
    /// solved token back to the in-flight refresh task.
    func resolveManual(token: String) {
        TURNLog.info("turncreds", "manual token resolved (length=\(token.count))")
        manualChallenge = nil
        CaptchaNotification.cancel()
        manualContinuation?.resume(returning: token)
        manualContinuation = nil
    }

    /// Called by `ManualCaptchaSheet.onCancel` — aborts the refresh.
    func cancelManual() {
        TURNLog.warn("turncreds", "manual captcha cancelled by user")
        manualChallenge = nil
        CaptchaNotification.cancel()
        manualContinuation?.resume(throwing: CaptchaError.cancelled)
        manualContinuation = nil
    }

    // MARK: – Private

    /// Overall watchdog: if the refresh hasn't completed in this many
    /// seconds, the Task is cancelled so `isRefreshing` flips back to
    /// false and the next Save attempt isn't dead in the water.
    /// Sized generously: per-request timeout is 20s, max 5 retries +
    /// up to 45s captcha solve = ~145s worst case. 180s gives slack.
    private static let watchdogTimeout: TimeInterval = 180

    /// Belt-and-suspenders guard: after a successful save, any
    /// `forceRefresh` replay within this window is programmatic noise
    /// (not a human tap) and would burn another VK captcha session.
    private static let forceRefreshDebounceAfterSave: TimeInterval = 2

    private var millisecondsSinceLastSave: Int? {
        guard let lastSaveAt else { return nil }
        return Int(Date().timeIntervalSince(lastSaveAt) * 1000)
    }

    private func startRefresh() {
        inFlight?.cancel()
        isRefreshing = true
        lastError = nil
        TURNLog.info("turncreds", "starting refresh task")

        inFlight = Task { @MainActor [weak self] in
            guard let self else { return }
            defer {
                self.isRefreshing = false
                self.inFlight = nil
            }
            do {
                let config = VKCredsConfig(
                    callHash: VKCredsPreferences.primaryCallHash,
                    secondaryHash: VKCredsPreferences.secondaryCallHash,
                    deviceID: VKCredsPreferences.deviceID
                )
                let hashPrefix = String(VKCredsPreferences.primaryCallHash.prefix(8))
                TURNLog.info("turncreds", "config built (hash=\(hashPrefix)...)")
                let client = VKCredsClient(config: config,
                                            captchaSolver: ChainedCaptchaSolver(refresher: self))
                // Race fetchCredentials against a watchdog so a wedged
                // network call or stuck WKWebView can't lock the
                // refresher into `isRefreshing=true` forever.
                let creds = try await withThrowingTaskGroup(of: VKTURNCredentials.self) { group in
                    group.addTask {
                        try await client.fetchCredentials()
                    }
                    group.addTask {
                        try await Task.sleep(nanoseconds: UInt64(Self.watchdogTimeout * 1_000_000_000))
                        TURNLog.error("turncreds", "watchdog fired — refresh exceeded \(Int(Self.watchdogTimeout))s")
                        throw VKCredsError.transport(step: "watchdog", underlying: CancellationError())
                    }
                    guard let first = try await group.next() else {
                        throw CancellationError()
                    }
                    group.cancelAll()
                    return first
                }
                TURNLog.info("turncreds", "creds received, saving")
                TURNCredsStore.shared.save(creds)
                // Push the fresh snapshot into the in-process Go VK
                // TURN runner so the next worker-group rotation uses
                // them — without this hop the runner kept reading the
                // creds it took at startup and started 401-ing once
                // the original 3600 s lifetime elapsed.
                //
                // The runner lives in the extension process, not the
                // main app, so this call against the main-app's own
                // (always-nil) runner returns "not running" — we
                // swallow that quietly and rely on the App Group
                // mirror + a follow-up provider message for the
                // cross-process plumbing.
                let credsJSON = vkCredsAsJSON(creds: creds)
                let updateErr = SamizdatBridge.updateVKTurnCreds(credsJSON)
                if updateErr.isEmpty {
                    TURNLog.info("turncreds", "VK TURN runner creds updated in-process")
                } else if updateErr == "not running" {
                    TURNLog.info("turncreds", "VK TURN runner not running in this process — App Group mirror still updated")
                } else {
                    TURNLog.warn("turncreds", "SocksstubUpdateVKTurnCreds returned: \(updateErr)")
                }
                self.lastSaveAt = Date()
                self.lastError = nil
                self.consecutiveFailures = 0
                CredsRefreshNotification.cancel()
                // After every successful refresh, queue the next BG
                // task so iOS has a fresh request to satisfy ~45 min
                // from now. iOS will only fire it when it has budget,
                // but at least the request is on the books.
                Self.scheduleBackgroundRefresh()
            } catch {
                let msg: String
                if let e = error as? VKCredsError {
                    msg = e.localizedDescription
                } else if let e = error as? CaptchaError {
                    msg = e.localizedDescription
                } else {
                    msg = error.localizedDescription
                }
                TURNLog.error("turncreds", "refresh failed: \(msg)")
                self.lastError = msg
                self.consecutiveFailures += 1
                TURNLog.warn("turncreds", "consecutive failures = \(self.consecutiveFailures)")
                if self.consecutiveFailures >= Self.failureNotificationThreshold {
                    TURNLog.warn("turncreds",
                        "failure threshold reached — scheduling captcha-needed notification")
                    CredsRefreshNotification.scheduleCaptchaNeeded()
                }
            }
        }
    }

    /// 3 in a row triggers the user-facing "капча требуется" local
    /// notification. We let the first couple slip silently because
    /// transient network blips are common and would otherwise spam
    /// the user every time they get on the bus.
    private static let failureNotificationThreshold = 3

    /// 5-minute foreground heartbeat cadence. Drives `refreshIfNeeded`,
    /// which itself is a no-op when creds are fresh.
    private static let heartbeatInterval: TimeInterval = 300

    /// Target spacing between BG refreshes — iOS treats this as a
    /// lower bound, not a contract. Real fire latency varies with
    /// device usage; the iOS scheduler aims to coalesce app refreshes
    /// roughly hourly, but on quiet devices we frequently see 45-60
    /// min cadences in practice.
    private static let backgroundRefreshTargetInterval: TimeInterval = 45 * 60

    /// Arm the 5-minute Timer. Idempotent — re-firing this swaps the
    /// timer cleanly rather than stacking multiple fires.
    private func startHeartbeat() {
        heartbeatTimer?.invalidate()
        let timer = Timer.scheduledTimer(
            withTimeInterval: Self.heartbeatInterval,
            repeats: true
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                TURNLog.info("turncreds", "heartbeat tick → refreshIfNeeded()")
                self.refreshIfNeeded()
            }
        }
        // Tolerance lets iOS coalesce the fire with other timers,
        // saving battery — a few seconds of skew on a 5-min beat is
        // fine.
        timer.tolerance = 30
        // Common run-loop mode so the timer keeps firing while we're
        // in a sheet / scrolling. Without this we miss ticks while
        // SwiftUI presents Settings.
        RunLoop.main.add(timer, forMode: .common)
        heartbeatTimer = timer
        TURNLog.info("turncreds", "heartbeat armed (\(Int(Self.heartbeatInterval))s interval)")
    }

    /// Schedule the next BG App Refresh request. Called after every
    /// successful refresh AND from App.swift on launch (so the very
    /// first request is on the books before any creds exist).
    /// Failure (no entitlement, simulator) is logged and swallowed —
    /// we never want to crash the launch path because of BG plumbing.
    ///
    /// `nonisolated` because callers include the BGTaskScheduler
    /// register-handler closure (unspecified queue) and the post-
    /// refresh path which is already on MainActor — we touch no
    /// instance state, just the `BGTaskScheduler` singleton.
    nonisolated static func scheduleBackgroundRefresh() {
        let req = BGAppRefreshTaskRequest(identifier: Self.backgroundTaskIdentifier)
        req.earliestBeginDate = Date(timeIntervalSinceNow: Self.backgroundRefreshTargetInterval)
        do {
            try BGTaskScheduler.shared.submit(req)
            TURNLog.info("turncreds",
                "BG refresh scheduled for ~\(Int(Self.backgroundRefreshTargetInterval / 60))min from now")
        } catch {
            TURNLog.warn("turncreds",
                "BG refresh schedule failed: \(error.localizedDescription) (simulator / missing entitlement / debugger attached are normal)")
        }
    }

    /// Drive a BG-task-bounded refresh. Called from App.swift's
    /// `BGTaskScheduler.register` handler. We give the work 25 s of
    /// wallclock — iOS budgets BG App Refresh at ~30 s, so 25 leaves
    /// room for the framework to wind us down cleanly via
    /// `setTaskCompleted(success:)`.
    ///
    /// The captured `BGTask` is held by the caller; we just kick the
    /// work and tell them when to finish. iOS may interrupt us
    /// earlier via `expirationHandler` — we honour the cancel by
    /// resolving the continuation.
    ///
    /// `nonisolated` because iOS calls register-handlers on an
    /// unspecified queue. All MainActor work happens inside the
    /// `Task { @MainActor in ... }` blocks below.
    nonisolated static func runBackgroundRefresh(task: BGAppRefreshTask) {
        TURNLog.info("turncreds", "BG refresh fired by iOS")
        // Always queue the next request — even on failure path. iOS
        // will not auto-renew; if we skip the resubmit, the app loses
        // its only autonomous refresh slot until next foreground.
        scheduleBackgroundRefresh()

        // 25-s budget watchdog. Fires the success/failure callback so
        // iOS marks us complete before it would have killed us.
        let budget: TimeInterval = 25
        let deadline = Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(budget * 1_000_000_000))
            TURNLog.warn("turncreds", "BG refresh budget exhausted (\(Int(budget))s) — marking complete")
            task.setTaskCompleted(success: false)
        }
        task.expirationHandler = {
            TURNLog.warn("turncreds", "BG refresh expired by iOS")
            deadline.cancel()
        }
        Task { @MainActor in
            TURNCredsRefresher.shared.refreshIfNeeded()
            // Give the in-flight Task time to finish before reporting
            // complete. Poll the isRefreshing flag with a 1-s interval
            // for up to 22 s (leaving 3 s slack against the 25 s
            // budget watchdog above).
            for _ in 0..<22 {
                if !TURNCredsRefresher.shared.isRefreshing { break }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
            deadline.cancel()
            let ok = (TURNCredsRefresher.shared.lastError == nil)
            TURNLog.info("turncreds", "BG refresh completing success=\(ok)")
            task.setTaskCompleted(success: ok)
        }
    }

    /// Emergency reset for the "stuck refresh" state. Cancels the
    /// in-flight Task (if any), drops the manual continuation, and
    /// flips `isRefreshing` back to false so a subsequent forceRefresh
    /// can start fresh. Exposed via Settings → VK TURN → Reset.
    func resetRefreshState() {
        TURNLog.warn("turncreds", "resetRefreshState called — cancelling in-flight task")
        inFlight?.cancel()
        inFlight = nil
        manualContinuation?.resume(throwing: CaptchaError.cancelled)
        manualContinuation = nil
        manualChallenge = nil
        CaptchaNotification.cancel()
        isRefreshing = false
        lastError = "Сброшено вручную"
    }

    /// Spawn a manual challenge and suspend until the user resolves
    /// (or cancels). Called by `ChainedCaptchaSolver` below when the
    /// auto solver bails with `.sliderRequired`.
    fileprivate func awaitManual(redirectURI: URL, sessionToken: String) async throws -> String {
        TURNLog.info("turncreds", "manual captcha requested (host=\(redirectURI.host ?? "<unknown>"))")
        // Fire the iOS notification so the user knows to open the app
        // even if it's in the background. Operator requirement: this
        // must be unconditional (bypass NotificationPreferences.enabled)
        // because the VPN silently dies otherwise.
        CaptchaNotification.post()
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            self.manualContinuation = cont
            self.manualChallenge = ManualChallenge(
                redirectURI: redirectURI,
                sessionToken: sessionToken
            )
        }
    }
}

/// Notification helper for the "auto-refresh ran out of options"
/// state: 3 consecutive failures (couldn't auto-solve, network timeout,
/// VK threw a slider) raise a local notification so the user opens
/// the app and resolves the manual captcha sheet.
///
/// Separate from `CaptchaNotification` (which fires for the
/// already-in-flight slider challenge) because we may want to coalesce
/// or differentiate the two later. Same App Group, same UN center,
/// different identifier.
enum CredsRefreshNotification {
    /// UN identifier. Kept stable so consecutive schedules collapse
    /// onto each other (iOS dedupes by identifier).
    static let identifier = "tamizdat.captcha-needed"

    /// Body kept short so it fits the lockscreen / banner. Russian
    /// per project i18n convention.
    private static let title = "Tamizdat"
    private static let body = "Капча требуется — откройте приложение"

    /// Coalesce: cancel any pending instance before scheduling a
    /// fresh one. Without the cancel, iOS just keeps the existing
    /// pending request (identifier-deduped) but doesn't surface a new
    /// banner — the user sees the same stale alert.
    @MainActor
    static func scheduleCaptchaNeeded() {
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized
                    || settings.authorizationStatus == .provisional
            else {
                TURNLog.warn("turncreds",
                    "captcha-needed notification not authorized — skip")
                return
            }
            center.removePendingNotificationRequests(withIdentifiers: [identifier])
            center.removeDeliveredNotifications(withIdentifiers: [identifier])
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            let req = UNNotificationRequest(
                identifier: identifier,
                content: content,
                trigger: nil
            )
            center.add(req, withCompletionHandler: nil)
            TURNLog.warn("turncreds",
                "captcha-needed notification scheduled (auto-refresh failed 3+ times)")
        }
    }

    /// Drop a pending / delivered captcha-needed banner — called when
    /// a refresh finally succeeds so the user doesn't see a stale
    /// "captcha needed" notification after the app already healed.
    @MainActor
    static func cancel() {
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [identifier])
        center.removeDeliveredNotifications(withIdentifiers: [identifier])
    }
}

/// Pluggable solver that tries the hidden WKWebView first, then
/// escalates to a manual SwiftUI sheet (`ManualCaptchaSheet`) on
/// `.sliderRequired`. The escalation is asynchronous — the refresh
/// task suspends until the user solves the slider or cancels.
///
/// `@unchecked Sendable` is safe here: the wrapped reference is only
/// touched on `@MainActor` (the protocol awaits on `awaitManual`,
/// which hops back to MainActor automatically).
private struct ChainedCaptchaSolver: VKCaptchaSolver, @unchecked Sendable {
    weak var refresher: TURNCredsRefresher?

    func solve(redirectURI: URL, sessionToken: String) async throws -> String {
        do {
            return try await CaptchaWebViewManager.shared.solveCaptcha(
                redirectURI: redirectURI,
                sessionToken: sessionToken
            )
        } catch CaptchaError.sliderRequired {
            guard let r = refresher else {
                throw CaptchaError.cancelled
            }
            // `awaitManual` is @MainActor-isolated; the await hops the
            // current task onto MainActor automatically.
            return try await r.awaitManual(
                redirectURI: redirectURI,
                sessionToken: sessionToken
            )
        }
    }
}
