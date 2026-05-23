import Foundation
import SwiftUI

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

    private init() {}

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
                self.lastSaveAt = Date()
                self.lastError = nil
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
            }
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
