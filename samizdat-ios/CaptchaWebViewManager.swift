import Foundation
import UIKit
import WebKit
import OSLog

/// Hidden-WKWebView VK Smart Captcha solver. Port of the Android donor
/// `CaptchaWebViewManager.kt` (~600 LoC) from
/// `amurcanov/proxy-turn-vk-android`.
///
/// WHY a real WKWebView: the server-side reverse-JS solver hits VK with
/// a synthesized HTTP/2 fingerprint that VK detects and rejects with
/// `status: "BOT"`. A real WebKit instance has a genuine
/// TLS+ALPN+h2-frame fingerprint that VK does not flag. The Android
/// donor's author confirmed RJS is no longer their primary path —
/// WebView is. We mirror their flow.
///
/// One solve = one fresh WKWebView (with frame `.zero`, never attached
/// to UI hierarchy):
///   1. Build configuration with a randomized viewport / Chrome build
///      so two consecutive solves don't share an obvious fingerprint.
///   2. Install the shared `CaptchaJSInterceptor` script + the
///      `tamizdatCaptcha` script-message handler.
///   3. Load `redirect_uri`, wait 2.5-3.5 s ("human read delay").
///   4. Locate `label.vkc__Checkbox-module__Checkbox`, get its rect.
///      If a slider is shown instead → throw `.sliderRequired` so the
///      caller can fall back to `ManualCaptchaSheet`.
///   5. Simulate a touch by dispatching `touchstart`/`touchend` from
///      JS at a randomized point inside the label. iOS WKWebView does
///      not expose UITouch synthesis (Apple's private API on Android
///      lets you do real MotionEvent.ACTION_DOWN — we can't), so
///      JS-dispatched TouchEvent is the only correct primitive.
///   6. Poll for post-click slider appearance for ~7 s. If a slider
///      appears, throw `.sliderRequired`.
///   7. Wait for `success_token` via the JS interceptor or hit the
///      45 s overall timeout.
///
/// Concurrency: actor isolation guarantees one solve at a time. UI
/// touch (WKWebView creation, JS evaluation) happens on `@MainActor`.
/// The hidden web view is destroyed in a `defer` regardless of
/// outcome — leaking a WKWebView would keep an SQLite handle + ~5 MB
/// of process state alive.
///
/// Logging: `os.Logger` subsystem `com.anarki.samizdat-test.captcha`.

/// Errors thrown by `CaptchaWebViewManager.solveCaptcha`.
enum CaptchaError: Error, LocalizedError {
    /// VK presented a slider/kaleidoscope page instead of the checkbox.
    /// Caller falls back to `ManualCaptchaSheet`.
    case sliderRequired
    /// 45 s overall timeout — page wedged or VK never responded.
    case timeout
    /// VK API returned a JSON error block in the captcha response.
    case vkError(message: String)
    /// Caller cancelled the task or process is shutting down.
    case cancelled
    /// WKWebView construction failed (very rare; usually OOM).
    case webViewUnavailable

    var errorDescription: String? {
        switch self {
        case .sliderRequired:    return "VK потребовал слайдер"
        case .timeout:           return "Таймаут решения капчи (45с)"
        case .vkError(let msg):  return "Ошибка VK: \(msg)"
        case .cancelled:         return "Решение капчи отменено"
        case .webViewUnavailable: return "Не удалось создать WebView"
        }
    }
}

/// Public actor-isolated entry point. One solve at a time.
actor CaptchaWebViewManager {

    static let shared = CaptchaWebViewManager()

    private let log = Logger(subsystem: "com.anarki.samizdat-test.captcha", category: "auto")

    // ─── Tuning constants (mirrors Kotlin reference) ─────────────────

    // NOTE: these constants are `fileprivate` (not `private`) because they
    // are consumed by the `SolveSession` helper defined later in the same
    // file. `private` would restrict access to the actor body itself; the
    // helper is a separate type, so it would fail to see them. (Build CI
    // caught this — 2026-05-23.)
    fileprivate static let overallTimeout: TimeInterval = 45.0

    /// Random viewport widths (pixels). Picking from a small pool means
    /// VK rarely sees the same viewport twice across solves; constant
    /// 360×400 would be a giveaway.
    fileprivate static let viewportWidths: [CGFloat] = [356, 358, 360, 362, 364, 366, 368]
    fileprivate static let viewportHeights: [CGFloat] = [376, 378, 380, 382, 384, 386, 388]

    /// Pool of Chrome desktop builds. Choose one per solve so the User-
    /// Agent rotates. Numbers chosen to be plausibly current as of
    /// 2026-05.
    fileprivate static let chromeBuilds: [String] = [
        "146.0.0.0", "145.0.6422.60", "145.0.6422.53",
        "144.0.6367.78", "144.0.6367.61", "143.0.6312.99",
    ]

    // Random-delay ranges, all in seconds (Kotlin used ms longs).
    fileprivate static let pageReadDelayRange: ClosedRange<Double> = 2.5...3.5
    fileprivate static let thinkBeforeClickRange: ClosedRange<Double> = 1.5...3.5
    fileprivate static let touchHoldRange: ClosedRange<Double> = 0.08...0.18
    fileprivate static let postClickPollInterval: Double = 0.65
    fileprivate static let postClickAttempts: Int = 12
    fileprivate static let postClickFirstDelay: Double = 0.9

    // ─── State (actor-isolated) ──────────────────────────────────────

    private var inFlight: Bool = false

    // ─── Public API ─────────────────────────────────────────────────

    /// Solve one VK captcha challenge.
    ///
    /// - Parameters:
    ///   - redirectURI: the `redirect_uri` from the VK error payload.
    ///   - sessionToken: the `session_token` query value (not used by
    ///                   the WebView solver itself — VK reads it from
    ///                   the page URL — kept for symmetry with the Go
    ///                   reference and for future logging).
    ///   - onStep: optional callback for "page loaded", "click",
    ///             "waiting" status text. Caller routes to UI.
    /// - Returns: `success_token` issued by VK.
    /// - Throws: `CaptchaError`.
    func solveCaptcha(redirectURI: URL,
                      sessionToken: String,
                      onStep: ((String) -> Void)? = nil) async throws -> String {
        // Serialize: actor isolation already enforces one-at-a-time,
        // but we keep an explicit flag for symmetry with the Kotlin
        // Mutex.withLock pattern and to bail cleanly if a re-entrancy
        // bug ever sneaks in.
        if inFlight {
            log.error("solveCaptcha: re-entrant call rejected")
            throw CaptchaError.cancelled
        }
        inFlight = true
        defer { inFlight = false }

        TURNLog.info("captcha", "auto-solve started (host=\(redirectURI.host ?? "<unknown>"))")
        let token = sessionToken.isEmpty ? "<empty>" : "\(sessionToken.prefix(8))..."
        log.info("solve start: redirect=\(redirectURI.absoluteString, privacy: .public) session=\(token, privacy: .public)")

        do {
            let result = try await withThrowingTaskGroup(of: String.self) { group in
                group.addTask { [redirectURI, onStep] in
                    try await Self.driveSolveOnMain(redirectURI: redirectURI, onStep: onStep)
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(Self.overallTimeout * 1_000_000_000))
                    throw CaptchaError.timeout
                }

                let first = try await group.next()!
                group.cancelAll()
                return first
            }
            log.info("solve ok: token=\(result.count, privacy: .public)chars")
            TURNLog.info("captcha", "success_token received (length=\(result.count))")
            return result
        } catch CaptchaError.timeout {
            TURNLog.error("captcha", "auto-solve timed out")
            log.error("solve failed: \(CaptchaError.timeout.localizedDescription, privacy: .public)")
            throw CaptchaError.timeout
        } catch CaptchaError.sliderRequired {
            TURNLog.warn("captcha", "slider detected, falling back to manual")
            log.error("solve failed: \(CaptchaError.sliderRequired.localizedDescription, privacy: .public)")
            throw CaptchaError.sliderRequired
        } catch let err as CaptchaError {
            TURNLog.error("captcha", "auto-solve failed: \(err.localizedDescription)")
            log.error("solve failed: \(err.localizedDescription, privacy: .public)")
            throw err
        } catch {
            TURNLog.error("captcha", "auto-solve failed: \(error.localizedDescription)")
            log.error("solve failed: \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }

    // ─── Internal drive loop (hops to MainActor) ─────────────────────

    /// All WKWebView work runs on `@MainActor` (Apple requires it).
    /// We wrap that work in a continuation-bridged async function so
    /// the actor's serial executor sees a single suspending await.
    @MainActor
    private static func driveSolveOnMain(redirectURI: URL,
                                          onStep: ((String) -> Void)?) async throws -> String {
        let session = SolveSession(log: Logger(subsystem: "com.anarki.samizdat-test.captcha", category: "session"))
        return try await session.run(redirectURI: redirectURI, onStep: onStep)
    }
}

// MARK: – SolveSession (per-solve state, MainActor-bound)

/// One captcha solve. Lives on the main actor; owns the WKWebView,
/// the message handler proxy, and the continuation that resolves to
/// the success token. The session destroys itself on completion via
/// `defer` so the WKWebView never outlives the solve.
@MainActor
private final class SolveSession {
    private let log: Logger

    private var webView: WKWebView?
    private var continuation: CheckedContinuation<String, Error>?
    private var continuationDone: Bool = false

    /// Strong ref to the message handler proxy so it lives as long as
    /// the WKUserContentController retains it (WKContentController only
    /// holds the handler weakly through its name registration).
    private var messageProxy: ScriptMessageProxy?

    /// Strong ref to the navigation delegate proxy — WKWebView only
    /// weak-refs `navigationDelegate`, so we own it here.
    private var navigationProxy: NavigationProxy?

    /// Post-click slider watcher cancellation token.
    private var watcherTask: Task<Void, Never>?

    init(log: Logger) {
        self.log = log
    }

    /// Drives one solve. Resolves to the `success_token` or throws
    /// `CaptchaError`. Always tears down the WKWebView before
    /// returning.
    func run(redirectURI: URL, onStep: ((String) -> Void)?) async throws -> String {
        defer { teardown() }

        // Randomize fingerprint per solve.
        let vw = Self.pick(from: CaptchaWebViewManager.viewportWidths)
        let vh = Self.pick(from: CaptchaWebViewManager.viewportHeights)
        let chrome = Self.pick(from: CaptchaWebViewManager.chromeBuilds)
        let userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/\(chrome) Safari/537.36"
        log.info("fingerprint: \(Int(vw))x\(Int(vh)), Chrome/\(chrome, privacy: .public)")
        TURNLog.info("captcha", "fingerprint: Chrome/\(chrome), viewport \(Int(vw))x\(Int(vh))")

        // Wire WKWebView config: data store is non-persistent so the
        // captcha solve leaves no cookies / storage on the device, and
        // each fresh solve starts cold.
        let config = WKWebViewConfiguration()
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        config.applicationNameForUserAgent = nil

        // User content controller carries the interceptor + the message
        // bridge back to native.
        let userContent = WKUserContentController()
        let proxy = ScriptMessageProxy(onEvent: { [weak self] event in
            self?.handleEvent(event)
        })
        userContent.add(proxy, name: CaptchaJSInterceptor.handlerName)
        let userScript = WKUserScript(source: CaptchaJSInterceptor.script,
                                       injectionTime: .atDocumentStart,
                                       forMainFrameOnly: false)
        userContent.addUserScript(userScript)
        config.userContentController = userContent
        self.messageProxy = proxy

        // Build the hidden web view. frame = zero so even if some
        // accidental superview attach happens, nothing renders. The
        // VK captcha page reads viewport from JS `window.innerWidth`,
        // which we set via a small `viewport` injection below — pixel
        // bounds of the actual WKWebView don't drive the page.
        let wv = WKWebView(frame: CGRect(x: 0, y: 0, width: vw, height: vh),
                            configuration: config)
        wv.customUserAgent = userAgent
        wv.isHidden = true
        wv.scrollView.isScrollEnabled = false
        wv.allowsLinkPreview = false
        self.webView = wv

        // Navigation delegate — drives the state machine after load.
        let navProxy = NavigationProxy(onPageStart: { [weak self] in
            self?.injectInterceptor()
        }, onPageFinish: { [weak self] url in
            self?.onPageFinished(url: url, onStep: onStep)
        })
        wv.navigationDelegate = navProxy
        // Hold the navigation proxy by binding its lifetime to the
        // session; WKWebView only weak-refs its delegate.
        self.navigationProxy = navProxy

        // Suspend until either:
        //  - the JS interceptor posts `{ kind: success }`
        //  - the JS posts `{ kind: slider }` or `{ kind: error }`
        //  - the post-click watcher sees a slider in DOM
        //  - the parent task group times out (caller-side)
        let token = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            self.continuation = cont
            self.continuationDone = false

            // Kick off page load.
            log.info("loading captcha page")
            onStep?("Загружаем страницу капчи...")
            var req = URLRequest(url: redirectURI)
            req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
            wv.load(req)
        }

        log.info("token received (\(token.count, privacy: .public) chars)")
        onStep?("Капча решена")
        return token
    }

    // MARK: – Page lifecycle hooks

    private func injectInterceptor() {
        guard let wv = webView else { return }
        // Idempotent install — the JS guards with __tamizdat_interceptor_installed.
        wv.evaluateJavaScript(CaptchaJSInterceptor.script) { [log] _, error in
            if let error {
                log.error("interceptor inject failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    private func onPageFinished(url: URL?, onStep: ((String) -> Void)?) {
        injectInterceptor()
        guard let url else { return }
        let s = url.absoluteString
        let isCaptchaPage = s.contains("not_robot_captcha")
                         || s.contains("id.vk.ru/captcha")
                         || s.contains("not_robot")
        guard isCaptchaPage else {
            log.info("page finished but not the captcha page: \(s, privacy: .public)")
            return
        }
        log.info("captcha page loaded; scheduling click")
        TURNLog.info("captcha", "page loaded, waiting human-read delay")
        onStep?("Решаем капчу...")

        // 2.5-3.5 s "page read" before we even look at the DOM —
        // mirrors a real user gazing at the widget.
        let delay = Double.random(in: CaptchaWebViewManager.pageReadDelayRange)
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard let self, !self.continuationDone else { return }
            self.solveCheckboxStep(onStep: onStep)
        }
    }

    // MARK: – Checkbox click logic

    private static let findLabelJS = """
    (function() {
        var slider = document.querySelector(
            '[class*="SliderCaptcha"], [class*="Kaleidoscope"], ' +
            '.vkc__SliderCaptcha-module__description, ' +
            '.vkc__KaleidoscopeScreen-module__captchaId'
        );
        if (slider) return '\(CaptchaJSInterceptor.errorSliderDetected)';

        var el = document.querySelector('label.vkc__Checkbox-module__Checkbox');
        if (!el) el = document.querySelector('label[for="not-robot-captcha-checkbox"]');
        if (!el) el = document.getElementById('not-robot-captcha-checkbox');
        if (!el) return 'not_found';

        var rect = el.getBoundingClientRect();
        var style = window.getComputedStyle(el);
        if (rect.width < 5 || rect.height < 5 ||
            style.display === 'none' || style.visibility === 'hidden') {
            return 'not_found';
        }
        return rect.left + ',' + rect.top + ',' + rect.width + ',' + rect.height;
    })();
    """

    private func solveCheckboxStep(onStep: ((String) -> Void)?) {
        guard let wv = webView, !continuationDone else { return }

        wv.evaluateJavaScript(Self.findLabelJS) { [weak self] value, error in
            guard let self else { return }
            if let error {
                self.log.error("findLabel eval failed: \(error.localizedDescription, privacy: .public)")
                return
            }
            let raw = (value as? String)?.replacingOccurrences(of: "\"", with: "") ?? ""
            self.log.debug("findLabel raw=\(raw, privacy: .public)")

            if raw == CaptchaJSInterceptor.errorSliderDetected {
                self.log.info("slider detected pre-click — fallback to manual")
                self.finish(with: .failure(CaptchaError.sliderRequired))
                return
            }
            let parts = raw.split(separator: ",")
            if raw == "not_found" || parts.count < 4 {
                self.log.warning("label not found — trying JS .click() fallback")
                self.tryJSClickFallback()
                return
            }
            guard
                let left = Double(parts[0]),
                let top = Double(parts[1]),
                let width = Double(parts[2]),
                let height = Double(parts[3])
            else {
                self.log.error("findLabel parse failed for: \(raw, privacy: .public)")
                self.tryJSClickFallback()
                return
            }

            // Random point inside the label (15-85% of width, 25-75%
            // of height). Real users click roughly in the middle, but
            // never the exact pixel-perfect center.
            let randX = left + width * (0.15 + Double.random(in: 0...0.7))
            let randY = top + height * (0.25 + Double.random(in: 0...0.5))
            self.log.info("click at (\(Int(randX)), \(Int(randY))) inside \(Int(width))x\(Int(height))")
            TURNLog.info("captcha", "checkbox located at \(Int(randX)),\(Int(randY))")

            let thinkDelay = Double.random(in: CaptchaWebViewManager.thinkBeforeClickRange)
            onStep?("Кликаем...")
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(thinkDelay * 1_000_000_000))
                guard let self, !self.continuationDone else { return }
                self.simulateTouch(cssX: randX, cssY: randY)
                self.startPostClickSliderWatcher()
            }
        }
    }

    /// Plain `el.click()` fallback when we can't locate the label via
    /// rect-based query — better than nothing, but VK has been known
    /// to ignore synthetic .click() without trusted event chain. Best-
    /// effort.
    private func tryJSClickFallback() {
        guard let wv = webView, !continuationDone else { return }
        let js = """
        (function() {
            var el = document.querySelector('label.vkc__Checkbox-module__Checkbox');
            if (!el) el = document.getElementById('not-robot-captcha-checkbox');
            if (el) { el.click(); return 'clicked'; }
            return 'nothing';
        })();
        """
        wv.evaluateJavaScript(js) { [weak self] value, _ in
            guard let self else { return }
            let v = (value as? String)?.replacingOccurrences(of: "\"", with: "") ?? ""
            self.log.info("JS click fallback result=\(v, privacy: .public)")
            if v == "clicked" {
                self.startPostClickSliderWatcher()
            }
        }
    }

    /// Dispatch a `touchstart` / `touchend` pair via JS — the only
    /// touch synthesis primitive WKWebView exposes (Apple's private
    /// UITouch creation is off-limits and the App Store rejects apps
    /// that swizzle into it).
    ///
    /// Adds a small jitter on `touchend` coordinates (palm-side
    /// movement when the user lifts a finger) and a randomized hold
    /// time between 80-180 ms.
    private func simulateTouch(cssX: Double, cssY: Double) {
        guard let wv = webView, !continuationDone else { return }
        let force = 0.5 + Double.random(in: 0...0.4)
        let holdSec = Double.random(in: CaptchaWebViewManager.touchHoldRange)
        let jitterX = cssX + Double.random(in: -1.0...1.0)
        let jitterY = cssY + Double.random(in: -0.5...0.5)
        let holdMs = Int(holdSec * 1000)

        let js = """
        (function() {
            var el = document.elementFromPoint(\(cssX), \(cssY));
            if (!el) return 'no_element';
            var target = el.closest('label.vkc__Checkbox-module__Checkbox') || el;
            function makeTouch(x, y) {
                return new Touch({
                    identifier: 0,
                    target: target,
                    clientX: x,
                    clientY: y,
                    pageX: x,
                    pageY: y,
                    radiusX: 11.5,
                    radiusY: 11.5,
                    rotationAngle: 0,
                    force: \(force)
                });
            }
            function makeEvent(type, x, y) {
                var t = makeTouch(x, y);
                return new TouchEvent(type, {
                    bubbles: true,
                    cancelable: true,
                    composed: true,
                    touches: type === 'touchend' ? [] : [t],
                    targetTouches: type === 'touchend' ? [] : [t],
                    changedTouches: [t]
                });
            }
            try {
                target.dispatchEvent(makeEvent('touchstart', \(cssX), \(cssY)));
            } catch (e) {
                // Touch / TouchEvent constructors are not always available
                // on older WebKit; fall back to .click() so we at least try.
                try { target.click(); } catch (e2) {}
                return 'fallback_click';
            }
            setTimeout(function() {
                try {
                    target.dispatchEvent(makeEvent('touchend', \(jitterX), \(jitterY)));
                } catch (e) {}
            }, \(holdMs));
            return 'dispatched';
        })();
        """
        wv.evaluateJavaScript(js) { [weak self] value, error in
            guard let self else { return }
            if let error {
                self.log.error("touch dispatch failed: \(error.localizedDescription, privacy: .public)")
                TURNLog.error("captcha", "touch dispatch failed: \(error.localizedDescription)")
            } else {
                let result = (value as? String) ?? "?"
                self.log.info("touch dispatched: \(result, privacy: .public)")
                TURNLog.info("captcha", "touch dispatched, awaiting interceptor")
            }
        }
    }

    // MARK: – Post-click slider watcher

    private static let detectSliderJS = """
    (function() {
        var slider = document.querySelector(
            '[class*="SliderCaptcha"], [class*="Kaleidoscope"], ' +
            '.vkc__SliderCaptcha-module__description, ' +
            '.vkc__KaleidoscopeScreen-module__captchaId, ' +
            '.vkc__SwipeButton-module__track'
        );
        if (slider) return 'slider';

        var success = document.querySelector(
            '[class*="success"], [class*="Success"], [class*="passed"], [class*="Passed"]'
        );
        if (success) return 'success_ui';

        return 'none';
    })();
    """

    /// Spin up an async poll (~7.8 s total) that watches for VK
    /// swapping in a slider after the checkbox click. If the interceptor
    /// fires `{ success }` we bail via `continuationDone`.
    private func startPostClickSliderWatcher() {
        watcherTask?.cancel()
        let task = Task { @MainActor [weak self] in
            // First wait — same 0.9 s as Kotlin reference.
            try? await Task.sleep(nanoseconds: UInt64(CaptchaWebViewManager.postClickFirstDelay * 1_000_000_000))
            guard let self else { return }

            var attemptsLeft = CaptchaWebViewManager.postClickAttempts
            while attemptsLeft > 0 {
                if self.continuationDone || Task.isCancelled { return }
                let outcome = await self.detectSliderOnce()
                switch outcome {
                case "slider":
                    self.log.info("post-click slider observed — fallback to manual")
                    self.finish(with: .failure(CaptchaError.sliderRequired))
                    return
                case "success_ui":
                    // Just an early hint; success_token still comes via
                    // interceptor. Stop polling.
                    return
                default:
                    break
                }
                attemptsLeft -= 1
                try? await Task.sleep(nanoseconds: UInt64(CaptchaWebViewManager.postClickPollInterval * 1_000_000_000))
            }
        }
        watcherTask = task
    }

    private func detectSliderOnce() async -> String {
        await withCheckedContinuation { (cont: CheckedContinuation<String, Never>) in
            guard let wv = webView else { cont.resume(returning: "none"); return }
            wv.evaluateJavaScript(Self.detectSliderJS) { value, _ in
                let raw = (value as? String)?.replacingOccurrences(of: "\"", with: "") ?? "none"
                cont.resume(returning: raw)
            }
        }
    }

    // MARK: – Bridge events

    fileprivate func handleEvent(_ event: CaptchaJSInterceptor.Event) {
        guard !continuationDone else { return }
        switch event {
        case .success(let token):
            log.info("interceptor: success_token (\(token.count) chars)")
            finish(with: .success(token))
        case .sliderDetected(let source):
            log.info("interceptor: slider (source=\(source, privacy: .public))")
            finish(with: .failure(CaptchaError.sliderRequired))
        case .error(let msg):
            log.error("interceptor: VK error: \(msg, privacy: .public)")
            finish(with: .failure(CaptchaError.vkError(message: msg)))
        }
    }

    private func finish(with result: Result<String, Error>) {
        guard !continuationDone, let cont = continuation else { return }
        continuationDone = true
        continuation = nil
        switch result {
        case .success(let v): cont.resume(returning: v)
        case .failure(let e): cont.resume(throwing: e)
        }
    }

    // MARK: – Teardown

    private func teardown() {
        watcherTask?.cancel()
        watcherTask = nil

        // Drop the message handler before the controller is released to
        // break the strong ref cycle WKContentController → handler ←—
        // session via the proxy's closure.
        if let wv = webView {
            wv.stopLoading()
            wv.loadHTMLString("<html></html>", baseURL: nil)
            let controller = wv.configuration.userContentController
            controller.removeAllUserScripts()
            controller.removeScriptMessageHandler(forName: CaptchaJSInterceptor.handlerName)
            wv.navigationDelegate = nil
        }
        webView = nil
        messageProxy = nil
        navigationProxy = nil

        // If the continuation hasn't fired (e.g. cancelled mid-flight),
        // resume with .cancelled so the caller doesn't deadlock. This
        // is a defence-in-depth net — the throwing TaskGroup at the
        // top will normally cancel first.
        if !continuationDone, let cont = continuation {
            continuationDone = true
            continuation = nil
            cont.resume(throwing: CaptchaError.cancelled)
        }
    }

    // MARK: – Utilities

    private static func pick<T>(from array: [T]) -> T {
        array[Int.random(in: 0..<array.count)]
    }
}

// MARK: – WKScriptMessageHandler proxy

/// Stand-alone NSObject that forwards script-message events to a Swift
/// closure. We can't make `SolveSession` itself the handler because
/// `WKUserContentController.add(_:name:)` only retains the handler
/// weakly — but `SolveSession`'s lifetime is also tied to one solve,
/// so the proxy gives us a clean, deterministic ownership story.
@MainActor
private final class ScriptMessageProxy: NSObject, WKScriptMessageHandler {
    private let onEvent: (CaptchaJSInterceptor.Event) -> Void

    init(onEvent: @escaping (CaptchaJSInterceptor.Event) -> Void) {
        self.onEvent = onEvent
        super.init()
    }

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard message.name == CaptchaJSInterceptor.handlerName else { return }
        guard let event = CaptchaJSInterceptor.Event.decode(message.body) else { return }
        onEvent(event)
    }
}

// MARK: – WKNavigationDelegate proxy

@MainActor
private final class NavigationProxy: NSObject, WKNavigationDelegate {
    private let onPageStart: () -> Void
    private let onPageFinish: (URL?) -> Void

    init(onPageStart: @escaping () -> Void,
         onPageFinish: @escaping (URL?) -> Void) {
        self.onPageStart = onPageStart
        self.onPageFinish = onPageFinish
        super.init()
    }

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
        onPageStart()
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        onPageFinish(webView.url)
    }

    /// Trust VK / OK certs; let everything else bubble up to the system
    /// default behaviour (which will reject for invalid pins).
    func webView(_ webView: WKWebView,
                 didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let host = challenge.protectionSpace.host
        if host.contains("vk.ru") || host.contains("vk.com") || host.contains("okcdn.ru") {
            if let trust = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
        }
        completionHandler(.performDefaultHandling, nil)
    }
}
