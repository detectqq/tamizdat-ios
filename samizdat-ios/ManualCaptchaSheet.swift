import Foundation
import SwiftUI
import WebKit
import OSLog

/// SwiftUI sheet that surfaces the VK captcha to the user when the
/// auto solver determined a slider/kaleidoscope is required. Port of
/// the Android donor's `ManlCaptchaWebViewManager.kt` (~388 LoC).
///
/// WHY a sheet, not a full screen: iOS users dislike modal takeovers
/// for what is effectively a 5-second interaction. A `.sheet`-style
/// half-modal keeps the rest of the app visible behind the captcha so
/// users see context — they came from the connect button, they will
/// return there once the slider is solved.
///
/// The web view here is VISIBLE (unlike the auto solver) and uses the
/// same `CaptchaJSInterceptor` so the success_token still bubbles up
/// the same channel — we just don't synthesize touches. The user
/// drags the slider, VK posts the result, the interceptor catches the
/// JSON body, and we hand the token back to the caller via the
/// `onSuccess` closure.
///
/// User-facing strings are in Russian per CLAUDE.md.
struct ManualCaptchaSheet: View {
    /// VK redirect_uri to load.
    let redirectURI: URL
    /// Captcha session token (kept for logging / future telemetry —
    /// VK reads it from the URL itself).
    let sessionToken: String
    /// Called with the success_token once VK confirms the captcha.
    let onSuccess: (String) -> Void
    /// Called if the user dismisses the sheet without solving.
    let onCancel: () -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var isLoading: Bool = true
    @State private var statusMessage: String = ""
    @State private var errorMessage: String?
    @State private var hasResolved: Bool = false

    /// Overall manual timeout — match Android (60 s).
    private static let manualTimeout: TimeInterval = 60.0

    private let log = Logger(subsystem: "com.anarki.samizdat-test.captcha", category: "manual")

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                ManualCaptchaWebViewContainer(
                    redirectURI: redirectURI,
                    onPageLoaded: {
                        isLoading = false
                    },
                    onEvent: { event in
                        handleEvent(event)
                    }
                )
                .edgesIgnoringSafeArea(.bottom)

                if isLoading {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .tint(.white)
                        .scaleEffect(1.5)
                }

                if let err = errorMessage {
                    VStack(spacing: 12) {
                        Text(err)
                            .font(.system(size: 14))
                            .foregroundStyle(.white)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 32)
                        Button("Закрыть") {
                            cancelAndDismiss()
                        }
                        .foregroundStyle(.white)
                        .padding(.horizontal, 24)
                        .padding(.vertical, 10)
                        .background(Color.red.opacity(0.8))
                        .clipShape(Capsule())
                    }
                }
            }
            .navigationTitle("Подтвердите, что вы не робот")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Отмена") {
                        cancelAndDismiss()
                    }
                }
            }
        }
        .preferredColorScheme(.dark)
        .onAppear {
            TURNLog.info("captcha", "manual sheet presented")
            startTimeout()
        }
        .interactiveDismissDisabled(false)
    }

    // MARK: – Event routing

    private func handleEvent(_ event: CaptchaJSInterceptor.Event) {
        guard !hasResolved else { return }
        switch event {
        case .success(let token):
            log.info("manual solve success (\(token.count) chars)")
            TURNLog.info("captcha", "manual token captured (length=\(token.count))")
            hasResolved = true
            onSuccess(token)
            dismiss()
        case .sliderDetected:
            // Already on the manual page — slider is expected here.
            log.info("manual: slider page confirmed")
        case .error(let msg):
            log.error("manual: VK error: \(msg, privacy: .public)")
            errorMessage = "Ошибка VK: \(msg)"
        }
    }

    private func cancelAndDismiss() {
        guard !hasResolved else { return }
        hasResolved = true
        log.info("manual cancelled by user")
        TURNLog.warn("captcha", "manual sheet cancelled")
        onCancel()
        dismiss()
    }

    private func startTimeout() {
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(Self.manualTimeout * 1_000_000_000))
            guard !hasResolved else { return }
            hasResolved = true
            log.info("manual timeout (60s)")
            TURNLog.warn("captcha", "manual sheet timed out")
            errorMessage = "Таймаут ввода капчи. Попробуйте ещё раз."
            // After 2 s for the user to read, cancel.
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            onCancel()
            dismiss()
        }
    }
}

// MARK: – WKWebView wrapper

/// `UIViewRepresentable` host for the visible captcha WKWebView. We
/// can't reuse `CaptchaWebViewManager`'s session (that one is hidden
/// and auto-solves); this is its visible cousin.
///
/// The same `CaptchaJSInterceptor.script` runs here — VK doesn't know
/// or care whether it's the auto checkbox or the manual slider that
/// fires `captchaNotRobot.check`. The interceptor catches either.
private struct ManualCaptchaWebViewContainer: UIViewRepresentable {
    let redirectURI: URL
    let onPageLoaded: () -> Void
    let onEvent: (CaptchaJSInterceptor.Event) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onPageLoaded: onPageLoaded, onEvent: onEvent)
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        config.allowsInlineMediaPlayback = true

        let userContent = WKUserContentController()
        userContent.add(context.coordinator, name: CaptchaJSInterceptor.handlerName)
        userContent.addUserScript(WKUserScript(
            source: CaptchaJSInterceptor.script,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false
        ))
        // Hide VK's chrome around the captcha frame so the user sees a
        // clean modal — port of `hideElementsJSCode` from Android.
        userContent.addUserScript(WKUserScript(
            source: Self.hideChromeJS,
            injectionTime: .atDocumentEnd,
            forMainFrameOnly: false
        ))
        config.userContentController = userContent

        let wv = WKWebView(frame: .zero, configuration: config)
        wv.customUserAgent = Self.mobileUserAgent
        wv.navigationDelegate = context.coordinator
        wv.scrollView.bounces = false
        wv.scrollView.isScrollEnabled = false
        wv.isOpaque = false
        wv.backgroundColor = .black
        wv.scrollView.backgroundColor = .black

        var req = URLRequest(url: redirectURI)
        req.setValue(Self.mobileUserAgent, forHTTPHeaderField: "User-Agent")
        wv.load(req)
        return wv
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        // No-op: the URL is loaded once in `makeUIView`. SwiftUI does
        // not re-create the representable for a stable identity.
    }

    static func dismantleUIView(_ uiView: WKWebView, coordinator: Coordinator) {
        uiView.stopLoading()
        uiView.configuration.userContentController.removeAllUserScripts()
        uiView.configuration.userContentController.removeScriptMessageHandler(
            forName: CaptchaJSInterceptor.handlerName
        )
        uiView.navigationDelegate = nil
    }

    // Mobile UA so VK serves the touch-friendly captcha layout. Picked
    // a recent Android Chrome string; iOS Safari works too, but Android
    // matches the donor and keeps the click-target sizes large.
    private static let mobileUserAgent: String =
        "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) " +
        "Chrome/146.0.0.0 Mobile Safari/537.36"

    /// CSS overlay that hides VK's logo / overlay backdrops / link
    /// chrome around the captcha card, so the user only sees the
    /// slider widget in our black modal. Port of `hideElementsJSCode`.
    private static let hideChromeJS: String = """
    (function() {
        const style = document.createElement('style');
        style.innerHTML = `
            .vkc__VisuallyHiddenModalOverlay-module__host,
            .vkc__ModalOverlay-module__host,
            .vkc__KaleidoscopeScreen-module__logoBlock,
            .vkc__KaleidoscopeScreen-module__captchaId,
            .vkc__SliderCaptcha-module__descriptionLink,
            .vkc__SliderCaptcha-module__changeTypeButton {
                display: none !important;
            }
            body, html, .vkc__ModalCard-module__host, .vkc__AppRoot-module__host, .vkui__root {
                background: transparent !important;
                box-shadow: none !important;
            }
            .vkc__ModalCardBase-module__container {
                background: #000000 !important;
                box-shadow: none !important;
            }
            .vkc__RefreshButton-module__text,
            .vkc__SliderCaptcha-module__description {
                color: #ffffff !important;
            }
            .vkc__SwipeButton-module__track {
                background-color: #ffffff !important;
            }
            .vkc__SwipeButton-module__track span {
                color: #0000FF !important;
            }
        `;
        document.head.appendChild(style);
    })();
    """

    // MARK: – Coordinator (delegate + message handler)

    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        private let onPageLoaded: () -> Void
        private let onEvent: (CaptchaJSInterceptor.Event) -> Void

        init(onPageLoaded: @escaping () -> Void,
             onEvent: @escaping (CaptchaJSInterceptor.Event) -> Void) {
            self.onPageLoaded = onPageLoaded
            self.onEvent = onEvent
            super.init()
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            onPageLoaded()
        }

        func webView(_ webView: WKWebView,
                     didReceive challenge: URLAuthenticationChallenge,
                     completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            let host = challenge.protectionSpace.host
            if (host.contains("vk.ru") || host.contains("vk.com") || host.contains("okcdn.ru")),
               let trust = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
            completionHandler(.performDefaultHandling, nil)
        }

        func userContentController(_ userContentController: WKUserContentController,
                                   didReceive message: WKScriptMessage) {
            guard message.name == CaptchaJSInterceptor.handlerName else { return }
            guard let event = CaptchaJSInterceptor.Event.decode(message.body) else { return }
            onEvent(event)
        }
    }
}
