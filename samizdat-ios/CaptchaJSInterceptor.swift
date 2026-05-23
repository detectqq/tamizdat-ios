import Foundation

/// JS interceptor injected into the VK captcha page.
///
/// WHY a single source string: both `CaptchaWebViewManager` (auto path)
/// and `ManualCaptchaSheet` (slider fallback) install the same hook —
/// override `fetch` + `XMLHttpRequest` so any response from
/// `captchaNotRobot.check` is parsed for `success_token`. The token is
/// then posted back to native code via
/// `webkit.messageHandlers.tamizdatCaptcha.postMessage(...)`.
///
/// The Android donor (`amurcanov/proxy-turn-vk-android`) uses
/// `WdttCaptcha.onSuccess/onError/onSliderDetected` on a Java bridge.
/// WKWebView has no `addJavascriptInterface`-equivalent — every message
/// goes through one `WKScriptMessageHandler`, so we shape the payload
/// as `{ kind: "success" | "error" | "slider", value: ... }` and
/// dispatch on the Swift side.
///
/// Idempotency: `window.__tamizdat_interceptor_installed` gates the
/// install so re-running `evaluateJavaScript` on every navigation event
/// (start, finish, redirect) is safe — VK's captcha SPA does internal
/// route changes that we'd otherwise hook twice.
enum CaptchaJSInterceptor {

    /// The handler name registered with `WKUserContentController.add(_:name:)`.
    /// Must match `window.webkit.messageHandlers.<name>.postMessage(...)`
    /// in the JS below.
    static let handlerName = "tamizdatCaptcha"

    /// Token returned by the slider-detection JS when the page already
    /// shows a slider instead of the simple checkbox. Caller throws
    /// `CaptchaError.sliderRequired` and falls back to `ManualCaptchaSheet`.
    static let errorSliderDetected = "slider_detected"

    /// Bridge script (idempotent, safe to inject on every page event).
    static let script: String = """
    (function() {
        if (window.__tamizdat_interceptor_installed) return;
        window.__tamizdat_interceptor_installed = true;

        function postNative(payload) {
            try {
                window.webkit.messageHandlers.\(handlerName).postMessage(payload);
            } catch (e) {
                // Handler not yet registered (rare race during fast reloads).
            }
        }

        const origFetch = window.fetch;
        window.fetch = async function() {
            const args = arguments;
            const url = args[0] || '';
            if (typeof url === 'string' && url.includes('captchaNotRobot.check')) {
                const response = await origFetch.apply(this, args);
                const clone = response.clone();
                try {
                    const data = await clone.json();
                    if (data.response && data.response.success_token) {
                        postNative({ kind: 'success', value: data.response.success_token });
                    } else if (
                        data.response &&
                        data.response.show_captcha_type === 'slider'
                    ) {
                        postNative({ kind: 'slider', value: 'check_response' });
                    } else if (data.error) {
                        postNative({ kind: 'error', value: JSON.stringify(data.error) });
                    }
                } catch (e) {
                    // Body parse failure — leave the original response untouched.
                }
                return response;
            }
            return origFetch.apply(this, args);
        };

        const origXHROpen = XMLHttpRequest.prototype.open;
        const origXHRSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.open = function(method, url) {
            this._tamizdat_url = url;
            return origXHROpen.apply(this, arguments);
        };
        XMLHttpRequest.prototype.send = function() {
            const xhr = this;
            if (xhr._tamizdat_url && xhr._tamizdat_url.includes('captchaNotRobot.check')) {
                xhr.addEventListener('load', function() {
                    try {
                        const data = JSON.parse(xhr.responseText);
                        if (data.response && data.response.success_token) {
                            postNative({ kind: 'success', value: data.response.success_token });
                        } else if (
                            data.response &&
                            data.response.show_captcha_type === 'slider'
                        ) {
                            postNative({ kind: 'slider', value: 'check_response' });
                        } else if (data.error) {
                            postNative({ kind: 'error', value: JSON.stringify(data.error) });
                        }
                    } catch (e) {
                        // ignore
                    }
                });
            }
            return origXHRSend.apply(this, arguments);
        };
    })();
    """

    /// Decoded interceptor payload. Mirrors `{ kind, value }` shape from
    /// the JS above. Callers switch on `kind` to drive the state machine
    /// (success, error, slider fallback).
    enum Event: Equatable {
        case success(token: String)
        case sliderDetected(source: String)
        case error(message: String)

        /// Decodes the message body posted from the JS bridge. The body
        /// is `Any` because WKScriptMessage delivers raw JS values; we
        /// normalize to NSDictionary to read string fields.
        static func decode(_ body: Any) -> Event? {
            guard let dict = body as? [String: Any],
                  let kind = dict["kind"] as? String else {
                return nil
            }
            let value = (dict["value"] as? String) ?? ""
            switch kind {
            case "success":
                return value.isEmpty ? nil : .success(token: value)
            case "slider":
                return .sliderDetected(source: value.isEmpty ? "unknown" : value)
            case "error":
                return .error(message: value.isEmpty ? "unknown" : value)
            default:
                return nil
            }
        }
    }
}
