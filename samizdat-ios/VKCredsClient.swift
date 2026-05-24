import Foundation
import OSLog

/// Swift port of the donor `creds.go` 5-call VK API flow for acquiring
/// TURN relay credentials. Built on `URLSession` with per-instance
/// cookie storage so the captcha-acquired session does not pollute the
/// main app's shared cookie store.
///
/// WHY a 5-call dance: VK's `vk.com/call/join/<hash>` flow needs three
/// progressively-scoped anon-tokens, the OK-CDN session key, and only
/// then the `joinConversationByLink` call returns the TURN realm
/// credentials. We mirror the donor's exact sequence — diverging is a
/// quick way to land in `bot_response` territory.
///
/// Step map (mirrors `donor_creds.go::getVKCredsOnce`):
///   1. POST `login.vk.ru/?act=get_anonym_token` (client-id seeded)
///   2. POST `login.vk.ru/?act=get_anonym_token` (payload = step-1 token)
///   3. POST `api.vk.ru/method/calls.getAnonymousToken` (vk_join_link)
///      — this is the step that can return VK error 14 (captcha). On
///        error 14 we hand the redirect_uri + session_token to the
///        `VKCaptchaSolver` and retry with captcha_sid + success_token.
///   4. POST `calls.okcdn.ru/fb.do` → `auth.anonymLogin` (OK session)
///   5. POST `calls.okcdn.ru/fb.do` → `vchat.joinConversationByLink`
///      — response includes the `turn_server` block with username /
///        credential / urls / lifetime.
///
/// Retry policy (mirror Go): up to `maxRetries` attempts with
/// exponential backoff (1 s, 2 s, 4 s, 8 s, 16 s, capped at 30 s)
/// plus a small jitter. Flood/throttle responses get a longer linear
/// backoff (5 s × attempt, capped at 60 s).
///
/// Concurrency model: `actor` ensures one in-flight fetch per
/// instance — caller can spam `fetchCredentials()` from multiple
/// scene-active events without spawning duplicate VK API roundtrips.

/// Caller-supplied captcha solver. Pluggable so tests can stub it.
protocol VKCaptchaSolver: Sendable {
    func solve(redirectURI: URL, sessionToken: String) async throws -> String
}

/// Production solver: drives the hidden WKWebView via
/// `CaptchaWebViewManager`. Throws `CaptchaError.sliderRequired` to
/// signal that the caller should escalate to the manual sheet.
struct WKWebViewCaptchaSolver: VKCaptchaSolver {
    func solve(redirectURI: URL, sessionToken: String) async throws -> String {
        try await CaptchaWebViewManager.shared.solveCaptcha(
            redirectURI: redirectURI,
            sessionToken: sessionToken
        )
    }
}

/// One (ClientID, ClientSecret) pair for a VK anonymous app. The
/// credential acquire flow runs against these as a list: when a step
/// trips VK error_code 29 (rate-limit), the client advances to the
/// next pair and retries — same behaviour as vk-turn-proxy's
/// `vkCredentialsList` rotation.
///
/// The five default entries are the public IDs shipped by donor
/// applications (vk.com, mvk.com, vkvideo, ID auth). Treating them as
/// a constant pool spreads rate-limit pressure across five separate
/// VK quotas and lets us survive a temporary ban on any single app.
///
/// Ported from cacggghp/vk-turn-proxy (GPL-3.0), commit e8a9696
/// (client/main.go:597-603).
struct VKAppCredentials: Equatable {
    let clientID: String
    let clientSecret: String
}

/// Tuning knobs / fixed strings. The defaults are the Android donor's
/// shipping values and produce traffic indistinguishable from their
/// production traffic. Override only when you have a documented reason.
struct VKCredsConfig {
    /// Ordered pool of VK app IDs / secrets to rotate through on
    /// rate-limit (VK error_code 29). The first entry is the
    /// historical default; the rest are vk-turn-proxy's fallbacks.
    /// The client actor starts at index 0 and advances on rate-limit
    /// responses; if every pair is exhausted, `fetchCredentials`
    /// throws `VKCredsError.allAppIDsExhausted`.
    ///
    /// Single-app callers (e.g. unit tests) can override with a
    /// one-element array.
    var vkAppIDs: [VKAppCredentials] = VKCredsConfig.defaultAppIDs
    /// Convenience accessor for the currently-active (index 0) app
    /// ID — kept for old call sites and unit-test mocks that still
    /// look at one pair.
    var appID: String { vkAppIDs.first?.clientID ?? "6287487" }
    var appSecret: String { vkAppIDs.first?.clientSecret ?? "QbYic1K3lEV5kTGiqlq2" }
    /// OK app key — burned into the donor flow.
    var okAppKey: String = "CGMMEJLGDIHBABABA"
    /// VK call hash — the per-deployment "room" id. MUST be set by the
    /// caller from server-pushed config or per-user pref.
    var callHash: String
    /// Optional secondary hash. If step 3 fails on the primary, the
    /// client retries the entire flow once against the secondary. Matches
    /// `GetCredsWithFallback` in the donor.
    var secondaryHash: String?
    /// Per-device pseudo-unique ID used as `device_id` in the OK CDN
    /// session_data payload. UUID is fine; donor uses uuid.New().
    var deviceID: String
    /// User-Agent the donor sends on the VK side — Android WebView.
    /// Adjust if VK ever flags this UA explicitly.
    var userAgent: String =
        "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) " +
        "Chrome/120.0.0.0 Mobile Safari/537.36"
    /// Profile display name (donor randomizes via name pools; we keep
    /// it static for now to reduce surface area). VK accepts any UTF-8.
    var profileName: String = "Гость"
    /// Maximum attempts of the whole 5-call dance before giving up.
    var maxRetries: Int = 5
    /// Per-request timeout (seconds).
    var perRequestTimeout: TimeInterval = 20

    /// Default VK app IDs the client rotates through on rate-limit.
    /// Five public anonymous-app credentials lifted from
    /// vk-turn-proxy (their `vkCredentialsList`). Order matches
    /// upstream so behaviour stays comparable.
    ///
    /// Ported from cacggghp/vk-turn-proxy (GPL-3.0), commit e8a9696
    /// (client/main.go:597-603).
    static let defaultAppIDs: [VKAppCredentials] = [
        VKAppCredentials(clientID: "6287487",  clientSecret: "QbYic1K3lEV5kTGiqlq2"),   // VK_WEB_APP_ID
        VKAppCredentials(clientID: "7879029",  clientSecret: "aR5NKGmm03GYrCiNKsaw"),   // VK_MVK_APP_ID
        VKAppCredentials(clientID: "52461373", clientSecret: "o557NLIkAErNhakXrQ7A"),   // VK_WEB_VKVIDEO_APP_ID
        VKAppCredentials(clientID: "52649896", clientSecret: "WStp4ihWG4l3nmXZgIbC"),   // VK_MVK_VKVIDEO_APP_ID
        VKAppCredentials(clientID: "51781872", clientSecret: "IjjCNl4L4Tf5QZEXIHKK"),   // VK_ID_AUTH_APP
    ]
}

/// Errors thrown by `VKCredsClient.fetchCredentials()`.
enum VKCredsError: Error, LocalizedError {
    /// All retries exhausted; last error is wrapped.
    case retriesExhausted(lastError: Error)
    /// The VK side returned an error block (other than captcha).
    case vkError(step: String, payload: [String: Any])
    /// HTTP transport-level failure.
    case transport(step: String, underlying: Error)
    /// Response body wasn't JSON / didn't have the expected shape.
    case malformedResponse(step: String, hint: String)
    /// The call hash is permanently dead — sentinel for VK code 9000.
    case deadHash
    /// Captcha solver failed (slider required → caller falls back).
    case captchaFailed(underlying: Error)
    /// All configured VK app IDs (`VKCredsConfig.vkAppIDs`) hit
    /// rate-limit responses in a row — every quota is exhausted and
    /// there is nothing left to rotate to. Caller MUST wait minutes,
    /// not seconds, before retrying.
    case allAppIDsExhausted
    /// VK returned error_code 29 (rate limit) for the currently
    /// selected app ID. Internal sentinel — the retry loop advances
    /// to the next app ID and retries. Never propagated past the
    /// retry loop unless every ID is exhausted (see above).
    case rateLimit(step: String, appID: String)

    var errorDescription: String? {
        switch self {
        case .retriesExhausted(let e):
            return "Исчерпаны попытки получения TURN-кредов: \(e.localizedDescription)"
        case .vkError(let step, let payload):
            return "Ошибка VK на шаге \(step): \(payload)"
        case .transport(let step, let underlying):
            return "Сетевая ошибка на шаге \(step): \(underlying.localizedDescription)"
        case .malformedResponse(let step, let hint):
            return "Некорректный ответ VK на шаге \(step): \(hint)"
        case .deadHash:
            return "VK хеш более не работает (code 9000)"
        case .captchaFailed(let underlying):
            return "Не удалось решить капчу: \(underlying.localizedDescription)"
        case .allAppIDsExhausted:
            return "Все VK App IDs упёрлись в rate-limit. Подожди несколько минут."
        case .rateLimit(let step, let appID):
            return "VK rate-limit на шаге \(step) (app_id=\(appID))"
        }
    }
}

/// VK-side captcha error data we parse out of the error block on step 3.
private struct VKCaptchaChallenge {
    let captchaSid: String
    let redirectURI: URL
    let sessionToken: String
    let captchaTs: String
    let captchaAttempt: String

    /// Decode a `{ "error": { ... } }` payload. Returns nil if the
    /// block isn't a captcha challenge (error_code != 14 or fields
    /// missing).
    static func decode(from errorBlock: [String: Any]) -> VKCaptchaChallenge? {
        let codeFloat = (errorBlock["error_code"] as? Double) ?? -1
        guard Int(codeFloat) == 14 else { return nil }
        guard let redirectStr = errorBlock["redirect_uri"] as? String,
              let redirectURL = URL(string: redirectStr) else {
            return nil
        }
        let captchaSid: String = {
            if let s = errorBlock["captcha_sid"] as? String { return s }
            if let n = errorBlock["captcha_sid"] as? Double { return String(format: "%.0f", n) }
            return ""
        }()
        let sessionToken: String = {
            let comps = URLComponents(url: redirectURL, resolvingAgainstBaseURL: false)
            return comps?.queryItems?.first(where: { $0.name == "session_token" })?.value ?? ""
        }()
        let captchaTs: String = {
            if let n = errorBlock["captcha_ts"] as? Double {
                return String(n)
            }
            if let s = errorBlock["captcha_ts"] as? String { return s }
            return ""
        }()
        let captchaAttempt: String = {
            if let n = errorBlock["captcha_attempt"] as? Double {
                return String(format: "%.0f", n)
            }
            if let s = errorBlock["captcha_attempt"] as? String { return s }
            return "1"
        }()
        return VKCaptchaChallenge(
            captchaSid: captchaSid,
            redirectURI: redirectURL,
            sessionToken: sessionToken,
            captchaTs: captchaTs,
            captchaAttempt: captchaAttempt
        )
    }
}

/// Actor wrapping one VK API session. One actor = one cookie jar = one
/// in-flight fetchCredentials.
actor VKCredsClient {
    private let config: VKCredsConfig
    private let captchaSolver: VKCaptchaSolver
    private let log = Logger(subsystem: "com.anarki.samizdat-test.captcha", category: "vkcreds")

    /// Per-instance URLSession backed by an isolated cookie jar — keeps
    /// the captcha-bound session_token / VK cookies out of the main
    /// app's shared cookie store.
    private let session: URLSession

    /// Index into `config.vkAppIDs`. Advances on VK error_code 29
    /// (rate-limit) and wraps to `allAppIDsExhausted` when every pair
    /// has been tried. Reset between `fetchCredentials` calls would
    /// make sense too, but VK rate-limits are app-id-scoped and last
    /// minutes — keeping the index across retries inside one
    /// `runWithRetries` matches what vk-turn-proxy does.
    private var currentAppIDIndex: Int = 0

    /// Currently-active (clientID, clientSecret) pair. Falls back to
    /// the historical default if the configured pool is empty.
    private var currentApp: VKAppCredentials {
        if currentAppIDIndex < config.vkAppIDs.count {
            return config.vkAppIDs[currentAppIDIndex]
        }
        return VKAppCredentials(clientID: config.appID, clientSecret: config.appSecret)
    }

    /// Advance to the next app ID in the pool. Returns `false` when
    /// the pool is exhausted — caller should throw
    /// `.allAppIDsExhausted` and stop.
    private func advanceAppID() -> Bool {
        if currentAppIDIndex + 1 < config.vkAppIDs.count {
            currentAppIDIndex += 1
            return true
        }
        return false
    }

    /// True when the given VK error block represents a rate-limit
    /// (error_code 29 OR an error_msg containing "rate limit" — VK
    /// occasionally reports the throttle as a text-only message).
    /// Mirror of vk-turn-proxy's `error_code:29` substring check.
    ///
    /// Ported from cacggghp/vk-turn-proxy (GPL-3.0), commit e8a9696
    /// (client/main.go:803).
    private static func isRateLimit(_ block: [String: Any]) -> Bool {
        let code = Int((block["error_code"] as? Double) ?? -1)
        if code == 29 { return true }
        let msg = (block["error_msg"] as? String ?? "").lowercased()
        return msg.contains("rate limit")
    }

    init(config: VKCredsConfig,
         captchaSolver: VKCaptchaSolver = WKWebViewCaptchaSolver()) {
        self.config = config
        self.captchaSolver = captchaSolver

        let cfg = URLSessionConfiguration.ephemeral
        cfg.httpCookieStorage = HTTPCookieStorage()
        cfg.httpShouldSetCookies = true
        cfg.httpCookieAcceptPolicy = .always
        cfg.timeoutIntervalForRequest = config.perRequestTimeout
        cfg.timeoutIntervalForResource = config.perRequestTimeout * 3
        cfg.httpAdditionalHeaders = [
            "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        ]
        self.session = URLSession(configuration: cfg)
    }

    deinit {
        session.invalidateAndCancel()
    }

    /// Run the 5-call dance up to `maxRetries` times against the
    /// configured `callHash` (and fall back once to `secondaryHash` if
    /// the primary returns dead-hash). Returns fully-populated creds.
    func fetchCredentials() async throws -> VKTURNCredentials {
        let hashPrefix = String(config.callHash.prefix(8))
        TURNLog.info("vkcreds", "fetchCredentials: starting (hash=\(hashPrefix)... appIDs=\(config.vkAppIDs.count))")
        do {
            return try await runWithRetries(hash: config.callHash)
        } catch VKCredsError.deadHash {
            TURNLog.error("vkcreds", "fetchCredentials: primary hash is dead (hash=\(hashPrefix)...)")
            if let secondary = config.secondaryHash, !secondary.isEmpty {
                log.warning("primary hash dead — trying secondary")
                return try await runWithRetries(hash: secondary, maxAttempts: max(1, config.maxRetries - 2))
            }
            throw VKCredsError.deadHash
        } catch VKCredsError.allAppIDsExhausted {
            // Don't try secondary hash on rate-limit exhaustion: same
            // pool of VK quotas, same exhaustion would just play out
            // again. Surface the dedicated error so UI can show a
            // "подожди X минут" message rather than a generic retry.
            throw VKCredsError.allAppIDsExhausted
        }
    }

    // MARK: – Retry loop

    private func runWithRetries(hash: String, maxAttempts: Int? = nil) async throws -> VKTURNCredentials {
        let attempts = maxAttempts ?? config.maxRetries
        var lastError: Error?
        for attempt in 0..<attempts {
            do {
                let creds = try await runOnce(hash: hash)
                return creds
            } catch VKCredsError.deadHash {
                throw VKCredsError.deadHash
            } catch let VKCredsError.rateLimit(step, appID) {
                // VK throttled the currently-selected app ID. Advance
                // to the next pair and retry quickly — the next app
                // has its own quota window. If the pool is exhausted
                // we surface `.allAppIDsExhausted` and STOP — there is
                // nothing more we can usefully try in the next few
                // minutes.
                //
                // Ported from cacggghp/vk-turn-proxy (GPL-3.0), commit
                // e8a9696 (client/main.go:803-805).
                TURNLog.warn("vkcreds", "rate-limit at \(step) on app_id=\(appID) — rotating")
                if !advanceAppID() {
                    TURNLog.error("vkcreds", "all \(config.vkAppIDs.count) app IDs exhausted at \(step)")
                    throw VKCredsError.allAppIDsExhausted
                }
                let nextID = currentApp.clientID
                TURNLog.info("vkcreds", "rotated to app_id=\(nextID), retrying immediately")
                // Skip the normal exponential backoff — moving to a
                // fresh app ID resets the rate-limit window, so we
                // want the retry to land before the user's session
                // throttles further. Tiny 250 ms pause just to keep
                // VK from seeing two requests at exactly the same
                // millisecond.
                try? await Task.sleep(nanoseconds: 250_000_000)
                continue
            } catch {
                lastError = error
                let backoff = Self.backoff(for: error, attempt: attempt)
                log.warning("attempt \(attempt + 1)/\(attempts) failed: \(error.localizedDescription, privacy: .public) — backoff \(backoff, format: .fixed(precision: 2))s")
                TURNLog.info("vkcreds", "retry attempt \(attempt + 1)/\(attempts) after backoff \(String(format: "%.1f", backoff))s")
                if attempt < attempts - 1 {
                    try? await Task.sleep(nanoseconds: UInt64(backoff * 1_000_000_000))
                }
            }
        }
        throw VKCredsError.retriesExhausted(lastError: lastError ?? VKCredsError.malformedResponse(step: "all", hint: "no attempts"))
    }

    /// Exponential backoff with jitter, plus a flood-specific linear
    /// schedule. Mirrors `getUniqueVKCreds` in `donor_creds.go`.
    private static func backoff(for error: Error, attempt: Int) -> Double {
        let msg = (error as? LocalizedError)?.errorDescription ?? "\(error)"
        let lower = msg.lowercased()
        if lower.contains("flood") {
            let secs = min(60, 5 * (attempt + 1))
            return Double(secs)
        }
        let base = min(30, 1 << min(attempt, 5))
        let jitter = Double.random(in: 0...1)
        return Double(base) + jitter
    }

    // MARK: – Single attempt

    /// One end-to-end run of the 5 calls. Throws on any failure; the
    /// outer retry loop decides whether to retry or bail.
    private func runOnce(hash: String) async throws -> VKTURNCredentials {
        // Snapshot the currently-active app pair for this whole pass.
        // The retry loop may advance `currentAppIDIndex` between
        // attempts, but inside ONE runOnce we use the same ID across
        // every call so VK sees a consistent identity per session.
        let app = currentApp
        let appID = app.clientID
        let appSecret = app.clientSecret

        // Step 1 — anonymous app token (seed for step 2)
        TURNLog.info("vkcreds", "step 1: getAnonymToken (seed, app_id=\(appID))")
        let step1 = "client_secret=\(appSecret)&client_id=\(appID)" +
                    "&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous" +
                    "&isApiOauthAnonymEnabled=false&version=1&app_id=\(appID)"
        let r1 = try await postJSON(step1, to: "https://login.vk.ru/?act=get_anonym_token",
                                     step: "1.getAnonymToken")
        if let errBlock = r1["error"] as? [String: Any], Self.isRateLimit(errBlock) {
            throw VKCredsError.rateLimit(step: "1", appID: appID)
        }
        try Self.assertNoError(r1, step: "1")
        let t1: String = try Self.requireString(r1, path: ["data", "access_token"], step: "1")
        TURNLog.info("vkcreds", "step 1 ok")

        // Step 2 — payload-bound anon token (the one with messages
        // scope) — fed into step 3.
        TURNLog.info("vkcreds", "step 2: getAnonymToken (payload-bound)")
        let step2 = "client_id=\(appID)&token_type=messages&payload=\(t1)" +
                    "&client_secret=\(appSecret)&version=1&app_id=\(appID)"
        let r2 = try await postJSON(step2, to: "https://login.vk.ru/?act=get_anonym_token",
                                     step: "2.getAnonymToken")
        if let errBlock = r2["error"] as? [String: Any], Self.isRateLimit(errBlock) {
            throw VKCredsError.rateLimit(step: "2", appID: appID)
        }
        try Self.assertNoError(r2, step: "2")
        let t3: String = try Self.requireString(r2, path: ["data", "access_token"], step: "2")
        TURNLog.info("vkcreds", "step 2 ok")

        // Pre-auth warmup — VK's rate limiter and captcha gate are
        // markedly more lenient against "browser-like" call sequences.
        // vk-turn-proxy fires `calls.getCallPreview` between step 1
        // and step 3 to look like a legitimate UI fetching the call
        // preview before joining. The body shape mirrors upstream;
        // failure is logged but never propagated — this is pure
        // noise traffic. The only exception we surface is rate-limit,
        // because a warmup throttle means step 3 is doomed and the
        // retry loop should rotate to the next app ID immediately.
        //
        // Ported from cacggghp/vk-turn-proxy (GPL-3.0), commit e8a9696
        // (client/main.go:897-901).
        TURNLog.info("vkcreds", "step 0.warmup: calls.getCallPreview")
        let warmupBody = "vk_join_link=https://vk.com/call/join/\(hash)&fields=photo_200&access_token=\(t1)"
        let warmupURL = "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id=\(appID)"
        if let warmupResp = try? await postJSON(warmupBody, to: warmupURL, step: "0.warmup") {
            if let errBlock = warmupResp["error"] as? [String: Any], Self.isRateLimit(errBlock) {
                throw VKCredsError.rateLimit(step: "0.warmup", appID: appID)
            }
            TURNLog.info("vkcreds", "step 0.warmup ok")
        } else {
            TURNLog.warn("vkcreds", "step 0.warmup failed (network) — continuing")
        }

        // Step 3 — getAnonymousToken; the captcha-prone step.
        TURNLog.info("vkcreds", "step 3: getAnonymousToken (captcha-prone)")
        let nameEnc = Self.urlEncoded(config.profileName)
        let step3Base = "vk_join_link=https://vk.com/call/join/\(hash)" +
                        "&name=\(nameEnc)&access_token=\(t3)"
        var r3 = try await postJSON(step3Base,
                                     to: "https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=\(appID)",
                                     step: "3.getAnonymousToken")

        if let errBlock = r3["error"] as? [String: Any] {
            let code = Int((errBlock["error_code"] as? Double) ?? -1)
            let errMsg = errBlock["error_msg"] as? String ?? ""
            if code == 9000 || errMsg.lowercased().contains("call not found") {
                TURNLog.error("vkcreds", "step 3: dead hash (code=\(code))")
                throw VKCredsError.deadHash
            }
            if Self.isRateLimit(errBlock) {
                throw VKCredsError.rateLimit(step: "3", appID: appID)
            }
            TURNLog.warn("vkcreds", "step 3: VK error error_code=\(code) error_msg=\(errMsg)")
            guard let challenge = VKCaptchaChallenge.decode(from: errBlock) else {
                throw VKCredsError.vkError(step: "3", payload: errBlock)
            }
            TURNLog.warn("vkcreds", "step 3: captcha required at step 3, dispatching to solver")
            log.info("captcha challenge sid=\(challenge.captchaSid, privacy: .public) ts=\(challenge.captchaTs, privacy: .public)")
            let successToken: String
            do {
                successToken = try await captchaSolver.solve(
                    redirectURI: challenge.redirectURI,
                    sessionToken: challenge.sessionToken
                )
            } catch {
                throw VKCredsError.captchaFailed(underlying: error)
            }
            // Re-issue step 3 with the success_token + captcha_sid.
            TURNLog.info("vkcreds", "step 3-retry: reissuing with captcha solution")
            let attempt = challenge.captchaAttempt.isEmpty || challenge.captchaAttempt == "0"
                ? "1" : challenge.captchaAttempt
            let tokEnc = Self.urlEncoded(successToken)
            let step3Retry = step3Base +
                "&captcha_key=&captcha_sid=\(challenge.captchaSid)&is_sound_captcha=0" +
                "&success_token=\(tokEnc)&captcha_ts=\(challenge.captchaTs)&captcha_attempt=\(attempt)"
            r3 = try await postJSON(step3Retry,
                                     to: "https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=\(appID)",
                                     step: "3-retry.getAnonymousToken")
            if let errBlock2 = r3["error"] as? [String: Any] {
                let code2 = Int((errBlock2["error_code"] as? Double) ?? -1)
                let errMsg2 = errBlock2["error_msg"] as? String ?? ""
                TURNLog.warn("vkcreds", "step 3-retry: VK error error_code=\(code2) error_msg=\(errMsg2)")
                if Self.isRateLimit(errBlock2) {
                    throw VKCredsError.rateLimit(step: "3-retry", appID: appID)
                }
                if code2 == 14 {
                    log.warning("VK still demands captcha after a successful solve — backing off")
                    try? await Task.sleep(nanoseconds: 30_000_000_000)
                    throw VKCredsError.vkError(step: "3-retry", payload: errBlock2)
                }
                throw VKCredsError.vkError(step: "3-retry", payload: errBlock2)
            }
            TURNLog.info("vkcreds", "step 3-retry ok")
        } else {
            TURNLog.info("vkcreds", "step 3 ok (no captcha)")
        }
        let t4: String = try Self.requireString(r3, path: ["response", "token"], step: "3")

        // Step 4 — OK CDN auth.anonymLogin (session_key)
        TURNLog.info("vkcreds", "step 4: auth.anonymLogin (OK CDN session)")
        let sessionData = "%7B%22version%22%3A2%2C%22device_id%22%3A%22\(config.deviceID)%22" +
                          "%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D"
        let step4 = "session_data=\(sessionData)&method=auth.anonymLogin&format=JSON&application_key=\(config.okAppKey)"
        let r4 = try await postJSON(step4,
                                     to: "https://calls.okcdn.ru/fb.do",
                                     step: "4.anonymLogin")
        try Self.assertNoError(r4, step: "4")
        let t5: String = try Self.requireString(r4, path: ["session_key"], step: "4")
        TURNLog.info("vkcreds", "step 4 ok")

        // Step 5 — vchat.joinConversationByLink. Returns turn_server.
        TURNLog.info("vkcreds", "step 5: vchat.joinConversationByLink")
        let step5 = "joinLink=\(hash)&isVideo=false&protocolVersion=5" +
                    "&anonymToken=\(t4)&method=vchat.joinConversationByLink" +
                    "&format=JSON&application_key=\(config.okAppKey)&session_key=\(t5)"
        let r5 = try await postJSON(step5,
                                     to: "https://calls.okcdn.ru/fb.do",
                                     step: "5.joinConversationByLink")
        try Self.assertNoError(r5, step: "5")
        guard let turnBlock = r5["turn_server"] as? [String: Any] else {
            throw VKCredsError.malformedResponse(step: "5", hint: "turn_server missing")
        }
        TURNLog.info("vkcreds", "step 5 ok — turn_server received")
        let creds = try Self.parseTurnBlock(turnBlock)
        TURNLog.info("vkcreds", "creds JSON: \(vkCredsAsJSON(creds: creds))")
        return creds
    }

    // MARK: – HTTP

    /// POST `formBody` (already URL-encoded) to `url`. Decodes the
    /// response as JSON and returns the top-level object. The header
    /// set matches the donor (Origin/Referer/Sec-Fetch-*).
    private func postJSON(_ formBody: String, to urlString: String, step: String) async throws -> [String: Any] {
        guard let url = URL(string: urlString) else {
            throw VKCredsError.malformedResponse(step: step, hint: "bad URL: \(urlString)")
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.httpBody = formBody.data(using: .utf8)
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.setValue(config.userAgent, forHTTPHeaderField: "User-Agent")
        req.setValue("\"Android\"", forHTTPHeaderField: "sec-ch-ua-platform")
        req.setValue("\"Not(A:Brand\";v=\"99\", \"Android WebView\";v=\"133\", \"Chromium\";v=\"133\"",
                     forHTTPHeaderField: "sec-ch-ua")
        req.setValue("?1", forHTTPHeaderField: "sec-ch-ua-mobile")
        req.setValue("cross-site", forHTTPHeaderField: "Sec-Fetch-Site")
        req.setValue("cors",       forHTTPHeaderField: "Sec-Fetch-Mode")
        req.setValue("empty",      forHTTPHeaderField: "Sec-Fetch-Dest")
        req.setValue("*/*",        forHTTPHeaderField: "Accept")

        if urlString.contains("api.vk.ru") {
            req.setValue("https://vk.com", forHTTPHeaderField: "Origin")
            req.setValue("https://vk.com/", forHTTPHeaderField: "Referer")
        } else {
            req.setValue("https://login.vk.ru", forHTTPHeaderField: "Origin")
            req.setValue("https://login.vk.ru/", forHTTPHeaderField: "Referer")
        }

        let data: Data
        do {
            let (body, _) = try await session.data(for: req)
            data = body
        } catch {
            throw VKCredsError.transport(step: step, underlying: error)
        }

        do {
            let obj = try JSONSerialization.jsonObject(with: data)
            guard let dict = obj as? [String: Any] else {
                let snippet = String(data: data.prefix(120), encoding: .utf8) ?? "<non-utf8>"
                throw VKCredsError.malformedResponse(step: step, hint: "non-object: \(snippet)")
            }
            return dict
        } catch let err as VKCredsError {
            throw err
        } catch {
            let snippet = String(data: data.prefix(120), encoding: .utf8) ?? "<non-utf8>"
            throw VKCredsError.malformedResponse(step: step, hint: "json parse: \(snippet)")
        }
    }

    // MARK: – Response helpers

    private static func assertNoError(_ payload: [String: Any], step: String) throws {
        if let err = payload["error"] {
            if let dict = err as? [String: Any] {
                throw VKCredsError.vkError(step: step, payload: dict)
            }
            throw VKCredsError.vkError(step: step, payload: ["raw": "\(err)"])
        }
    }

    private static func requireString(_ payload: [String: Any], path: [String], step: String) throws -> String {
        var cur: Any = payload
        for key in path {
            guard let dict = cur as? [String: Any], let next = dict[key] else {
                throw VKCredsError.malformedResponse(step: step,
                                                    hint: "missing path \(path.joined(separator: "."))")
            }
            cur = next
        }
        guard let s = cur as? String, !s.isEmpty else {
            throw VKCredsError.malformedResponse(step: step,
                                                hint: "non-string at \(path.joined(separator: "."))")
        }
        return s
    }

    private static func parseTurnBlock(_ block: [String: Any]) throws -> VKTURNCredentials {
        guard let user = block["username"] as? String, !user.isEmpty else {
            throw VKCredsError.malformedResponse(step: "5", hint: "missing username")
        }
        guard let pass = block["credential"] as? String, !pass.isEmpty else {
            throw VKCredsError.malformedResponse(step: "5", hint: "missing credential")
        }
        let rawURLs = block["urls"] as? [String] ?? []
        let servers: [TurnServer] = rawURLs.compactMap { raw in
            // VK ships URLs like `turn:1.2.3.4:80?transport=tcp` or
            // `turns:1.2.3.4:443`. Preserve all three pieces so the Go
            // dispatcher can route over the right wire transport — the
            // old "strip everything to host:port then hard-force UDP"
            // path silently broke TCP-only relays.
            //
            // Split scheme then host:port then optional query.
            var clean = raw
            var scheme = "turn"
            if clean.hasPrefix("turns:") {
                scheme = "turns"
                clean.removeFirst("turns:".count)
            } else if clean.hasPrefix("turn:") {
                clean.removeFirst("turn:".count)
            }
            let (hostPortPart, queryPart): (String, String?) = {
                if let q = clean.firstIndex(of: "?") {
                    let h = String(clean[..<q])
                    let qs = String(clean[clean.index(after: q)...])
                    return (h, qs)
                }
                return (clean, nil)
            }()
            // RFC 3261 — split last `:` so IPv4 literals + bracketed
            // IPv6 work. VK's relay IPs are v4 today; the simple
            // split is sufficient for what they actually ship.
            let parts = hostPortPart.split(separator: ":", maxSplits: 1).map(String.init)
            guard parts.count == 2,
                  let port = Int(parts[1]),
                  !parts[0].isEmpty else {
                return nil
            }
            var transport = "udp"
            if let queryPart {
                for kv in queryPart.split(separator: "&") {
                    let pair = kv.split(separator: "=", maxSplits: 1).map(String.init)
                    if pair.count == 2, pair[0].lowercased() == "transport" {
                        let t = pair[1].lowercased()
                        if t == "tcp" || t == "udp" {
                            transport = t
                        }
                    }
                }
            }
            return TurnServer(host: parts[0], port: port, scheme: scheme, transport: transport)
        }
        guard !servers.isEmpty else {
            throw VKCredsError.malformedResponse(step: "5", hint: "no TURN urls")
        }
        // VK ships `lifetime` (sec) in some responses and `ttl` in others;
        // sometimes neither (build-227 log showed step 5 ok then immediate
        // re-refresh — root cause was lifetime=0, expiresAt = acquiredAt,
        // needsRefresh always true → infinite refresh loop). Fall back to
        // 3600s (one hour) — the donor's empirical default and a safe
        // floor: VK invalidates creds long before they actually go stale.
        let lifetime: TimeInterval = {
            if let life = block["lifetime"] as? Double, life > 0 {
                TURNLog.info("vkcreds", "parsed lifetime=\(Int(life))s from response")
                return life
            }
            if let ttl = block["ttl"] as? Double, ttl > 0 {
                TURNLog.info("vkcreds", "parsed ttl=\(Int(ttl))s from response")
                return ttl
            }
            TURNLog.warn("vkcreds", "no lifetime/ttl in step 5 response — using default 3600s")
            return 3600
        }()
        return VKTURNCredentials(
            username: user,
            password: pass,
            turnServers: servers,
            lifetime: lifetime,
            acquiredAt: Date()
        )
    }

    // MARK: – Misc

    /// URL-encode for `application/x-www-form-urlencoded` values. Path
    /// separators / `+` need escaping; we go via the more conservative
    /// `urlQueryAllowed` set then patch `+` and `&`.
    private static func urlEncoded(_ s: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "+&=")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }
}
