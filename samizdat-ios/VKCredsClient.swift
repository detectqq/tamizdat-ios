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

/// Tuning knobs / fixed strings. The defaults are the Android donor's
/// shipping values and produce traffic indistinguishable from their
/// production traffic. Override only when you have a documented reason.
struct VKCredsConfig {
    /// VK App ID + Secret are the donor's "anonymous app" credentials —
    /// effectively a constant; we keep them in config so unit tests
    /// can override and to leave room for future rotation.
    var appID: String = "6287487"
    var appSecret: String = "QbYic1K3lEV5kTGiqlq2"
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
        TURNLog.info("vkcreds", "fetchCredentials: starting (hash=\(hashPrefix)...)")
        do {
            return try await runWithRetries(hash: config.callHash)
        } catch VKCredsError.deadHash {
            TURNLog.error("vkcreds", "fetchCredentials: primary hash is dead (hash=\(hashPrefix)...)")
            if let secondary = config.secondaryHash, !secondary.isEmpty {
                log.warning("primary hash dead — trying secondary")
                return try await runWithRetries(hash: secondary, maxAttempts: max(1, config.maxRetries - 2))
            }
            throw VKCredsError.deadHash
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
        // Step 1 — anonymous app token (seed for step 2)
        TURNLog.info("vkcreds", "step 1: getAnonymToken (seed)")
        let step1 = "client_secret=\(config.appSecret)&client_id=\(config.appID)" +
                    "&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous" +
                    "&isApiOauthAnonymEnabled=false&version=1&app_id=\(config.appID)"
        let r1 = try await postJSON(step1, to: "https://login.vk.ru/?act=get_anonym_token",
                                     step: "1.getAnonymToken")
        try Self.assertNoError(r1, step: "1")
        let t1: String = try Self.requireString(r1, path: ["data", "access_token"], step: "1")
        TURNLog.info("vkcreds", "step 1 ok")

        // Step 2 — payload-bound anon token (the one with messages
        // scope) — fed into step 3.
        TURNLog.info("vkcreds", "step 2: getAnonymToken (payload-bound)")
        let step2 = "client_id=\(config.appID)&token_type=messages&payload=\(t1)" +
                    "&client_secret=\(config.appSecret)&version=1&app_id=\(config.appID)"
        let r2 = try await postJSON(step2, to: "https://login.vk.ru/?act=get_anonym_token",
                                     step: "2.getAnonymToken")
        try Self.assertNoError(r2, step: "2")
        let t3: String = try Self.requireString(r2, path: ["data", "access_token"], step: "2")
        TURNLog.info("vkcreds", "step 2 ok")

        // Step 3 — getAnonymousToken; the captcha-prone step.
        TURNLog.info("vkcreds", "step 3: getAnonymousToken (captcha-prone)")
        let nameEnc = Self.urlEncoded(config.profileName)
        let step3Base = "vk_join_link=https://vk.com/call/join/\(hash)" +
                        "&name=\(nameEnc)&access_token=\(t3)"
        var r3 = try await postJSON(step3Base,
                                     to: "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264",
                                     step: "3.getAnonymousToken")

        if let errBlock = r3["error"] as? [String: Any] {
            let code = Int((errBlock["error_code"] as? Double) ?? -1)
            let errMsg = errBlock["error_msg"] as? String ?? ""
            if code == 9000 || errMsg.lowercased().contains("call not found") {
                TURNLog.error("vkcreds", "step 3: dead hash (code=\(code))")
                throw VKCredsError.deadHash
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
                                     to: "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264",
                                     step: "3-retry.getAnonymousToken")
            if let errBlock2 = r3["error"] as? [String: Any] {
                let code2 = Int((errBlock2["error_code"] as? Double) ?? -1)
                let errMsg2 = errBlock2["error_msg"] as? String ?? ""
                TURNLog.warn("vkcreds", "step 3-retry: VK error error_code=\(code2) error_msg=\(errMsg2)")
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
        TURNLog.info("vkcreds", "creds JSON: \(Self.credsLogJSONString(creds))")
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

    private static func credsLogJSONString(_ creds: VKTURNCredentials) -> String {
        struct LogShape: Encodable {
            let username: String
            let password: String
            let turn_servers: [String]
            let lifetime_sec: Int
        }

        let shape = LogShape(
            username: creds.username,
            password: creds.password,
            turn_servers: creds.turnURLs,
            lifetime_sec: Int(creds.lifetime)
        )

        do {
            let data = try JSONEncoder().encode(shape)
            guard let json = String(data: data, encoding: .utf8) else {
                return "<encode-failed: non-utf8 JSON>"
            }
            return json
        } catch {
            return "<encode-failed: \(error)>"
        }
    }

    private static func parseTurnBlock(_ block: [String: Any]) throws -> VKTURNCredentials {
        guard let user = block["username"] as? String, !user.isEmpty else {
            throw VKCredsError.malformedResponse(step: "5", hint: "missing username")
        }
        guard let pass = block["credential"] as? String, !pass.isEmpty else {
            throw VKCredsError.malformedResponse(step: "5", hint: "missing credential")
        }
        let rawURLs = block["urls"] as? [String] ?? []
        let urls: [String] = rawURLs.compactMap { raw in
            // VK ships URLs with `turn:` / `turns:` scheme and an
            // optional `?transport=tcp` suffix; strip both so callers
            // get a bare host:port to feed into libice / Pion.
            let trimmed = raw.split(separator: "?", maxSplits: 1).first.map(String.init) ?? raw
            var clean = trimmed
            if clean.hasPrefix("turns:") { clean.removeFirst("turns:".count) }
            else if clean.hasPrefix("turn:") { clean.removeFirst("turn:".count) }
            return clean.isEmpty ? nil : clean
        }
        guard !urls.isEmpty else {
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
            turnURLs: urls,
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
