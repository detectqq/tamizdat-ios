import Foundation

/// Provider behind the generic TURN relay transport. The Network Extension
/// still consumes the same App-Group TURN-credentials JSON; only the main app
/// acquisition flow differs.
enum TURNRelayProvider: String, CaseIterable, Identifiable, Hashable {
    case vk
    case yandex

    var id: String { rawValue }

    var label: String {
        switch self {
        case .vk: return "VK"
        case .yandex: return "Yandex"
        }
    }
}

enum TURNRelayPreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let providerKey = "tamizdat.turnProvider"
    private static let yandexLinkKey = "tamizdat.yandexTelemostLink"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    static var provider: TURNRelayProvider {
        get {
            guard let raw = defaults?.string(forKey: providerKey),
                  let p = TURNRelayProvider(rawValue: raw) else {
                return .vk
            }
            return p
        }
        set { defaults?.set(newValue.rawValue, forKey: providerKey) }
    }

    static var yandexLink: String {
        get { defaults?.string(forKey: yandexLinkKey) ?? "" }
        set { defaults?.set(newValue.trimmingCharacters(in: .whitespacesAndNewlines), forKey: yandexLinkKey) }
    }
}

struct TURNActivationConfig {
    var provider: TURNRelayProvider?
    var peer: String?
    var password: String?
    var vkCallHash: String?
    var yandexLink: String?
}

enum TURNCredentialParser {
    /// Parses the extension's existing generic TURN-credentials JSON or
    /// a credentialed TURN URI. The saved VKTURNCredentials type is now
    /// generic despite the historical VK prefix.
    static func parse(_ raw: String) -> VKTURNCredentials? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if let json = parseJSON(trimmed) { return json }
        if let uri = parseCredentialURI(trimmed) { return uri }
        return nil
    }

    private struct ManualJSON: Decodable {
        struct Server: Decodable {
            let host: String
            let port: Int
            let scheme: String?
            let transport: String?
        }
        let username: String?
        let password: String?
        let credential: String?
        let turn_servers: [String]?
        let urls: [String]?
        let turn_servers_v2: [Server]?
        let lifetime_sec: Int?
        let lifetime: Int?
    }

    private static func parseJSON(_ raw: String) -> VKTURNCredentials? {
        guard let data = raw.data(using: .utf8),
              let shape = try? JSONDecoder().decode(ManualJSON.self, from: data) else {
            return nil
        }
        guard let username = shape.username?.trimmingCharacters(in: .whitespacesAndNewlines), !username.isEmpty else {
            return nil
        }
        let password = (shape.password ?? shape.credential ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !password.isEmpty else { return nil }

        var servers: [TurnServer] = []
        if let v2 = shape.turn_servers_v2 {
            servers.append(contentsOf: v2.map {
                TurnServer(host: $0.host, port: $0.port, scheme: $0.scheme ?? "turn", transport: $0.transport ?? "udp")
            })
        }
        let legacyURLs = (shape.turn_servers ?? []) + (shape.urls ?? [])
        servers.append(contentsOf: legacyURLs.compactMap(parseServerURL))
        guard !servers.isEmpty else { return nil }
        let lifetime = TimeInterval(shape.lifetime_sec ?? shape.lifetime ?? 3600)
        return VKTURNCredentials(username: username,
                                 password: password,
                                 turnServers: servers,
                                 lifetime: lifetime,
                                 acquiredAt: Date())
    }

    private static func parseCredentialURI(_ raw: String) -> VKTURNCredentials? {
        // Accept turn://user:pass@host:port?transport=udp and
        // turns://user:pass@host:port?transport=tcp. RFC-style
        // turn:host:port without credentials is intentionally rejected:
        // the runner needs username/password for Allocate.
        guard let comps = URLComponents(string: raw),
              let scheme = comps.scheme?.lowercased(),
              scheme == "turn" || scheme == "turns",
              let host = comps.host,
              let port = comps.port,
              let user = comps.user?.removingPercentEncoding,
              let pass = comps.password?.removingPercentEncoding,
              !user.isEmpty,
              !pass.isEmpty else {
            return nil
        }
        let transport = comps.queryItems?
            .first(where: { $0.name.lowercased() == "transport" })?
            .value ?? (scheme == "turns" ? "tcp" : "udp")
        return VKTURNCredentials(username: user,
                                 password: pass,
                                 turnServers: [TurnServer(host: host, port: port, scheme: scheme, transport: transport)],
                                 lifetime: 3600,
                                 acquiredAt: Date())
    }

    private static func parseServerURL(_ raw: String) -> TurnServer? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let scheme: String
        let body: String
        if trimmed.hasPrefix("turns:") {
            scheme = "turns"
            body = String(trimmed.dropFirst("turns:".count))
        } else if trimmed.hasPrefix("turn:") {
            scheme = "turn"
            body = String(trimmed.dropFirst("turn:".count))
        } else {
            scheme = "turn"
            body = trimmed
        }
        let parts = body.split(separator: "?", maxSplits: 1).map(String.init)
        let hostPort = parts[0]
        let transport: String = {
            guard parts.count > 1 else { return scheme == "turns" ? "tcp" : "udp" }
            return URLComponents(string: "x://x?\(parts[1])")?
                .queryItems?
                .first(where: { $0.name.lowercased() == "transport" })?
                .value ?? (scheme == "turns" ? "tcp" : "udp")
        }()
        let hp = hostPort.split(separator: ":", maxSplits: 1).map(String.init)
        guard hp.count == 2, let port = Int(hp[1]) else { return nil }
        return TurnServer(host: hp[0], port: port, scheme: scheme, transport: transport)
    }
}

enum TURNActivationParser {
    /// Accepts any of:
    /// - `wgturn://46.29.164.99:5000?password=...&hash=...`
    /// - `vkturn://?peer=46.29.164.99:5000&password=...&vk=...`
    /// - `https://vk.ru/call/join/<hash>` / `https://vk.com/call/join/<hash>`
    /// - `https://telemost.yandex.ru/j/<id>`
    /// - bare `host:port` peer.
    static func parse(_ raw: String) -> TURNActivationConfig {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return TURNActivationConfig() }

        var out = TURNActivationConfig()
        if let url = URL(string: trimmed), let scheme = url.scheme?.lowercased() {
            let host = url.host ?? ""
            let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
            let q = Dictionary(uniqueKeysWithValues: (comps?.queryItems ?? []).compactMap { item -> (String, String)? in
                guard let value = item.value else { return nil }
                return (item.name.lowercased(), value)
            })

            if host.contains("telemost.yandex.ru") || scheme == "yandexturn" {
                out.provider = .yandex
                out.yandexLink = trimmed
            }
            if host.contains("vk.") || trimmed.contains("/call/join/") || scheme == "vkturn" {
                out.provider = .vk
                if let hash = normalizeVKHash(trimmed), !hash.isEmpty {
                    out.vkCallHash = hash
                }
            }
            if scheme == "wgturn" || scheme == "vkturn" || scheme == "tamizdat-turn" || scheme == "turn" || scheme == "turns" {
                if !host.isEmpty {
                    let port = url.port.map(String.init)
                    if let port, !port.isEmpty {
                        out.peer = "\(host):\(port)"
                    }
                }
                out.provider = providerFrom(q["provider"]) ?? out.provider
                out.peer = firstNonEmpty(q["peer"], q["server"], q["wgturn"], out.peer)
                out.password = firstNonEmpty(q["password"], q["pwd"], q["connect_password"], q["connpassword"])
                out.vkCallHash = firstNonEmpty(q["hash"], q["vk"], q["vk_hash"], out.vkCallHash)
                out.yandexLink = firstNonEmpty(q["yandex"], q["yandex_link"], q["telemost"], out.yandexLink)
            }
        }

        if out.peer == nil,
           trimmed.range(of: #"^[A-Za-z0-9._-]+:\d{1,5}$"#, options: .regularExpression) != nil {
            out.peer = trimmed
        }
        if out.vkCallHash == nil, let hash = normalizeVKHash(trimmed), !hash.isEmpty {
            out.provider = out.provider ?? .vk
            out.vkCallHash = hash
        }
        return out
    }

    static func normalizeVKHash(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let range = s.range(of: "/call/join/") {
            s = String(s[range.upperBound...])
        } else if !(s.contains("/") || s.contains(":")) {
            return s.trimmingCharacters(in: CharacterSet(charactersIn: "/?#"))
        } else {
            return nil
        }
        if let q = s.firstIndex(where: { $0 == "?" || $0 == "#" }) {
            s = String(s[..<q])
        }
        return s.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    private static func providerFrom(_ raw: String?) -> TURNRelayProvider? {
        guard let raw else { return nil }
        let s = raw.lowercased()
        if s == "vk" { return .vk }
        if s == "ya" || s == "yandex" || s == "telemost" { return .yandex }
        return nil
    }

    private static func firstNonEmpty(_ values: String?...) -> String? {
        for v in values {
            if let t = v?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty {
                return t
            }
        }
        return nil
    }
}
