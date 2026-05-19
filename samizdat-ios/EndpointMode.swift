import Foundation

/// EndpointMode — manual endpoint selection (IPA-P) and the future
/// auto-detection mode (IPA-Q).
///
/// Persisted in App Group UserDefaults so the extension can read the
/// current mode at startTunnel time and the main app can write to it
/// instantly on UI tap. Live mode flips while connected go through
/// VPNProfileStore.switchEndpoint(...) which sends a provider message
/// (UserDefaults write is the source of truth; the message is the
/// "wake up and re-read" prod).
enum EndpointMode: String, CaseIterable, Identifiable {
    case primary
    case backup
    case auto       // IPA-Q: WhitelistDetector picks. Disabled in IPA-P UI.

    var id: String { rawValue }

    var label: String {
        switch self {
        case .primary: return "Main"
        case .backup:  return "Whitelist"
        case .auto:    return "Auto"
        }
    }
}

/// Single source of truth for the endpoint preference. Lives in the
/// App Group UserDefaults so both the iOS app process and the
/// NEPacketTunnelProvider extension see the same value without
/// crossing IPC.
enum EndpointModeStore {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let key = "endpointMode"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    static var current: EndpointMode {
        get {
            guard let raw = defaults?.string(forKey: key),
                  let m = EndpointMode(rawValue: raw)
            else { return .primary }
            return m
        }
        set {
            defaults?.set(newValue.rawValue, forKey: key)
        }
    }
}

/// Manual FragPoC-transport toggle. Persisted in App Group UserDefaults so
/// the NEPacketTunnelProvider extension reads the same value the main-app
/// Settings toggle writes. When true, the Go socksstub builds a FragPoC
/// client (hardcoded test server) instead of the H2 client.
enum FragPoCTransportStore {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let key = "fragpocTransportEnabled"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    static var enabled: Bool {
        get { defaults?.bool(forKey: key) ?? false }
        set { defaults?.set(newValue, forKey: key) }
    }
}

/// Optional FragPoC endpoint URI. Empty means the Go bridge keeps its
/// historical built-in sync2 test endpoint. A non-empty value is a separate
/// FragPoC URI, not the normal tamizdat:// H2 URI, for example:
/// `fragpoc://<shortid>@ai-archive.ru:31503?secure=1`.
/// The Settings Port mode remains the source of truth for requested/probed
/// server ports.
enum FragPoCConfigStore {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let key = "fragpocConfigBlob"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    static var configBlob: String {
        get { defaults?.string(forKey: key) ?? "" }
        set {
            let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                defaults?.removeObject(forKey: key)
            } else {
                defaults?.set(trimmed, forKey: key)
            }
        }
    }

    static var hasConfig: Bool {
        !configBlob.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    static func summaryLabel(for blob: String = configBlob) -> String {
        let trimmed = blob.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "Legacy sync2" }
        guard let components = URLComponents(string: trimmed),
              components.scheme == "fragpoc",
              let host = components.host else { return "Custom FragPoC" }
        let port = components.port ?? 443
        return "\(host):\(port)"
    }

}

/// FragPoC UDP toggle. When disabled, the FragPoC transport drops all UDP
/// flows (DNS, QUIC, etc.) instead of tunnelling them over TCP. Useful to
/// reduce op-token pressure — DNS falls back to the system resolver and
/// QUIC downgrades to HTTP/2 through the TCP tunnel.
enum FragPoCUDPStore {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let key = "fragpocUDPEnabled"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Defaults to true — UDP forwarding is on unless explicitly disabled.
    static var enabled: Bool {
        get { defaults?.bool(forKey: key) ?? true }
        set { defaults?.set(newValue, forKey: key) }
    }
}

/// FragPoC port mode — a manual test knob (like the FragPoC transport
/// toggle) picking how the Go SOCKS stub spreads per-op dials across
/// server ports.
enum FragPoCPortMode: String, CaseIterable, Identifiable {
    case single
    case dual
    case multi

    var id: String { rawValue }

    /// Short label for the segmented control.
    var label: String {
        switch self {
        case .single: return "One port"
        case .dual:   return "80 + 443"
        case .multi:  return "Multi-port"
        }
    }

    /// One-line explanation shown under the segmented control.
    var hint: String {
        switch self {
        case .single:
            return "A single server port. Smallest footprint."
        case .dual:
            return "Two well-known ports a mobile carrier rarely throttles."
        case .multi:
            return "Dials spread across a pool of ports for throughput."
        }
    }
}

/// FragPoC port configuration — the selected port mode plus the editable
/// port list for each mode. Persisted in App Group UserDefaults so the
/// NEPacketTunnelProvider extension reads the same values the Settings UI
/// writes. The extension forwards the active list to the Go socksstub via
/// SocksstubSetFragPoCPorts; socksstub treats element 0 as the base server
/// port and the remaining entries as the dynamic dial pool.
enum FragPoCPortConfigStore {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let modeKey   = "fragpocPortMode"
    private static let singleKey = "fragpocPortsSingle"
    private static let dualKey   = "fragpocPortsDual"
    private static let multiKey  = "fragpocPortsMulti"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Default multi-port pool — matches the IPA-D37 hardcoded socksstub
    /// behaviour (base 31503 + dynamic 31510…31560), so an install that
    /// never opens this UI keeps dialling byte-identically to D37.
    static let defaultSinglePorts: [Int] = [31503]
    static let defaultDualPorts:   [Int] = [443, 80]
    static let defaultMultiPorts:  [Int] = {
        var ports = [31503]
        for p in 31510...31560 { ports.append(p) }
        return ports
    }()

    static var mode: FragPoCPortMode {
        get {
            guard let raw = defaults?.string(forKey: modeKey),
                  let m = FragPoCPortMode(rawValue: raw)
            else { return .multi }
            return m
        }
        set { defaults?.set(newValue.rawValue, forKey: modeKey) }
    }

    /// Returns the stored port list for `mode`, or its default if unset.
    static func ports(for mode: FragPoCPortMode) -> [Int] {
        switch mode {
        case .single: return read(singleKey) ?? defaultSinglePorts
        case .dual:   return read(dualKey)   ?? defaultDualPorts
        case .multi:  return read(multiKey)  ?? defaultMultiPorts
        }
    }

    /// Persists `ports` as the list for `mode`. Empty lists are ignored.
    static func setPorts(_ ports: [Int], for mode: FragPoCPortMode) {
        guard !ports.isEmpty else { return }
        let key: String
        switch mode {
        case .single: key = singleKey
        case .dual:   key = dualKey
        case .multi:  key = multiKey
        }
        defaults?.set(ports.map(String.init).joined(separator: ","), forKey: key)
    }

    /// Default port list for `mode`.
    static func defaultPorts(for mode: FragPoCPortMode) -> [Int] {
        switch mode {
        case .single: return defaultSinglePorts
        case .dual:   return defaultDualPorts
        case .multi:  return defaultMultiPorts
        }
    }

    /// Port list for the active mode — element 0 is the base server port,
    /// the rest form the dynamic dial pool.
    static var activePorts: [Int] { ports(for: mode) }

    /// Comma-separated `activePorts` — the wire format passed to
    /// SocksstubSetFragPoCPorts.
    static var activePortsCSV: String {
        activePorts.map(String.init).joined(separator: ",")
    }

    private static func read(_ key: String) -> [Int]? {
        guard let raw = defaults?.string(forKey: key) else { return nil }
        let parsed = parsePorts(raw)
        return parsed.isEmpty ? nil : parsed
    }

    /// Parses a comma/space/newline-separated port list — keeps only valid
    /// 1…65535 entries, in order, de-duplicated.
    static func parsePorts(_ raw: String) -> [Int] {
        var seen = Set<Int>()
        var out: [Int] = []
        let separators = CharacterSet(charactersIn: ", \n\t\r")
        for token in raw.components(separatedBy: separators) {
            let trimmed = token.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, let port = Int(trimmed),
                  port >= 1, port <= 65535, !seen.contains(port)
            else { continue }
            seen.insert(port)
            out.append(port)
        }
        return out
    }
}

/// Splits a combined samizdat:// URL into (primary, backup) parts for
/// UI display. The combined form is `samizdat://...primary...&backup=
/// <base64url(samizdat://...backup...)>`. Returns the backup only if
/// the `&backup=` parameter was present and decoded successfully.
enum SamizdatURLCodec {
    /// Extracts the primary URL (everything except &backup=...) and
    /// the backup URL (base64url-decoded) from a combined blob.
    /// If no &backup= is present, returns (combined, nil).
    static func split(_ combined: String) -> (primary: String, backup: String?) {
        guard let q = combined.range(of: "?") else {
            return (combined, nil)
        }
        let prefix = String(combined[..<q.upperBound]) // "samizdat://...?"
        let qs = String(combined[q.upperBound...])
        var primaryParts: [String] = []
        var backupB64: String?
        for part in qs.split(separator: "&", omittingEmptySubsequences: false) {
            let kv = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if kv.count == 2 && String(kv[0]) == "backup" {
                backupB64 = String(kv[1])
            } else {
                primaryParts.append(String(part))
            }
        }
        let primary = prefix + primaryParts.joined(separator: "&")
        // Trim a potential trailing "?" if everything was &backup=…
        let primaryTrimmed = primary.hasSuffix("?") ? String(primary.dropLast()) : primary

        guard let b64 = backupB64, !b64.isEmpty,
              let backup = base64URLDecode(b64) else {
            return (primaryTrimmed, nil)
        }
        return (primaryTrimmed, backup)
    }

    /// Composes a combined URL from a primary samizdat:// and an
    /// optional backup samizdat://. If backup is nil/empty, returns the
    /// primary unchanged.
    static func compose(primary: String, backup: String?) -> String {
        guard let backup = backup, !backup.isEmpty else { return primary }
        let encoded = base64URLEncode(backup)
        let sep = primary.contains("?") ? "&" : "?"
        return primary + sep + "backup=" + encoded
    }

    /// base64url with no padding (RFC 4648 §5).
    private static func base64URLEncode(_ s: String) -> String {
        let raw = Data(s.utf8).base64EncodedString()
        return raw
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func base64URLDecode(_ s: String) -> String? {
        var t = s
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Pad to a multiple of 4.
        let pad = (4 - t.count % 4) % 4
        t += String(repeating: "=", count: pad)
        guard let data = Data(base64Encoded: t),
              let out = String(data: data, encoding: .utf8) else {
            return nil
        }
        return out
    }
}
