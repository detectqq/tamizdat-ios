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

/// Splits a combined samizdat:// URL into (primary, backup) parts for
/// UI display. The combined form is `samizdat://...primary...&backup=
/// <base64url(samizdat://...backup...)>`. Returns the backup only if
/// the `&backup=` parameter was present and decoded successfully.
enum SamizdatURLCodec {
    struct H2PeerConfig: Equatable {
        let server: String
        let shortID: String
    }

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

    /// Extract the H2 peer tuple used by VK TURN: server comes from the
    /// H2 tamizdat:// URI authority, password comes from that URI's shortid.
    /// Prefer the Whitelist/backup H2 URI because TURN replaces that endpoint;
    /// fall back to primary for single-endpoint configs.
    static func h2PeerConfig(from combined: String) -> H2PeerConfig? {
        let parts = split(combined)
        if let backup = parts.backup?.trimmingCharacters(in: .whitespacesAndNewlines),
           !backup.isEmpty {
            return h2PeerConfigFromSingleURL(backup)
        }
        let primary = parts.primary.trimmingCharacters(in: .whitespacesAndNewlines)
        return h2PeerConfigFromSingleURL(primary)
    }

    private static func h2PeerConfigFromSingleURL(_ raw: String) -> H2PeerConfig? {
        guard let components = URLComponents(string: raw),
              let scheme = components.scheme?.lowercased(),
              scheme == "tamizdat" || scheme == "samizdat",
              let host = components.host,
              !host.isEmpty else {
            return nil
        }
        let shortID = components.queryItems?
            .first { $0.name.lowercased() == "shortid" }?
            .value?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !shortID.isEmpty else { return nil }

        let displayHost = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        let port = components.port ?? 443
        return H2PeerConfig(server: "\(displayHost):\(port)", shortID: shortID)
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
