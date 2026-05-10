import Foundation
import Darwin
import NetworkExtension
import SamizdatClient

final class VPNProfileStore {
    static let shared = VPNProfileStore()

    private let providerBundleIdentifier = "com.anarki.samizdat-test.tunnel"
    private let localizedDescription = "Tamizdat"

    /// Cache of the loaded NETunnelProviderManager. Each
    /// loadAllFromPreferences call is an XPC roundtrip to nesessionmanager,
    /// which under load can take 5-50 ms. The previous design called it
    /// from connectionStatus() and extensionLogs() at 4 Hz combined =
    /// ~16 XPC/sec to a daemon already busy with our active VPN. iOS
    /// flagged the extension as "high non-tunnel work" and reaped it.
    /// With the cache + NEVPNConfigurationChange listener the daemon
    /// is hit at most on actual config edits.
    private var cachedManager: NETunnelProviderManager?
    private var cacheLock = NSLock()
    private var configChangeObserver: NSObjectProtocol?

    private init() {
        configChangeObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNConfigurationChange,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            // Force a reload on the next access — config edited under us
            // (e.g. user toggled VPN in Settings).
            self?.cacheLock.lock()
            self?.cachedManager = nil
            self?.cacheLock.unlock()
        }
    }

    deinit {
        if let observer = configChangeObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func startTunnel(configBlob: String) async throws {
        SamizdatAddLog("info: preparing VPN profile")
        // Path 3 final architecture: SocksStub + samizdat live INSIDE the
        // extension process (alongside hev), not in this main-app process.
        // Reason: iOS suspends backgrounded apps after ~30 s, which kills
        // any cross-process loopback listener and breaks Speedtest in
        // Safari. With hev replacing gVisor (the original memory hog) and
        // a single-conn samizdat H2 client (no gVisor pools, no per-flow
        // goroutine fan-out), extension RSS sits at ~25-30 MB — well
        // under the 50 MB cap. App-side does NOT call SocksstubStart or
        // SocksstubSetSamizdatConfig. The extension does both at
        // startTunnel.
        let serverIP = await resolvedIPv4Address(from: configBlob)
        let engineConfigBlob = configBlobWithConnectEndpoint(serverIP, in: configBlob) ?? configBlob
        if let serverIP {
            SamizdatAddLog("info: resolved server IPv4 before VPN start: \(serverIP)")
        } else {
            SamizdatAddLog("warn: server IPv4 resolve timed out before VPN start")
        }

        let manager = try await ensureProfile(
            configBlob: configBlob,
            engineConfigBlob: engineConfigBlob,
            serverIP: serverIP
        )
        if manager.connection.status != .connected && manager.connection.status != .connecting {
            SamizdatAddLog("info: starting NETunnelProviderSession")
            try manager.connection.startVPNTunnel()
        }
    }

    func stopTunnel() {
        Task {
            guard let manager = await currentManager() else { return }
            manager.connection.stopVPNTunnel()
        }
    }

    /// Returns the manager from cache if present, otherwise loads it once
    /// from preferences (XPC). Subsequent calls are O(1).
    func currentManager() async -> NETunnelProviderManager? {
        cacheLock.lock()
        if let m = cachedManager {
            cacheLock.unlock()
            return m
        }
        cacheLock.unlock()
        guard let m = try? await loadExistingManager() else { return nil }
        cacheLock.lock()
        cachedManager = m
        cacheLock.unlock()
        return m
    }

    func connectionStatus() async -> NEVPNStatus {
        guard let manager = await currentManager() else { return .disconnected }
        return manager.connection.status
    }

    func extensionLogs() async -> String? {
        try? await sendProviderMessage("logs")
    }

    func clearExtensionLogs() async {
        _ = try? await sendProviderMessage("clearLogs")
    }

    /// IPA-P: live-switch the active endpoint without disconnecting the
    /// VPN. Writes EndpointModeStore.current first (source of truth)
    /// then pokes the extension via provider message so it re-reads
    /// and rewires its samizdat client over the current network.
    func switchEndpoint(to mode: EndpointMode) async {
        EndpointModeStore.current = mode
        _ = try? await sendProviderMessage("switchEndpoint")
    }

    /// Triggers extension to rebuild the samizdat client. Used by the
    /// IPA-X V1/V2/V3 picker so flipping the variant immediately
    /// reflects in the live transport (the new client picks up
    /// PoolVariantPreferences.current when it constructs the
    /// ClientConfig).
    func refreshSamizdatClient() async {
        _ = try? await sendProviderMessage("refreshSamizdatClient")
    }

    /// IPA-D21: poke the extension to re-read PingURLPreferences.url
    /// from App Group UserDefaults and push it into the Go-side ping
    /// prober (SocksstubSetPingProbeURL). Lightweight — does not
    /// rebuild the samizdat client; the prober picks up the new URL
    /// on its next 10 s tick.
    func refreshPingURL() async {
        _ = try? await sendProviderMessage("refreshPingURL")
    }

    /// IPA-Z: fetch one snapshot of the live realtime / RTT state from
    /// the extension. Used by the main-screen lamp at 500 ms cadence.
    /// Returns `.offline` on any failure (extension not running, RPC
    /// timeout, JSON malformed) — caller renders this as "— offline —".
    func fetchTamizdatStatus() async -> TamizdatStatusSnapshot {
        guard let manager = await currentManager(),
              let session = manager.connection as? NETunnelProviderSession else {
            return .offline
        }
        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            break
        default:
            return .offline
        }
        let data = "status".data(using: .utf8) ?? Data()
        let response: Data? = await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            do {
                try session.sendProviderMessage(data) { responseData in
                    cont.resume(returning: responseData)
                }
            } catch {
                cont.resume(returning: nil)
            }
        }
        guard let response, !response.isEmpty else {
            return .offline
        }
        let decoded = try? JSONDecoder().decode(TamizdatStatusSnapshot.self, from: response)
        return decoded ?? .offline
    }

    @discardableResult
    private func ensureProfile(configBlob: String, engineConfigBlob: String, serverIP: String?) async throws -> NETunnelProviderManager {
        let manager: NETunnelProviderManager
        if let existingManager = await currentManager() {
            manager = existingManager
        } else {
            manager = NETunnelProviderManager()
        }
        configure(manager, configBlob: configBlob, engineConfigBlob: engineConfigBlob, serverIP: serverIP)
        try await save(manager)
        try await load(manager)
        // Save can succeed but trigger NEVPNConfigurationChange, which our
        // observer reacts to by clearing the cache. Re-pin the saved
        // manager here so subsequent currentManager() calls don't roundtrip
        // to nesessionmanager again.
        cacheLock.lock()
        cachedManager = manager
        cacheLock.unlock()
        return manager
    }

    private func configure(_ manager: NETunnelProviderManager, configBlob: String, engineConfigBlob: String, serverIP: String?) {
        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleIdentifier
        proto.serverAddress = "Samizdat"
        var providerConfiguration: [String: String] = [
            "configBlob": configBlob,
            "engineConfigBlob": engineConfigBlob,
        ]
        if let serverIP {
            providerConfiguration["serverIP"] = serverIP
        }
        proto.providerConfiguration = providerConfiguration

        manager.protocolConfiguration = proto
        manager.localizedDescription = localizedDescription
        manager.isEnabled = true
    }

    private func loadExistingManager() async throws -> NETunnelProviderManager? {
        let managers = try await loadAll()
        return managers.first { manager in
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return proto.providerBundleIdentifier == providerBundleIdentifier
        }
    }

    private func loadAll() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: managers ?? [])
            }
        }
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }
    }

    private func load(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: ())
            }
        }
    }

    private func sendProviderMessage(_ message: String) async throws -> String {
        guard let manager = await currentManager(),
              let session = manager.connection as? NETunnelProviderSession else {
            return ""
        }
        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            break
        default:
            return ""
        }

        let data = message.data(using: .utf8) ?? Data()
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            do {
                try session.sendProviderMessage(data) { responseData in
                    let response = responseData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private func resolvedIPv4Address(from configBlob: String) async -> String? {
        guard let host = URL(string: configBlob)?.host else { return nil }
        var parsed = in_addr()
        if inet_pton(AF_INET, host, &parsed) == 1 {
            return isReservedFakeIPv4(host) ? nil : host
        }

        let systemResult: String? = await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            let lock = NSLock()
            var didResume = false

            func resumeOnce(_ value: String?) {
                lock.lock()
                defer { lock.unlock() }
                guard !didResume else { return }
                didResume = true
                continuation.resume(returning: value)
            }

            DispatchQueue.global(qos: .utility).async {
                resumeOnce(Self.resolveIPv4Address(host: host))
            }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2.5) {
                resumeOnce(nil)
            }
        }
        if let systemResult, !isReservedFakeIPv4(systemResult) {
            return systemResult
        }
        if let systemResult {
            SamizdatAddLog("warn: ignoring fake/reserved DNS result: \(systemResult)")
        }
        return await resolveIPv4AddressWithDoH(host: host)
    }

    private static func resolveIPv4Address(host: String) -> String? {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let result else { return nil }
        defer { freeaddrinfo(result) }

        var addr = result.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
            return nil
        }
        return String(cString: buffer)
    }

    private func resolveIPv4AddressWithDoH(host: String) async -> String? {
        var components = URLComponents(string: "https://1.1.1.1/dns-query")
        components?.queryItems = [
            URLQueryItem(name: "name", value: host),
            URLQueryItem(name: "type", value: "A"),
        ]
        guard let url = components?.url else { return nil }
        var request = URLRequest(url: url)
        request.setValue("application/dns-json", forHTTPHeaderField: "Accept")

        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            let response = try JSONDecoder().decode(DNSJSONResponse.self, from: data)
            let address = response.Answer?
                .filter { $0.type == 1 }
                .map(\.data)
                .first { isUsableIPv4($0) }
            if let address {
                SamizdatAddLog("info: resolved server IPv4 via DoH: \(address)")
            }
            return address
        } catch {
            SamizdatAddLog("warn: DoH resolve failed: \(error.localizedDescription)")
            return nil
        }
    }

    private func isUsableIPv4(_ address: String) -> Bool {
        var parsed = in_addr()
        return inet_pton(AF_INET, address, &parsed) == 1 && !isReservedFakeIPv4(address)
    }

    private func isReservedFakeIPv4(_ address: String) -> Bool {
        let parts = address.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }
        // 198.18.0.0/15 is reserved for benchmarking and commonly used as fake-ip.
        if parts[0] == 198 && (parts[1] == 18 || parts[1] == 19) { return true }
        if parts[0] == 0 || parts[0] == 127 || parts[0] >= 224 { return true }
        return false
    }

    private func configBlobWithConnectEndpoint(_ host: String?, in configBlob: String) -> String? {
        guard let host,
              var components = URLComponents(string: configBlob),
              let port = components.port else { return nil }
        var queryItems = components.queryItems ?? []
        queryItems.removeAll { $0.name == "connect_host" || $0.name == "connect_port" }
        queryItems.append(URLQueryItem(name: "connect_host", value: host))
        queryItems.append(URLQueryItem(name: "connect_port", value: String(port)))
        components.queryItems = queryItems
        return components.string
    }
}

private struct DNSJSONResponse: Decodable {
    let Answer: [DNSJSONAnswer]?
}

private struct DNSJSONAnswer: Decodable {
    let type: Int
    let data: String
}
