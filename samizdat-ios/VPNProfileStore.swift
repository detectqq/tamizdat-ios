import Foundation
import NetworkExtension

final class VPNProfileStore {
    static let shared = VPNProfileStore()

    private let providerBundleIdentifier = "com.anarki.samizdat-test.tunnel"
    private let localizedDescription = "Samizdat Test"

    private init() {}

    func startTunnel(configBlob: String) async throws {
        let manager = try await ensureProfile(configBlob: configBlob)
        if manager.connection.status != .connected && manager.connection.status != .connecting {
            try manager.connection.startVPNTunnel()
        }
    }

    func stopTunnel() {
        Task {
            guard let manager = try? await loadExistingManager() else { return }
            manager.connection.stopVPNTunnel()
        }
    }

    func connectionStatus() async -> NEVPNStatus {
        guard let manager = try? await loadExistingManager() else { return .disconnected }
        return manager.connection.status
    }

    @discardableResult
    private func ensureProfile(configBlob: String) async throws -> NETunnelProviderManager {
        let manager: NETunnelProviderManager
        if let existingManager = try await loadExistingManager() {
            manager = existingManager
        } else {
            manager = NETunnelProviderManager()
        }
        configure(manager, configBlob: configBlob)
        try await save(manager)
        try await load(manager)
        return manager
    }

    private func configure(_ manager: NETunnelProviderManager, configBlob: String) {
        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerBundleIdentifier
        proto.serverAddress = "Samizdat"
        proto.providerConfiguration = ["configBlob": configBlob]

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
}
