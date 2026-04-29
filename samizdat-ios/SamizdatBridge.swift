import Foundation
import Combine
import NetworkExtension
import SamizdatClient // gomobile-generated framework

/// SamizdatBridge wraps the gomobile-generated `SamizdatClient` framework so
/// the rest of the SwiftUI code talks to a friendly Swift API instead of the
/// raw `Samizdat…()` C-bridge functions.
///
/// State is published; ContentView observes it and re-renders.
@MainActor
final class SamizdatBridge: ObservableObject {

    enum State: String {
        case disconnected, connecting, connected, error
    }

    @Published private(set) var state: State = .disconnected
    @Published private(set) var lastError: String = ""
    @Published private(set) var socksAddr: String = ""
    @Published private(set) var logs: [String] = []

    private var pollTask: Task<Void, Never>?
    private var lastExtensionLogPoll = Date.distantPast
    private var extensionLogDump = ""
    /// Synthetic events the Bridge wants to surface in the unified log
    /// (state transitions, extension-not-responding). Capped FIFO. Appears
    /// on its own line in the LogView, prefixed `bridge:` so the user can
    /// distinguish it from Go-shim logs.
    private var bridgeEvents: [String] = []
    private let bridgeEventsCap = 200
    private var previousNEStatus: String = "init"
    private var lastSuccessfulExtensionPoll = Date.distantPast
    private var didLogExtensionLoss = false

    init() {
        startPolling()
    }

    deinit {
        pollTask?.cancel()
    }

    // MARK: – Public API

    /// Validate a config blob without connecting. Returns nil on success,
    /// or a human-readable error message.
    static func validate(_ blob: String) -> String? {
        let err = SamizdatParseConfigError(blob)
        return err.isEmpty ? nil : err
    }

    /// Starts the system VPN configuration backed by PacketTunnelProvider.
    func connect(_ blob: String) async throws {
        state = .connecting
        lastError = ""
        try await VPNProfileStore.shared.startTunnel(configBlob: blob)
        await refresh()
    }

    func disconnect() {
        VPNProfileStore.shared.stopTunnel()
        state = .disconnected
    }

    func clearLogs() {
        SamizdatClearLogs()
        extensionLogDump = ""
        Task {
            await VPNProfileStore.shared.clearExtensionLogs()
        }
        logs = []
    }

    var version: String {
        SamizdatVersion()
    }

    // MARK: – Polling

    private func startPolling() {
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 250_000_000) // 4 Hz
            }
        }
    }

    private func refresh() async {
        let raw = await VPNProfileStore.shared.connectionStatus()
        let rawName = neStatusName(raw)
        let newState: State
        switch raw {
        case .invalid, .disconnected:
            newState = .disconnected
        case .connecting, .reasserting:
            newState = .connecting
        case .connected:
            newState = .connected
        case .disconnecting:
            newState = .disconnected
        @unknown default:
            newState = .error
        }

        if rawName != previousNEStatus {
            appendBridgeEvent("status \(previousNEStatus) → \(rawName)")
            previousNEStatus = rawName
            // Reset death-detection on every transition that brings the
            // tunnel back up.
            if raw == .connected || raw == .connecting {
                didLogExtensionLoss = false
            }
        }

        var err = SamizdatLastError()
        let socks = ""
        var dump = SamizdatLogs(0)

        if Date().timeIntervalSince(lastExtensionLogPoll) >= 1 {
            lastExtensionLogPoll = Date()
            let extensionDump = await VPNProfileStore.shared.extensionLogs()
            if let extensionDump, !extensionDump.isEmpty {
                extensionLogDump = extensionDump
                lastSuccessfulExtensionPoll = Date()
                didLogExtensionLoss = false
                if err.isEmpty,
                   let lastErrorLine = extensionDump.components(separatedBy: "\n").last(where: { $0.contains(" error:") }) {
                    err = lastErrorLine
                }
            } else if raw == .connected,
                      !didLogExtensionLoss,
                      Date().timeIntervalSince(lastSuccessfulExtensionPoll) > 3 {
                // Status says connected but we cannot reach the extension's
                // log RPC for >3s. Almost always means iOS killed the
                // extension (memory cap, watchdog) and is about to flip
                // status. Surface it loudly, once, so the next dump shows
                // the moment of death.
                didLogExtensionLoss = true
                appendBridgeEvent("extension log RPC stopped responding (extension likely killed by iOS)")
            }
        }

        dump = [dump, extensionLogDump, bridgeEvents.joined(separator: "\n")]
            .filter { !$0.isEmpty }
            .joined(separator: "\n")
        let lines = dump.isEmpty ? [] : dump.components(separatedBy: "\n")

        if state != newState { state = newState }
        if lastError != err { lastError = err }
        if socksAddr != socks { socksAddr = socks }
        if logs != lines { logs = lines }
    }

    private func appendBridgeEvent(_ message: String) {
        let stamp = SamizdatBridge.timeFormatter.string(from: Date())
        bridgeEvents.append("\(stamp) bridge: \(message)")
        if bridgeEvents.count > bridgeEventsCap {
            bridgeEvents.removeFirst(bridgeEvents.count - bridgeEventsCap)
        }
    }

    private func neStatusName(_ s: NEVPNStatus) -> String {
        switch s {
        case .invalid:       return "invalid"
        case .disconnected:  return "disconnected"
        case .connecting:    return "connecting"
        case .connected:     return "connected"
        case .reasserting:   return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default:    return "unknown(\(s.rawValue))"
        }
    }

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()
}
