import SwiftUI

struct ContentView: View {
    @StateObject private var bridge = SamizdatBridge()
    @State private var showConfig = false
    @State private var showLogs = false
    @State private var showTelegram = false
    @State private var hasConfig = ConfigStore.shared.load() != nil
    @State private var hasBackupConfigured = ContentView.checkBackupConfigured()

    // IPA-P.1: split the 3-way segmented picker into a clearer
    // "Auto detection on/off" toggle + a manual endpoint picker that
    // is only shown when auto is off. The persistent EndpointMode in
    // App Group UserDefaults still has three values (primary/backup/
    // auto) — this UI just maps them to two controls.
    @State private var isAutoMode: Bool = (EndpointModeStore.current == .auto)
    @State private var manualEndpoint: EndpointMode = {
        let cur = EndpointModeStore.current
        return cur == .auto ? .primary : cur
    }()
    @State private var isPreparingVPN = false
    @State private var vpnProfileError: String?

    private static func checkBackupConfigured() -> Bool {
        guard let blob = ConfigStore.shared.load() else { return false }
        return SamizdatURLCodec.split(blob).backup != nil
    }

    var body: some View {
        VStack(spacing: 28) {
            // ── Status ─────────────────────────────────────────────────────
            VStack(spacing: 12) {
                Image(systemName: stateIcon)
                    .font(.system(size: 88))
                    .foregroundStyle(stateColor)
                    .symbolEffect(.pulse, isActive: bridge.state == .connecting)

                Text(stateTitle)
                    .font(.title)
                    .bold()

                if !bridge.lastError.isEmpty && bridge.state == .error {
                    Text(bridge.lastError)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                if let vpnProfileError {
                    Text(vpnProfileError)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                if !bridge.socksAddr.isEmpty && bridge.state == .connected {
                    Text("SOCKS5: \(bridge.socksAddr)")
                        .font(.footnote.monospaced())
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            // ── Connect/Disconnect ─────────────────────────────────────────
            Button(action: toggleConnection) {
                Text(buttonTitle)
                    .font(.title2.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
            }
            .buttonStyle(.borderedProminent)
            .tint(buttonTint)
            .disabled(bridge.state == .connecting || isPreparingVPN || !hasConfig)

            if !hasConfig {
                Text("Paste a samizdat:// config first")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            // ── Endpoint controls (only when backup configured) ────────────
            if hasBackupConfigured {
                VStack(alignment: .leading, spacing: 10) {
                    Toggle(isOn: $isAutoMode) {
                        HStack(spacing: 6) {
                            Image(systemName: "antenna.radiowaves.left.and.right")
                            Text("Auto-detect whitelist")
                                .font(.subheadline.weight(.medium))
                        }
                    }
                    .onChange(of: isAutoMode) { _, newAuto in
                        let newMode: EndpointMode = newAuto ? .auto : manualEndpoint
                        Task {
                            await VPNProfileStore.shared.switchEndpoint(to: newMode)
                        }
                    }

                    if isAutoMode {
                        // Whitelist status fonarь — placeholder в P.1.
                        // В IPA-Q здесь будет состояние от WhitelistDetector.
                        HStack(spacing: 6) {
                            Image(systemName: "circle.fill")
                                .foregroundStyle(.gray)
                                .font(.caption)
                            Text("Whitelist: monitoring activates after next update")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Picker("Endpoint", selection: $manualEndpoint) {
                            Text(EndpointMode.primary.label).tag(EndpointMode.primary)
                            Text(EndpointMode.backup.label).tag(EndpointMode.backup)
                        }
                        .pickerStyle(.segmented)
                        .onChange(of: manualEndpoint) { _, newEndpoint in
                            guard !isAutoMode else { return }
                            Task {
                                await VPNProfileStore.shared.switchEndpoint(to: newEndpoint)
                            }
                        }
                    }
                }
                .padding(.horizontal, 4)
            }

            // ── Sub-buttons ────────────────────────────────────────────────
            HStack(spacing: 12) {
                Button {
                    showConfig = true
                } label: {
                    Label("Config", systemImage: "key.fill")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)

                Button {
                    showLogs = true
                } label: {
                    Label("Logs", systemImage: "doc.text.fill")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)

                Button {
                    showTelegram = true
                } label: {
                    Label("Telegram", systemImage: "paperplane.fill")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)
            }

            Text(buildLabel)
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .padding(24)
        .sheet(isPresented: $showConfig) {
            ConfigPasteView { saved in
                hasConfig = saved
                hasBackupConfigured = ContentView.checkBackupConfigured()
                // If backup got removed:
                //  - manualEndpoint can no longer be .backup
                //  - if current persisted mode was .backup, demote to .primary
                if !hasBackupConfigured {
                    if manualEndpoint == .backup {
                        manualEndpoint = .primary
                    }
                    if EndpointModeStore.current == .backup {
                        EndpointModeStore.current = .primary
                    }
                }
            }
        }
        .sheet(isPresented: $showLogs) {
            LogView(bridge: bridge)
        }
        .sheet(isPresented: $showTelegram) {
            TelegramSettingsView()
        }
    }

    // MARK: – derived

    private var stateIcon: String {
        switch bridge.state {
        case .disconnected: "shield.slash"
        case .connecting:   "shield.lefthalf.filled"
        case .connected:    "shield.lefthalf.filled.badge.checkmark"
        case .error:        "exclamationmark.shield.fill"
        }
    }

    private var stateColor: Color {
        switch bridge.state {
        case .disconnected: .secondary
        case .connecting:   .yellow
        case .connected:    .green
        case .error:        .red
        }
    }

    private var stateTitle: String {
        switch bridge.state {
        case .disconnected: "Disconnected"
        case .connecting:   "Connecting…"
        case .connected:    "Connected"
        case .error:        "Error"
        }
    }

    private var buttonTitle: String {
        if isPreparingVPN { return "Preparing VPN..." }
        switch bridge.state {
        case .connected:  return "Disconnect"
        case .connecting: return "Connecting…"
        default:          return "Connect"
        }
    }

    private var buttonTint: Color {
        bridge.state == .connected ? .red : .blue
    }

    /// "v0.2.42-fab1f9e (build 42)" — pulled from Info.plist, which the
    /// CI workflow stamps with MARKETING_VERSION = 0.2.<run>-<git-sha>
    /// and CURRENT_PROJECT_VERSION = <run>. Updates on every build.
    private var buildLabel: String {
        let info = Bundle.main.infoDictionary
        let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "v\(marketing) (build \(build))"
    }

    private func toggleConnection() {
        if bridge.state == .connected {
            bridge.disconnect()
            return
        }
        guard let blob = ConfigStore.shared.load() else { return }

        isPreparingVPN = true
        vpnProfileError = nil

        Task { @MainActor in
            defer { isPreparingVPN = false }
            do {
                try await bridge.connect(blob)
            } catch {
                vpnProfileError = error.localizedDescription
            }
        }
    }
}

#Preview {
    ContentView()
}
