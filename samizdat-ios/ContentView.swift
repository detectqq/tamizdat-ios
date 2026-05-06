import SwiftUI

struct ContentView: View {
    @StateObject private var bridge = SamizdatBridge()
    @State private var showSettings = false
    @State private var showLogs = false
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

    // IPA-Q: live whitelist-detection status, polled from App Group
    // UserDefaults every 2 s while the view is visible.
    @State private var whitelistStatus: WhitelistStatus = .unknown
    @State private var whitelistActiveEndpoint: EndpointMode = .primary
    @State private var statusPollTimer: Timer?

    // IPA-Z: live shape/RTT lamp identical to the Windows-GUI line
    // ("○ bulk • RTT 17ms" / "● lite • RTT 23ms"). Polled at 500 ms
    // via a Timer owned by TamizdatStatusStore (in-process gomobile
    // calls, no HTTP).
    @StateObject private var lampStore = TamizdatStatusStore()

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

                // IPA-Z: shape + RTT lamp. Same single-line format the
                // Windows GUI shows ("○ bulk • RTT 17ms"). Hidden while
                // tunnel is offline — TamizdatStatusStore returns
                // "— offline —" but we just suppress the line entirely
                // for less visual noise on the main screen.
                if bridge.state == .connected && !lampStore.realShape.isEmpty {
                    Text(lampStore.lampLabel)
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
                        // IPA-Q: live status from WhitelistDetector via
                        // WhitelistStatusStore (App Group UserDefaults).
                        HStack(spacing: 6) {
                            Image(systemName: "circle.fill")
                                .foregroundStyle(statusColor)
                                .font(.caption)
                            Text(statusText)
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
                    showLogs = true
                } label: {
                    Label("Logs", systemImage: "doc.text.fill")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .buttonStyle(.bordered)

                Button {
                    showSettings = true
                } label: {
                    Label("Settings", systemImage: "gearshape.fill")
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
        .sheet(isPresented: $showSettings) {
            SettingsView(onConfigChanged: { saved in
                hasConfig = saved
                hasBackupConfigured = ContentView.checkBackupConfigured()
                if !hasBackupConfigured {
                    if manualEndpoint == .backup {
                        manualEndpoint = .primary
                    }
                    if EndpointModeStore.current == .backup {
                        EndpointModeStore.current = .primary
                    }
                }
            })
        }
        .sheet(isPresented: $showLogs) {
            LogView(bridge: bridge)
        }
        .onAppear {
            startStatusPolling()
            lampStore.start()
        }
        .onDisappear {
            stopStatusPolling()
            lampStore.stop()
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

    /// IPA milestone tag rendered next to the version in the footer.
    /// Bump this when promoting a new milestone IPA so testers can tell
    /// at a glance which build is on the device. Source of truth:
    /// `ipa/milestones/<TAG>-...` directory name.
    private static let milestoneTag = "C5"

    /// "IPA-Z6 · v0.2.42-fab1f9e (build 42)" — milestone tag is
    /// hardcoded above; rest is pulled from Info.plist, which the CI
    /// workflow stamps with MARKETING_VERSION = 0.2.<run>-<git-sha> and
    /// CURRENT_PROJECT_VERSION = <run>. Updates on every build.
    private var buildLabel: String {
        let info = Bundle.main.infoDictionary
        let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "IPA-\(Self.milestoneTag) · v\(marketing) (build \(build))"
    }

    // IPA-Q: status badge colour + text driven by WhitelistDetector.
    private var statusColor: Color {
        switch whitelistStatus {
        case .off:        return .green
        case .detected:   return .red
        case .frozen:     return .yellow
        case .noNetwork:  return .gray
        case .unknown:    return .gray
        }
    }

    private var statusText: String {
        switch whitelistStatus {
        case .off:
            return "Whitelist: off (using main)"
        case .detected:
            let ep = whitelistActiveEndpoint == .backup ? "whitelist server" : "main"
            return "Whitelist: ON — using \(ep)"
        case .frozen:
            return "Frozen: captive portal suspected"
        case .noNetwork:
            return "Whitelist: no network (paused)"
        case .unknown:
            return "Whitelist: monitoring…"
        }
    }

    private func refreshWhitelistStatus() {
        whitelistStatus = WhitelistStatusStore.current
        whitelistActiveEndpoint = WhitelistStatusStore.activeEndpoint
        // The detector cycle cadence is 30 s normal / 60 s on-backup
        // / up to 180 s in Low Power Mode. Stale-out at 3× the longest
        // expected cadence so we don't misreport detector death on
        // perfectly-healthy LPM devices. 200 s = generous.
        if isAutoMode && bridge.state == .connected
            && WhitelistStatusStore.ageSeconds > 200 {
            whitelistStatus = .unknown
        }
    }

    private func startStatusPolling() {
        statusPollTimer?.invalidate()
        let timer = Timer(timeInterval: 2.0, repeats: true) { _ in
            refreshWhitelistStatus()
        }
        RunLoop.main.add(timer, forMode: .common)
        statusPollTimer = timer
        refreshWhitelistStatus() // immediate
    }

    private func stopStatusPolling() {
        statusPollTimer?.invalidate()
        statusPollTimer = nil
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
