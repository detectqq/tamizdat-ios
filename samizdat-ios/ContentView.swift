import SwiftUI

/// IPA-D22: Home screen — full SwiftUI rewrite per the 2026 design
/// handoff at `C:\var-tmp\ios-redesign\design_handoff_samizdat_vpn_2026\`.
///
/// Top bar (SZ-mark + Tamizdat wordmark + Logs/Settings buttons),
/// large 220px ShieldMark hero, status label + mint Ping chip,
/// 3 stat tiles (Mode/Uptime/Data), Auto-detect whitelist row when
/// backup configured, big 60pt Connect/Disconnect button, mono caption.
///
/// State machine: 6 states `off / connecting / connected /
/// reconnecting / failed / error`. Phase C iOS-notify observer
/// preserved from D20 — server alerts still render via `.alert(...)`.
struct ContentView: View {
    @Environment(\.themeTokens) private var theme

    @StateObject private var bridge = SamizdatBridge()
    @StateObject private var lampStore = TamizdatStatusStore()
    @StateObject private var serverNotif = ServerNotificationObserver()
    @StateObject private var exitIP = ExitIPStore()
    // IPA-D28: main-app WhitelistMonitor — runs while VPN is OFF +
    // auto mode + foreground, so WhitelistStatusStore.activeEndpoint
    // is already correct by the time the user taps Connect.
    @StateObject private var whitelistMonitor = WhitelistMonitor()

    @State private var showSettings = false
    @State private var showLogs = false
    @State private var showEndpoints = false
    @State private var hasConfig = ConfigStore.shared.load() != nil
    @State private var hasBackupConfigured = ContentView.checkBackupConfigured()

    @State private var isAutoMode: Bool = (EndpointModeStore.current == .auto)
    @State private var manualEndpoint: EndpointMode = {
        let cur = EndpointModeStore.current
        return cur == .auto ? .primary : cur
    }()

    @State private var whitelistStatus: WhitelistStatus = .unknown
    @State private var whitelistActiveEndpoint: EndpointMode = .primary
    @State private var statusPollTimer: Timer?

    @State private var isPreparingVPN = false
    @State private var vpnProfileError: String?

    /// IPA-D25 fix6: optimistic "we just asked for a switch" flag.
    /// Set immediately when the user taps the manual segment or flips
    /// the auto toggle, so the shield flips to amber "Reconnecting…"
    /// without waiting for the 500 ms status-poll cycle to pick up the
    /// extension's isRewiring flag. Auto-clears after 3 s (long enough
    /// for the real rewire to complete on most networks; the status
    /// poll then takes over). Operator: "должен быть моментальный
    /// рестарт".
    @State private var pendingSwitch: Bool = false
    @State private var pendingSwitchClearTask: Task<Void, Never>?

    private static func checkBackupConfigured() -> Bool {
        guard let blob = ConfigStore.shared.load() else { return false }
        return SamizdatURLCodec.split(blob).backup != nil
    }

    /// IPA milestone tag rendered in the build caption.
    private static let milestoneTag = "D30"

    // MARK: – Derived state

    /// 6-state derivation. Order of precedence:
    ///   1. `.error`         (bridge.state == .error)
    ///   2. `.reconnecting`  (lampStore.isReconnecting && was connected)
    ///   3. `.connecting`    (bridge.state == .connecting)
    ///   4. `.failed`        (connected but ping prober says failed)
    ///   5. `.connected`     (bridge.state == .connected)
    ///   6. `.off`           (otherwise)
    private enum HomeState {
        case off, connecting, connected, reconnecting, failed, error

        var statusLabel: String {
            switch self {
            case .off:          return "Off"
            case .connecting:   return "Connecting…"
            case .connected:    return "Connected"
            case .reconnecting: return "Reconnecting…"
            case .failed:       return "Proxy unreachable"
            case .error:        return "Error"
            }
        }

        func accent(theme: ThemeTokens) -> Color {
            switch self {
            case .off:          return theme.red
            case .connecting:   return theme.amber
            case .connected:    return theme.mint
            case .reconnecting: return theme.amber
            case .failed:       return theme.amber
            case .error:        return theme.red
            }
        }

        var connectButtonLabel: String {
            switch self {
            case .connected:    return "Disconnect"
            case .reconnecting: return "Disconnect"
            case .failed:       return "Disconnect"
            case .connecting:   return "Connecting…"
            default:            return "Connect"
            }
        }

        var isConnectButtonRed: Bool {
            switch self {
            case .connected, .reconnecting, .failed: return true
            default: return false
            }
        }

        var showsPingChip: Bool {
            self == .connected || self == .failed
        }
    }

    private var homeState: HomeState {
        switch bridge.state {
        case .error:
            return .error
        case .connecting:
            return .connecting
        case .connected:
            // Optimistic flip first — gives instant feedback on a tap
            // while the extension's rewire is still in-flight.
            if pendingSwitch { return .reconnecting }
            if lampStore.isReconnecting { return .reconnecting }
            if lampStore.snapshot.pingFailed { return .failed }
            // IPA-D27: green "Connected" only after ping has actually
            // validated through the tunnel. Until the first successful
            // probe of this session lands (pingMs >= 0), stay in
            // .connecting ("Connecting…" amber). Otherwise iOS marks
            // bridge.state = .connected the moment NETunnelProvider
            // session is up, which is BEFORE the samizdat client has
            // dialed the upstream — UI would falsely glow green for
            // 1-5s.
            if lampStore.snapshot.pingMs < 0 { return .connecting }
            return .connected
        case .disconnected:
            return .off
        }
    }

    // MARK: – Body

    var body: some View {
        ZStack {
            ThemeBackground(theme: theme)

            VStack(spacing: 0) {
                topBar
                    .padding(.horizontal, 20)
                    .padding(.top, 8)
                    .padding(.bottom, 6)

                hero
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                statTiles
                    .padding(.horizontal, 16)
                    .padding(.top, 4)

                // IPA-D25 fix5: row is always visible. The picker
                // inside the row is gated on hasBackupConfigured —
                // when no Whitelist endpoint configured, we show a
                // hint instead of hiding the entire control.
                autoDetectRow
                    .padding(.horizontal, 16)
                    .padding(.top, 12)

                connectButton
                    .padding(.horizontal, 16)
                    .padding(.top, 14)

                buildCaption
                    .padding(.top, 10)
                    .padding(.bottom, 18)
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .sheet(isPresented: $showSettings) {
            SettingsView(onConfigChanged: { saved in
                hasConfig = saved
                hasBackupConfigured = ContentView.checkBackupConfigured()
                if !hasBackupConfigured {
                    if manualEndpoint == .backup { manualEndpoint = .primary }
                    if EndpointModeStore.current == .backup {
                        EndpointModeStore.current = .primary
                    }
                }
            })
            .environment(\.themeTokens, theme)
        }
        .sheet(isPresented: $showLogs) {
            LogView(injectedBridge: bridge)
                .environment(\.themeTokens, theme)
        }
        .sheet(isPresented: $showEndpoints) {
            EndpointsView { saved in
                hasConfig = saved
                hasBackupConfigured = ContentView.checkBackupConfigured()
                if !hasBackupConfigured {
                    if manualEndpoint == .backup { manualEndpoint = .primary }
                    if EndpointModeStore.current == .backup {
                        EndpointModeStore.current = .primary
                    }
                }
            }
            .environment(\.themeTokens, theme)
        }
        .onAppear {
            startStatusPolling()
            lampStore.start()
            exitIP.start(isConnected: bridge.state == .connected)
            // IPA-D28: only run the main-app monitor while VPN is off
            // and auto-mode is selected. Once the extension is up,
            // its own WhitelistDetector takes over (it has actual
            // physical-iface binding + ICMP probes; we'd just be
            // writing conflicting values).
            updateWhitelistMonitorState()
        }
        .onDisappear {
            stopStatusPolling()
            lampStore.stop()
            exitIP.stop()
            whitelistMonitor.stop()
        }
        .onChange(of: bridge.state) { _, newState in
            // Refetch exit IP immediately on connect/disconnect so the
            // surface flips without waiting up to 60s for the next tick.
            let isUp = (newState == .connected)
            exitIP.refreshSoon(isConnected: isUp)
            // Stop monitor when extension takes over; resume when
            // tunnel drops back to disconnected.
            updateWhitelistMonitorState()
        }
        .onChange(of: isAutoMode) { _, _ in
            // Toggle auto-mode → maybe start/stop monitor accordingly.
            updateWhitelistMonitorState()
        }
        // Phase C iOS-notify (preserved from D20): server-pushed alert.
        .alert(
            serverNotif.latest?.title.isEmpty == false
                ? (serverNotif.latest?.title ?? "Сообщение")
                : "Сообщение",
            isPresented: Binding(
                get: { serverNotif.latest != nil },
                set: { if !$0 { serverNotif.dismiss() } }
            ),
            presenting: serverNotif.latest
        ) { _ in
            Button("OK", role: .cancel) { serverNotif.dismiss() }
        } message: { payload in
            Text(payload.body)
        }
    }

    // MARK: – Top bar

    private var topBar: some View {
        HStack {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: 7)
                        .fill(theme.mintDim)
                        .frame(width: 28, height: 28)
                    Text("SZ")
                        .font(.geist(.bold, size: 13))
                        .tracking(-0.52)
                        .foregroundStyle(theme.mint)
                }
                Text("Tamizdat")
                    .font(.geist(.semibold, size: 15))
                    .tracking(-0.15)
                    .foregroundStyle(theme.text)
            }
            Spacer()
            HStack(spacing: 8) {
                circleIconButton(systemName: "doc.text") { showLogs = true }
                circleIconButton(systemName: "gearshape") { showSettings = true }
            }
        }
    }

    private func circleIconButton(systemName: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            ZStack {
                Circle().fill(theme.chip).frame(width: 34, height: 34)
                Image(systemName: systemName)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(theme.textDim)
            }
        }
        .buttonStyle(.plain)
    }

    // MARK: – Hero

    private var hero: some View {
        VStack(spacing: 18) {
            ShieldMark(
                size: 220,
                color: homeState.accent(theme: theme),
                dim: theme.isDark ? theme.mintInk : Color.black.opacity(0.18)
            )

            VStack(spacing: 12) {
                Text(homeState.statusLabel)
                    .font(.geist(.bold, size: 38))
                    .tracking(-1.14)
                    .foregroundStyle(theme.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)

                if homeState.showsPingChip {
                    PingChip(
                        pingMs: lampStore.snapshot.pingMs >= 0 ? lampStore.snapshot.pingMs : nil
                    )
                }

                // IPA-D24: exit IP under the Ping chip. URLSession.shared
                // follows the system default route — through the tunnel
                // when on, real ISP when off. Quiet failure: line hides.
                if let ip = exitIP.ip {
                    HStack(spacing: 4) {
                        Text(exitIP.isFromTunnel ? "Exit" : "Network")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textMuted)
                        Text("·")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textMuted)
                        Text(ip)
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    .padding(.top, 2)
                }

                if !bridge.lastError.isEmpty && bridge.state == .error {
                    Text(bridge.lastError)
                        .font(.geist(.regular, size: 13))
                        .foregroundStyle(theme.textDim)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }
                if let vpnProfileError {
                    Text(vpnProfileError)
                        .font(.geist(.regular, size: 13))
                        .foregroundStyle(theme.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }
                if !hasConfig {
                    Text("Paste a tamizdat:// link in Settings → Proxies to begin.")
                        .font(.geist(.regular, size: 13))
                        .foregroundStyle(theme.textDim)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
            }
        }
    }

    // MARK: – Stat tiles

    private var statTiles: some View {
        HStack(spacing: 8) {
            StatTile(label: "Mode",
                     value: TamizdatStatusStore.modeLabel(active: effectiveEndpoint),
                     unit: nil)
            StatTile(label: "Uptime",
                     value: lampStore.uptimeText,
                     unit: lampStore.uptimeUnit.isEmpty ? nil : lampStore.uptimeUnit)
            StatTile(label: "Data",
                     value: lampStore.dataText.value,
                     unit: lampStore.dataText.unit)
        }
    }

    /// "Effective" endpoint for label purposes:
    ///   - manual primary/backup → the picked one
    ///   - auto                 → WhitelistStatusStore.activeEndpoint
    private var effectiveEndpoint: EndpointMode {
        if EndpointModeStore.current == .auto {
            return whitelistActiveEndpoint
        }
        return EndpointModeStore.current
    }

    // MARK: – Auto-detect Whitelist row

    private var autoDetectRow: some View {
        CardContainer(padding: 0) {
            VStack(spacing: 0) {
                DesignRow(
                    icon: IconCard(systemName: "dot.radiowaves.up.forward",
                                   bg: theme.blueDim,
                                   fg: theme.blue),
                    title: "Auto-detect Whitelist",
                    sub: whitelistSub,
                    isLast: isAutoMode    // last only when picker is hidden
                ) {
                    HStack(spacing: 8) {
                        Toggle("", isOn: $isAutoMode)
                            .labelsHidden()
                            .tint(theme.mint)
                            .onChange(of: isAutoMode) { _, newAuto in
                                noteSwitchPending()
                                let newMode: EndpointMode = newAuto ? .auto : manualEndpoint
                                Task {
                                    await VPNProfileStore.shared.switchEndpoint(to: newMode)
                                }
                            }
                        // IPA-D24: chevron signals the card itself is
                        // tappable — opens the Proxies sheet so the
                        // user can jump straight to URL edit.
                        Image(systemName: "chevron.right")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(theme.textMuted)
                    }
                }
                // IPA-D24: card-level tap opens Proxies. SwiftUI gesture
                // priority lets the inner Toggle / segmented picker
                // intercept their own taps; the surrounding tap on
                // icon / title / sub area lands here.
                .contentShape(Rectangle())
                .onTapGesture { showEndpoints = true }

                // IPA-D22 fix: when auto-detect is off, expose the manual
                // Main/Whitelist picker inline below the toggle — port of
                // the pre-D22 segmented control that was lost in the rewrite.
                if !isAutoMode {
                    HStack(spacing: 0) {
                        manualPickerSegment(label: "Main",
                                            isSelected: manualEndpoint == .primary,
                                            tap: { selectManual(.primary) })
                        manualPickerSegment(label: "Whitelist",
                                            isSelected: manualEndpoint == .backup,
                                            tap: { selectManual(.backup) })
                    }
                    .padding(4)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .padding(.horizontal, 16)
                    .padding(.bottom, 14)
                }
            }
        }
    }

    private func manualPickerSegment(label: String,
                                     isSelected: Bool,
                                     tap: @escaping () -> Void) -> some View {
        Button(action: tap) {
            Text(label)
                .font(.geist(.semibold, size: 13))
                .tracking(-0.13)
                .foregroundStyle(isSelected ? theme.chipActiveText : theme.text)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .background(isSelected ? theme.chipActive : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 9))
        }
        .buttonStyle(.plain)
    }

    private func selectManual(_ ep: EndpointMode) {
        guard !isAutoMode else { return }
        manualEndpoint = ep
        noteSwitchPending()
        Task {
            await VPNProfileStore.shared.switchEndpoint(to: ep)
        }
    }

    /// IPA-D28: start/stop the main-app WhitelistMonitor based on the
    /// current VPN state + auto-mode toggle. Runs ONLY when
    ///   - bridge.state == .disconnected (extension's own detector
    ///     would conflict otherwise)
    ///   - isAutoMode == true (no point monitoring if user picked
    ///     manual endpoint)
    private func updateWhitelistMonitorState() {
        let shouldRun = bridge.state == .disconnected && isAutoMode
        if shouldRun {
            whitelistMonitor.start()
        } else {
            whitelistMonitor.stop()
        }
    }

    /// IPA-D25 fix6: flip the optimistic "reconnecting" flag instantly
    /// so the shield turns amber the moment the user taps. The flag
    /// auto-clears after 3 s — by then the extension's isRewiring
    /// has propagated via the 500 ms status poll, so `homeState`
    /// keeps showing `.reconnecting` from the real signal until the
    /// new client finishes warming.
    ///
    /// IPA-D25 fix7: also kick the ExitIP store to refetch immediately
    /// (otherwise the IP chip stays on the OLD exit IP for up to 5s
    /// until the next regular poll lands).
    private func noteSwitchPending() {
        pendingSwitchClearTask?.cancel()
        pendingSwitch = true
        // The actual TLS handshake to the new upstream takes some
        // time; refetch the exit IP a moment later (1.5 s gives the
        // new samizdat client a chance to be fully ready). ExitIPStore
        // itself also polls every 5 s now, so this is just a fast-path
        // bump.
        exitIP.refreshSoon(isConnected: bridge.state == .connected)
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            exitIP.refreshSoon(isConnected: bridge.state == .connected)
        }
        pendingSwitchClearTask = Task { @MainActor in
            try? await Task.sleep(for: .seconds(3))
            if !Task.isCancelled {
                pendingSwitch = false
            }
        }
    }

    private var whitelistSub: String {
        // Detector status takes precedence — it's the live signal user wants
        // to see ("Paused — no network" matters in elevator/metro).
        switch whitelistStatus {
        case .noNetwork:  return "Paused — no network"
        case .frozen:     return "Frozen — captive portal?"
        case .detected:   return "Whitelist active"
        case .off:        return isAutoMode ? "Free internet" : "Manual"
        case .unknown:    return isAutoMode ? "Monitoring…" : "Manual"
        }
    }

    // MARK: – Connect button

    private var connectButton: some View {
        Button(action: toggleConnection) {
            HStack(spacing: 10) {
                Circle()
                    .fill(homeState.isConnectButtonRed ? Color.white : theme.mintInk)
                    .frame(width: 8, height: 8)
                Text(homeState.connectButtonLabel)
                    .font(.geist(.bold, size: 18))
                    .tracking(-0.18)
            }
            .frame(maxWidth: .infinity)
            .frame(height: 60)
            .background(homeState.isConnectButtonRed ? theme.red : theme.mint)
            .foregroundStyle(homeState.isConnectButtonRed ? Color.white : theme.mintInk)
            .clipShape(RoundedRectangle(cornerRadius: 20))
            .shadow(
                color: homeState.isConnectButtonRed
                    ? Color.red.opacity(0.32)
                    : theme.mint.opacity(0.28),
                radius: 12, x: 0, y: 6
            )
        }
        .buttonStyle(.plain)
        .disabled(bridge.state == .connecting || isPreparingVPN || !hasConfig)
        .opacity((bridge.state == .connecting || isPreparingVPN || !hasConfig) ? 0.6 : 1.0)
    }

    // MARK: – Build caption

    private var buildCaption: some View {
        Text(buildLabel.uppercased())
            .font(.geistMono(.semibold, size: 10.5))
            .tracking(0.42)
            .foregroundStyle(theme.textMuted)
    }

    private var buildLabel: String {
        let info = Bundle.main.infoDictionary
        let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "Tamizdat · v\(marketing) (build \(build)) · IPA-\(Self.milestoneTag)"
    }

    // MARK: – Actions

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

    // MARK: – Status polling

    private func refreshWhitelistStatus() {
        whitelistStatus = WhitelistStatusStore.current
        whitelistActiveEndpoint = WhitelistStatusStore.activeEndpoint
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
        refreshWhitelistStatus()
    }

    private func stopStatusPolling() {
        statusPollTimer?.invalidate()
        statusPollTimer = nil
    }
}

// MARK: – Phase C iOS-notify server-message observer (preserved verbatim from D20)
//
// Sits on the app side; listens for a Darwin notification posted by the
// NE-side `NotificationBridge` whenever a server-pushed
// `CoverConfigBundle.Notification` has been persisted into App Group
// UserDefaults.
final class ServerNotificationObserver: ObservableObject {
    @Published var latest: NotificationPayload?

    init() {
        readFromGroup()
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        CFNotificationCenterAddObserver(
            center, observer,
            { _, observerPtr, _, _, _ in
                guard let observerPtr = observerPtr else { return }
                let me = Unmanaged<ServerNotificationObserver>
                    .fromOpaque(observerPtr).takeUnretainedValue()
                DispatchQueue.main.async { me.readFromGroup() }
            },
            ServerNotificationConstants.darwinNotificationName,
            nil, .deliverImmediately
        )
    }

    deinit {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        CFNotificationCenterRemoveEveryObserver(center, observer)
    }

    private func readFromGroup() {
        guard
            let defaults = UserDefaults(suiteName: ServerNotificationConstants.appGroupID),
            let data = defaults.data(forKey: ServerNotificationConstants.userDefaultsKey),
            let payload = try? JSONDecoder().decode(NotificationPayload.self, from: data)
        else { return }
        if payload != latest {
            latest = payload
        }
    }

    func dismiss() {
        UserDefaults(suiteName: ServerNotificationConstants.appGroupID)?
            .removeObject(forKey: ServerNotificationConstants.userDefaultsKey)
        latest = nil
    }
}

#Preview {
    ContentView()
        .environment(\.themeTokens, ThemeTokens.cream)
}
