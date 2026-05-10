import SwiftUI
import UserNotifications

/// Standard "Settings" screen. Houses notification preferences,
/// shortcuts to existing config sheets, and an About section.
struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var notificationsEnabled: Bool = NotificationPreferences.enabled
    @State private var permissionStatus: UNAuthorizationStatus = .notDetermined
    @State private var permissionDeniedAlert: Bool = false

    @State private var poolVariant: PoolVariant = PoolVariantPreferences.current

    // IPA-D21: user-configurable target for the real-internet ping
    // prober. Bound to a TextField; persisted to App Group UserDefaults
    // on commit. A live "refreshPingURL" provider message wakes the
    // extension to pick up the new value without disconnect.
    @State private var pingURL: String = PingURLPreferences.url

    @State private var showConfig = false
    @State private var showTelegram = false

    /// Callback so the parent can react to config changes (e.g.,
    /// re-check whether a backup endpoint is now configured).
    var onConfigChanged: (Bool) -> Void = { _ in }

    var body: some View {
        NavigationStack {
            Form {
                // ── Notifications ────────────────────────────────────────
                Section {
                    Toggle(isOn: $notificationsEnabled) {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Whitelist alerts")
                                Text("Notify when whitelist mode toggles on/off")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: "bell.badge")
                        }
                    }
                    .onChange(of: notificationsEnabled) { _, newValue in
                        if newValue {
                            Task { await handleEnableNotifications() }
                        } else {
                            NotificationPreferences.enabled = false
                        }
                    }
                    if permissionStatus == .denied && notificationsEnabled {
                        Label {
                            Text("Notifications are blocked in iOS Settings. Tap to open Settings.")
                                .font(.caption)
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        }
                        .onTapGesture { openSystemSettings() }
                    }
                } header: {
                    Text("Notifications")
                } footer: {
                    Text("Local push when the auto-detector switches between Main and Whitelist endpoints. No remote push, no server-side telemetry — strictly on-device.")
                }

                // ── Endpoints ────────────────────────────────────────────
                Section {
                    Button {
                        showConfig = true
                    } label: {
                        Label("Endpoints (Main + Whitelist)", systemImage: "key.fill")
                    }
                } header: {
                    Text("Configuration")
                } footer: {
                    Text("Paste tamizdat:// URLs for Main and (optionally) Whitelist server.")
                }

                // ── Pool variant ─────────────────────────────────────────
                Section {
                    Picker(selection: $poolVariant) {
                        ForEach(PoolVariant.allCases) { variant in
                            Text(variant.displayName).tag(variant)
                        }
                    } label: {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Pool variant")
                                Text(poolVariant.caption)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: "rectangle.connected.to.line.below")
                        }
                    }
                    .pickerStyle(.menu)
                    .onChange(of: poolVariant) { _, newValue in
                        PoolVariantPreferences.current = newValue
                        Task {
                            await VPNProfileStore.shared.refreshSamizdatClient()
                        }
                    }
                } header: {
                    Text("Connection pool")
                } footer: {
                    Text("How many simultaneous TCP/443 connections the client opens to the server. V1 = one (stealth, slow), V2 = up to two (balanced), V3 = adaptive 2..4 (fastest, taller TLS fingerprint per ISP). V1 also engages strict-single-H2 mode. Plan B+ realtime auto-shape (voice / games stay on the lite transport) runs identically across all three.")
                }

                // ── Ping probe ───────────────────────────────────────────
                // IPA-D21: target URL for the real-internet ping prober.
                // Every 10 s the Go side opens an HTTP HEAD via the
                // samizdat tunnel; the latency feeds the shield status.
                // 2+ consecutive misses → "Proxy unreachable" yellow shield.
                Section {
                    Label {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Ping probe URL")
                            TextField("https://example.com/probe", text: $pingURL)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled(true)
                                .keyboardType(.URL)
                                .font(.callout.monospaced())
                                .onSubmit { savePingURL() }
                        }
                    } icon: {
                        Image(systemName: "dot.radiowaves.left.and.right")
                    }
                    HStack {
                        Button("Save") { savePingURL() }
                            .buttonStyle(.borderedProminent)
                        Spacer()
                        Button("Reset to default") {
                            pingURL = PingURLPreferences.defaultURL
                            savePingURL()
                        }
                        .buttonStyle(.bordered)
                    }
                } header: {
                    Text("Ping probe")
                } footer: {
                    Text("Every 10 seconds the client opens an HTTP HEAD request through the tunnel to this URL. Latency appears under the shield as “Ping XXms”. Two consecutive failures flip the shield to yellow (“Proxy unreachable”). Default: http://www.gstatic.com/generate_204 (Google connectivity probe — 204 No Content). Use cp.cloudflare.com/generate_204 for a Cloudflare alternative.")
                }

                // ── Diagnostics ──────────────────────────────────────────
                Section {
                    Button {
                        showTelegram = true
                    } label: {
                        Label("Telegram log uploader", systemImage: "paperplane.fill")
                    }
                } header: {
                    Text("Diagnostics")
                } footer: {
                    Text("Bot token + chat ID for sending the in-app log to a Telegram chat. Used for debugging.")
                }

                // ── About ────────────────────────────────────────────────
                Section {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text(versionLabel)
                            .foregroundStyle(.secondary)
                            .font(.body.monospaced())
                    }
                    Link(destination: URL(string: "https://github.com/detectqq/tamizdat")!) {
                        Label("Project on GitHub", systemImage: "arrow.up.right.square")
                    }
                } header: {
                    Text("About")
                } footer: {
                    Text("Tamizdat — anti-censorship tunnel client. Renamed from samizdat 2026-05-01.")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task {
                permissionStatus = await NotificationPreferences.currentSystemAuthorization()
            }
            .alert("Notifications were not granted", isPresented: $permissionDeniedAlert) {
                Button("Open iOS Settings") { openSystemSettings() }
                Button("Cancel", role: .cancel) { }
            } message: {
                Text("Enable notifications for Tamizdat in iOS Settings to receive whitelist-detection alerts.")
            }
            .sheet(isPresented: $showConfig) {
                ConfigPasteView { saved in
                    onConfigChanged(saved)
                }
            }
            .sheet(isPresented: $showTelegram) {
                TelegramSettingsView()
            }
        }
    }

    private var versionLabel: String {
        let info = Bundle.main.infoDictionary
        let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(marketing) (\(build))"
    }

    private func handleEnableNotifications() async {
        let granted = await NotificationPreferences.requestPermission()
        permissionStatus = await NotificationPreferences.currentSystemAuthorization()
        if granted {
            NotificationPreferences.enabled = true
        } else {
            // Bounce toggle back; surface alert directing to iOS Settings.
            NotificationPreferences.enabled = false
            notificationsEnabled = false
            permissionDeniedAlert = true
        }
    }

    private func openSystemSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }

    /// IPA-D21: persist the typed ping URL and poke the extension to
    /// pick it up live. Trims whitespace; an empty string falls back to
    /// the default in PingURLPreferences. Sending the provider message
    /// is a no-op when the tunnel is not running — next startTunnel
    /// will read the new value from App Group UserDefaults itself.
    private func savePingURL() {
        let trimmed = pingURL.trimmingCharacters(in: .whitespacesAndNewlines)
        PingURLPreferences.url = trimmed
        // Re-read so the field reflects what's actually stored (e.g.
        // empty -> default URL).
        pingURL = PingURLPreferences.url
        Task {
            await VPNProfileStore.shared.refreshPingURL()
        }
    }
}
