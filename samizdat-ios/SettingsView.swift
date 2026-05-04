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
}
