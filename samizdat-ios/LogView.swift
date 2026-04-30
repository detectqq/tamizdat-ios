import SwiftUI

struct LogView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var bridge: SamizdatBridge

    @State private var filter: LogFilter = .all
    @State private var autoScroll = true
    @State private var copiedFlash = false
    @State private var sendStatus: SendStatus = .idle

    enum SendStatus: Equatable {
        case idle
        case sending
        case sent
        case failed(String)

        var label: String {
            switch self {
            case .idle:    return "Telegram"
            case .sending: return "Sending…"
            case .sent:    return "Sent ✓"
            case .failed:  return "Failed"
            }
        }
        var icon: String {
            switch self {
            case .idle:    return "paperplane"
            case .sending: return "paperplane.fill"
            case .sent:    return "checkmark.circle"
            case .failed:  return "exclamationmark.triangle"
            }
        }
    }

    enum LogFilter: String, CaseIterable, Identifiable {
        case all   = "all"
        case info  = "info"
        case warn  = "warn"
        case error = "error"
        var id: String { rawValue }
    }

    private var filtered: [String] {
        guard filter != .all else { return bridge.logs }
        let needle = " \(filter.rawValue):"
        return bridge.logs.filter { $0.contains(needle) }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Picker("Filter", selection: $filter) {
                    ForEach(LogFilter.allCases) { f in
                        Text(f.rawValue.capitalized).tag(f)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)
                .padding(.vertical, 8)

                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(filtered.enumerated()), id: \.offset) { idx, line in
                                Text(line)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(color(for: line))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(idx)
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                    }
                    .background(Color(.secondarySystemBackground))
                    .onChange(of: filtered.count) {
                        guard autoScroll, !filtered.isEmpty else { return }
                        withAnimation { proxy.scrollTo(filtered.count - 1, anchor: .bottom) }
                    }
                    .onAppear {
                        guard !filtered.isEmpty else { return }
                        proxy.scrollTo(filtered.count - 1, anchor: .bottom)
                    }
                }

                HStack {
                    Toggle(isOn: $autoScroll) {
                        Label("Auto-scroll", systemImage: "arrow.down.to.line")
                            .labelStyle(.titleAndIcon)
                    }
                    .toggleStyle(.button)
                    .controlSize(.small)

                    Spacer()

                    Button {
                        UIPasteboard.general.string = filtered.joined(separator: "\n")
                        copiedFlash = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
                            copiedFlash = false
                        }
                    } label: {
                        Label(copiedFlash ? "Copied!" : "Copy", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    Button {
                        sendToTelegram()
                    } label: {
                        Label(sendStatus.label, systemImage: sendStatus.icon)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(sendStatus == .sending)
                    .tint(telegramTint)

                    Button(role: .destructive) {
                        bridge.clearLogs()
                    } label: {
                        Label("Clear", systemImage: "trash")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                .padding()
            }
            .navigationTitle("Logs")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
        }
    }

    private func color(for line: String) -> Color {
        if line.contains(" error:") { return .red }
        if line.contains(" warn:")  { return .orange }
        return .primary
    }

    private var telegramTint: Color {
        switch sendStatus {
        case .idle:    return .blue
        case .sending: return .gray
        case .sent:    return .green
        case .failed:  return .red
        }
    }

    private func sendToTelegram() {
        guard TelegramReporter.isConfigured else {
            sendStatus = .failed("Configure bot token in Telegram settings")
            DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
                if case .failed = sendStatus { sendStatus = .idle }
            }
            return
        }
        sendStatus = .sending
        let body = filtered.joined(separator: "\n")
        let caption = TelegramReporter.defaultCaption(extra: "vpn=\(bridge.state.rawValue)")
        TelegramReporter.sendLog(text: body, caption: caption) { result in
            switch result {
            case .success:
                sendStatus = .sent
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
                    if case .sent = sendStatus { sendStatus = .idle }
                }
            case .failure(let err):
                sendStatus = .failed(err.errorDescription ?? "?")
                DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
                    if case .failed = sendStatus { sendStatus = .idle }
                }
            }
        }
    }
}
