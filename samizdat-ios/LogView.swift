import SwiftUI
import SamizdatClient // for SocksstubWriteHeapProfile (D10 heap dump button)

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

                    // IPA-D9: heap profile to telegram
                    Button {
                        sendHeapToTelegram()
                    } label: {
                        Label("Heap", systemImage: "memorychip")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(sendStatus == .sending)

                    Button(role: .destructive) {
                        bridge.clearLogs()
                    } label: {
                        Label("Clear", systemImage: "trash")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                .padding(.horizontal)
                .padding(.top, 8)

                // Telegram send result detail — surfaced below the
                // button so the user can actually read why "Failed"
                // happened (Telegram block in RU, no token, HTTP 4xx,
                // …). Tappable: copies the message to the clipboard
                // so it can be pasted back to me for diagnosis.
                if let detail = sendStatusDetail {
                    Button {
                        UIPasteboard.general.string = detail
                    } label: {
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: detailIcon)
                                .foregroundStyle(detailColor)
                                .font(.caption)
                            Text(detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.leading)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            Image(systemName: "doc.on.doc")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal)
                    .padding(.bottom, 8)
                }
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

    private var sendStatusDetail: String? {
        switch sendStatus {
        case .failed(let msg): return "Telegram send failed: \(msg). Tap to copy."
        case .sent:            return "Sent ✓"
        default:               return nil
        }
    }

    private var detailIcon: String {
        switch sendStatus {
        case .failed: return "exclamationmark.triangle.fill"
        case .sent:   return "checkmark.circle.fill"
        default:      return "info.circle"
        }
    }

    private var detailColor: Color {
        switch sendStatus {
        case .failed: return .red
        case .sent:   return .green
        default:      return .secondary
        }
    }

    /// IPA-D9: dumps heap + goroutine profile NOW and uploads both as
    /// Telegram documents. Operator hits this button under load to get
    /// a snapshot of where memory is going.
    private func sendHeapToTelegram() {
        guard TelegramReporter.isConfigured else {
            sendStatus = .failed("Configure bot token in Telegram settings (gear icon).")
            return
        }
        sendStatus = .sending

        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: SamizdatBridge.appGroupID
        ) else {
            sendStatus = .failed("App Group container not available")
            return
        }
        let stamp = Int(Date().timeIntervalSince1970)
        let heapPath = containerURL.appendingPathComponent("heap-manual-\(stamp).pb.gz").path

        let heapErr = SocksstubWriteHeapProfile(heapPath)
        if !heapErr.isEmpty {
            sendStatus = .failed("WriteHeapProfile: \(heapErr)")
            return
        }

        guard let heapData = try? Data(contentsOf: URL(fileURLWithPath: heapPath)) else {
            sendStatus = .failed("Could not read heap profile back")
            return
        }

        let caption = TelegramReporter.defaultCaption(extra: "heap snapshot")
        let heapName = "heap-\(stamp).pb.gz"

        TelegramReporter.sendFile(
            data: heapData,
            filename: heapName,
            mimeType: "application/gzip",
            caption: caption
        ) { result in
            switch result {
            case .success:
                sendStatus = .sent
                DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
                    if case .sent = sendStatus { sendStatus = .idle }
                }
            case .failure(let err):
                sendStatus = .failed("heap: \(err.errorDescription ?? "unknown")")
            }
        }
    }

    private func sendToTelegram() {
        guard TelegramReporter.isConfigured else {
            sendStatus = .failed("Configure bot token in Telegram settings (gear icon).")
            return
        }
        sendStatus = .sending
        let body = filtered.joined(separator: "\n")
        let caption = TelegramReporter.defaultCaption(extra: "vpn=\(bridge.state.rawValue)")
        TelegramReporter.sendLog(text: body, caption: caption) { result in
            switch result {
            case .success:
                sendStatus = .sent
                // Auto-reset only success — user wants to see error
                // text long enough to read + copy it.
                DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
                    if case .sent = sendStatus { sendStatus = .idle }
                }
            case .failure(let err):
                // Surface error verbatim. No auto-reset — user dismisses
                // by tapping Telegram again or closing the sheet.
                sendStatus = .failed(err.errorDescription ?? "unknown error")
            }
        }
    }
}
