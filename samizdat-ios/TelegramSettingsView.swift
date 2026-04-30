import SwiftUI
import UIKit

/// Form for entering the Telegram Bot API token + chat ID used by the
/// "Telegram" button in LogView. Stored in `UserDefaults` (not Keychain
/// — these are debug credentials, not user secrets, and we want them
/// trivially clearable).
struct TelegramSettingsView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var botToken: String = TelegramReporter.botToken
    @State private var chatID:   String = TelegramReporter.chatID
    @State private var testStatus: TestStatus = .idle

    enum TestStatus: Equatable {
        case idle, sending, ok, failed(String)

        var label: String {
            switch self {
            case .idle:    return "Send test message"
            case .sending: return "Sending…"
            case .ok:      return "Sent ✓"
            case .failed:  return "Failed"
            }
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Bot token", text: $botToken)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                    TextField("Chat ID", text: $chatID)
                        .keyboardType(.numbersAndPunctuation)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                } header: {
                    Text("Telegram destination")
                } footer: {
                    Text("""
                        Used by the "Telegram" button in Logs. Stored only on this device. \
                        Get a token from @BotFather; chat ID is the destination user/group/channel ID. \
                        For a private chat, send any message to your bot then visit \
                        https://api.telegram.org/bot<TOKEN>/getUpdates to find the chat id.
                        """)
                        .font(.caption)
                }

                if let status = footerStatus {
                    Section {
                        Text(status)
                            .font(.caption)
                            .foregroundStyle(testStatus == .ok ? .green : .red)
                    }
                }

                Section {
                    Button {
                        sendTest()
                    } label: {
                        Label(testStatus.label,
                              systemImage: testStatus == .ok
                                ? "checkmark.circle"
                                : "paperplane")
                    }
                    .disabled(testStatus == .sending || !looksValid)

                    Button(role: .destructive) {
                        TelegramReporter.botToken = ""
                        TelegramReporter.chatID = ""
                        botToken = ""
                        chatID = ""
                        testStatus = .idle
                    } label: {
                        Label("Clear", systemImage: "trash")
                    }
                }
            }
            .navigationTitle("Telegram")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        TelegramReporter.botToken = botToken
                        TelegramReporter.chatID   = chatID
                        dismiss()
                    }
                    .disabled(!looksValid)
                }
            }
        }
    }

    private var looksValid: Bool {
        let t = botToken.trimmingCharacters(in: .whitespacesAndNewlines)
        let c = chatID.trimmingCharacters(in: .whitespacesAndNewlines)
        // Telegram tokens look like "<digits>:<35-ish chars>".
        let tokenOK = t.contains(":") && t.count >= 30
        let chatOK  = !c.isEmpty
        return tokenOK && chatOK
    }

    private var footerStatus: String? {
        if case .failed(let msg) = testStatus { return msg }
        if case .ok = testStatus { return "Test message delivered." }
        return nil
    }

    private func sendTest() {
        // Persist before testing so TelegramReporter picks them up.
        TelegramReporter.botToken = botToken
        TelegramReporter.chatID   = chatID
        testStatus = .sending
        let caption = TelegramReporter.defaultCaption(extra: "test message")
        TelegramReporter.sendLog(text: "Samizdat Telegram test \(Date())\n",
                                 caption: caption) { result in
            switch result {
            case .success:
                testStatus = .ok
            case .failure(let err):
                testStatus = .failed(err.errorDescription ?? "?")
            }
        }
    }
}
