import SwiftUI

struct ConfigPasteView: View {
    @Environment(\.dismiss) private var dismiss

    // IPA-P: split the stored combined URL on entry so the UI can show
    // two TextFields. On Save we compose them back into one Keychain
    // blob via SamizdatURLCodec.
    @State private var primary: String
    @State private var backup: String
    @State private var validationError: String?

    /// Called on dismiss with `true` if a config is now stored, `false` if cleared.
    var onClose: (Bool) -> Void

    init(onClose: @escaping (Bool) -> Void) {
        self.onClose = onClose
        let stored = ConfigStore.shared.load() ?? ""
        let split = SamizdatURLCodec.split(stored)
        _primary = State(initialValue: split.primary)
        _backup  = State(initialValue: split.backup ?? "")
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Paste your main samizdat:// config URL. Optionally paste a Whitelist URL — the app can fail over to it automatically when TSPU whitelist mode kicks in.")
                        .font(.callout)
                        .foregroundStyle(.secondary)

                    Text("Main")
                        .font(.subheadline.bold())

                    TextEditor(text: $primary)
                        .font(.body.monospaced())
                        .scrollContentBackground(.hidden)
                        .padding(8)
                        .background(
                            RoundedRectangle(cornerRadius: 10)
                                .fill(Color(.secondarySystemBackground))
                        )
                        .frame(minHeight: 120)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)

                    Text("Whitelist server (optional, for auto-failover)")
                        .font(.subheadline.bold())
                        .padding(.top, 4)

                    TextEditor(text: $backup)
                        .font(.body.monospaced())
                        .scrollContentBackground(.hidden)
                        .padding(8)
                        .background(
                            RoundedRectangle(cornerRadius: 10)
                                .fill(Color(.secondarySystemBackground))
                        )
                        .frame(minHeight: 120)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)

                    if let validationError {
                        Label(validationError, systemImage: "exclamationmark.triangle.fill")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }

                    HStack {
                        Menu {
                            Button("Paste into Main")      { pastePrimary() }
                            Button("Paste into Whitelist") { pasteBackup() }
                        } label: {
                            Label("Paste from clipboard", systemImage: "doc.on.clipboard")
                        }
                        .buttonStyle(.bordered)

                        Spacer()

                        Button(role: .destructive) {
                            ConfigStore.shared.delete()
                            primary = ""
                            backup = ""
                            validationError = nil
                        } label: {
                            Label("Clear", systemImage: "trash")
                        }
                        .buttonStyle(.bordered)
                        .disabled(primary.isEmpty && backup.isEmpty)
                    }

                    Spacer(minLength: 24)
                }
                .padding()
            }
            .navigationTitle("Configuration")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        onClose(ConfigStore.shared.load() != nil)
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .disabled(primary.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }

    // MARK: – actions

    private func pastePrimary() {
        guard let pasted = UIPasteboard.general.string else { return }
        primary = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
        validationError = nil
    }

    private func pasteBackup() {
        guard let pasted = UIPasteboard.general.string else { return }
        backup = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
        validationError = nil
    }

    private func save() {
        let p = primary.trimmingCharacters(in: .whitespacesAndNewlines)
        let b = backup.trimmingCharacters(in: .whitespacesAndNewlines)

        if let err = SamizdatBridge.validate(p) {
            validationError = "Main: \(err)"
            return
        }
        if !b.isEmpty {
            if let err = SamizdatBridge.validate(b) {
                validationError = "Whitelist: \(err)"
                return
            }
        }
        let combined = SamizdatURLCodec.compose(primary: p, backup: b.isEmpty ? nil : b)
        ConfigStore.shared.save(combined)
        onClose(true)
        dismiss()
    }
}

