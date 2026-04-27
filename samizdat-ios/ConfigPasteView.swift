import SwiftUI

struct ConfigPasteView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var blob: String = ConfigStore.shared.load() ?? ""
    @State private var validationError: String?

    /// Called on dismiss with `true` if a config is now stored, `false` if cleared.
    var onClose: (Bool) -> Void

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Text("Paste a samizdat:// config URL.")
                    .font(.callout)
                    .foregroundStyle(.secondary)

                TextEditor(text: $blob)
                    .font(.body.monospaced())
                    .scrollContentBackground(.hidden)
                    .padding(8)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(Color(.secondarySystemBackground))
                    )
                    .frame(minHeight: 160)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)

                if let validationError {
                    Label(validationError, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }

                HStack {
                    Button {
                        if let pasted = UIPasteboard.general.string {
                            blob = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
                            validationError = nil
                        }
                    } label: {
                        Label("Paste from clipboard", systemImage: "doc.on.clipboard")
                    }
                    .buttonStyle(.bordered)

                    Spacer()

                    Button(role: .destructive) {
                        ConfigStore.shared.delete()
                        blob = ""
                        validationError = nil
                    } label: {
                        Label("Clear", systemImage: "trash")
                    }
                    .buttonStyle(.bordered)
                    .disabled(blob.isEmpty)
                }

                Spacer()
            }
            .padding()
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
                    Button("Save") {
                        let trimmed = blob.trimmingCharacters(in: .whitespacesAndNewlines)
                        if let err = SamizdatBridge.validate(trimmed) {
                            validationError = err
                            return
                        }
                        ConfigStore.shared.save(trimmed)
                        onClose(true)
                        dismiss()
                    }
                    .disabled(blob.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}
