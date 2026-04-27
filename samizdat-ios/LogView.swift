import SwiftUI

struct LogView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var bridge: SamizdatBridge

    @State private var filter: LogFilter = .all
    @State private var autoScroll = true
    @State private var copiedFlash = false

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
}
