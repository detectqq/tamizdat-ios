import Foundation
import UIKit

/// Sends the current log buffer to a user-configured Telegram chat as a
/// `.txt` file via the Bot API. Credentials (bot token + chat ID) live
/// in `UserDefaults` and are entered via `TelegramSettingsView` — they
/// are NEVER stored in source control.
///
/// One-shot helper, no state. Call `send` from the main thread; result
/// is delivered on the main queue.
///
/// IMPORTANT: When the VPN tunnel is up and broken, every TCP egress
/// (including this Telegram POST) goes through the broken data plane
/// and times out. So this helper uses a per-request timeout of 10 s —
/// if the call fails because of the broken tunnel, `send` calls back
/// with `.failure` quickly and the user knows to disconnect the VPN
/// and try again.
enum TelegramReporter {

    // MARK: – Credential storage

    private static let tokenKey  = "telegram.botToken"
    private static let chatKey   = "telegram.chatID"

    static var botToken: String {
        get { UserDefaults.standard.string(forKey: tokenKey) ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: tokenKey) }
    }

    static var chatID: String {
        get { UserDefaults.standard.string(forKey: chatKey) ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: chatKey) }
    }

    static var isConfigured: Bool {
        let t = botToken.trimmingCharacters(in: .whitespacesAndNewlines)
        let c = chatID.trimmingCharacters(in: .whitespacesAndNewlines)
        return !t.isEmpty && !c.isEmpty
    }

    // MARK: – Errors

    enum SendError: LocalizedError {
        case notConfigured
        case http(Int, String)
        case transport(Error)
        case encoding

        var errorDescription: String? {
            switch self {
            case .notConfigured:
                return "Set bot token and chat ID first (gear icon)"
            case .http(let code, let body):
                return "HTTP \(code): \(body.prefix(200))"
            case .transport(let err):
                return "Transport: \(err.localizedDescription)"
            case .encoding:
                return "Could not encode log"
            }
        }
    }

    // MARK: – Send

    /// Sends `text` as a `.txt` document attached to a Telegram message.
    /// `caption` shows up next to the file in the chat.
    static func sendLog(
        text: String,
        caption: String,
        completion: @escaping (Result<Void, SendError>) -> Void
    ) {
        let token = botToken.trimmingCharacters(in: .whitespacesAndNewlines)
        let chat  = chatID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty, !chat.isEmpty else {
            DispatchQueue.main.async { completion(.failure(.notConfigured)) }
            return
        }
        guard let payload = text.data(using: .utf8) else {
            DispatchQueue.main.async { completion(.failure(.encoding)) }
            return
        }
        let url = URL(string: "https://api.telegram.org/bot\(token)/sendDocument")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let boundary = "Boundary-\(UUID().uuidString)"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

        var body = Data()
        func append(_ s: String) { body.append(Data(s.utf8)) }

        // chat_id
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n")
        append("\(chat)\r\n")

        // caption
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"caption\"\r\n\r\n")
        append("\(caption)\r\n")

        // document
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let filename = "samizdat-\(stamp).log"
        append("--\(boundary)\r\n")
        append("Content-Disposition: form-data; name=\"document\"; filename=\"\(filename)\"\r\n")
        append("Content-Type: text/plain; charset=utf-8\r\n\r\n")
        body.append(payload)
        append("\r\n--\(boundary)--\r\n")

        request.httpBody = body

        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 10
        cfg.timeoutIntervalForResource = 15
        let session = URLSession(configuration: cfg)

        session.dataTask(with: request) { data, response, error in
            session.finishTasksAndInvalidate()
            DispatchQueue.main.async {
                if let error {
                    completion(.failure(.transport(error)))
                    return
                }
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                if (200...299).contains(code) {
                    completion(.success(()))
                } else {
                    let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? "(empty)"
                    completion(.failure(.http(code, body)))
                }
            }
        }.resume()
    }

    /// Builds a one-line caption with device + app metadata.
    static func defaultCaption(extra: String? = nil) -> String {
        let device = UIDevice.current
        let bundle = Bundle.main.infoDictionary
        let app = bundle?["CFBundleShortVersionString"] as? String ?? "?"
        let build = bundle?["CFBundleVersion"] as? String ?? "?"
        var parts = [
            "Tamizdat \(app) (\(build))",
            "iOS \(device.systemVersion)",
            device.model,
        ]
        if let extra, !extra.isEmpty {
            parts.append(extra)
        }
        return parts.joined(separator: " · ")
    }
}
