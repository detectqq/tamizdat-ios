import Foundation
import Security

/// ConfigStore persists the samizdat:// config blob in the iOS Keychain so it
/// survives reinstalls and is encrypted at rest. The blob contains a server
/// pubkey and short-id which, while not strictly secret, are sensitive
/// enough to warrant Keychain rather than UserDefaults.
final class ConfigStore {
    static let shared = ConfigStore()

    private let service = "com.anarki.samizdat-test.config"
    private let account = "samizdat-url"

    func load() -> String? {
        let q: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     service,
            kSecAttrAccount as String:     account,
            kSecReturnData as String:      true,
            kSecMatchLimit as String:      kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    func save(_ blob: String) -> Bool {
        guard let data = blob.data(using: .utf8) else { return false }
        let q: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        // Try update first; if not found, add.
        let attrs: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(q as CFDictionary, attrs as CFDictionary)
        if status == errSecSuccess { return true }
        if status == errSecItemNotFound {
            var add = q
            add[kSecValueData as String] = data
            return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
        }
        return false
    }

    @discardableResult
    func delete() -> Bool {
        let q: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(q as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
