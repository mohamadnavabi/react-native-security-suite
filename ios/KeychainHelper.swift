import Foundation
import Security

enum KeychainError: Error {
    case unexpectedStatus(OSStatus)
    case invalidData
}

@available(iOS 13.0, *)
final class KeychainHelper {
    static let shared = KeychainHelper()

    private init() {}

    func save(_ data: Data, service: String, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)

        var attributes = query
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    func load(service: String, account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.unexpectedStatus(status)
        }
        return data
    }

    func delete(service: String, account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    func listAccounts(service: String) throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }

        if let items = result as? [[String: Any]] {
            return items.compactMap { $0[kSecAttrAccount as String] as? String }
        }
        if let item = result as? [String: Any],
           let account = item[kSecAttrAccount as String] as? String {
            return [account]
        }
        return []
    }

    func saveECDHKeyPair(privateKey: Data, publicKey: Data) throws {
        try save(privateKey, service: "com.securitysuite.ecdh", account: "private")
        try save(publicKey, service: "com.securitysuite.ecdh", account: "public")
    }

    func loadECDHKeyPair() throws -> (privateKey: Data, publicKey: Data)? {
        guard let privateKey = try load(service: "com.securitysuite.ecdh", account: "private"),
              let publicKey = try load(service: "com.securitysuite.ecdh", account: "public") else {
            return nil
        }
        return (privateKey, publicKey)
    }
}
