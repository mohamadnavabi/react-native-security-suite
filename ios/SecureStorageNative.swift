import Foundation

@available(iOS 13.0, *)
final class SecureStorageNative {
    static let shared = SecureStorageNative()
    private let service = "com.securitysuite.secure_storage"
    private let keyPrefix = "rss:"
    private let keychain = KeychainHelper.shared

    private init() {}

    private func namespacedKey(_ key: String) throws -> String {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw secureStorageError("Storage key is required")
        }
        return "\(keyPrefix)\(trimmed)"
    }

    private func secureStorageError(_ detail: String) -> NSError {
        NSError(
            domain: "SecureStorage",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Secure storage operation failed: \(detail)"]
        )
    }

    func setItem(key: String, value: String) throws {
        let data = Data(value.utf8)
        do {
            try keychain.save(data, service: service, account: try namespacedKey(key))
        } catch {
            throw secureStorageError(error.localizedDescription)
        }
    }

    func getItem(key: String) throws -> String? {
        do {
            guard let data = try keychain.load(service: service, account: try namespacedKey(key)) else {
                return nil
            }
            guard let value = String(data: data, encoding: .utf8) else {
                throw secureStorageError("Stored value is not valid UTF-8 text")
            }
            return value
        } catch let error as NSError where error.domain == "SecureStorage" {
            throw error
        } catch {
            throw secureStorageError(error.localizedDescription)
        }
    }

    func removeItem(key: String) throws {
        do {
            try keychain.delete(service: service, account: try namespacedKey(key))
        } catch {
            throw secureStorageError(error.localizedDescription)
        }
    }

    func getAllKeys() throws -> [String] {
        do {
            return try keychain
                .listAccounts(service: service)
                .filter { $0.hasPrefix(keyPrefix) }
                .map { String($0.dropFirst(keyPrefix.count)) }
                .sorted()
        } catch {
            throw secureStorageError(error.localizedDescription)
        }
    }

    func clear() throws {
        do {
            for key in try getAllKeys() {
                try removeItem(key: key)
            }
        } catch let error as NSError where error.domain == "SecureStorage" {
            throw error
        } catch {
            throw secureStorageError(error.localizedDescription)
        }
    }
}
